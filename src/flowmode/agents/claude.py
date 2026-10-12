"""Claude Code wire formats: hook stdin fields, the hookSpecificOutput stdout envelopes, and the
`.claude/settings.json` / `.mcp.json` files written by `flowmode install claude`."""

import json
from pathlib import Path

from flowmode.hooks import HookRequest, HookResponse, HookResult, fallback_external_id
from flowmode.member_config import MemberConfig
from flowmode.paths import symlink_on_the_way, write_no_follow

FILE_FIELDS = {"Edit": "file_path", "Write": "file_path", "MultiEdit": "file_path", "NotebookEdit": "notebook_path"}
READ_TOOL = "Read"  # S11 F-11-28: a finished Read gives HookRequest.read_path only — never a claim, never a denial
COMMAND_TOOLS = ("Bash",)
HOOK_PREFIX = "flowmode hook "
TOOL_MATCHER = "Edit|Write|MultiEdit|NotebookEdit|Bash"
# S20 L-6 (a): Claude's own attribution settings, turned off in the project settings by `flowmode install claude`
ATTRIBUTION_OFF: dict = {"attribution": {"commit": "", "pr": ""}, "includeCoAuthoredBy": False}
MCP_PREFIX = "mcp__flowmode__"  # Claude's name for the tools of the `flowmode` MCP server (.mcp.json)
# S9 §4.2 / §3.2: the hooks also look at these Flowmode MCP calls
PRE_MATCHER = TOOL_MATCHER + f"|{MCP_PREFIX}release"
POST_MATCHER = TOOL_MATCHER + f"|Read|{MCP_PREFIX}handoff"  # Read: the required reading is recorded (S11 F-11-28)
# S10 F-10-19: PreToolUse must outlive any approval wait. `.claude/settings.json` is committed and shared, so it cannot
# follow one member's setting: the longest wait `flowmode init` accepts (3600 s) plus a margin; the hook itself never
# waits longer than its member's approval_timeout_seconds.
PRE_TOOL_USE_TIMEOUT = 3600 + 60
# (settings event, flowmode event, matcher, timeout seconds)
HOOK_EVENTS = (
    ("SessionStart", "session-start", None, 30),
    ("PreToolUse", "pre-tool-use", PRE_MATCHER, PRE_TOOL_USE_TIMEOUT),
    ("PostToolUse", "post-tool-use", POST_MATCHER, 10),
    ("Stop", "stop", None, 10),
    ("SessionEnd", "session-end", None, 10),
)


def flowmode_hook_groups(agent: str, events=HOOK_EVENTS) -> dict[str, dict]:
    """{settings event: hook group} running `flowmode hook <event> --agent <agent>`."""
    groups = {}
    for name, event, matcher, timeout in events:
        group = {"matcher": matcher} if matcher else {}
        group["hooks"] = [{"type": "command", "command": f"{HOOK_PREFIX}{event} --agent {agent}", "timeout": timeout}]
        groups[name] = group
    return groups


def _is_flowmode(hook) -> bool:
    return isinstance(hook, dict) and str(hook.get("command", "")).startswith(HOOK_PREFIX)


def merge_hooks(hooks: dict, groups: dict[str, dict]) -> dict:
    """Drop every Flowmode hook (and groups left empty), keep everything else, then append `groups` once each."""
    merged = {}
    for event, event_groups in hooks.items():
        kept = []
        for group in event_groups:
            inner = group.get("hooks", []) if isinstance(group, dict) else []
            if not any(_is_flowmode(h) for h in inner):
                kept.append(group)
            elif rest := [h for h in inner if not _is_flowmode(h)]:
                kept.append({**group, "hooks": rest})
        if kept:
            merged[event] = kept
    for event, group in groups.items():
        merged.setdefault(event, []).append(group)
    return merged


def merge_mcp(mcp: dict, server_url: str) -> dict:
    """Add the Flowmode HTTP server; the token is referenced as ${FLOWMODE_TOKEN}, never written."""
    servers = dict(mcp.get("mcpServers") or {})
    servers["flowmode"] = {
        "type": "http",
        "url": f"{server_url}/mcp",
        "headers": {"Authorization": "Bearer ${FLOWMODE_TOKEN}"},
    }
    return {**mcp, "mcpServers": servers}


def read_json(path: Path) -> dict:
    """Existing JSON object at `path`, {} if missing; ValueError if it is not a JSON object."""
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text() or "{}")
    except json.JSONDecodeError:
        data = None
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a valid JSON object")  # noqa: TRY004 — install's contract is ValueError
    return data


def refuse_links(repo: Path, *paths: Path) -> None:
    """ValueError when a config file Flowmode writes into the checkout is a symbolic link or lies under one (F-11-41
    round 3, as the skills: a committed link must not make Flowmode write outside the checkout). Called before
    anything is read or written, so a refusal leaves every file as it was."""

    def name(p: Path) -> Path:
        return p.relative_to(repo) if p.is_relative_to(repo) else p

    for path in paths:
        if (link := symlink_on_the_way(repo, path)) is not None:
            raise ValueError(
                f"{name(path)}: a symbolic link ({name(link)}) — flowmode does not write through it;"
                " replace it with a regular file"
            )


def write_json(path: Path, data: dict) -> None:
    """Write `data`; never through a link at `path` (O_NOFOLLOW; `refuse_links` checked the way there)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    write_no_follow(path, (json.dumps(data, indent=2) + "\n").encode("utf-8"), replace=True)


def _failed(response) -> bool:
    """A tool response that reports an error (MCP `isError`, or Claude's `is_error`)."""
    return isinstance(response, dict) and bool(response.get("isError") or response.get("is_error"))


def new_file_text(tool_input: dict) -> str:
    """The text a file tool would write: Write's `content`, Edit's `new_string`, MultiEdit's `edits[].new_string`,
    NotebookEdit's `new_source` (S20 F-20-81 reads it for hooksPath)."""
    parts = [tool_input.get(k) for k in ("content", "new_string", "new_source")]
    edits = tool_input.get("edits")
    if isinstance(edits, list):
        parts += [e.get("new_string") for e in edits if isinstance(e, dict)]
    return "\n".join(p for p in parts if isinstance(p, str))


class ClaudeAdapter:
    name = "claude"
    skills_dir = ".claude/skills"  # S11 F-11-01: where the shipped skills go

    def parse(self, event: str, stdin_text: str) -> HookRequest:
        data = json.loads(stdin_text)  # ValueError on bad JSON
        if not isinstance(data, dict):
            raise ValueError("hook stdin is not a JSON object")  # noqa: TRY004 — parse raises ValueError on bad input
        cwd = Path(data["cwd"]) if isinstance(data.get("cwd"), str) and data["cwd"] else Path.cwd()
        tool_name = data.get("tool_name") if isinstance(data.get("tool_name"), str) else None
        tool_input = data.get("tool_input") if isinstance(data.get("tool_input"), dict) else {}
        file_paths, command, new_text = [], None, ""
        if tool_name in FILE_FIELDS and isinstance(tool_input.get(FILE_FIELDS[tool_name]), str):
            file_paths = [tool_input[FILE_FIELDS[tool_name]]]
            new_text = new_file_text(tool_input)
        elif tool_name in COMMAND_TOOLS and isinstance(tool_input.get("command"), str):
            command = tool_input["command"]
        read_path = None
        if tool_name == READ_TOOL and event == "post-tool-use" and isinstance(tool_input.get("file_path"), str):
            read_path = tool_input["file_path"]
        mcp_tool = None
        if tool_name and tool_name.startswith(MCP_PREFIX):
            mcp_tool = tool_name[len(MCP_PREFIX) :]
        session_id = data.get("session_id")
        source = data.get("source") if isinstance(data.get("source"), str) else None
        return HookRequest(
            event=event,
            agent=self.name,
            external_id=session_id if isinstance(session_id, str) and session_id else fallback_external_id(cwd),
            cwd=cwd,
            tool_name=tool_name,
            file_paths=file_paths,
            command=command,
            read_path=read_path,
            source=source,
            mcp_tool=mcp_tool,
            tool_input=tool_input if mcp_tool else {},
            tool_failed=_failed(data.get("tool_response")),
            tool_response=data["tool_response"] if isinstance(data.get("tool_response"), dict) else {},
            new_text=new_text,
            file_input=tool_input if file_paths else {},
        )

    def render(self, req: HookRequest, resp: HookResponse) -> HookResult:
        stderr = resp.stderr + "\n" if resp.stderr else ""
        message = {}
        if resp.notice:  # S20 L-10, C1e: Claude Code shows `systemMessage` to the person, Codex gets stderr
            if self.name == "claude":
                message = {"systemMessage": resp.notice}
            else:
                stderr += resp.notice + "\n"
        if resp.decision is not None:
            out = {
                "hookEventName": "PreToolUse",
                "permissionDecision": resp.decision,
                "permissionDecisionReason": resp.reason,
            }
        elif req.event == "session-start":
            out = {"hookEventName": "SessionStart", "additionalContext": resp.context}
        elif req.event == "post-tool-use" and resp.context:  # notes to this agent (S7 §9)
            out = {"hookEventName": "PostToolUse", "additionalContext": resp.context}
        else:
            stdout = json.dumps(message) + "\n" if message else ""
            return HookResult(exit_code=0, stdout=stdout, stderr=stderr)
        return HookResult(exit_code=0, stdout=json.dumps({**message, "hookSpecificOutput": out}) + "\n", stderr=stderr)

    def install(self, repo: Path, cfg: MemberConfig) -> tuple[list[Path], list[str]]:
        """Merge hooks into <repo>/.claude/settings.json and the MCP server into <repo>/.mcp.json."""
        settings_path, mcp_path = repo / ".claude" / "settings.json", repo / ".mcp.json"
        refuse_links(repo, settings_path, mcp_path)
        settings, mcp = read_json(settings_path), read_json(mcp_path)  # validate both before writing either
        settings["hooks"] = merge_hooks(settings.get("hooks") or {}, flowmode_hook_groups(self.name))
        # S20 L-6 (a): Claude adds no co-author trailer or "Generated with" line to commits and pull requests
        replaced = [k for k, v in ATTRIBUTION_OFF.items() if k in settings and settings[k] != v]
        settings.update(ATTRIBUTION_OFF)
        write_json(settings_path, settings)
        write_json(mcp_path, merge_mcp(mcp, cfg.server_url))
        note = (
            f"note: replaced your {', '.join(replaced)} in .claude/{settings_path.name}: this team's commits and pull"
            " requests never name an agent as author or co-author"
        )
        notes = [note] if replaced else []
        return [settings_path, mcp_path], [
            *notes,
            (
                "next: start with  flowmode work ; only if you start claude yourself, export FLOWMODE_TOKEN in that"
                ' shell first, e.g.  eval "$(flowmode env)"'
            ),
        ]
