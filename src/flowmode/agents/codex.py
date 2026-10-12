"""Codex wire formats: Claude-compatible stdin fields and envelopes, Codex tool names (apply_patch, shell lists),
and the `.codex/hooks.json` / `$CODEX_HOME/config.toml` files written by `flowmode install codex`."""

import json
import os
import re
import tomllib
from pathlib import Path

from flowmode.agents import claude
from flowmode.agents.claude import (
    ClaudeAdapter,
    flowmode_hook_groups,
    merge_hooks,
    read_json,
    refuse_links,
    write_json,
)
from flowmode.hooks import HookRequest
from flowmode.member_config import MemberConfig, _toml_str

FILE_TOOLS = ("Edit", "Write")
PATCH_TOOLS = ("apply_patch",)
COMMAND_TOOLS = ("Bash", "shell", "local_shell", "exec_command", "container.exec")
PATCH_PATH = re.compile(r"^\*\*\* (?:Add File|Update File|Delete File|Move to): (.+?)\s*$", re.MULTILINE)
TOOL_MATCHER = "Bash|apply_patch|Edit|Write"
HOOK_EVENTS = tuple(
    (name, event, TOOL_MATCHER if matcher else None, timeout) for name, event, matcher, timeout in claude.HOOK_EVENTS
)
# a `[table]` / `[[array]]` header line; commas excluded so array rows like `[1, 2],` never match
TOML_HEADER = re.compile(r"^\[\[?\s*([^\[\],]+?)\s*\]\]?\s*(?:#.*)?$")
HOOKS_KEY = re.compile(r"""^\s*["']?hooks["']?\s*=""")


def codex_home() -> Path:
    """$CODEX_HOME, else $HOME/.codex."""
    return Path(os.environ["CODEX_HOME"]) if os.environ.get("CODEX_HOME") else Path.home() / ".codex"


def _table_name(line: str) -> str | None:
    m = TOML_HEADER.match(line)
    return ".".join(part.strip().strip("\"'") for part in m.group(1).split(".")) if m else None


def _blocks(text: str) -> list[list[str]]:
    """[preamble lines, then one line list per header block (header first)]."""
    blocks: list[list[str]] = [[]]
    for line in text.splitlines():
        if _table_name(line) is not None:
            blocks.append([])
        blocks[-1].append(line)
    return blocks


def _with_hooks_true(block: list[str]) -> list[str]:
    for i, line in enumerate(block):
        if HOOKS_KEY.match(line):
            return [*block[:i], "hooks = true", *block[i + 1 :]]
    last = max(i for i, line in enumerate(block) if line.strip())
    return [*block[: last + 1], "hooks = true", *block[last + 1 :]]


def merge_codex_config(text: str, server_url: str) -> str:
    """`text` with `[features] hooks = true` and our `[mcp_servers.flowmode]` block; everything else kept verbatim.
    ValueError if `text` (or the result) is not valid TOML."""
    tomllib.loads(text)
    ours = [
        "[mcp_servers.flowmode]",
        f"url = {_toml_str(server_url + '/mcp')}",
        'bearer_token_env_var = "FLOWMODE_TOKEN"',
    ]
    lines, found = [], set()
    for block in _blocks(text):
        name = _table_name(block[0]) if block and not block[0].startswith("[[") else None
        kept = block
        if name == "features":
            kept = _with_hooks_true(block)
        elif name == "mcp_servers.flowmode":
            trailing = len(block) - 1 - max(j for j, line in enumerate(block) if line.strip())
            kept = ours + [""] * trailing
        found.add(name)
        lines += kept
    for name, block in (("features", ["[features]", "hooks = true"]), ("mcp_servers.flowmode", ours)):
        if name not in found:
            lines += ([""] if lines and lines[-1].strip() else []) + block
    merged = "\n".join(lines) + "\n"
    try:
        cfg = tomllib.loads(merged)
        ok = cfg["features"]["hooks"] is True and cfg["mcp_servers"]["flowmode"] == {
            "url": server_url + "/mcp",
            "bearer_token_env_var": "FLOWMODE_TOKEN",
        }
    except (tomllib.TOMLDecodeError, KeyError, TypeError):
        ok = False
    if not ok:
        raise ValueError("cannot add [features] hooks / [mcp_servers.flowmode] textually; edit it by hand")
    return merged


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)


def patch_paths(tool_input: dict) -> list[str]:
    """Paths named by apply_patch markers in any string of tool_input (field name unverified), deduplicated."""
    paths = [m for text in _strings(tool_input) for m in PATCH_PATH.findall(text)]
    return list(dict.fromkeys(paths))


def _command(tool_input: dict) -> str | None:
    cmd = tool_input.get("command", tool_input.get("cmd"))
    if isinstance(cmd, str):
        return cmd
    if isinstance(cmd, list) and all(isinstance(part, str) for part in cmd):
        return " ".join(cmd)
    return None


class CodexAdapter(ClaudeAdapter):
    name = "codex"
    skills_dir = ".agents/skills"  # S11 F-11-01

    def parse(self, event: str, stdin_text: str) -> HookRequest:
        req = super().parse(event, stdin_text)  # common fields, agent=self.name
        tool_input = json.loads(stdin_text).get("tool_input")
        tool_input = tool_input if isinstance(tool_input, dict) else {}
        req.file_paths, req.command, req.new_text, req.file_input = [], None, "", {}
        if req.tool_name in FILE_TOOLS and isinstance(tool_input.get("file_path"), str):
            req.file_paths = [tool_input["file_path"]]
            req.new_text = claude.new_file_text(tool_input)
        elif req.tool_name in PATCH_TOOLS:
            req.file_paths = patch_paths(tool_input)
            # the lines the patch adds (S20 F-20-81 reads them for hooksPath)
            req.new_text = "\n".join(ln for t in _strings(tool_input) for ln in t.splitlines() if ln.startswith("+"))
        elif req.tool_name in COMMAND_TOOLS:
            req.command = _command(tool_input)
        if req.file_paths:
            req.file_input = tool_input  # F-20-88: the agent hooks' new text
        return req

    def install(self, repo: Path, cfg: MemberConfig) -> tuple[list[Path], list[str]]:
        """Merge hooks into <repo>/.codex/hooks.json; enable hooks + the MCP server in $CODEX_HOME/config.toml."""
        hooks_path, config_path = repo / ".codex" / "hooks.json", codex_home() / "config.toml"
        refuse_links(repo, hooks_path)  # config.toml is the member's own file, outside the checkout
        data = read_json(hooks_path)  # validate both before writing either
        try:
            config = merge_codex_config(config_path.read_text() if config_path.exists() else "", cfg.server_url)
        except tomllib.TOMLDecodeError:
            raise ValueError(f"{config_path} is not valid TOML") from None
        except ValueError as exc:
            raise ValueError(f"{config_path}: {exc}") from None
        data["hooks"] = merge_hooks(data.get("hooks") or {}, flowmode_hook_groups(self.name, HOOK_EVENTS))
        write_json(hooks_path, data)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(config)
        return [hooks_path, config_path], [
            "next: Codex asks once to trust this repo's hooks (.codex/hooks.json) — approve it when prompted",
            (
                "next: start with  flowmode work ; only if you start codex yourself, export FLOWMODE_TOKEN in that"
                ' shell first, e.g.  eval "$(flowmode env)"'
            ),
        ]
