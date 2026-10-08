"""S17 F-17-12: `flowmode doctor` — the repo report of card 3 (docs/slices/S17.md §4, §6 F-17-12, §10; INV-C2 §4).

`collect` gathers the §4 facts of the clone: whether it has an origin and its canonical form (hosted repositories
only: never a local path, never a remote's user info), the agents on PATH, their hooks (Claude: `.claude/settings.json`
+ `.mcp.json`; Codex: `.codex/hooks.json` **and** `$CODEX_HOME/config.toml`), whether those hook files are tracked in
git (`git ls-files` with fixed arguments, no shell), `gh` installed and signed in (`gh_ready`, `FLOWMODE_GH`
honoured), the CLI version and the OS. Nothing else leaves the computer: no file contents, no path.

`doctor_cmd` prints each fact with ✓/✗ and, for ✗, the fix from `shared.repo_fixes` (the one mapping the API
uses too), sends the report (`POST /api/me/facts`) and exits 0 only when card 3's rule is met and the report was
sent — 1 outside a git repo, with the rule unmet, or when the report could not be sent (one line says so).
`send_after_install` is `flowmode install`'s best-effort copy: one line either way, never a failure.

Every home it reads moves with its variable: FLOWMODE_HOME (config.toml), CODEX_HOME, GH_CONFIG_DIR / XDG_CONFIG_HOME,
HOME."""

import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import flowmode
from flowmode import shared
from flowmode.agents.claude import HOOK_PREFIX
from flowmode.agents.codex import codex_home
from flowmode.github_cli import gh_ready
from flowmode.member_config import MemberConfig, load_member_config, old_token_hint
from flowmode.refs import display_safe
from flowmode.repo import find_repo, is_checkout

GIT_TIMEOUT_SECONDS = 10
MAX_CONFIG_BYTES = 1_000_000  # a hook file larger than this is not ours: not read
_LABEL_DROP = re.compile(r"[^A-Za-z0-9 ._+()/-]")  # what the route accepts in a version or an OS name
NOT_SIGNED_IN = "this computer is not signed in (run flowmode login)"
TEAM_REPO_UNKNOWN = "the team repo"


# --- the facts ---------------------------------------------------------------------------------------------------------


def _json(path: Path) -> dict:
    """A regular file's JSON object, {} for anything else (missing, too large, not JSON, a FIFO or a device)."""
    try:
        if not path.is_file() or path.stat().st_size > MAX_CONFIG_BYTES:
            return {}
        data = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _has_flowmode_hook(path: Path) -> bool:
    """A hooks file (Claude's settings or Codex's hooks.json) with at least one `flowmode hook …` command."""
    hooks = _json(path).get("hooks")
    groups = (
        [g for event in hooks.values() if isinstance(event, list) for g in event] if isinstance(hooks, dict) else []
    )
    return any(
        isinstance(hook, dict) and str(hook.get("command", "")).startswith(HOOK_PREFIX)
        for group in groups
        if isinstance(group, dict) and isinstance(group.get("hooks"), list)
        for hook in group["hooks"]
    )


def _claude_hooks(root: Path) -> bool:
    servers = _json(root / ".mcp.json").get("mcpServers")
    return _has_flowmode_hook(root / ".claude" / "settings.json") and isinstance(
        servers.get("flowmode") if isinstance(servers, dict) else None, dict
    )


def _codex_home_config() -> bool:
    """`$CODEX_HOME/config.toml` enables hooks and names the flowmode MCP server (what `flowmode install codex` writes
    outside the clone: a Codex member cannot skip it — INV-C2 trap 7)."""
    path = codex_home() / "config.toml"
    try:
        if not path.is_file() or path.stat().st_size > MAX_CONFIG_BYTES:
            return False
        config = tomllib.loads(path.read_text())
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return False
    features, servers = config.get("features"), config.get("mcp_servers")
    return (
        isinstance(features, dict)
        and features.get("hooks") is True
        and isinstance(servers, dict)
        and isinstance(servers.get("flowmode"), dict)
    )


def _tracked(root: Path, paths: list[str]) -> bool:
    """Every one of `paths` (fixed names from `shared.HOOK_FILES`) is tracked in the clone's git index. git runs
    with fixed arguments, no shell, the clone as its directory and no GIT_* variable (it never reads another repo)."""
    if not paths:
        return False
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    try:
        done = subprocess.run(
            ["git", "ls-files", "--", *paths],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return done.returncode == 0 and set(paths) <= set(done.stdout.splitlines())


def _gh_installed() -> bool:
    named = os.environ.get("FLOWMODE_GH")
    return bool(shutil.which(named) if named else shutil.which("gh"))


def _label(text: str, limit: int) -> str:
    return _LABEL_DROP.sub("", text)[:limit]


def collect(root: Path, origin: str | None) -> dict:
    """The §4 facts body of the clone at `root` whose origin URL is `origin` (as written; only its canonical hosted
    form is kept)."""
    agents = {agent: shutil.which(agent) is not None for agent in shared.AGENTS}
    hooks = {
        "claude": _claude_hooks(root),
        "codex": _has_flowmode_hook(root / ".codex" / "hooks.json") and _codex_home_config(),
    }
    ready = [agent for agent in shared.AGENTS if agents[agent] and hooks[agent]]
    return {
        "repo": shared.public_repo(origin),
        "origin": origin is not None,
        "hooks": hooks,
        "hooks_tracked": _tracked(root, [path for agent in ready for path in shared.HOOK_FILES[agent]]),
        "gh": {"installed": _gh_installed(), "signed_in": gh_ready()},
        "agents": agents,
        "cli_version": _label(flowmode.__version__, 64),
        "os": _label(f"{platform.system()} {platform.machine()}".strip(), 100),
    }


# --- sending -----------------------------------------------------------------------------------------------------------


def _why(exc: Exception, cfg: MemberConfig) -> str:
    """One terminal-safe reason a call failed; never the token."""
    from flowmode.api_client import ApiError, ServerUnreachable

    if isinstance(exc, ServerUnreachable):
        return f"could not reach {cfg.server_url} ({exc})"
    if isinstance(exc, ApiError):
        if exc.status == 401:
            return f"token rejected by {cfg.server_url}"
        detail = exc.detail if exc.status != 422 else "the server refused the report's fields"
        return f"{detail} ({exc.status})"
    return type(exc).__name__


def send(cfg: MemberConfig | None, body: dict, best_effort: bool = False) -> tuple[dict | None, str | None]:
    """(the facts route's answer, a JSON object, None) or (None, why it was not sent). Never raises: a send is one
    outcome."""
    from flowmode.api_client import ApiClient

    if cfg is None:
        return None, NOT_SIGNED_IN
    if old := old_token_hint(cfg.server_url, cfg.token):  # S17 F-17-31: nothing is sent with it
        return None, old
    client = None
    try:
        client = ApiClient(cfg.server_url, cfg.token, timeout=cfg.request_timeout_seconds)
        answer = client.post_facts(body, best_effort=best_effort)
    except Exception as exc:  # noqa: BLE001 — any failure is the one "not sent" line, never a traceback
        return None, display_safe(_why(exc, cfg))
    finally:
        if client is not None:
            client.close()
    if not isinstance(answer, dict):
        return None, "the server's answer was not understood"
    return answer, None


def _outcome(answer: dict) -> tuple[str, str | None, bool, bool]:
    """(card 3's state, the team repo, leader, whether this report set or changed the team repo) from an answer,
    whatever its fields hold."""
    card = answer.get("card")
    state = card.get("state") if isinstance(card, dict) else None
    team = answer.get("team_repo")
    team = shared.public_repo(team) if isinstance(team, str) else None
    return display_safe(str(state)), team, answer.get("leader") is True, answer.get("team_repo_changed") is True


def _team_line(team: str | None) -> str:
    return f"team repo set: {team} (your report as a leader)"


def _team_repo_hint(cfg: MemberConfig | None) -> str:
    """The team repo's clone URL from card 3's detail (best effort), for the "not in a git repo" line."""
    from flowmode.api_client import ApiClient

    if cfg is None:
        return TEAM_REPO_UNKNOWN
    client = None
    try:
        client = ApiClient(cfg.server_url, cfg.token, timeout=cfg.request_timeout_seconds)
        cards = client.my_cards(best_effort=True)
        team = next(c for c in cards["cards"] if c.get("card") == shared.REPO_CARD)["detail"]["team_repo"]
    except Exception:  # noqa: BLE001 — a hint only
        return TEAM_REPO_UNKNOWN
    finally:
        if client is not None:
            client.close()
    team = shared.public_repo(team) if isinstance(team, str) else None
    return shared.clone_url(team) if team else TEAM_REPO_UNKNOWN


def send_after_install(repo: Path, cfg: MemberConfig) -> None:
    """F-17-12.e: `flowmode install`'s report, best effort — one line either way (plus one when a leader's report set
    the team repo); a failure never fails the install. A directory that is not a git checkout has nothing to report."""
    try:
        info = find_repo(repo.resolve())
        if info.broken or not is_checkout(info):
            return
        answer, why = send(cfg, collect(info.root, info.origin), best_effort=True)
    except Exception as exc:  # noqa: BLE001 — the install is done; its report is best effort
        answer, why = None, type(exc).__name__
    if answer is None:
        print(f"note: repo report not sent ({why}); run flowmode doctor in the clone later", file=sys.stderr)
        return
    state, team, _leader, changed = _outcome(answer)
    print(f"repo report sent: card 3 {state} (flowmode doctor shows each fact)")
    if changed:
        print(_team_line(team))


# --- printing ------------------------------------------------------------------------------------------------------


def _origin_line(facts: dict, team: str | None, sent: bool) -> str:
    if not facts["origin"]:
        return "origin: none"
    repo = facts["repo"]
    if repo is None:
        return "origin: not a hosted repository"
    if not sent:
        return f"origin: {repo}"
    if team is None:
        return f"origin: {repo} (the team repo is not set yet)"
    if repo == team:
        return f"origin: {repo} is the team repo"
    if shared.same_repo(repo, team):
        return f"origin: {repo} is the team repo {team} (it differs only in letter case: the same repository)"
    return f"origin: {repo} is not the team repo {team}"


def _older_line(facts: dict, answer: dict | None) -> str | None:
    """The one `!` line when the server's answer says this client is older than the server; a warning, not a fix."""
    client = answer.get("client") if answer else None
    if not isinstance(client, dict) or client.get("outdated") is not True or not isinstance(client.get("latest"), str):
        return None
    latest = display_safe(client["latest"])
    return f"! flowmode {facts['cli_version']} is older than this server's {latest}: git pull && ./setup.sh"


def _lines(facts: dict, fixes: list[dict], team: str | None, sent: bool, answer: dict | None = None) -> list[str]:
    """Each fact with ✓/✗, the fixes of a ✗ fact under it, then the old-client warning when the server sent one."""
    open_facts = {fix["fact"] for fix in fixes}
    names = shared.AGENT_NAMES
    gh = facts["gh"]
    rows = [("origin", "origin" not in open_facts and facts["repo"] is not None, _origin_line(facts, team, sent))]
    for agent in shared.AGENTS:
        rows.append((f"agents.{agent}", facts["agents"][agent], f"{agent} on PATH"))
        where = (
            ".claude/settings.json + .mcp.json" if agent == "claude" else ".codex/hooks.json + $CODEX_HOME/config.toml"
        )
        rows.append((f"hooks.{agent}", facts["hooks"][agent], f"{names[agent]} hooks ({where})"))
    rows += [
        ("hooks_tracked", facts["hooks_tracked"], "hook files tracked in git"),
        ("gh", gh["installed"] and gh["signed_in"], "gh installed and signed in"),
        ("cli", True, f"flowmode {facts['cli_version']}"),
        ("os", True, f"OS: {facts['os']}"),
    ]
    lines = []
    for key, ok, text in rows:
        lines.append(f"{'✓' if ok else '✗'} {text}")
        for fix in (f for f in fixes if f["fact"] == key):
            lines.append(f"    fix: {fix['command']}  ({fix['text']})" if "command" in fix else f"    {fix['text']}")
        if key == "cli" and (older := _older_line(facts, answer)):
            lines.append(older)
    return lines


def doctor_cmd(args) -> int:
    cfg = load_member_config()
    info = find_repo(Path.cwd())
    if info.broken:
        print(f"error: {info.repair_hint()}", file=sys.stderr)
        return 1
    if not is_checkout(info):
        print(f"not in a git repo: cd into your clone of {_team_repo_hint(cfg)}", file=sys.stderr)
        return 1
    facts = collect(info.root, info.origin)
    answer, why = send(cfg, {**facts, "set_team_repo": True} if args.team_repo else facts)
    sent = answer is not None
    state, team, leader, changed = _outcome(answer) if sent else ("", None, False, False)
    fixes = shared.repo_fixes(facts, team, leader, team_known=sent)
    if args.json:
        if sent:
            print(json.dumps(answer, indent=2))
    else:
        print("\n".join(_lines(facts, fixes, team, sent, answer)))
        if changed:
            print(_team_line(team))
        if sent:
            print(f"card 3: {state}")
    if not sent:
        print(f"report not sent: {why}", file=sys.stderr)
    return 0 if sent and not fixes else 1
