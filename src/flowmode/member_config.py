"""Member-side config: $FLOWMODE_HOME/config.toml (server URL + device tokens), env overrides.

S19 §4.4: one computer, several workspaces. The file keeps its four v0.18 keys (top-level `token` = the first
workspace's token, so a v0.18 client reads it) and one `[workspaces.<id>]` table (`name`, `repo`, `token`) per
workspace. A command's token: `FLOWMODE_TOKEN` > `--workspace <id>` > the entry whose `repo` is the clone's origin
(case-insensitive) > the only entry > else `WorkspaceUnclear`, naming the entries (never a token)."""

import json
import os
import re
import secrets
import tomllib
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field, field_validator

from flowmode.refs import display_safe
from flowmode.repo import find_repo
from flowmode.shared import flowmode_home, public_repo, same_repo

# S17 F-17-31: the prefixes of the retired member tokens and approver keys (the server mints neither any more)
OLD_TOKEN_PREFIXES = ("fm_", "fma_")


class NotConfigured(Exception):
    """No server URL + token from the config file or the environment (run `flowmode login --server <url>`)."""


class WorkspaceUnclear(Exception):
    """S19 §4.4: config.toml holds several workspaces and nothing says which one this command is for. The message
    names each entry (id and name), never a token; it is raised before any request."""


# S19 §4.4 / L-12: the server's refusal codes (`auth.py`, L-9) a client turns into one "wrong workspace" sentence
WORKSPACE_REFUSALS = {
    (403, "no_workspace"): "this computer's token belongs to no workspace on the server (run flowmode login)",
    (409, "workspace_mismatch"): "this computer's token is for another workspace (run flowmode doctor)",
    (409, "repo_in_other_workspace"): "this clone's repo is the team repo of another workspace, not of this"
    " token's workspace (use flowmode --workspace <id>, or flowmode login in that workspace)",
}

_CLI = {"workspace": None}  # `flowmode --workspace <id>`, set once per command by cli.main (see choose_workspace)


class MemberConfig(BaseModel):
    server_url: str
    token: str
    approval_timeout_seconds: int = Field(300, ge=1, le=3600)
    request_timeout_seconds: float = 5.0
    workspace: str | None = None  # S19: the `[workspaces.<id>]` entry the token came from (None: env or v0.18 key)

    @field_validator("server_url")
    @classmethod
    def _http_url(cls, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            raise ValueError("server_url must start with http:// or https://")
        return url.rstrip("/")


def config_path() -> Path:
    return flowmode_home() / "config.toml"


def choose_workspace(workspace: str | None) -> None:
    """`cli.main` hands the global `--workspace <id>` here once per command (None when absent): the ~20 commands that
    load the config (tasks, review, sync, work, chat, …) then honour it without each taking the flag."""
    _CLI["workspace"] = workspace


def workspace_refusal(status: int, detail: object) -> str | None:
    """The one sentence for a 403/409 workspace refusal (never naming the other workspace); None for anything else."""
    return WORKSPACE_REFUSALS.get((status, detail)) if isinstance(detail, str) else None


def read_config_file() -> dict:
    """config.toml as it is on disk (no environment); {} when missing or unreadable."""
    try:
        return tomllib.loads(config_path().read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return {}


def workspace_entries(data: dict) -> dict[str, dict]:
    """The `[workspaces.<id>]` tables with a token, in file order: {id: {name, repo, token}} (strings; repo may be
    None). Anything else in the table is ignored."""
    tables = data.get("workspaces")
    entries: dict[str, dict] = {}
    for wid, entry in tables.items() if isinstance(tables, dict) else ():
        if isinstance(entry, dict) and isinstance(entry.get("token"), str) and entry["token"]:
            name, repo = entry.get("name"), entry.get("repo")
            entries[str(wid)] = {
                "name": name if isinstance(name, str) else "",
                "repo": repo if isinstance(repo, str) and repo else None,
                "token": entry["token"],
            }
    return entries


def entries_named(entries: dict[str, dict]) -> str:
    """`<id> (<name>)` of each entry, comma-separated: what a pick error says. Never a token."""
    named = [
        f"{display_safe(wid)} ({display_safe(e['name'])})" if e["name"] else display_safe(wid)
        for wid, e in entries.items()
    ]
    return ", ".join(named) or "none"


def orphan_token(data: dict) -> str | None:
    """A top-level token that is no entry's token while entries exist (a v0.18 sign-in whose workspace was never
    named, e.g. `/api/me` could not be reached at the upgrade): its workspace is unknown. Retired tokens are not
    counted (`old_token_hint` speaks for them)."""
    entries = workspace_entries(data)
    top = data.get("token")
    if not entries or not isinstance(top, str) or not top or top.startswith(OLD_TOKEN_PREFIXES):
        return None
    return None if any(e["token"] == top for e in entries.values()) else top


def pick_entry(data: dict, workspace: str | None, origin) -> tuple[str | None, str | None]:
    """(entry id, token) from the file's data: `workspace` (the flag) > the entry whose `repo` is the clone's origin
    (case-insensitive; `origin` is a zero-argument callable, asked only when needed) > the only candidate (an entry,
    or the v0.18 top-level token when there are no tables). An orphan top-level token (`orphan_token`) is a candidate
    of unknown workspace: with it, only the flag or an origin match chooses. Raises WorkspaceUnclear naming the
    entries otherwise (never a token); (None, None) when the file holds no token at all."""
    entries = workspace_entries(data)
    top = data.get("token") if isinstance(data.get("token"), str) and data.get("token") else None
    if workspace is not None:
        if workspace in entries:
            return workspace, entries[workspace]["token"]
        raise WorkspaceUnclear(
            f"no workspace with that id on this computer; its workspaces: {entries_named(entries)}"
            " (flowmode login adds one)"
        )
    if not entries:
        return None, top
    orphan = orphan_token(data)
    if len(entries) > 1 or orphan:
        repo = public_repo(origin())
        for wid, entry in entries.items():
            if repo and same_repo(entry["repo"], repo):
                return wid, entry["token"]
        if orphan:
            raise WorkspaceUnclear(
                "an older sign-in on this computer has no workspace yet and this clone's origin matches none of"
                f" {entries_named(entries)}: run flowmode login in this clone, or flowmode --workspace <id> <command>"
            )
        raise WorkspaceUnclear(
            "this computer has several workspaces and this clone's origin is none of their repos: run"
            f" flowmode --workspace <id> <command>, one of: {entries_named(entries)}"
        )
    ((wid, entry),) = entries.items()
    return wid, entry["token"]


def load_member_config(cwd: Path | None = None, workspace: str | None = None, *, cli_flag: bool = True):
    """File (if present) < FLOWMODE_SERVER_URL / FLOWMODE_TOKEN env; the token picked as the module docstring says
    (`cwd`'s clone, default the current directory; `workspace` or, with `cli_flag`, the command's `--workspace`).
    None when url or token is missing; WorkspaceUnclear when several entries leave the choice open."""
    data = read_config_file()
    if os.environ.get("FLOWMODE_SERVER_URL"):
        data["server_url"] = os.environ["FLOWMODE_SERVER_URL"]
    wid, token = None, os.environ.get("FLOWMODE_TOKEN") or None
    if token is None:
        flag = workspace if workspace is not None else (_CLI["workspace"] if cli_flag else None)
        wid, token = pick_entry(data, flag, lambda: find_repo(Path.cwd() if cwd is None else Path(cwd)).origin)
    if not data.get("server_url") or not token:
        return None
    fields = {k: data[k] for k in ("server_url", "approval_timeout_seconds", "request_timeout_seconds") if k in data}
    return MemberConfig(**fields, token=token, workspace=wid)


def old_token_hint(server_url: str, token: str) -> str | None:
    """S17 F-17-31.c: the one sentence for a config or FLOWMODE_TOKEN that still holds a retired member token or
    approver key (`fm_…` / `fma_…`) — the CLI, the hooks and `flowmode logout` say it and send nothing with it; None
    for any other token. Never names the token."""
    if not token.startswith(OLD_TOKEN_PREFIXES):
        return None
    return f"this is an old member token: run flowmode login --server {server_url or '<url>'}"


def _toml_str(value: str) -> str:
    """A TOML basic string. ensure_ascii=False avoids surrogate-pair escapes (invalid TOML); DEL must be escaped."""
    return json.dumps(value, ensure_ascii=False).replace("\x7f", "\\u007f")


_BARE_KEY = re.compile(r"[A-Za-z0-9_-]+")


def _config_text(
    server_url: str,
    token: str,
    approval_timeout_seconds: int,
    request_timeout_seconds: float,
    entries: dict[str, dict] | None = None,
) -> str:
    text = (
        f"server_url = {_toml_str(server_url)}\n"
        f"token = {_toml_str(token)}\n"
        f"approval_timeout_seconds = {int(approval_timeout_seconds)}\n"
        f"request_timeout_seconds = {float(request_timeout_seconds)}\n"
    )
    for wid, entry in (entries or {}).items():
        key = wid if _BARE_KEY.fullmatch(wid) else _toml_str(wid)
        text += f"\n[workspaces.{key}]\n"
        text += "".join(f"{k} = {_toml_str(entry[k])}\n" for k in ("name", "repo", "token") if entry.get(k))
    return text


def _write_config(text: str) -> Path:
    """S14 F-14-13 (CODE-15): the folder 0700, the text into a fresh 0600 file beside the config (`O_EXCL |
    O_NOFOLLOW`: never through a planted file or link), flushed, then `os.replace`d over it — a reader sees the old
    config or the new one, never half of one, and a symlink at the config's place is replaced, not followed."""
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    temp = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise
    return path


def save_member_config(cfg: MemberConfig, entries: dict[str, dict] | None = None) -> Path:
    """Write the 4 keys (and the workspace tables) as TOML by hand, mode 0600, atomically."""
    return _write_config(
        _config_text(cfg.server_url, cfg.token, cfg.approval_timeout_seconds, cfg.request_timeout_seconds, entries)
    )


def upsert_workspace(cfg: MemberConfig, wid: str, name: str, repo: str | None, old: dict) -> Path:
    """S19 §4.4 (`flowmode login`): write `cfg` with the entry `wid` = {name, repo, cfg.token} added or replaced in
    place; every other entry of `old` (the file as it was, same server) stays. The top-level token stays the first
    workspace's: the old one, unless it was this entry's old token, a retired one or empty."""
    entries = workspace_entries(old)
    replaced = entries.get(wid, {}).get("token")
    entries[wid] = {"name": name, "repo": repo, "token": cfg.token}
    top = old.get("token") if isinstance(old.get("token"), str) else ""
    if not top or top == replaced or top.startswith(OLD_TOKEN_PREFIXES):
        top = next(iter(entries.values()))["token"]
    return save_member_config(cfg.model_copy(update={"token": top}), entries)


def _text_of(data: dict, top: str, entries: dict[str, dict]) -> str:
    """The file text for `data`'s server and timeouts with `top` and `entries`."""
    try:
        cfg = MemberConfig(**{**data, "token": ""})
        return _config_text(cfg.server_url, top, cfg.approval_timeout_seconds, cfg.request_timeout_seconds, entries)
    except ValueError:  # a hand-edited file outside the rules: written with the defaults
        return _config_text(str(data.get("server_url") or ""), top, 300, 5.0, entries)


def set_workspace_repo(wid: str, repo: str) -> bool:
    """S19 §4.4: the team repo the server reported for entry `wid` (e.g. after `doctor --team-repo`) becomes the
    entry's `repo`, so its clones keep matching by origin. Rewrites the file (0600, atomic) only when it changes."""
    data = read_config_file()
    entries = workspace_entries(data)
    if wid not in entries or same_repo(entries[wid]["repo"], repo):
        return False
    entries[wid] = {**entries[wid], "repo": repo}
    _write_config(_text_of(data, data.get("token") if isinstance(data.get("token"), str) else "", entries))
    return True


def remove_member_token(token: str | None = None) -> Path | None:
    """S14 F-14-13 (`flowmode logout`): the config keeps its server and timeouts, `token` (default: the top-level one)
    removed — S19: its `[workspaces.<id>]` entry goes and the other entries stay; the top-level token becomes the
    next entry's, or empty (not configured until the next login). The old file is backed up first, without the token
    (it may still be valid on the server when the server could not be told). The backup's path; None when the file
    did not hold that token (nothing written)."""
    try:
        data = tomllib.loads(config_path().read_text(encoding="utf-8"))
    except (FileNotFoundError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return None
    token = token or (data.get("token") if isinstance(data.get("token"), str) else None)
    entries = workspace_entries(data)
    kept = {wid: e for wid, e in entries.items() if e["token"] != token}
    if not token or (data.get("token") != token and len(kept) == len(entries)):
        return None
    top = data.get("token") if data.get("token") != token else next((e["token"] for e in kept.values()), "")
    text = _text_of(data, top, kept)
    backup = backup_member_config(without=token)
    _write_config(text)
    return backup


BACKUPS_KEPT = 5
_BACKUP = re.compile(r"^config\.toml\.(\d{8}-\d{6})(?:-(\d+))?\.bak$")


def _utc_stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%d-%H%M%S")


def backup_member_config(without: str | None = None) -> Path | None:
    """F-12-01: keep the current config as `config.toml.<UTC YYYYmmdd-HHMMSS>[-N].bak` beside it before it is
    replaced. Created with O_EXCL and mode 0600 and filled with the old bytes (never a copy that would carry a looser
    source mode) — minus every occurrence of `without` (S14: `flowmode logout` keeps no token in its backup); only
    the newest BACKUPS_KEPT backups stay. None when there is no config to keep."""
    path = config_path()
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return None
    if without:
        data = data.replace(without.encode(), b"")
    stamp, n = _utc_stamp(), 0
    while True:
        bak = path.with_name(f"{path.name}.{stamp}{f'-{n}' if n else ''}.bak")
        try:
            fd = os.open(bak, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            break
        except FileExistsError:
            n += 1
    with os.fdopen(fd, "wb") as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(data)
    _prune_backups(path.parent)
    return bak


def _prune_backups(directory: Path) -> None:
    ours = []
    for p in directory.iterdir():
        if m := _BACKUP.match(p.name):
            ours.append(((m.group(1), int(m.group(2) or 0)), p))
    ours.sort()
    for _, p in ours[:-BACKUPS_KEPT]:
        p.unlink(missing_ok=True)
