"""Member-side config: $FLOWMODE_HOME/config.toml (server URL + personal token), env overrides."""

import json
import os
import re
import secrets
import tomllib
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field, field_validator

from flowmode.shared import flowmode_home

# S17 F-17-31: the prefixes of the retired member tokens and approver keys (the server mints neither any more)
OLD_TOKEN_PREFIXES = ("fm_", "fma_")


class NotConfigured(Exception):
    """No server URL + token from the config file or the environment (run `flowmode login --server <url>`)."""


class MemberConfig(BaseModel):
    server_url: str
    token: str
    approval_timeout_seconds: int = Field(300, ge=1, le=3600)
    request_timeout_seconds: float = 5.0

    @field_validator("server_url")
    @classmethod
    def _http_url(cls, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            raise ValueError("server_url must start with http:// or https://")
        return url.rstrip("/")


def config_path() -> Path:
    return flowmode_home() / "config.toml"


def load_member_config() -> MemberConfig | None:
    """File (if present) < FLOWMODE_SERVER_URL / FLOWMODE_TOKEN env. None when url or token is missing."""
    path = config_path()
    data = tomllib.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    for env, key in (("FLOWMODE_SERVER_URL", "server_url"), ("FLOWMODE_TOKEN", "token")):
        if os.environ.get(env):
            data[key] = os.environ[env]
    if not data.get("server_url") or not data.get("token"):
        return None
    return MemberConfig(**data)


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


def _config_text(server_url: str, token: str, approval_timeout_seconds: int, request_timeout_seconds: float) -> str:
    return (
        f"server_url = {_toml_str(server_url)}\n"
        f"token = {_toml_str(token)}\n"
        f"approval_timeout_seconds = {int(approval_timeout_seconds)}\n"
        f"request_timeout_seconds = {float(request_timeout_seconds)}\n"
    )


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


def save_member_config(cfg: MemberConfig) -> Path:
    """Write the 4 keys as TOML by hand, mode 0600, atomically."""
    return _write_config(
        _config_text(cfg.server_url, cfg.token, cfg.approval_timeout_seconds, cfg.request_timeout_seconds)
    )


def remove_member_token() -> Path | None:
    """S14 F-14-13 (`flowmode logout`): the config keeps its server and timeouts, its token emptied (not configured
    until the next login or init); the old file is backed up first, without the token (it may still be valid on the
    server when the server could not be told). The backup's path; None when the file held no token (nothing
    written)."""
    try:
        data = tomllib.loads(config_path().read_text(encoding="utf-8"))
    except (FileNotFoundError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return None
    if not data.get("token"):
        return None
    try:
        kept = MemberConfig(**{**data, "token": ""})
        text = _config_text(kept.server_url, "", kept.approval_timeout_seconds, kept.request_timeout_seconds)
    except ValueError:  # a hand-edited file outside the rules: the token goes all the same
        text = _config_text(str(data.get("server_url") or ""), "", 300, 5.0)
    backup = backup_member_config(without=str(data["token"]))
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
