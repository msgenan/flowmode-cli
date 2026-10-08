"""The session watcher (S12 F-12-03, `security.md` R-3): a forgotten session ends when its agent process dies.

The session-start hook leaves one detached `flowmode watch --pid P --start S --cache C` per session: P is the agent
process (`CLAUDE_PID`, else the first `claude`/`codex` ancestor by name — the Codex side is unconfirmed), S its start
time (a reused pid is another process), C the hook's session cache. The argv never carries the token or the session
id: the session id is read from the cache, the token from the member config on disk, as the hooks do. While P lives
the watcher polls every few seconds and leaves as soon as the cache is gone or names another session or another
watcher (a resume starts a new one and stops the old). When P dies it reads the cache once more and ends the session
(`reason: watcher`) only if the cache still names the same session and this very watcher; any answer is final.
"""

import contextlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from flowmode.api_client import ApiClient, ApiError, ServerUnreachable
from flowmode.member_config import load_member_config

WATCH_EVERY = 5.0
AGENT_NAMES = ("claude", "codex")
MAX_ANCESTORS = 32
PS_TIMEOUT = 5.0
_GONE = object()  # the cache file does not exist (an unreadable one is only "not known now")


# --- the agent process -----------------------------------------------------------------------------------------


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _ps(pid: int, *fields: str) -> str | None:
    """`ps` columns of one process without headers; None when it is not there (or ps cannot run)."""
    columns = [arg for field in fields for arg in ("-o", f"{field}=")]
    try:
        out = subprocess.run(
            ["ps", *columns, "-p", str(pid)],
            capture_output=True,
            text=True,
            timeout=PS_TIMEOUT,
            stdin=subprocess.DEVNULL,
            check=False,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    return out or None


def _proc_stat(pid: int) -> list[str] | None:
    """Linux: the fields of /proc/<pid>/stat after the command name (field 3 on); None elsewhere."""
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    _, _, rest = text.rpartition(")")  # field 2 is the name in parentheses, which may hold spaces or ')'
    return rest.split() or None


def start_time(pid: int) -> str | None:
    """The process start time the watcher is keyed on: /proc/<pid>/stat field 22 (ticks since boot) on Linux, else
    `ps -o lstart=` (macOS). None when the process is not there."""
    stat = _proc_stat(pid)
    if stat and len(stat) > 19:
        return stat[19]
    return _ps(pid, "lstart")


def same_process(pid: int, start: str) -> bool | None:
    """True: `pid` is the process that started at `start`; False: it is not (dead, or the pid was reused); None: its
    start time cannot be read right now (never taken as a death)."""
    if not alive(pid):
        return False
    stat = _proc_stat(pid)
    if stat and len(stat) > 19 and stat[19] == start:
        return True
    lstart = _ps(pid, "lstart")  # a caller that keyed it on `ps` (on Linux too)
    return None if lstart is None else lstart == start


def _parent_and_name(pid: int) -> tuple[int, str] | None:
    stat = _proc_stat(pid)
    if stat and len(stat) > 1:
        try:
            name = Path(f"/proc/{pid}/comm").read_text().strip()
            return int(stat[1]), name
        except (OSError, ValueError):
            return None
    out = _ps(pid, "ppid", "comm")
    if not out:
        return None
    ppid, _, comm = out.partition(" ")
    try:
        return int(ppid), Path(comm.strip()).name
    except ValueError:
        return None


def agent_pid(agent: str) -> int | None:
    """The agent process this hook runs under: `CLAUDE_PID` (Claude Code exports it to its hooks), else the first
    ancestor named `claude` or `codex` (Codex: unconfirmed, D-9), else None (no watcher)."""
    if agent == "claude":
        try:
            pid = int(os.environ.get("CLAUDE_PID", ""))
        except ValueError:
            pid = 0
        if pid > 1 and alive(pid):
            return pid
    pid = os.getppid()
    for _ in range(MAX_ANCESTORS):
        if pid <= 1:
            return None
        found = _parent_and_name(pid)
        if found is None:
            return None
        ppid, name = found
        if name in AGENT_NAMES:
            return pid
        pid = ppid
    return None


# --- spawning and stopping (the session-start hook) ----------------------------------------------------------


def spawn(pid: int, start: str, cache: Path) -> int | None:
    """Start a detached watcher for `pid`; its pid, or None. Its stdio is /dev/null and it runs in its own session:
    a child holding the hook's stdout pipe would hang the hook (and the agent) until it exits (`code.md` §3.3)."""
    try:
        child = subprocess.Popen(
            [sys.executable, "-m", "flowmode", "watch", "--pid", str(pid), "--start", start, "--cache", str(cache)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
        )
    except OSError:
        return None
    return child.pid


def stop(pid: object) -> None:
    """SIGTERM an earlier watcher — only when `pid` is still a `flowmode watch` process (a pid may be reused)."""
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1 or pid == os.getpid():
        return
    args = _ps(pid, "args")
    if not args or "flowmode watch" not in args:
        return
    with contextlib.suppress(OSError):
        os.kill(pid, signal.SIGTERM)


# --- the watcher itself ------------------------------------------------------------------------------------------


def _read(cache: Path) -> object:
    """The cache as a dict, _GONE when the file is missing, None when it cannot be read or parsed right now (a
    write in progress)."""
    try:
        data = json.loads(cache.read_text())
    except FileNotFoundError:
        return _GONE
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _settled(cache: Path, tries: int = 5) -> object:
    for _ in range(tries):
        data = _read(cache)
        if data is not None:
            return data
        time.sleep(0.1)
    return None


def _superseded(data: object, session_id: str, me: int) -> bool:
    """The cache is gone, or names another session or another watcher (a watcher not yet written in is waited for)."""
    if data is _GONE:
        return True
    if not isinstance(data, dict):
        return False
    return data.get("session_id") != session_id or ("watcher_pid" in data and data["watcher_pid"] != me)


def watch(pid: int, start: str, cache: Path, every: float = WATCH_EVERY) -> int:
    """Always 0: a watcher that cannot vouch for the session leaves without a call."""
    first = _settled(cache)
    if not isinstance(first, dict) or not first.get("session_id"):
        return 0
    session_id = first["session_id"]
    me = os.getpid()
    if same_process(pid, start) is not True:
        return 0
    while True:
        time.sleep(max(every, 0.05))
        if not alive(pid) or same_process(pid, start) is False:
            break
        if _superseded(_read(cache), session_id, me):
            return 0
    final = _settled(cache)
    if not isinstance(final, dict) or final.get("session_id") != session_id or final.get("watcher_pid") != me:
        return 0
    _end(session_id)
    _forget(cache, session_id, me)
    return 0


def _end(session_id: str) -> None:
    cfg = load_member_config()
    if cfg is None:
        return
    client = ApiClient(cfg.server_url, cfg.token, timeout=cfg.request_timeout_seconds)
    try:
        client.end_session(session_id, reason="watcher")
    except (ApiError, ServerUnreachable):  # ended already (409), gone (404), or no server: no retry either way
        pass
    finally:
        client.close()


def _forget(cache: Path, session_id: str, me: int) -> None:
    """Drop this watcher's pid from the cache (the rest stays for a resume): a later resume must not signal a pid
    that another process may own by then."""
    data = _read(cache)
    if not isinstance(data, dict) or data.get("session_id") != session_id or data.get("watcher_pid") != me:
        return
    data.pop("watcher_pid", None)
    write_cache(cache, data)


def write_cache(cache: Path, data: dict) -> None:
    """Replace the cache in one step, so a watcher reading it never sees half a file."""
    tmp = cache.with_name(f".{cache.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data))
    os.replace(tmp, cache)
