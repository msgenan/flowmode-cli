"""$FLOWMODE_HOME/worktrees.json: which local worktree belongs to which task/handoff (S4 §6).
Pure JSON — no git, no HTTP — because hooks import it; a missing or corrupt file reads as empty."""

import contextlib
import json
import os
from pathlib import Path

from flowmode.shared import flowmode_home


def registry_path() -> Path:
    return flowmode_home() / "worktrees.json"


def _key(path) -> str:
    return str(Path(path).resolve())


def load_registry() -> dict[str, dict]:
    """{resolved worktree path: entry}; {} when the file is missing or unreadable."""
    try:
        data = json.loads(registry_path().read_text(encoding="utf-8"))
        worktrees = data["worktrees"]
    except (OSError, ValueError, TypeError, KeyError):
        return {}
    return {k: v for k, v in worktrees.items() if isinstance(v, dict)} if isinstance(worktrees, dict) else {}


def _save(worktrees: dict[str, dict]) -> None:
    path = registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"worktrees": worktrees}, f, indent=2)
        f.write("\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def register_worktree(path, entry: dict) -> None:
    """Add or replace the entry for `path`."""
    worktrees = load_registry()
    worktrees[_key(path)] = dict(entry)
    _save(worktrees)


def lookup_worktree(path, repo: str | None = None, branch: str | None = None) -> dict | None:
    """The entry keyed by `path`; on a miss (S11 F-11-31 b: the worktree moved) the entry with the same (repo,
    branch), re-keyed to `path` so the next lookup is direct."""
    from flowmode.repo import canonical_repo

    try:
        key = _key(path)
    except (OSError, RuntimeError):  # resolve() on a broken path / symlink loop
        return None
    worktrees = load_registry()
    if (entry := worktrees.get(key)) is not None:
        return entry
    if repo is None or branch is None:
        return None
    for old_key, entry in worktrees.items():
        if (
            canonical_repo(entry.get("repo")) == repo and entry.get("branch") == branch and not Path(old_key).exists()
        ):  # only a worktree that is gone from its old place
            del worktrees[old_key]
            worktrees[key] = dict(entry)
            with contextlib.suppress(OSError):
                _save(worktrees)
            return worktrees[key]
    return None


def find_worktree(task_id: str | None, repo: str | None, branch: str | None) -> str | None:
    """The registered worktree path of a task: by task_id, else by (repo, branch); None when unknown here."""
    from flowmode.repo import canonical_repo

    entries = load_registry()
    for path, e in entries.items():
        if task_id is not None and e.get("task_id") == task_id:
            return path
    for path, e in entries.items():
        if repo is not None and canonical_repo(e.get("repo")) == repo and e.get("branch") == branch:
            return path
    return None


def forget_worktree(path) -> None:
    worktrees = load_registry()
    if worktrees.pop(_key(path), None) is not None:
        _save(worktrees)
