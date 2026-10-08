"""Repo identity from `.git` metadata (pure Python, never the git binary) and repo-relative paths (S2 §4)."""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

_URL = re.compile(r"^\s*url\s*=\s*(.+?)\s*$")
# S11 F-11-26: the clone forms of one repository. Host case never matters; user info and an ssh/https port are not
# part of the identity; the path keeps its case (GitHub folds it, other hosts may not).
_HOST = r"(?P<host>[A-Za-z0-9.-]+)"
_SCP = re.compile(rf"^(?:[A-Za-z0-9._-]+@)?{_HOST}:(?P<path>[^/].*)$")  # git@github.com:o/r.git
_SCHEME = re.compile(rf"^(?:ssh|git|https?)://(?:[^@/]+@)?{_HOST}(?::\d+)?/(?P<path>.+)$")  # https://github.com/o/r


def canonical_repo(url: str | None) -> str:
    """One identity for every clone form of a hosted repository (S11 F-11-26): the scp-like SSH form with `.git`
    and a lower-cased host — `git@github.com:acme/app.git` for `https://github.com/acme/app/`,
    `ssh://git@github.com:22/acme/app`, `git@GitHub.com:acme/app`… Anything else (a local path, `file://`, a bare
    `acme/app`) is returned as it is, stripped and without a trailing slash. Idempotent."""
    text = (url or "").strip().rstrip("/")
    m = _SCP.fullmatch(text) or _SCHEME.fullmatch(text)
    if m is None or "/" not in m["path"].rstrip("/"):
        return text
    path = m["path"].strip("/").removesuffix(".git").rstrip("/")
    if not path or ":" in path:
        return text
    return f"git@{m['host'].lower()}:{path}.git"


@dataclass
class RepoInfo:
    root: Path
    repo: str
    branch: str | None
    detached: bool = field(default=False, compare=False)  # HEAD is a commit, not a branch (S9 §2)
    origin: str | None = field(default=None, compare=False)  # the origin URL as written (S11 F-11-26)
    broken: str | None = field(default=None, compare=False)  # `.git` names a missing gitdir (moved, S11 F-11-31)
    default_branch: str | None = field(default=None, compare=False)  # what origin/HEAD says (S11 F-11-32)

    @property
    def on_default_branch(self) -> bool:
        return self.default_branch is not None and self.branch == self.default_branch

    def repair_hint(self) -> str:
        """The one line every surface prints for a moved checkout."""
        return (
            f"this checkout was moved: {self.root}/.git points at {self.broken}, which does not exist. Run"
            f"  git worktree repair {self.root}  in the main checkout and start the agent again"
        )


def _read(path: Path) -> str | None:
    try:
        return path.read_text()
    except (OSError, UnicodeDecodeError):
        return None


def _gitdir(root: Path) -> Path | None:
    dot_git = root / ".git"
    if dot_git.is_dir():
        return dot_git
    text = _read(dot_git) or ""
    if not text.startswith("gitdir:"):
        return None
    return root / text[len("gitdir:") :].strip()  # an absolute target replaces root


def _branch(gitdir: Path) -> str | None:
    """The branch HEAD points at; None for a detached HEAD (a commit is not a branch, S10 F-10-07)."""
    head = (_read(gitdir / "HEAD") or "").strip()
    if head.startswith("ref:"):
        ref = head[len("ref:") :].strip()
        return ref.removeprefix("refs/heads/") or None
    return None


def _origin_url(commondir: Path) -> str | None:
    section = None
    for line in (_read(commondir / "config") or "").splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            section = stripped
            continue
        match = _URL.match(line)
        if match and section == '[remote "origin"]':
            return match.group(1)
    return None


def _default_branch(commondir: Path) -> str | None:
    """S11 F-11-32: the branch `refs/remotes/origin/HEAD` points at — what the clone knows as the remote's default.
    Nothing else is guessed: a checkout without it (a `git init` + `remote add`) has no default branch here."""
    head = (_read(commondir / "refs" / "remotes" / "origin" / "HEAD") or "").strip()
    if head.startswith("ref:"):
        return head[len("ref:") :].strip().removeprefix("refs/remotes/origin/") or None
    return None


def _commondir(gitdir: Path) -> Path:
    commondir_text = (_read(gitdir / "commondir") or "").strip()
    return gitdir / commondir_text if commondir_text else gitdir


def origin_url(root: Path) -> str | None:
    """The `origin` URL of the checkout at `root` (a RepoInfo root); None without a checkout or an origin."""
    gitdir = _gitdir(Path(root))
    return _origin_url(_commondir(gitdir)) if gitdir is not None else None


def find_repo(cwd: Path) -> RepoInfo:
    cwd = Path(cwd)
    for root in (cwd, *cwd.parents):
        if (root / ".git").exists():
            break
    else:
        return RepoInfo(root=cwd, repo=cwd.name, branch=None)
    gitdir = _gitdir(root)
    if gitdir is None:
        return RepoInfo(root=root, repo=root.name, branch=None)
    if not gitdir.is_dir():  # S11 F-11-31: a `.git` file whose target moved away — never the folder name as the id
        return RepoInfo(root=root, repo=root.name, branch=None, broken=str(gitdir))
    head = (_read(gitdir / "HEAD") or "").strip()
    commondir = _commondir(gitdir)
    origin = _origin_url(commondir)
    return RepoInfo(
        root=root,
        repo=canonical_repo(origin) if origin else root.name,
        branch=_branch(gitdir),
        detached=bool(head) and not head.startswith("ref:"),
        origin=origin,
        default_branch=_default_branch(commondir),
    )


def is_checkout(info: RepoInfo) -> bool:
    """`find_repo` found a real `.git` (not the fallback for a plain directory)."""
    return (Path(info.root) / ".git").exists()


def relative_path(info: RepoInfo, cwd: Path, path: str) -> str | None:
    """Repo-relative POSIX path, or None when `path` lies outside the repo root (symlinks not resolved)."""
    full = Path(os.path.normpath(Path(cwd) / path))  # an absolute `path` replaces cwd
    try:
        rel = full.relative_to(info.root)
    except ValueError:
        return None
    return rel.as_posix() if rel.parts else None
