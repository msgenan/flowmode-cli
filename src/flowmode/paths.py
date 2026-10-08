"""Claim path validation shared by the REST routes and the MCP tools; the symlink guard of the files Flowmode writes
into a checkout (skills, agent config)."""

import fnmatch
import functools
import os
import posixpath
import re
import unicodedata
from pathlib import Path

from flowmode.limits import MAX_PATH_LEN

MAX_PATH_BYTES = 4096  # S13 F-13-20: a repo path's UTF-8 size (git allows more; nothing real comes near it)
_UNSEEN = frozenset({"Cc", "Cf", "Zl", "Zp"})  # controls, format (bidi, zero-width), line and paragraph separators


def claim_path(path: str) -> str:
    """Repo-relative POSIX path, normalised (`./a//b` → `a/b`). ValueError for empty, absolute, `..`, or NUL."""
    if not path or path.startswith("/") or "\0" in path:
        raise ValueError("path must be a non-empty repo-relative path")
    norm = posixpath.normpath(path)
    if ".." in path.split("/") or ".." in norm.split("/") or norm == ".":
        raise ValueError("path must stay inside the repo")
    return norm


def valid_repo_path(path) -> bool:
    """S13 F-13-20 (security.md S13-04): a path from a member's tree or a pull request's `touches`, as git lists it —
    1 to MAX_PATH_LEN characters and at most MAX_PATH_BYTES in UTF-8, no leading `/`, no empty, `.` or `..` segment,
    no character that prints as nothing or moves the text (Unicode Cc, Cf, Zl, Zp). Never normalised: a path that is
    not already in git's form is dropped, not rewritten."""
    if not isinstance(path, str) or not 1 <= len(path) <= MAX_PATH_LEN or path.startswith("/"):
        return False
    try:
        if len(path.encode("utf-8")) > MAX_PATH_BYTES:
            return False
    except UnicodeEncodeError:  # a lone surrogate
        return False
    if any(segment in ("", ".", "..") for segment in path.split("/")):
        return False
    return not any(unicodedata.category(ch) in _UNSEEN for ch in path)


# S14 F-14-05 (D-16, CODE-11): names that usually hold a secret, matched case-insensitively on the last segment
_SECRET_NAMES = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.p8",
    "*.jks",
    "*.keystore",
    "*.ppk",
    "*.kdbx",
    "id_rsa*",
    "id_dsa*",
    "id_ecdsa*",
    "id_ed25519*",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "_netrc",
    ".git-credentials",
    ".htpasswd",
    ".dockercfg",
    "credentials*",
    "*credentials.json",
    "secrets.*",
    "service-account*.json",
    "*.tfstate",
    "*.tfstate.*",
    "*.tfvars",
)
_ENV_TEMPLATES = (".env.example", ".env.*.example", ".env.sample", ".env.template")  # shared on purpose, kept
_SECRET_FOLDERS = frozenset({".ssh", ".aws", ".gnupg", ".docker"})  # anything under one of these


def _globs(patterns) -> re.Pattern:
    return re.compile("|".join(fnmatch.translate(p) for p in patterns))


_SECRET_RE = _globs(_SECRET_NAMES)
_TEMPLATE_RE = _globs(_ENV_TEMPLATES)


@functools.lru_cache(maxsize=16)
def _extra_re(extra: tuple[str, ...]) -> re.Pattern | None:
    return _globs(extra) if extra else None


def secret_looking(path: str, extra=()) -> bool:
    """S14 F-14-05: True for a path that is never reported to the server — a secret-looking name (`_SECRET_NAMES`,
    case-insensitive on the last segment, `.env` templates excepted), anything under `.ssh/`, `.aws/`, `.gnupg/` or
    `.docker/`, or a match of one of the repo's `tree_exclude` globs (`extra`: fnmatch, case-sensitive, on the full
    path and on the last segment). Pure."""
    *folders, name = path.split("/")
    low = name.lower()
    if any(folder.lower() in _SECRET_FOLDERS for folder in folders):
        return True
    if _SECRET_RE.match(low) and not _TEMPLATE_RE.match(low):
        return True
    pattern = _extra_re(tuple(extra))
    return pattern is not None and bool(pattern.match(path) or pattern.match(name))


def symlink_on_the_way(root: Path, path: Path) -> Path | None:
    """The first symbolic link from `root` (exclusive: the checkout may live behind one) down to `path` (inclusive),
    dangling or not; `path` itself when it is not under `root`; None when a write to `path` stays inside `root`
    (review P1a-R2-1: a committed link must not make Flowmode write outside the checkout)."""
    try:
        rel = Path(path).relative_to(root)
    except ValueError:
        return Path(path)
    cur = Path(root)
    for part in rel.parts:
        cur = cur / part
        if part == ".." or cur.is_symlink():
            return cur
    return None


def write_no_follow(path: Path, data: bytes, *, replace: bool) -> None:
    """Write `data` to `path` without following a link at `path` (O_NOFOLLOW: a link made since the check fails
    with OSError instead of being written through). `replace` False: only a new file (O_EXCL)."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | (os.O_TRUNC if replace else os.O_EXCL)
    fd = os.open(path, flags, 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
