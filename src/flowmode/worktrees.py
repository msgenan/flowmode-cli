"""The git layer of `flowmode task …` (S4 §5): the only module that runs the git binary. Never pushes or pulls —
members touch the network with their own credentials; the one fetch (`fetch_branch`, one branch) is `flowmode work`'s
(S11 F-11-39), and the default branch's for the conflict check of `flowmode check` and session start (F-11-45),
short and best effort."""

import contextlib
import os
import re
import signal
import subprocess
from pathlib import Path

from flowmode.limits import MAX_PATH_LEN
from flowmode.paths import claim_path


class GitError(Exception):
    """git exited non-zero; str(exc) is its stderr, stripped."""

    def __init__(self, stderr: str, returncode: int):
        super().__init__(stderr.strip() or f"git exited with {returncode}")
        self.returncode = returncode


class GitTimeout(GitError):
    """git did not answer within the caller's timeout (a lock, a hung filesystem, a huge index)."""


HOOK_TIMEOUT = 2  # S10 F-10-05: seconds a hook-side git call may take; the first timeout ends the check


def _env(timed: bool) -> dict[str, str]:
    """git's environment: never prompt; a call that may be killed at its timeout also takes no optional lock, so a
    killed `git status` cannot leave `.git/index.lock` behind (S10 F-10-05)."""
    return {**os.environ, "GIT_TERMINAL_PROMPT": "0", **({"GIT_OPTIONAL_LOCKS": "0"} if timed else {})}


def _git(cwd: Path, *args: str, timeout: float | None = None, strip: bool = True) -> str:
    """stdout of `git args` in `cwd` (stripped unless `strip` is False: a `-z` listing keeps its leading status
    column). No timeout by default (the CLI's own calls: a person is watching); a hook passes one, and a git that
    does not answer in time is a GitTimeout."""
    try:
        r = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_env(timeout is not None),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise GitTimeout(f"git {args[0] if args else ''} timed out after {timeout:g} s", -1) from exc
    except OSError as exc:  # git missing, or cwd gone
        raise GitError(str(exc), -1) from exc
    if r.returncode != 0:
        raise GitError(r.stderr, r.returncode)
    return r.stdout.strip() if strip else r.stdout


def _succeeds(cwd: Path, *args: str, timeout: float | None = None) -> bool:
    """git exits 0; a timeout is not an answer and propagates (GitTimeout) so the caller stops there."""
    try:
        _git(cwd, *args, timeout=timeout)
    except GitTimeout:
        raise
    except GitError:
        return False
    return True


def git_root(cwd: Path) -> Path:
    """Top of the work tree containing `cwd` (a linked worktree's own root). GitError outside a work tree."""
    return Path(_git(cwd, "rev-parse", "--show-toplevel"))


def main_root(cwd: Path) -> Path:
    """The main checkout: parent of the common git dir (from a linked worktree too)."""
    common = Path(_git(cwd, "rev-parse", "--git-common-dir"))
    return (Path(cwd) / common).resolve().parent  # an absolute `common` replaces cwd


def short_head(root: Path) -> str:
    """`git rev-parse --short HEAD`: the commit checked out at `root`. GitError when there is none yet."""
    return _git(root, "rev-parse", "--short", "HEAD")


def valid_branch_name(branch: str, cwd: Path | None = None) -> bool:
    """`git check-ref-format --branch` accepts it (works outside a repository too)."""
    return bool(branch) and _succeeds(cwd or Path.cwd(), "check-ref-format", "--branch", branch)


def branch_exists(root: Path, branch: str, *, timeout: float | None = None) -> bool:
    return _succeeds(root, "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}", timeout=timeout)


def remote_branch_exists(root: Path, branch: str, *, timeout: float | None = None) -> bool:
    return _succeeds(root, "rev-parse", "--verify", "--quiet", f"refs/remotes/origin/{branch}", timeout=timeout)


FETCH_TIMEOUT = 60  # seconds `fetch_branch` may take


BATCH_SSH = "ssh -o BatchMode=yes"  # ssh fails at once instead of asking (host key, passphrase, password)


def _batch_ssh(root: Path) -> tuple[str, ...]:
    """git options that keep an ssh fetch from waiting on a question nobody can answer (a hook has no terminal; the
    CLI's fetch is best effort too): `-c core.sshCommand=ssh -o BatchMode=yes` — unless the person chose their own
    ssh (GIT_SSH_COMMAND, core.sshCommand or GIT_SSH), which is left exactly as it is."""
    if os.environ.get("GIT_SSH_COMMAND") or os.environ.get("GIT_SSH"):
        return ()
    try:
        _git(root, "config", "--get", "core.sshCommand", timeout=HOOK_TIMEOUT)
    except GitTimeout:
        return ()  # could not tell: leave the person's setup alone
    except GitError:
        return ("-c", f"core.sshCommand={BATCH_SSH}")  # exit 1: not set
    return ()


GROUP_GRACE = 1.0  # seconds a timed-out fetch gets after SIGTERM to remove its lock files, before SIGKILL
# no tags, no FETCH_HEAD, no submodules, no maintenance: the fetch changes origin/<branch> and nothing else (git 2.29+)
FETCH_FLAGS = ("--quiet", "--no-tags", "--no-write-fetch-head", "--no-recurse-submodules", "--no-auto-maintenance")


def _run_group(cwd: Path, args: tuple[str, ...], timeout: float) -> tuple[str, str, int]:
    """`git args` in a process group of its own: (stdout, stderr, returncode). At the timeout the whole group is
    ended — SIGTERM first, so git removes its `*.lock` files (a ref it was writing stays usable for the person's own
    git), then SIGKILL for what is left after GROUP_GRACE (ssh, upload-pack, a hook) — and GitTimeout is raised."""
    try:
        proc = subprocess.Popen(
            ["git", *args],
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            text=True,
            env=_env(True),
            start_new_session=True,
        )
    except OSError as exc:  # git missing, or cwd gone
        raise GitError(str(exc), -1) from exc
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _end_group(proc)
        raise GitTimeout(f"git {args[0] if args else ''} timed out after {timeout:g} s", -1) from None
    return out, err, proc.returncode


def _end_group(proc: subprocess.Popen) -> None:
    for sig in (signal.SIGTERM, signal.SIGKILL):
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, sig)  # the group id is git's pid (start_new_session)
        try:
            proc.communicate(timeout=GROUP_GRACE)  # reaps git, drains the pipes
        except subprocess.TimeoutExpired:
            continue
        if sig == signal.SIGTERM:
            continue  # git is gone; SIGKILL whatever of its group is still there
        return
    proc.kill()  # a pipe held open by something outside the group: stop waiting for it
    proc.wait()


def fetch_branch(root: Path, branch: str, timeout: float = FETCH_TIMEOUT) -> bool:
    """S11 F-11-39: `git fetch origin <branch>` into origin/<branch> — the one network call of this module, made by
    `flowmode work`, `flowmode check` and session start (F-11-45, with a timeout of a few seconds) with the member's
    own credentials (never a prompt — it runs in a session of its own, without a terminal: no terminal prompt, ssh in
    batch mode unless the person set their own ssh). Only that ref changes (FETCH_FLAGS); a fetch cut off at `timeout` leaves no lock and no process behind
    (`_run_group`). True when origin/<branch> exists afterwards; a failed or slow fetch is False, never an error."""
    try:
        _, _err, code = _run_group(
            root,
            (*_batch_ssh(root), "fetch", *FETCH_FLAGS, "origin", f"+refs/heads/{branch}:refs/remotes/origin/{branch}"),
            timeout,
        )
        return code == 0 and remote_branch_exists(root, branch, timeout=min(timeout, HOOK_TIMEOUT))
    except GitError:
        return False


_TREE_ID = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")


def parse_merge_tree(returncode: int, stdout: str) -> list[str] | None:
    """S11 F-11-45: `git merge-tree --write-tree --name-only -z --no-messages` read — the tree id, then one path per
    conflicted file. Exit 0 is a clean merge ([]), exit 1 with a tree id a conflicted one (the paths, once each, in
    git's order); anything else — exit 1 without a tree id (an unknown revision), 128 (unrelated histories, a git
    older than 2.38) — is None: git could not say."""
    fields = stdout.split("\0")
    if returncode not in (0, 1) or not _TREE_ID.match(fields[0]):
        return None
    if returncode == 0:
        return []
    return list(dict.fromkeys(f for f in fields[1:] if f))


def merge_tree_conflicts(
    root: Path, base: str, head: str = "HEAD", *, timeout: float | None = None
) -> list[str] | None:
    """S11 F-11-45: the files a merge of `base` into `head` would leave in conflict — `git merge-tree --write-tree`,
    which only writes objects: the working tree, the index, HEAD, every ref and the stash stay as they are. [] when it
    merges cleanly; None when git could not say (see parse_merge_tree) or did not answer within `timeout`."""
    try:
        r = subprocess.run(
            ["git", "merge-tree", "--write-tree", "--name-only", "-z", "--no-messages", base, head],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_env(timeout is not None),
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError, ValueError):  # ValueError: a path that is not text
        return None
    return parse_merge_tree(r.returncode, r.stdout)


def add_worktree(
    root: Path,
    path: Path,
    branch: str,
    *,
    base: str | None = None,
    track_remote: bool = False,
    detach: bool = False,
    start_point: str | None = None,
) -> None:
    """Existing branch → check it out as is; else track origin/<branch>; else a new branch from `base` (HEAD).
    S12 F-12-13: `detach` → a detached HEAD at `start_point` (default origin/<branch>), no branch at all: git refuses a
    second checkout of a branch the author still has out, a detached worktree of its commit is always allowed."""
    if detach:
        _git(root, "worktree", "add", "--detach", str(path), start_point or f"origin/{branch}")
    elif branch_exists(root, branch):
        _git(root, "worktree", "add", str(path), branch)
    elif track_remote:
        _git(root, "worktree", "add", "--track", "-b", branch, str(path), f"origin/{branch}")
    else:
        _git(root, "worktree", "add", "-b", branch, str(path), base or "HEAD")


def remove_worktree(root: Path, path: Path, *, delete_branch: str | None = None) -> None:
    _git(root, "worktree", "remove", "--force", str(path))
    if delete_branch:
        _git(root, "branch", "-D", delete_branch)


def parse_worktree_list(porcelain: str) -> list[dict]:
    """`git worktree list --porcelain` → [{"path": Path, "branch": str | None, "head": str}] (detached: None)."""
    result, cur = [], {}
    for line in [*porcelain.splitlines(), ""]:
        if not line:
            if cur:
                result.append({"branch": None, "head": "", **cur})
            cur = {}
            continue
        key, _, value = line.partition(" ")
        if key == "worktree":
            cur["path"] = Path(value)
        elif key == "HEAD":
            cur["head"] = value
        elif key == "branch":
            cur["branch"] = value.removeprefix("refs/heads/")
    return result


def list_worktrees(root: Path) -> list[dict]:
    return parse_worktree_list(_git(root, "worktree", "list", "--porcelain"))


def default_worktree_dir(main_root: Path, name: str) -> Path:
    """Sibling directory of the main checkout: <parent>/<main name>-worktrees/<name with / as ->."""
    main_root = Path(main_root)
    return main_root.parent / f"{main_root.name}-worktrees" / name.replace("/", "-")


def change_context(cwd: Path, pushing: bool) -> tuple[str | None, int | None]:
    """S8 §5 / S9 §9: (diffstat, commits ahead) of the checkout at `cwd` for an approval request. Not a push: `git
    diff --shortstat HEAD` (None when clean), no count. A push: diffstat and count of `<base>..HEAD`, the base being
    the upstream, else origin/HEAD; (None, None) without either. Never raises: any git failure gives None, and the
    first slow git (2 s) ends it with (None, None)."""
    try:
        return _change_context(cwd, pushing)
    except GitTimeout:
        return None, None


def _change_context(cwd: Path, pushing: bool) -> tuple[str | None, int | None]:
    def run(*args: str) -> str | None:
        out = _quick(cwd, *args)
        return out.strip() if out is not None else None

    if not pushing:
        diffstat = run("diff", "--shortstat", "HEAD") or None
        return (diffstat[:200] if diffstat else None), None
    # S9 §9 (amendment A2): a push sends commits, not the working tree — what lies between its base and HEAD
    base = next(
        (
            b
            for b in ("@{upstream}", "refs/remotes/origin/HEAD")
            if run("rev-parse", "--verify", "--quiet", b) is not None
        ),
        None,
    )
    if base is None:
        return None, None
    diffstat = run("diff", "--shortstat", f"{base}..HEAD") or None
    count = run("rev-list", "--count", f"{base}..HEAD")
    ahead = int(count) if count and count.isdigit() else None
    return (diffstat[:200] if diffstat else None), ahead


def _quick_run(cwd: Path, args: tuple[str, ...], *, text: bool) -> subprocess.CompletedProcess | None:
    try:
        r = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            capture_output=True,
            text=text,
            timeout=HOOK_TIMEOUT,
            env=_env(True),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise GitTimeout(f"git {args[0] if args else ''} timed out after {HOOK_TIMEOUT:g} s", -1) from exc
    except (OSError, subprocess.SubprocessError):
        return None
    return r if r.returncode == 0 else None


def _quick(cwd: Path, *args: str) -> str | None:
    """git with a HOOK_TIMEOUT limit for the hooks: stdout, or None on any failure; GitTimeout when git does not
    answer in time, so the caller stops at the first timeout."""
    r = _quick_run(cwd, args, text=True)
    return r.stdout if r is not None else None


def _quick_z(cwd: Path, *args: str) -> list[str] | None:
    """`_quick` for a `-z` command: its NUL-separated fields, UTF-8 (bytes that are not stay as surrogates, so the
    fields keep their places and `_claimable` drops them); None on any failure."""
    r = _quick_run(cwd, args, text=False)
    if r is None:
        return None
    return [field.decode("utf-8", "surrogateescape") for field in r.stdout.split(b"\0") if field]


def _claimable(path: str) -> str | None:
    """`path` as `claim_path` normalises it, or None when the server would refuse it or no claim could match it."""
    try:
        path.encode("utf-8")
        return claim_path(path) if len(path) <= MAX_PATH_LEN else None
    except (UnicodeEncodeError, ValueError):
        return None


def changed_paths(root: Path, limit: int = 50) -> list[str]:
    """S9 §6: files with uncommitted changes (untracked included) and files changed in commits not on the upstream
    (else origin/HEAD) — repo-relative, sorted, at most `limit`; [] on any git failure and at the first timeout.
    S10 F-10-09: read with `-z` (real names: non-ASCII letters, quotes, tabs), a rename by its new name, and only
    paths `claim_path` accepts."""
    try:
        return _changed_paths(root, limit)
    except GitTimeout:
        return []


def _changed_paths(root: Path, limit: int) -> list[str]:
    names: list[str] = []
    fields = iter(_quick_z(root, "status", "--porcelain", "-z", "--untracked-files=all") or [])
    for entry in fields:  # `XY path`; a rename or copy is followed by its source, which is not a change of ours
        if len(entry) > 3:
            names.append(entry[3:])
        if "R" in entry[:2] or "C" in entry[:2]:
            next(fields, None)
    for base in ("@{upstream}", "refs/remotes/origin/HEAD"):
        if _quick(root, "rev-parse", "--verify", "--quiet", base) is not None:
            names.extend(_quick_z(root, "diff", "--name-only", "-z", f"{base}...HEAD") or [])
            break
    found = {path for path in map(_claimable, names) if path}
    return sorted(found)[:limit]


def has_changes(root: Path, path: str) -> bool | None:
    """S9 §4.2: `path` (repo-relative) is modified, staged or untracked in the checkout at `root`; None on a git
    error or when git does not answer within HOOK_TIMEOUT (it runs in the PreToolUse hook)."""
    try:
        return bool(_git(root, "status", "--porcelain", "--", path, timeout=HOOK_TIMEOUT))
    except GitError:
        return None


def changes_in_checkouts(root: Path, cwd: Path, path: str) -> bool | None:
    """S10 F-10-10: `path` has changes (modified, staged or untracked) in the checkout at `root` or in the checkout
    holding `cwd`, when that is another worktree of the same repository (both are in the `git worktree list` of
    either). A git error on one checkout skips it; None at the first timeout — the check ends there (F-10-05). At most
    five git calls (status, rev-parse, the worktree list from one root and, if that fails, the other, status), each
    within HOOK_TIMEOUT."""
    try:
        return _changes_in_checkouts(root, cwd, path)
    except GitTimeout:
        return None


def _resolved(path: str | Path) -> Path | None:
    try:
        return Path(path).resolve()
    except (OSError, RuntimeError):
        return None


def _changes_in_checkouts(root: Path, cwd: Path, path: str) -> bool:
    if _quick(root, "status", "--porcelain", "--", path):
        return True
    top = _quick(cwd, "rev-parse", "--show-toplevel")
    here, mine = _resolved(top.strip()) if top else None, _resolved(root)
    if here is None or mine is None or here == mine:
        return False
    listed = _quick(root, "worktree", "list", "--porcelain") or _quick(here, "worktree", "list", "--porcelain")
    if not listed or not {here, mine} <= {_resolved(w["path"]) for w in parse_worktree_list(listed)}:
        return False
    return bool(_quick(here, "status", "--porcelain", "--", path))


def remote_ref_matches(root: Path, branch: str) -> bool | None:
    """S11 F-11-30: after a push, `refs/remotes/origin/<branch>` names the same commit as `refs/heads/<branch>` in
    the checkout at `root` (git updates the remote-tracking ref only when the push went through). None when git
    cannot answer (no such branch, a timeout)."""
    try:
        local = _quick(root, "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}")
        remote = _quick(root, "rev-parse", "--verify", "--quiet", f"refs/remotes/origin/{branch}")
    except GitTimeout:
        return None
    if local is None:
        return None
    return remote is not None and remote.strip() == local.strip()


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


# S10 F-10-18: what `flowmode install` writes into a repository — untracked, it is setup, not work left behind
FLOWMODE_CONFIG_FILES = frozenset({".claude/settings.json", ".mcp.json", ".codex/hooks.json"})
# S11 F-11-01: the shipped skills, where `install claude` / `install codex` put them — exactly these files, so a
# person's own skill or another file in those folders is still work to commit
FLOWMODE_SKILLS = ("flow-start", "flow-sync", "flow-handoff", "flow-review", "flow-blocked")
FLOWMODE_SKILL_ROOTS = (".claude/skills", ".agents/skills")
FLOWMODE_SKILL_FILES = tuple(f"{root}/{name}/SKILL.md" for root in FLOWMODE_SKILL_ROOTS for name in FLOWMODE_SKILLS)


def _is_setup(name: str) -> bool:
    return name in FLOWMODE_CONFIG_FILES or name in FLOWMODE_SKILL_FILES


def uncommitted_files(status_z: str) -> list[str]:
    """The files of a `git status --porcelain -z --untracked-files=all` listing, repo-relative, in git's order: a
    rename or copy by its new name (its source is not a change of ours), untracked Flowmode config left out."""
    names: list[str] = []
    fields = iter(field for field in status_z.split("\0") if field)
    for entry in fields:
        code, name = entry[:2], entry[3:]
        if "R" in code or "C" in code:
            next(fields, None)
        if name and not (code == "??" and _is_setup(name)):
            names.append(name)
    return names


def branch_state(root: Path, branch: str | None, *, timeout: float | None = HOOK_TIMEOUT) -> dict | None:
    """S9 §3: where `branch` stands against origin, from local refs only (never the network).
    {"on_remote", "ahead", "uncommitted", "files"} — `files` the uncommitted ones by name (S10 F-10-18, see
    `uncommitted_files`), `uncommitted` their count; None when the branch is not in this checkout or git fails. Each
    git call has `timeout` (HOOK_TIMEOUT: the PostToolUse hook runs this; the CLI passes None) and the first timeout
    ends it: one stuck git, one wait."""
    if not branch:
        return None
    t = timeout
    try:
        if not branch_exists(root, branch, timeout=t):
            return None
        merge = (
            _git(root, "config", "--get", f"branch.{branch}.merge", timeout=t)
            if _succeeds(root, "config", "--get", f"branch.{branch}.merge", timeout=t)
            else ""
        )
        tracks_itself = merge == f"refs/heads/{branch}" and _succeeds(
            root, "rev-parse", "--verify", "--quiet", f"{branch}@{{upstream}}", timeout=t
        )
        base = (
            f"{branch}@{{upstream}}"
            if tracks_itself
            else (f"refs/remotes/origin/{branch}" if remote_branch_exists(root, branch, timeout=t) else None)
        )
        ahead = int(_git(root, "rev-list", "--count", f"{base}..refs/heads/{branch}", timeout=t)) if base else None
        files = uncommitted_files(
            _git(root, "status", "--porcelain", "-z", "--untracked-files=all", timeout=t, strip=False)
        )
    except (GitError, ValueError):
        return None
    return {"on_remote": base is not None, "ahead": ahead, "uncommitted": len(files), "files": files}


def _named(files: list[str], shown: int = 3) -> str:
    """S10 F-10-18: ` (a.txt, src/new.py, src/second.py and 2 more)` — the first `shown` names; '' without names."""
    if not files:
        return ""
    rest = len(files) - shown
    return f" ({', '.join(files[:shown])}{f' and {rest} more' if rest > 0 else ''})"


def push_hints(state: dict | None, branch: str, to: str | None, asks_approval: bool) -> list[tuple[str, str]]:
    """S9 §3.1: the (key, sentence) pairs a handoff shows for `state` — `push` and/or `uncommitted` (naming up to
    three files, S10 F-10-18); [] when all is committed and on the remote (or the branch is unknown here)."""
    if state is None:
        return []
    ask = "  (it asks the team for approval)" if asks_approval else ""
    hints = []
    if not state["on_remote"]:
        hints.append(
            (
                "push",
                (
                    f"branch '{branch}' is not on origin yet — ask your person to run  git push -u origin"
                    f" {branch}{ask}"
                    f"  so {to or 'a teammate'} can take it"
                ),
            )
        )
    elif state["ahead"]:
        hints.append(
            (
                "push",
                (
                    f"{_plural(state['ahead'], 'commit')} not pushed — ask your person to run  git push origin"
                    f" {branch}{ask}"
                ),
            )
        )
    if state["uncommitted"]:
        hints.append(
            (
                "uncommitted",
                (
                    f"{_plural(state['uncommitted'], 'file')} with changes that are not committed"
                    f"{_named(state.get('files') or [])} — they stay on this machine; commit them,"
                    " then ask your person to push"
                ),
            )
        )
    return hints
