"""`flowmode install <agent>`: write the agent's hook + MCP config for one repo (formats live in the adapter) and,
since S11 (F-11-01 / F-11-41), the Flowmode skills."""

import hashlib
import os
import re
import shlex
import shutil
import subprocess
import sys
from importlib import resources
from pathlib import Path

from flowmode.agents import get_adapter
from flowmode.member_config import MemberConfig
from flowmode.paths import symlink_on_the_way, write_no_follow
from flowmode.repo import _commondir, _gitdir, find_repo, is_checkout
from flowmode.worktrees import FLOWMODE_SKILLS as SKILLS

MARKER = re.compile(r"<!-- flowmode-skill v(\d+) -->\s*$")
# sha256 of every earlier shipped text of each skill (review P1a-5): an untouched copy of one of them is replaced by
# the shipped one; any other text was edited by the person (or written by a newer flowmode) and is kept. When a
# SKILL.md changes, bump its marker and add the old text's hash here.
SHIPPED_BEFORE = {
    "flow-start": frozenset(
        {
            "6b42ce5f98940313a5ee61015480f40c9a605d93953563353aa30dfe7a551404",  # v1
            "ed3c5a02ffc2bd8630a63da87cb3c336773d806c8c73c99df1a4bbab130f4069",
        }
    ),  # v2 before F-12-13
    "flow-sync": frozenset(
        {
            "ca345aa9a65d97bceb8381ae84ea6fc1f0de8be38407db61e218a2063ee116a5",  # v1 before F-11-45
            "b7a18c871c9683bf9dc45f97b637bf5c4daafdcd2c0f0de20583e72baf7e7c13",  # v1 before F-12-02
            "f99582e34423478d29db02ee36361dce979ca67aa059dac2181ec67a5a147417",
        }
    ),  # v2 before F-12-13
    "flow-handoff": frozenset({"87fdfc104910abb93f0b208445f4ec0fcbf092883f4eb47c006d61904d553bb0"}),  # v1
    "flow-review": frozenset(
        {
            "209da69e91fd9d2f84a8a7156e2e68f596cc8946d7bb2017d2271868911f9203",  # v1
            "a3cf7f3f13ef69901562273b3e3452c5cb908e8c58225474517a0bbfb59f6657",
        }
    ),  # v2 before F-12-13
    "flow-blocked": frozenset(
        {
            "9b93fef6c8a8ae40e19ed67350819039a8ad2935f98b358640118a5b81ee9dca",  # v1 before F-11-45
            "8717373805b7ec296c5182f43926d931d93c0fd298d7ad2baf4ee955254d8962",
        }
    ),  # v1 before F-12-02
}


def shipped_skill(name: str) -> str:
    """The SKILL.md shipped inside the package."""
    return (resources.files("flowmode") / "skills" / name / "SKILL.md").read_text(encoding="utf-8")


def text_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _version(text: str) -> int:
    found = MARKER.search(text)
    return int(found[1]) if found else 0


def _kept_because(name: str, existing: str, shipped: str) -> str | None:
    """Why an installed skill that differs from the shipped text stays as it is; None: it is an untouched copy of an
    earlier shipped version, so the shipped one replaces it."""
    if text_hash(existing) in SHIPPED_BEFORE.get(name, ()) and _version(existing) <= _version(shipped):
        return None
    if _version(existing) > _version(shipped):
        return f"written by a newer flowmode (v{_version(existing)})"
    return "edited locally"


def install(agent: str, repo_path: Path, cfg: MemberConfig, force: bool = False) -> tuple[list[Path], list[str]]:
    """(absolute paths written, next-step lines). ValueError if an existing config file is not valid.
    The skills: a missing file, or an untouched copy of an earlier shipped version, gets the shipped text; any other
    text (the person edited it, even with the marker kept) is left alone and named once on stderr, unless `force`.
    A skill path that is a symbolic link, or lies under one, is never written, `force` or not (review P1a-R2-1)."""
    adapter = get_adapter(agent)
    root = repo_path.resolve()
    written, next_steps = adapter.install(root, cfg)
    wrote_skills = False
    for name in SKILLS:
        path = root / adapter.skills_dir / name / "SKILL.md"
        text = shipped_skill(name)
        if (link := symlink_on_the_way(root, path)) is not None:
            print(
                f"skipped {path.relative_to(root)}: a symbolic link ({link.relative_to(root)}) — flowmode does"
                " not write through it",
                file=sys.stderr,
            )
            continue
        if path.exists() and not force:
            existing = path.read_text(encoding="utf-8")
            if existing == text:
                continue
            if why := _kept_because(name, existing, text):
                print(f"skipped {path.relative_to(root)}: {why} — rerun with --force to replace", file=sys.stderr)
                continue
        path.parent.mkdir(parents=True, exist_ok=True)
        write_no_follow(path, text.encode("utf-8"), replace=True)
        written.append(path)
        wrote_skills = True
    hook, why = install_commit_msg_hook(root)
    if hook is not None:
        written.append(hook)
    elif why == EDITED_HOOK_KEPT:
        print(f"note: commit-msg check: {why}", file=sys.stderr)
    elif why:
        print(f"note: commit-msg check not installed: {why}", file=sys.stderr)
    if wrote_skills:  # review P1a-2: committed, every clone has them; a task worktree gets a copy either way
        # F-20-100: the skills plus every file this install wrote in the clone (the adapter's own list)
        files = [
            str(path.relative_to(root))
            for path in written
            if path.is_relative_to(root) and ".git" not in path.relative_to(root).parts and path.name != "SKILL.md"
        ]
        next_steps.append(
            "next: commit these with the config so every clone has them:  git add "
            + " ".join([adapter.skills_dir, *files])
        )
    return written, next_steps


# --- S20 L-6 (c): the git commit-msg hook -----------------------------------------------------------------------------

COMMIT_MSG_MARKER = "# flowmode commit-msg check (S20 L-6)"
_ADD_IT = 'add  flowmode check commit-msg "$1"  to it'
EDITED_HOOK_KEPT = "your commit-msg hook has lines of its own next to the Flowmode check — kept as it is"


def _flowmode_path() -> str | None:
    """This flowmode (next to the running interpreter), else the one on PATH; None when neither exists."""
    here = Path(sys.executable).parent / "flowmode"
    if here.is_file() and os.access(here, os.X_OK):
        return str(here)
    return shutil.which("flowmode")


def commit_msg_hook_text(flowmode: str | None) -> str:
    """The hook: the flowmode resolved at install time, PATH as the fallback; neither → a loud warning and the commit
    goes through (a person's commit is never blocked by a missing tool; the agent hook and settings still hold)."""
    first = (
        f'if [ -x {shlex.quote(flowmode)} ]; then exec {shlex.quote(flowmode)} check commit-msg "$1"; fi\n'
        if flowmode
        else ""
    )
    return (
        "#!/bin/sh\n"
        f"{COMMIT_MSG_MARKER}: commits never name an agent as author or co-author\n"
        f"{first}"
        'if command -v flowmode >/dev/null 2>&1; then exec flowmode check commit-msg "$1"; fi\n'
        'echo "flowmode: WARNING: flowmode not found — this commit message was NOT checked for agent attribution'
        ' (reinstall flowmode or fix PATH)" >&2\n'
        "exit 0\n"
    )


def _is_flowmode_template(text: str) -> bool:
    """`text` is exactly a hook Flowmode wrote (for whatever flowmode path it names): only then may install rewrite
    it; a member's added line is never lost."""
    if text == commit_msg_hook_text(None):
        return True
    lines = text.split("\n")
    if len(lines) < 3 or not lines[2].startswith("if [ -x "):
        return False
    try:
        words = shlex.split(lines[2])
    except ValueError:
        return False
    return len(words) > 3 and text == commit_msg_hook_text(words[3])


def _hooks_path(root: Path) -> str | None:
    """`core.hooksPath` as git sees it in `root` (repo, global or system config); None when unset or git fails."""
    try:
        out = subprocess.run(
            ["git", "config", "--get", "core.hooksPath"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout.strip() or None


def _commit_msg_hook(root: Path) -> tuple[Path | None, str | None]:
    """(the commit-msg hook file Flowmode may own, None) or (None, why not)."""
    info = find_repo(root)
    gitdir = _gitdir(Path(info.root)) if is_checkout(info) else None
    if gitdir is None or not gitdir.is_dir():
        return None, "not a git checkout"
    if hooks_path := _hooks_path(Path(info.root)):
        return None, f"core.hooksPath is set ({hooks_path}) — {_ADD_IT} in that folder's commit-msg hook"
    return _commondir(gitdir) / "hooks" / "commit-msg", None


def commit_msg_hook_state(root: Path) -> tuple[bool, str | None]:
    """For doctor: (installed, None) or (False, why not). Recomputed from the repo, never stored."""
    path, why = _commit_msg_hook(root)
    if path is None:
        return False, why
    try:
        text = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else None
    except OSError:
        text = None
    if text is not None and COMMIT_MSG_MARKER in text:
        return True, None
    if os.path.lexists(path):
        return False, f"the repo already has its own commit-msg hook — {_ADD_IT}"
    return False, "not installed yet — run  flowmode install claude  (or codex)"


def _words(line: str) -> list[str]:
    try:
        return shlex.split(line)
    except ValueError:
        return line.split()


# `exit`, `exit 0;`, `return;`, or `exec <command>` (replaces the shell; `exec 2>&1` only redirects) at the line start
_ENDS_THE_HOOK = re.compile(r"(?:exit|return)\b|exec\s+(?!(?:[0-9]*|\{[A-Za-z_][A-Za-z0-9_]*\})[<>&])\S")


def _check_runs(path: Path) -> str | None:
    """Why the commit-msg hook at `path` would not run `flowmode check commit-msg`, or None when it does."""
    if not os.path.lexists(path):
        return "the commit-msg hook is missing"
    if not os.access(path, os.X_OK):
        return "the commit-msg hook is not executable"
    try:
        text = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
    except OSError:
        text = ""
    runs = [ln for ln in text.splitlines() if "check commit-msg" in ln and not ln.strip().startswith("#")]
    if not runs:
        return "the commit-msg hook no longer runs  flowmode check commit-msg"
    for line in text.splitlines():  # an unindented `exit`/`return`/`exec <cmd>` before the check line ends the hook
        if line in runs:
            break
        if _ENDS_THE_HOOK.match(line):
            return "the commit-msg hook exits before it runs  flowmode check commit-msg"
    named = [w for ln in runs for w in _words(ln) if os.path.isabs(w) and os.path.basename(w) == "flowmode"]
    if shutil.which("flowmode") is None and not any(os.access(w, os.X_OK) for w in named):
        return "flowmode is not found where the commit-msg hook looks for it, so every commit passes unchecked"
    return None


def commit_msg_check_off(root: Path) -> str | None:
    """S20 F-20-81, for doctor and the session start: why this checkout's commit-msg check would not run (missing,
    not executable, its check line gone or commented out, core.hooksPath pointing at a folder without it, the
    flowmode it runs gone), or None when it runs — or when `root` is no git checkout (nothing to say)."""
    info = find_repo(Path(root))
    gitdir = _gitdir(Path(info.root)) if is_checkout(info) else None
    if gitdir is None or not gitdir.is_dir():
        return None
    if hooks_path := _hooks_path(Path(info.root)):
        why = _check_runs(Path(info.root) / os.path.expanduser(hooks_path) / "commit-msg")
        return f"core.hooksPath points at {hooks_path}: {why}" if why else None
    return _check_runs(_commondir(gitdir) / "hooks" / "commit-msg")


def commit_msg_fix(why: str, agent: str) -> str:
    """The fix for a check that is off, to run from the person's own terminal (an agent is refused the change)."""
    if why.startswith("core.hooksPath"):
        return f"{_ADD_IT} in that folder's commit-msg hook, or unset core.hooksPath and run  flowmode install {agent}"
    return f"run  flowmode install {agent}  from your terminal"


def install_commit_msg_hook(root: Path) -> tuple[Path | None, str | None]:
    """(path written, None), (None, None) when Flowmode's hook is already there unchanged, or (None, why not). Only
    when no commit-msg hook exists and `core.hooksPath` is unset; another hook is never touched; Flowmode's own is
    refreshed (the flowmode path may have moved) only while it is exactly Flowmode's text — one with a member's
    lines added is kept (EDITED_HOOK_KEPT). Writes only inside the repo's git folder."""
    path, why = _commit_msg_hook(root)
    if path is None:
        return None, why
    text = commit_msg_hook_text(_flowmode_path())
    installed, why = commit_msg_hook_state(root)
    if not installed and os.path.lexists(path):
        return None, why
    try:
        if installed:
            if path.is_symlink():
                return None, None
            current = path.read_text(encoding="utf-8", errors="replace")
            if current == text:
                return None, None
            if not _is_flowmode_template(current):
                return None, EDITED_HOOK_KEPT
            write_no_follow(path, text.encode("utf-8"), replace=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            write_no_follow(path, text.encode("utf-8"), replace=False)
        path.chmod(0o755)
    except OSError as exc:
        return None, f"could not write {path.name}: {exc.strerror or exc}"
    return path, None


def path_warning() -> str | None:
    """S9 §13: the hooks run `flowmode` from the agent's PATH. A warning when that is not this flowmode (the one
    next to the running interpreter), None when it is, or when there is no flowmode next to the interpreter to
    compare with (a source checkout run another way)."""
    import shutil
    import sys

    here = Path(sys.executable).parent
    expected = here / "flowmode"
    if not expected.exists():
        return None
    found = shutil.which("flowmode")
    if found is None:
        return (
            f"warning: flowmode is not on PATH, so the agent's hooks will not run — add {here} to the PATH of the"
            " shell that starts the agent"
        )
    try:
        same = Path(found).resolve() == expected.resolve()
    except OSError:
        same = False
    if same:
        return None
    return f"warning: the hooks will run {found}, not this flowmode ({expected}) — fix the PATH or reinstall"
