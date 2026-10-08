"""`flowmode install <agent>`: write the agent's hook + MCP config for one repo (formats live in the adapter) and,
since S11 (F-11-01 / F-11-41), the Flowmode skills."""

import hashlib
import re
import sys
from importlib import resources
from pathlib import Path

from flowmode.agents import get_adapter
from flowmode.member_config import MemberConfig
from flowmode.paths import symlink_on_the_way, write_no_follow
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
    if wrote_skills:  # review P1a-2: committed, every clone has them; a task worktree gets a copy either way
        next_steps.append(
            "next: commit the skills with the config so every clone has them:  git add " + adapter.skills_dir
        )
    return written, next_steps


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
