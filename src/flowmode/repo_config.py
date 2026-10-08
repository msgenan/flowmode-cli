"""`flowmode.toml` at a repository's root (S11 F-11-28 / F-11-29): the required reading and the checks.

    read_first = ["AGENTS.md", "docs/ARCHITECTURE.md"]      # read before the first edit
    checks = ["uv run pytest -q"]                            # run by `flowmode check` in the task worktree
    person_checks = ["Screenshots at 1440 and 390 in the PR"]  # only a person can do these
    tree_exclude = ["private/**"]                            # never reported to the server (S14 F-14-05)

Missing file → `AGENTS.md` when it exists (else nothing), no checks, and a hint. Unknown keys are ignored; a parse
error is reported once (`RepoConfig.error`) and the fallback applies. Pure file reads, never raises."""

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

FILE_NAME = "flowmode.toml"
MAX_EXCLUDE = 100  # S14 F-14-05: `tree_exclude` globs kept
MAX_EXCLUDE_LEN = 200  # characters per glob
HINT = f"create {FILE_NAME} at the repo root (read_first = [...], checks = [...], person_checks = [...])"


@dataclass
class RepoConfig:
    read_first: list[str] = field(default_factory=list)
    checks: list[str] = field(default_factory=list)
    person_checks: list[str] = field(default_factory=list)
    tree_exclude: list[str] = field(default_factory=list)  # S14 F-14-05: globs never reported to the server
    present: bool = False  # the file exists and parsed
    error: str | None = None  # the parse error, when the file exists but could not be read

    @property
    def hint(self) -> str | None:
        """One line for the session-start context when the file is missing or broken."""
        if self.error:
            return f"{FILE_NAME} could not be read ({self.error}); the defaults apply"
        return None if self.present else HINT


def _strings(value) -> list[str]:
    return [v for v in value if isinstance(v, str) and v.strip()] if isinstance(value, list) else []


def _globs(value) -> list[str]:
    """`tree_exclude`: at most MAX_EXCLUDE globs of at most MAX_EXCLUDE_LEN characters (a longer one is dropped)."""
    return [g for g in _strings(value) if len(g) <= MAX_EXCLUDE_LEN][:MAX_EXCLUDE]


def load_repo_config(root: Path) -> RepoConfig:
    """The repository's config, read from `<root>/flowmode.toml`."""
    path = Path(root) / FILE_NAME
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        fallback = ["AGENTS.md"] if (Path(root) / "AGENTS.md").is_file() else []
        return RepoConfig(read_first=fallback)
    except OSError as exc:
        return RepoConfig(error=str(exc))
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        fallback = ["AGENTS.md"] if (Path(root) / "AGENTS.md").is_file() else []
        return RepoConfig(read_first=fallback, error=str(exc).splitlines()[0][:120])
    return RepoConfig(
        read_first=_strings(data.get("read_first")),
        checks=_strings(data.get("checks")),
        person_checks=_strings(data.get("person_checks")),
        tree_exclude=_globs(data.get("tree_exclude")),
        present=True,
    )
