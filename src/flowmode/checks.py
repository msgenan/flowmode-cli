"""S11 F-11-29: the completion check, the pure part — run the repository's `checks` in a worktree, read the task's
acceptance criteria out of its issue body, list the person-only checks, and shape the rows the server stores
(`task_checks`: kind `command|criterion|person`, name, status `passed|failed|open|done`, detail).

S11 F-11-45: the conflict check with the default branch (`main_conflicts`: fetch it, then `git merge-tree`, both
through `worktrees`), its texts, and its last result per checkout (kept under $FLOWMODE_HOME for the push approval's
snapshot)."""

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from flowmode.redact import redact_secrets
from flowmode.risky import DEFAULT_RISKY_PATTERNS, RUNTIME_COMMAND, is_risky, patterns_for
from flowmode.shared import flowmode_home
from flowmode.worktrees import GitError, _git, fetch_branch, merge_tree_conflicts

CRITERION = re.compile(r"^\s*[-*]\s+\[[ xX]\]\s+(.+?)\s*$")
TAIL = 2000  # characters of output kept per command, on this machine only (never sent)
TIMEOUT = 600  # seconds per command
DETAIL_LEN = 200  # a stored detail: one line (SPEC §3: output may be code or secrets, it never goes to the server)
MAX_NAME = 2000  # = limits.MAX_COMMAND_LEN: a check's name (a command is its own name)
MAX_ROWS = 200  # rows in one `flowmode check` run
REFUSED = "refused: needs approval — run it yourself"


@dataclass
class CheckRow:
    kind: str  # command | criterion | person
    name: str
    status: str  # passed | failed | open | done
    detail: str | None = None  # what the server gets: `exit N`, `timed out after N s`, the refusal — never output
    tail: str | None = None  # the command's output tail, printed on this machine only

    @property
    def refused(self) -> bool:
        return self.kind == "command" and bool(self.detail) and self.detail.startswith("refused")

    def as_body(self) -> dict:
        return {"kind": self.kind, "name": self.name, "status": self.status, "detail": self.detail}


def one_line(detail: str | None) -> str | None:
    """The one line of detail the server keeps: the first non-empty line, its secrets masked (`redact`: tokens,
    credentials in URLs, S14 F-14-05), at most DETAIL_LEN characters; None when there is none."""
    lines = [line.strip() for line in (detail or "").splitlines() if line.strip()]
    if not lines:
        return None
    return redact_secrets(lines[0])[:DETAIL_LEN]


def criteria(issue_body: str | None) -> list[str]:
    """The `- [ ] …` (or `- [x]`) lines of an issue body, in order, without repeats, each at most MAX_NAME long."""
    seen, out = set(), []
    for line in (issue_body or "").splitlines():
        m = CRITERION.match(line)
        name = m.group(1)[:MAX_NAME] if m else None
        if name and name not in seen:
            seen.add(name)
            out.append(name)
    return out


def run_command(command: str, cwd: Path, timeout: int = TIMEOUT) -> CheckRow:
    """Run one check through the shell in `cwd`. The detail is its exit code (None when it passed); the last `TAIL`
    characters of its output are the local tail."""
    try:
        r = subprocess.run(  # noqa: S602 — a check is the team's own shell command from flowmode.toml
            command, shell=True, cwd=str(cwd), capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        return CheckRow("command", command, "failed", f"timed out after {timeout} s")
    except OSError as exc:
        return CheckRow("command", command, "failed", f"could not run ({exc.strerror or 'OS error'})")
    output = (r.stdout + ("\n" if r.stdout and r.stderr else "") + r.stderr).strip()
    return CheckRow(
        "command",
        command,
        "passed" if r.returncode == 0 else "failed",
        None if r.returncode == 0 else f"exit {r.returncode}",
        output[-TAIL:] or None,
    )


def _normal_set(team_patterns: list[str] | None) -> list[str]:
    team = [p for p in team_patterns or () if isinstance(p, str)]
    return [*DEFAULT_RISKY_PATTERNS, *(p for p in team if p not in DEFAULT_RISKY_PATTERNS)]


def toml_patterns(team_patterns: list[str] | None = None) -> list[str]:
    """The risky patterns a `checks` line of the committed flowmode.toml is classified with: the built-in (normal)
    set plus the team's — the file is team-reviewed, so installs, `git commit` or a plain `rm` run there (F-11-29
    check rules, lead decision round 3); a push, `rm -rf` or curl is still refused."""
    return _normal_set(team_patterns)


def check_patterns(team_patterns: list[str] | None = None) -> list[str]:
    """The risky patterns an ad hoc check command (`flowmode check --also`) is classified with: the built-in and the
    team's ones plus the strict-mode set (F-11-29-R8) — a command any session mode would ask approval for is
    refused, never run. Its order puts the normal set first, so `reason_for` names the same pattern for a toml line."""
    return patterns_for("strict", _normal_set(team_patterns))


def _refused(command: str, patterns: list[str], team: bool) -> bool:
    """A check line is not run when a risky pattern matches it. S20 F-20-88: a committed flowmode.toml line (`team`) is
    team-reviewed and no stronger than a script, so a line the hook only cannot read statically (`$PYTHON -m pytest`,
    `find … -exec bash -n {} +`) still runs; an agent's ad hoc `--also` line is refused for it too."""
    found = is_risky(command, patterns)
    return bool(found) and not (team and found == RUNTIME_COMMAND)


def rows_for(
    commands: list[str],
    cwd: Path,
    issue_body: str | None,
    person_checks: list[str],
    timeout: int = TIMEOUT,
    risky_patterns: list[str] | None = None,
    also: list[str] = (),
    also_patterns: list[str] | None = None,
) -> list[CheckRow]:
    """Every row of one `flowmode check` run: the commands (run now), the criteria and the person checks (open).
    `commands` are the flowmode.toml ones, classified with `risky_patterns` (default `toml_patterns()`); `also` the ad
    hoc ones, after them, with `also_patterns` (default `check_patterns()`: strict). A flagged command is not run: it
    would pass the approval a risky command needs; it is reported as refused (a failed row)."""
    toml = toml_patterns() if risky_patterns is None else risky_patterns
    strict = check_patterns() if also_patterns is None else also_patterns
    rows = [
        CheckRow("command", c, "failed", REFUSED) if _refused(c, patterns, team) else run_command(c, cwd, timeout)
        for c, patterns, team in [*((c, toml, True) for c in commands), *((c, strict, False) for c in also)]
    ]
    rows += [CheckRow("criterion", c, "open") for c in criteria(issue_body)]
    rows += [CheckRow("person", p, "open") for p in person_checks]
    return rows[:MAX_ROWS]


def summary(rows: list[dict]) -> dict:
    """What a push approval carries (S11 F-11-29): the names by outcome, and whether any command ran at all; S12
    F-12-31 (F-11-29-R6): `ran_at`, the newest command row's time (`at`), None when none ran."""
    passed = [r["name"] for r in rows if r["kind"] == "command" and r["status"] == "passed"]
    failed = [r["name"] for r in rows if r["kind"] == "command" and r["status"] == "failed"]
    open_ = [r["name"] for r in rows if r["status"] == "open"]
    done = [r["name"] for r in rows if r["kind"] != "command" and r["status"] in ("passed", "done")]
    return {
        "passed": passed,
        "failed": failed,
        "open": open_,
        "done": done,
        "missing": not any(r["kind"] == "command" for r in rows),
        "ran_at": max((r["at"] for r in rows if r["kind"] == "command" and r.get("at")), default=None),
    }


# S12 F-12-13b: the last section of a pull request's text — work born here but outside the task's scope, one draft per
# item. The shape sits in an HTML comment (GitHub does not show it, and `flowmode review followups` never reads it as
# a draft); `(none)` stays until the agent writes the first draft.
FOLLOW_UPS = (
    "## Follow-ups\n\n"
    "<!-- Out-of-scope work only, one draft per item; the review session opens them as issues after the merge,"
    ' on your person\'s "open":\n'
    "### <module>: <title>\n"
    "Goal: <one line>\n"
    "Acceptance: <one line>\n"
    "-->\n"
    "(none)\n"
)


def pr_text(rows: list[dict], issue_url: str | None = None) -> str:
    """The "What I verified" block for a pull request description; with the task's issue (S12 F-12-14) it opens with
    GitHub's own closing keyword, so the merge of the pull request closes the issue. S12 F-12-13b: it ends with the
    `## Follow-ups` section (FOLLOW_UPS)."""
    lines = [f"Closes {issue_url}", ""] if issue_url else []
    lines += ["## What I verified", ""]
    for r in rows:
        mark = {"passed": "x", "done": "x"}.get(r["status"], " ")
        label = {"command": "", "criterion": "criterion: ", "person": "person-only: "}[r["kind"]]
        state = "" if r["status"] in ("passed", "done") else f" — {r['status']}"
        lines.append(
            f"- [{mark}] {label}`{r['name']}`{state}"
            if r["kind"] == "command"
            else f"- [{mark}] {label}{r['name']}{state}"
        )
    return "\n".join(lines) + "\n\n" + FOLLOW_UPS


# --- S11 F-11-45: conflicts with main -----------------------------------------------------------------------------

CHECK_FETCH_TIMEOUT = 5  # seconds `flowmode check` waits for the fetch of the default branch
HOOK_FETCH_TIMEOUT = 2  # the same at session start (a hook: it must stay quick)
MAX_CONFLICTS = 200  # paths a push approval carries at most


@dataclass
class MainConflicts:
    default: str  # the default branch, as origin/HEAD names it
    head: str  # the commit compared
    files: list[str]  # [] = merges cleanly


def main_conflicts(
    root: Path, default_branch: str | None, fetch_timeout: float = CHECK_FETCH_TIMEOUT, timeout: float | None = None
) -> MainConflicts | None:
    """Fetch origin/<default> (best effort, `fetch_timeout`), then `git merge-tree --write-tree origin/<default>
    HEAD`: no change to the working tree, the index, HEAD, a local branch or the stash. None — skipped — without a
    default branch (origin/HEAD, nothing guessed), when the fetch failed or timed out (offline: never compared with
    the last-known origin/<default>), or when git could not say. Never raises."""
    if not default_branch:
        return None
    if not fetch_branch(root, default_branch, timeout=fetch_timeout):
        return None
    try:
        head = _git(root, "rev-parse", "--verify", "HEAD", timeout=timeout)
    except GitError:
        return None
    files = merge_tree_conflicts(root, f"refs/remotes/origin/{default_branch}", head, timeout=timeout)
    return None if files is None else MainConflicts(default_branch, head, files)


SHOWN_CONFLICTS = 20  # paths named in a conflict text; the rest are counted
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _conflict_names(files: list[str]) -> str:
    """The paths for one line of text: control characters (a newline in a committed path) as `?`, so a path cannot
    start a line of its own; the first SHOWN_CONFLICTS named, then `and N more`."""
    shown = ", ".join(_CONTROL.sub("?", f) for f in files[:SHOWN_CONFLICTS])
    return shown + (f" and {len(files) - SHOWN_CONFLICTS} more" if len(files) > SHOWN_CONFLICTS else "")


def conflicts_line(found: MainConflicts) -> str:
    """`flowmode check`'s line: the files, or that it compared and found none."""
    if not found.files:
        return f"no conflicts with main (origin/{found.default})"
    return f"conflicts with main: {_conflict_names(found.files)} (origin/{found.default})"


def conflicts_advice(found: MainConflicts) -> str | None:
    """The session-start line when the branch conflicts with the default branch: the files and the one way out —
    proposed to the person first, done only after a yes. None when nothing conflicts."""
    if not found.files:
        return None
    base = f"origin/{found.default}"
    return (
        f"Flowmode: conflicts with main: {_conflict_names(found.files)} — this branch no longer merges cleanly with"
        f" {base}. Propose to your person, in one sentence, to bring it up to date by merging {base} into it"
        " (never rebase, never force push), resolving in main's favour where your task does not own the change,"
        " then re-run the checks (flowmode check); do it only after a yes."
    )


def _conflicts_file(root: Path) -> Path:
    key = hashlib.sha256(str(Path(root).resolve()).encode()).hexdigest()[:24]
    return flowmode_home() / "conflicts" / f"{key}.json"


def remember_conflicts(root: Path, found: MainConflicts) -> None:
    """Keep the result for the next push approval from this checkout (best effort: a write error is ignored)."""
    path = _conflicts_file(root)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "root": str(Path(root).resolve()),
                    "default": found.default,
                    "head": found.head,
                    "files": found.files[:MAX_CONFLICTS],
                }
            )
        )
    except OSError:
        pass


def conflicts_for_push(cwd: Path, timeout: float | None = None) -> list[str] | None:
    """What a push from the checkout around `cwd` carries: its last conflict check, when it compared the commit
    checked out now. None outside a checkout, or when git does not answer within `timeout`."""
    try:
        root, head = _git(cwd, "rev-parse", "--show-toplevel", "HEAD", timeout=timeout).splitlines()
    except (GitError, ValueError):
        return None
    return last_conflicts(Path(root), head)


def last_conflicts(root: Path, head: str | None) -> list[str] | None:
    """The files of the last conflict check of this checkout when it compared this very commit `head`; None when
    there is none (never checked, skipped since, or computed for another commit)."""
    try:
        data = json.loads(_conflicts_file(root).read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not head or data.get("head") != head or not isinstance(data.get("files"), list):
        return None
    return [str(f) for f in data["files"]][:MAX_CONFLICTS]
