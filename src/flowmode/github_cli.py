"""GitHub through the member's own `gh` (S7 §4): the only module that runs gh. The executable is `$FLOWMODE_GH` or
`gh` on PATH, run with the caller's environment and its own login — Flowmode never sees or stores a GitHub token.
The server never imports this module."""

import json
import os
import re
import subprocess
from pathlib import Path

__all__ = [
    "GhError",
    "GhMissing",
    "assign_to_me",
    "gh_ready",
    "github_repo_of",
    "hook_pr_line",
    "issue_create",
    "issue_list_open",
    "issue_view",
    "merge_flag",
    "merge_methods",
    "pr_body",
    "pr_comment",
    "pr_for_branch",
    "pr_line",
    "pr_list_since",
    "pr_report",
    "pr_view",
]

TIMEOUT_SECONDS = 30  # a person is waiting at a prompt; a hook passes its own cap (S12 F-12-10: 2 s), check 5 s
PR_FIELDS = (
    "number,state,mergedAt,headRefOid,isCrossRepository,mergeable,mergeStateStatus,reviewDecision,"
    "statusCheckRollup,baseRefName,url"
)

_HOST = r"(?P<host>[A-Za-z0-9.-]+)"
_SCP = re.compile(rf"^[A-Za-z0-9._-]+@{_HOST}:(?P<path>[^/].*)$")  # git@github.com:o/r.git
_SSH = re.compile(rf"^ssh://(?:[^@/]+@)?{_HOST}(?::\d+)?/(?P<path>.+)$")  # ssh://git@github.com/o/r
_HTTPS = re.compile(rf"^https://(?:[^@/]+@)?(?P<hostport>{_HOST}(?::\d+)?)/(?P<path>.+)$")  # https://github.com/o/r
_SEGMENT = re.compile(r"^[A-Za-z0-9_.-]+$")


class GhMissing(Exception):
    """The gh executable does not exist."""


class GhError(Exception):
    """gh exited non-zero or answered something unreadable; str(exc) is the first line of gh's stderr."""


class GhTimeout(GhError):
    """gh did not answer in time: what it was asked may or may not have happened."""


def github_repo_of(origin: str | None) -> str | None:
    """The `[HOST/]OWNER/REPO` (the form `gh --repo` takes) of a git remote URL: git@github.com:o/r(.git),
    ssh://git@github.com/o/r(.git), https://github.com/o/r(.git) → "o/r"; the same forms on another host →
    "host/o/r" (an https port stays, an ssh port is dropped: it is not the web host's); anything else → None."""
    origin = (origin or "").strip()
    for pattern in (_SCP, _SSH, _HTTPS):
        m = pattern.fullmatch(origin)
        if m is not None:
            break
    else:
        return None
    host = (m.groupdict().get("hostport") or m["host"]).lower()
    parts = m["path"].rstrip("/").split("/")
    if len(parts) != 2:
        return None
    owner, name = parts[0], parts[1].removesuffix(".git")
    if not all(_SEGMENT.fullmatch(p) and p not in (".", "..") for p in (owner, name)):
        return None
    return f"{owner}/{name}" if host == "github.com" else f"{host}/{owner}/{name}"


def _gh(args: list[str], cwd: Path, timeout: float = TIMEOUT_SECONDS) -> str:
    gh = os.environ.get("FLOWMODE_GH") or "gh"
    try:
        r = subprocess.run([gh, *args], cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise GhMissing(gh) from exc
    except subprocess.TimeoutExpired as exc:
        raise GhTimeout(f"gh did not answer within {timeout:g} seconds") from exc
    except OSError as exc:  # e.g. not executable
        raise GhError(str(exc)) from exc
    if r.returncode != 0:
        first = next((line.strip() for line in r.stderr.splitlines() if line.strip()), "")
        raise GhError(first or f"gh exited with {r.returncode}")
    return r.stdout


def issue_view(number: int, cwd: Path) -> dict:
    """`gh issue view <n> --json number,title,url,state,body` in `cwd` (gh picks the checkout's repo)."""
    out = _gh(["issue", "view", str(number), "--json", "number,title,url,state,body"], cwd)
    try:
        data = json.loads(out)
    except ValueError as exc:
        raise GhError(f"unreadable answer from gh issue view {number}") from exc
    if not isinstance(data, dict):
        raise GhError(f"unreadable answer from gh issue view {number}")
    return data


def assign_to_me(issue: dict, cwd: Path) -> None:
    """`gh issue edit <n> --repo <issue.repo> --add-assignee @me`."""
    _gh(["issue", "edit", str(issue["number"]), "--repo", issue["repo"], "--add-assignee", "@me"], cwd)


# --- pull requests (S12 F-12-10): read with the member's own gh, reported to the server as facts only ------------------


def _json(out: str, what: str):
    try:
        return json.loads(out)
    except ValueError as exc:
        raise GhError(f"unreadable answer from gh {what}") from exc


TOKEN_ENV = ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN")


def gh_ready() -> bool:
    """Whether gh can answer without a login prompt: FLOWMODE_GH names one, a token is in the environment, or gh's
    config directory ($GH_CONFIG_DIR, else $XDG_CONFIG_HOME/gh, else ~/.config/gh) holds the hosts.yml that
    `gh auth login` writes. The unasked paths (session start, flowmode check) skip a gh that cannot be logged in
    rather than spend their seconds on it; `flowmode pr` asks anyway and prints gh's own error."""
    if os.environ.get("FLOWMODE_GH") or any(os.environ.get(name) for name in TOKEN_ENV):
        return True
    if os.environ.get("GH_CONFIG_DIR"):
        config = Path(os.environ["GH_CONFIG_DIR"])
    elif os.environ.get("XDG_CONFIG_HOME"):
        config = Path(os.environ["XDG_CONFIG_HOME"]) / "gh"
    else:
        config = Path(os.environ.get("HOME") or Path.home()) / ".config" / "gh"
    return (config / "hosts.yml").is_file()


def pr_for_branch(branch: str, cwd: Path, timeout: float = TIMEOUT_SECONDS) -> dict | None:
    """The pull request of `branch` in the checkout's repo: `gh pr list --head <branch> --state all --json …`; an
    open one first, else the newest; None when there is none."""
    found = _json(
        _gh(["pr", "list", "--head", branch, "--state", "all", "--json", PR_FIELDS, "--limit", "20"], cwd, timeout),
        "pr list",
    )
    if not isinstance(found, list):
        raise GhError("unreadable answer from gh pr list")
    prs = [p for p in found if isinstance(p, dict) and isinstance(p.get("number"), int)]
    prs.sort(key=lambda p: (p.get("state") == "OPEN", p["number"]), reverse=True)
    return prs[0] if prs else None


# S13 F-13-01: what `flowmode pr sync` asks of the repo's pull requests and open issues (the body stays on this
# machine: only its closing references are sent)
SYNC_PR_FIELDS = (
    "number,state,mergedAt,createdAt,updatedAt,closedAt,headRefName,headRefOid,baseRefName,"
    "isCrossRepository,title,url,body,author"
)
SYNC_ISSUE_FIELDS = "number,title,labels,updatedAt,url"
SYNC_LIMIT = 300


def _listed(out: str, what: str, prefix: str) -> list[dict]:
    """gh's JSON list, keeping the objects with an integer number whose `url` lies under `prefix` (an answer about
    another repository — a redirect, a fork, a wrong `--repo` — is dropped; GitHub folds the path's case)."""
    found = _json(out, what)
    if not isinstance(found, list):
        raise GhError(f"unreadable answer from gh {what}")
    return [
        item
        for item in found
        if isinstance(item, dict)
        and isinstance(item.get("number"), int)
        and not isinstance(item["number"], bool)
        and str(item.get("url") or "").lower().startswith(prefix.lower())
    ]


def pr_list_since(
    repo: str, since: str, cwd: Path, limit: int = SYNC_LIMIT, timeout: float = TIMEOUT_SECONDS
) -> list[dict]:
    """S13 F-13-01: the pull requests of `repo` (`owner/name` on github.com) updated on or after `since`
    (YYYY-MM-DD), newest update first: `gh pr list --repo <o/r> --state all --search "updated:>=<since>
    sort:updated-desc" --limit <limit> --json …`. Rows whose `url` is not under https://github.com/<o/r>/pull/ are
    dropped."""
    out = _gh(
        [
            "pr",
            "list",
            "--repo",
            repo,
            "--state",
            "all",
            "--search",
            f"updated:>={since} sort:updated-desc",
            "--limit",
            str(limit),
            "--json",
            SYNC_PR_FIELDS,
        ],
        cwd,
        timeout,
    )
    return _listed(out, "pr list", f"https://github.com/{repo}/pull/")


def issue_list_open(repo: str, cwd: Path, limit: int = SYNC_LIMIT, timeout: float = TIMEOUT_SECONDS) -> list[dict]:
    """S13 F-13-01: the open issues of `repo` (metadata only): `gh issue list --repo <o/r> --state open --limit
    <limit> --json number,title,labels,updatedAt,url`; rows not under https://github.com/<o/r>/issues/ are dropped."""
    out = _gh(
        ["issue", "list", "--repo", repo, "--state", "open", "--limit", str(limit), "--json", SYNC_ISSUE_FIELDS],
        cwd,
        timeout,
    )
    return _listed(out, "issue list", f"https://github.com/{repo}/issues/")


# S12 F-12-13: what `flowmode review <n>` needs of a pull request (its head, whether it comes from a fork, its title)
REVIEW_FIELDS = "number,title,state,headRefName,headRefOid,isCrossRepository,baseRefName,url"


def pr_view(number: int, cwd: Path, timeout: float = TIMEOUT_SECONDS, fields: str = PR_FIELDS) -> dict:
    """`gh pr view <n> --json …` in `cwd`."""
    found = _json(_gh(["pr", "view", str(number), "--json", fields], cwd, timeout), f"pr view {number}")
    if not isinstance(found, dict):
        raise GhError(f"unreadable answer from gh pr view {number}")
    return found


_PASSED = {"SUCCESS", "NEUTRAL", "SKIPPED"}
_PENDING = {"", "PENDING", "EXPECTED", "QUEUED", "IN_PROGRESS", "WAITING", "REQUESTED"}


def _checks(rollup) -> dict:
    """{passed, failed, pending} of gh's statusCheckRollup (check runs: status + conclusion; statuses: state)."""
    counts = {"passed": 0, "failed": 0, "pending": 0}
    for item in rollup if isinstance(rollup, list) else []:
        if not isinstance(item, dict):
            continue
        word = str(item.get("conclusion") or item.get("state") or "").upper()
        if item.get("status") and str(item["status"]).upper() != "COMPLETED" and not item.get("state"):
            word = "PENDING"
        counts["passed" if word in _PASSED else "pending" if word in _PENDING else "failed"] += 1
    return counts


def pr_report(pr: dict, touches: list[str] | None = None) -> dict:
    """The body of `POST /api/tasks/{id}/pr` from gh's JSON: numbers, states and paths — never a title or a body."""
    merged = bool(pr.get("mergedAt")) or pr.get("state") == "MERGED"
    state = "merged" if merged else ("closed" if pr.get("state") == "CLOSED" else "open")
    merge_state = str(pr.get("mergeStateStatus") or "").lower() or None
    if merge_state in (None, "unknown") and pr.get("mergeable") == "CONFLICTING":
        merge_state = "dirty"
    review = str(pr.get("reviewDecision") or "").lower() or None
    return {
        "number": pr["number"],
        "state": state,
        "merged": merged,
        "merged_at": pr.get("mergedAt") if merged else None,
        "head_sha": str(pr.get("headRefOid") or "").lower(),
        "mergeable_state": merge_state,
        "checks": _checks(pr.get("statusCheckRollup")),
        "review": review,
        "fork": bool(pr.get("isCrossRepository")),
        "touches": list(touches or [])[:200],
    }


def _check_words(checks: dict, long: bool) -> str | None:
    passed, failed, pending = (int(checks.get(k) or 0) for k in ("passed", "failed", "pending"))
    if failed:
        return f"checks {failed} failed" if long else "checks failing"
    if pending:
        return f"checks {pending} pending" if long else "checks pending"
    if passed:
        return f"checks {passed} passed" if long else "checks passing"
    return None


MERGE_WORDS = {
    "clean": "mergeable",
    "unstable": "mergeable",
    "has_hooks": "mergeable",
    "blocked": "blocked",
    "draft": "draft",
}


def _merge_words(state: str | None, base: str) -> str | None:
    if state == "behind":
        return f"behind {base}"
    if state == "dirty":
        return f"conflicts with {base}"
    return MERGE_WORDS.get(state or "")


def pr_line(report: dict, base: str | None = None) -> str:
    """`pr: #12 open · checks 2 passed · review approved · mergeable` (flowmode pr / check)."""
    parts = [f"#{report['number']} {report['state']}"]
    if report["state"] != "merged":
        review = report.get("review")
        parts += [
            w
            for w in (
                _check_words(report.get("checks") or {}, True),
                f"review {review.replace('_', ' ')}" if review else None,
                _merge_words(report.get("mergeable_state"), base or "main"),
            )
            if w
        ]
    return "pr: " + " · ".join(parts)


def hook_pr_line(report: dict, base: str | None = None) -> str:
    """Session start: `Pull request #12: open · checks failing · behind main — <what to do>`."""
    base = base or "main"
    state = report.get("mergeable_state")
    checks = _check_words(report.get("checks") or {}, False)
    review = report.get("review")
    parts = [report["state"]]
    if report["state"] != "merged":
        parts += [
            w
            for w in (
                checks,
                "changes requested" if review == "changes_requested" else "approved" if review == "approved" else None,
                _merge_words(state, base),
            )
            if w
        ]
    steps = []
    if report["state"] == "open":
        if state == "behind":
            steps.append(f"bring the branch up to date with {base} (merge origin/{base}, never rebase or force-push)")
        elif state == "dirty":
            steps.append(f"merge origin/{base} and resolve the conflicts (never rebase or force-push)")
        if checks == "checks failing" or review == "changes_requested":
            steps.append("fix")
        if steps:
            steps += ["re-run flowmode check", "then ask your person to push"]
    line = f"Pull request #{report['number']}: " + " · ".join(parts)
    return line + (" — " + ", ".join(steps) if steps else "")


# --- the review session (S12 F-12-13) -------------------------------------------------------------------------------

METHOD_FIELDS = {"squash": "squashMergeAllowed", "merge": "mergeCommitAllowed", "rebase": "rebaseMergeAllowed"}


def merge_methods(repo: str, cwd: Path, timeout: float = TIMEOUT_SECONDS) -> list[str]:
    """The merge methods the repository allows (D-14): `gh repo view <repo> --json squashMergeAllowed,
    mergeCommitAllowed,rebaseMergeAllowed` → e.g. ["squash", "merge"] (in that order). GhError / GhMissing when gh
    cannot say."""
    found = _json(_gh(["repo", "view", repo, "--json", ",".join(METHOD_FIELDS.values())], cwd, timeout), "repo view")
    if not isinstance(found, dict):
        raise GhError("unreadable answer from gh repo view")
    return [method for method, field in METHOD_FIELDS.items() if found.get(field) is True]


def merge_flag(methods: list[str]) -> str | None:
    """Exactly one `gh pr merge` method flag (D-14): the only allowed method, else `--squash` when it is among
    several, else `--merge`; None when the repository allows none (or gh could not say)."""
    if len(methods) == 1:
        return f"--{methods[0]}"
    if not methods:
        return None
    return "--squash" if "squash" in methods else "--merge"


def pr_comment(
    number: int, body_path: Path, cwd: Path, repo: str | None = None, timeout: float = TIMEOUT_SECONDS
) -> str:
    """`gh pr comment <n> --body-file <path> [--repo <repo>]` — the text only ever from a file (R-7), never argv."""
    return _gh(
        ["pr", "comment", str(int(number)), "--body-file", str(body_path), *(["--repo", repo] if repo else [])],
        cwd,
        timeout,
    ).strip()


# --- follow-up issues after the merge (S12 F-12-13b) ------------------------------------------------------------------


def pr_body(number: int, cwd: Path, timeout: float = TIMEOUT_SECONDS) -> str:
    """`gh pr view <n> --json body` → the pull request's description ("" when it has none). Read on the member's
    machine only: it never goes to the server."""
    found = pr_view(int(number), cwd, timeout, fields="body")
    body = found.get("body")
    return body if isinstance(body, str) else ""


def issue_create(
    repo: str, title: str, body_path: Path, labels: list[str] | None, cwd: Path, timeout: float = TIMEOUT_SECONDS
) -> str:
    """`gh issue create --repo <repo> --title <title> --body-file <path> [--label <l>]…` → the new issue's address
    (gh prints it). The body only ever from a file (R-7); never `--body`, never `--assignee` (Flowmode holds no GitHub
    logins). An argv list, no shell."""
    args = ["issue", "create", "--repo", repo, "--title", title, "--body-file", str(body_path)]
    for label in labels or []:
        args += ["--label", label]
    out = _gh(args, cwd, timeout)
    return next((line.strip() for line in reversed(out.splitlines()) if line.strip().startswith("https://")), "")


def followup_marker(followup_id: str) -> str:
    """The line a follow-up's issue body carries, so a rerun finds the issue its earlier run opened (F-12-13b)."""
    return f"<!-- flowmode-followup {followup_id} -->"


def issue_find(repo: str, followup_id: str, cwd: Path, timeout: float = TIMEOUT_SECONDS) -> str | None:
    """The address of `repo`'s issue whose body carries the follow-up's marker line (the lowest number when there are
    several), via the free `gh issue list --search "<id> in:body"`; the body is checked for the marker itself, since
    search matches words. None when there is none (GitHub's search may lag behind a just-created issue)."""
    out = _gh(
        [
            "issue",
            "list",
            "--repo",
            repo,
            "--state",
            "all",
            "--search",
            f"{followup_id} in:body",
            "--json",
            "number,url,body",
        ],
        cwd,
        timeout,
    )
    found = _json(out, "issue list")
    marker = followup_marker(followup_id)
    hits = (
        [
            i
            for i in found
            if isinstance(i, dict)
            and isinstance(i.get("number"), int)
            and str(i.get("url") or "").startswith("https://")
            and any(line.strip() == marker for line in str(i.get("body") or "").splitlines())
        ]
        if isinstance(found, list)
        else []
    )
    return min(hits, key=lambda i: i["number"])["url"] if hits else None
