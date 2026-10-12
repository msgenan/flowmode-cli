"""S13 F-13-01: `flowmode pr sync` — fill the server with the past from the member's own `gh` (docs/slices/S13.md §4).

The CLI side only: the repo's pull requests updated in the last N days (30 by default, 1–30) and its open issues,
read through `github_cli` with the member's own login, sent to `POST /api/repos/sync` as facts, titles and the
closing references computed here from each body — the body itself never leaves this machine (D-4). The server never
calls GitHub.

The automatic part: session start calls `due(info, session)` (local reads only: `$FLOWMODE_HOME/sync.json`, no `gh`,
no network) and, when due, `spawn(root)` — a detached `python -m flowmode pr sync --auto --repo <root>` whose stdio is
/dev/null and which runs in its own session, so the hook never waits for it. The child is silent, exits 0 whatever
happens, holds a per-repo `O_EXCL` lock and records `{"<canonical repo>": {"pulls_at": iso}}` in `sync.json`. Under
pytest `FLOWMODE_NO_AUTOSYNC` is set for every test (`testguard.py`), so nothing is spawned unless a test lifts it.

F-13-20 (§5): the file tree is the step after the pulls, for any origin (GitHub or not): the path list of
`origin/<default>` (`git ls-tree -r -z --name-only`) with its commit, and the last 7 days of first-parent changes
(path → commit, time, the PR its subject names) — paths only, never contents (A-13-1). It is sent only when the
server's tree is another commit; `sync.json` keeps the last `tree_sha`, and session start is also due when the
clone's `origin/<default>` moved from it (one `git rev-parse`). The automatic child then skips the pulls when they
were synced within 24 hours: it never asks gh for them twice a day."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from flowmode import github_cli
from flowmode.paths import secret_looking, valid_repo_path
from flowmode.refs import display_safe, terminal_safe, valid_ref_name
from flowmode.repo import RepoInfo, find_repo, is_checkout
from flowmode.repo_config import load_repo_config
from flowmode.shared import closing_refs, flowmode_home

AUTOSYNC_OFF = "FLOWMODE_NO_AUTOSYNC"
STATE_FILE = "sync.json"
PULLS_EVERY = timedelta(hours=24)  # the automatic pull sync runs at most once a day per member and repo
PULLS_RETRY = timedelta(hours=6)  # after gh was missing, not signed in or failing, the automatic child waits this long
LOCK_STALE_SECONDS = 600  # a lock older than this is left over from a child that died: it is replaced
MAX_DAYS = 30
MAX_TITLE = 200
MAX_LABELS = 10
MAX_LABEL = 50
MAX_CLOSES = 10
SHA_RE = re.compile(r"[0-9a-f]{40}([0-9a-f]{24})?")
LOGIN_RE = re.compile(r"[A-Za-z0-9-]{1,39}")  # the server's `author_login` rule (`SyncPullIn`)
ISSUE_REPO_RE = re.compile(r"([A-Za-z0-9.-]+/)?[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")

NOT_GITHUB = "pulls: not sent — origin is not on GitHub"
NO_GH = "pulls: not sent — gh is not installed or not signed in (gh auth login)"
NOT_KNOWN = "not reported: the server does not know {repo} yet (no task or live session)"
NO_HEAD = "tree: not sent — origin/HEAD is not set (git remote set-head origin -a)"

TREE_MAX_PATHS = 20_000  # S13 D-6: the server refuses more; a larger tree is cut and says so (truncated, total)
TREE_BUDGET = 900_000  # bytes of the whole report: under the server's 1 MiB and Caddy's 1 MB door
TREE_MAX_CHANGES = 2_000
TREE_CHANGES_PER_COMMIT = 200
TREE_DAYS = 7
GIT_TIMEOUT = 60  # seconds for one git listing (a person or the detached child waits, never a hook)
REV_PARSE_TIMEOUT = 2  # the one git call of `due` (session start)
PR_OF_SUBJECT = (re.compile(r"\(#(\d{1,10})\)$"), re.compile(r"^Merge pull request #(\d{1,10}) "))


def days_arg(text: str) -> int:
    """argparse type of `--days`: a whole number of days from 1 to 30 (anything else exits 2 before gh runs)."""
    if not text.isdigit() or not 1 <= int(text) <= MAX_DAYS:
        raise argparse.ArgumentTypeError(f"--days takes a number from 1 to {MAX_DAYS}, not '{text}'")
    return int(text)


# --- sync.json and the lock ------------------------------------------------------------------------------------------


def state_path() -> Path:
    return flowmode_home() / STATE_FILE


def read_state() -> dict:
    """`sync.json` as a dict; {} when it is missing or unreadable (the next sync writes it again)."""
    try:
        data = json.loads(state_path().read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def write_state(data: dict) -> None:
    """Replace `sync.json` in one step (the `watcher.write_cache` pattern): a reader never sees half a file."""
    path = state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data))
    os.replace(tmp, path)


def mark(repo: str, **fields) -> None:
    """Record `fields` (e.g. `pulls_at`) under the canonical `repo` in `sync.json`."""
    data = read_state()
    entry = data.get(repo) if isinstance(data.get(repo), dict) else {}
    data[repo] = {**entry, **fields}
    write_state(data)


def lock_path(repo: str) -> Path:
    name = hashlib.sha1(repo.encode(), usedforsecurity=False).hexdigest()  # a file name, not a secret
    return flowmode_home() / f"sync.{name}.lock"


def take_lock(repo: str, now: float | None = None) -> Path | None:
    """The per-repo lock of the automatic sync, created O_EXCL; None when another child holds a fresh one. A lock
    older than LOCK_STALE_SECONDS is a dead child's and is replaced."""
    path = lock_path(repo)
    path.parent.mkdir(parents=True, exist_ok=True)
    now = time.time() if now is None else now
    for _ in range(2):
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            try:
                stale = now - path.stat().st_mtime > LOCK_STALE_SECONDS
            except OSError:
                stale = True  # gone meanwhile: try again
            if not stale:
                return None
            path.unlink(missing_ok=True)
            continue
        with os.fdopen(fd, "w") as f:
            f.write(str(os.getpid()))
        return path
    return None


# --- the automatic trigger (session start) ---------------------------------------------------------------------------


def github_path(info: RepoInfo) -> str | None:
    """`owner/name` when the checkout's origin is on github.com; None for any other host or form."""
    found = github_cli.github_repo_of(info.origin)
    return found if found is not None and found.count("/") == 1 else None


def _parse(value) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def pulls_fresh(entry, now: datetime | None = None) -> bool:
    """A pull sync of the repo is recorded in its `sync.json` entry within the last 24 hours, or a try that gh
    failed (`pulls_tried_at`) within the last `PULLS_RETRY` (so a member without `gh auth` does not start a child at
    every session start)."""
    if not isinstance(entry, dict):
        return False
    now = now or datetime.now(UTC)
    return any(
        last is not None and now - every < last <= now + timedelta(minutes=10)
        for last, every in (
            (_parse(entry.get("pulls_at")), PULLS_EVERY),
            (_parse(entry.get("pulls_tried_at")), PULLS_RETRY),
        )
    )


def local_head(root: Path, branch: str | None, timeout: float | None = GIT_TIMEOUT) -> str | None:
    """The commit `origin/<branch>` names in the clone at `root`; None when it cannot be read."""
    if not branch:
        return None
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--verify", "-q", f"refs/remotes/origin/{branch}^{{commit}}"],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"},
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    sha = r.stdout.strip()
    return sha if r.returncode == 0 and SHA_RE.fullmatch(sha) else None


def due(info: RepoInfo, session: dict | None = None, now: datetime | None = None) -> bool:
    """Whether session start should spawn the automatic sync: not switched off (`FLOWMODE_NO_AUTOSYNC` unset or
    `0`), a working checkout, and either the pulls are due (an origin on GitHub and no pull sync of this repo
    recorded in `sync.json` within the last 24 hours) or the tree is (any origin: the clone's `origin/<default>` is
    not the `tree_sha` last sent). Local reads only — `sync.json` and at most one `git rev-parse`, never `gh`,
    never the network; never raises."""
    try:
        if os.environ.get(AUTOSYNC_OFF, "") not in ("", "0"):
            return False
        if not is_checkout(info) or info.broken:
            return False
        entry = read_state().get(info.repo)
        if github_path(info) is not None and not pulls_fresh(entry, now):
            return True
        head = local_head(info.root, info.default_branch, timeout=REV_PARSE_TIMEOUT)
        return head is not None and head != (entry.get("tree_sha") if isinstance(entry, dict) else None)
    except Exception:  # noqa: BLE001 — the automatic sync must never break a session start
        return False


def spawn(root: Path | str) -> int | None:
    """Start the detached `pr sync --auto` child for the checkout at `root`; its pid, or None. Its stdio is /dev/null
    and it runs in its own session (a child holding the hook's stdout pipe would hang the hook); the token stays in
    `$FLOWMODE_HOME`, never in argv."""
    try:
        child = subprocess.Popen(
            [sys.executable, "-P", "-m", "flowmode", "pr", "sync", "--auto", "--repo", str(root)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
        )
    except OSError:
        return None
    return child.pid


# --- what is sent ----------------------------------------------------------------------------------------------------


def _time(value) -> str | None:
    """A time gh wrote, kept as written when it parses (GitHub's zero time for "never" is dropped)."""
    parsed = _parse(value) if isinstance(value, str) else None
    return value if parsed is not None and parsed.year > 1970 else None


def _title(value) -> str | None:
    text = display_safe(value)[:MAX_TITLE] if isinstance(value, str) else ""
    return text or None


def _login(author) -> str | None:
    """gh's `author {login}` when it is a GitHub user name the server takes; None otherwise (a bot's `app/…`)."""
    login = author.get("login") if isinstance(author, dict) else None
    return login if isinstance(login, str) and LOGIN_RE.fullmatch(login) else None


def pull_item(pr: dict) -> dict | None:
    """One pull request of the report from gh's JSON; None when its head branch or head commit cannot be sent (a
    name git would refuse). The body stays here: only its closing references go (`shared.closing_refs`)."""
    head, sha = pr.get("headRefName"), pr.get("headRefOid")
    if not isinstance(head, str) or not valid_ref_name(head) or not isinstance(sha, str) or not SHA_RE.fullmatch(sha):
        return None
    word = str(pr.get("state") or "").upper()
    merged_at = _time(pr.get("mergedAt"))
    merged = merged_at is not None or word == "MERGED"
    base = pr.get("baseRefName")
    body = pr.get("body") if isinstance(pr.get("body"), str) else ""
    closes = [
        [repo, number] for repo, number in closing_refs(body[:65536]) if repo is None or ISSUE_REPO_RE.fullmatch(repo)
    ][:MAX_CLOSES]
    created_at = _time(pr.get("createdAt"))
    return {
        "number": pr["number"],
        "state": "merged" if merged else ("closed" if word == "CLOSED" else "open"),
        "merged": merged,
        "merged_at": merged_at if merged else None,
        "created_at": created_at,
        "updated_at": _time(pr.get("updatedAt")) or created_at or _now_z(),
        "closed_at": _time(pr.get("closedAt")) if word in ("CLOSED", "MERGED") or merged else None,
        "head_ref": head,
        "base_ref": base if isinstance(base, str) and valid_ref_name(base) else None,
        "head_sha": sha,
        "fork": bool(pr.get("isCrossRepository")),
        "author_login": _login(pr.get("author")),
        "title": _title(pr.get("title")),
        "closes": closes,
    }


def issue_item(issue: dict) -> dict:
    """One open issue of the report: number, title, label names, update time — never its body or URL."""
    labels = [
        display_safe(label["name"])[:MAX_LABEL]
        for label in issue.get("labels") or []
        if isinstance(label, dict) and isinstance(label.get("name"), str)
    ]
    return {
        "number": issue["number"],
        "title": _title(issue.get("title")) or "",
        "labels": [label for label in labels if label][:MAX_LABELS],
        "updated_at": _time(issue.get("updatedAt")),
    }


def _now_z() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _plural(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


def held_line(held: dict) -> str:
    """`#14 merged — detect-risk-tests stays open: only bob or alice can finish it (flowmode pr sync as one of them,
    or Mark done)`."""
    owner, assigner = held.get("owner"), held.get("assigner")
    who = f"{owner} or {assigner}" if assigner and assigner != owner else str(owner)
    as_whom = "one of them" if assigner and assigner != owner else owner
    return (
        f"#{held.get('number')} merged — {held.get('task')} stays open: only {who} can finish it (flowmode pr "
        f"sync as {as_whom}, or Mark done)"
    )


def pulls_line(answer: dict, sent: int, days: int, truncated: bool) -> str:
    counts = answer.get("pulls") or {}
    parts = [f"pulls: {sent} reported ({_plural(days, 'day')})"]
    if answer.get("finished"):
        parts.append(f"{_plural(len(answer['finished']), 'task')} finished")
    if counts.get("kept"):
        parts.append(f"{counts['kept']} kept (webhook)")
    if truncated:
        parts.append("only the newest 300 (use --days to narrow it)")
    return " · ".join(parts)


# --- the command -----------------------------------------------------------------------------------------------------


def run(args: argparse.Namespace) -> int:
    """`flowmode pr sync [--days N] [--repo DIR]`: 0 when everything was sent, 1 when a part was not (gh missing or
    not signed in, a gh error, a repo the server does not know). With `--auto` (the detached child) nothing is
    printed and the exit is 0 whatever happens."""
    from flowmode.tasks import _run

    if args.auto:
        try:
            _sync(args, lambda _line: None)
        except Exception:  # noqa: BLE001 — the child is silent and never fails anything
            return 0
        return 0
    failed = []

    def command(a: argparse.Namespace) -> None:
        failed.append(_sync(a, print))

    return _run(command, args) or int(any(failed))


def _sync(args: argparse.Namespace, say) -> bool:
    """One sync of the checkout around `--repo`; True when a part was not sent. The automatic child holds the
    repo's lock for the whole run and stops at once when another child holds it."""
    from flowmode.tasks import Failed, _checkout, _config

    cfg = _config()
    root, _main, repo = _checkout(args.repo)
    info = find_repo(root)
    if not info.origin:
        raise Failed(f"{root} has no origin remote")
    lock = take_lock(repo) if args.auto else None
    if args.auto and lock is None:
        return False
    try:
        if args.auto and pulls_fresh(read_state().get(repo)):
            pulls_failed = False  # the child came for a moved tree: the pulls were asked for within 24 hours
        else:
            pulls_failed = _pulls_part(args, cfg, root, info, repo, say)
        tree_failed = _tree_part(cfg, root, info, repo, say)
        return pulls_failed or tree_failed
    finally:
        if lock is not None:
            lock.unlink(missing_ok=True)


def _pulls_part(args: argparse.Namespace, cfg, root: Path, info: RepoInfo, repo: str, say) -> bool:
    """The pull requests and open issues: not sent for an origin off GitHub (not a failure) or without a usable gh
    (a failure: gh is never started then); True when this part was not sent."""
    owner_name = github_path(info)
    if owner_name is None:
        say(NOT_GITHUB)
        return False
    if not github_cli.gh_ready():
        say(NO_GH)
        _tried(repo)
        return True
    return _send_pulls(args, cfg, root, repo, owner_name, say)


def _tried(repo: str) -> None:
    """Record a pull sync that gh could not serve: the automatic child backs off for `PULLS_RETRY`."""
    mark(repo, pulls_tried_at=datetime.now(UTC).isoformat(timespec="seconds"))


def _send_pulls(args: argparse.Namespace, cfg, root: Path, repo: str, owner_name: str, say) -> bool:
    """Ask gh for the pull requests and the open issues, post the report, print what happened; True when a part
    was not sent."""
    from flowmode.tasks import _client

    since = (datetime.now(UTC).date() - timedelta(days=args.days)).isoformat()
    try:
        listed = github_cli.pr_list_since(owner_name, since, root)
    except github_cli.GhMissing:
        say(NO_GH)
        _tried(repo)
        return True
    except github_cli.GhError as exc:
        say(f"pulls: not sent — gh: {exc}")
        _tried(repo)
        return True
    failed = False
    try:
        open_issues, complete = github_cli.issue_list_open(owner_name, root), True
    except (github_cli.GhMissing, github_cli.GhError) as exc:
        say(f"issues: not read — gh: {exc}")
        open_issues, complete, failed = [], False, True
    pulls = [item for item in (pull_item(p) for p in listed) if item is not None]
    issues = [issue_item(i) for i in open_issues]
    truncated = len(listed) >= github_cli.SYNC_LIMIT
    body = {
        "repo": repo,
        "days": args.days,
        "auto": bool(args.auto),
        "pulls": pulls,
        "issues": issues,
        "issues_complete": complete and len(open_issues) < github_cli.SYNC_LIMIT,
        "truncated": truncated,
    }
    with _client(cfg) as client:
        answer = client.sync_repo(body)
    if answer.get("ignored") == "repo":
        say(NOT_KNOWN.format(repo=repo))
        return True
    mark(repo, pulls_at=datetime.now(UTC).isoformat(timespec="seconds"))
    if answer.get("skipped") == "recent":
        say("pulls: skipped — sent within the last 24 hours")
        return failed
    say(terminal_safe(pulls_line(answer, len(pulls), args.days, truncated), 2000))  # S20 F-20-90: the server's counts
    if complete:
        say(f"issues: {len(issues)} open")
    for held in answer.get("held") or []:
        say(terminal_safe(held_line(held), 2000))
    return failed


# --- the file tree (F-13-20) -----------------------------------------------------------------------------------------


def _git_bytes(root: Path, *args: str) -> bytes | None:
    """stdout of `git args` as bytes (a `-z` listing is decoded name by name); None when git fails."""
    try:
        r = subprocess.run(
            ["git", *args],
            cwd=str(root),
            capture_output=True,
            timeout=GIT_TIMEOUT,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout if r.returncode == 0 else None


def _name(raw: bytes) -> str | None:
    """One path as git wrote it: strict UTF-8 and the server's path rule, else None (skipped and counted)."""
    try:
        path = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return path if valid_repo_path(path) else None


def tree_paths(root: Path, sha: str, extra=()) -> tuple[list[str], int] | None:
    """(the paths of commit `sha`, how many names were skipped: not UTF-8, failing the path rule, secret-looking or
    matching the repo's `tree_exclude` globs `extra` — S14 F-14-05); None when git cannot list them."""
    out = _git_bytes(root, "ls-tree", "-r", "-z", "--name-only", sha)
    if out is None:
        return None
    names = [raw for raw in out.split(b"\0") if raw]
    paths = [path for path in (_name(raw) for raw in names) if path is not None and not secret_looking(path, extra)]
    return paths, len(names) - len(paths)


def pr_of(subject: str) -> int | None:
    """The pull request a first-parent commit's subject names: a squash `Fix totals (#14)` or a merge `Merge pull
    request #11 from …`; None otherwise."""
    for pattern in PR_OF_SUBJECT:
        m = pattern.search(subject)
        if m is not None:
            return int(m.group(1))
    return None


def parse_changes(out: bytes, extra=()) -> list[dict]:
    """The `git log -z --name-only --format=%x1e%H%x1f%cI%x1f%s` listing (newest commit first) → one entry per path
    (its newest commit, that commit's time and PR), at most 200 paths per commit and 2 000 entries; secret-looking
    paths and the repo's `tree_exclude` globs `extra` are left out (S14 F-14-05)."""
    changes: dict[str, dict] = {}
    for chunk in out.split(b"\x1e")[1:]:
        head, _, rest = chunk.partition(b"\0")
        fields = head.decode("utf-8", errors="replace").split("\x1f", 2)
        if len(fields) != 3 or not SHA_RE.fullmatch(fields[0]) or _parse(fields[1]) is None:
            continue
        sha, at, subject = fields
        pr = pr_of(subject)
        for raw in rest.removeprefix(b"\n").split(b"\0")[:TREE_CHANGES_PER_COMMIT]:
            path = _name(raw) if raw else None
            if path is not None and path not in changes and not secret_looking(path, extra):
                changes[path] = {"path": path, "sha": sha, "at": at, "pr": pr}
                if len(changes) >= TREE_MAX_CHANGES:
                    return list(changes.values())
    return list(changes.values())


def fit(body: dict, paths: list[str]) -> list[str]:
    """The paths that fit: at most TREE_MAX_PATHS, and the whole report as JSON under TREE_BUDGET bytes (counted as
    `json.dumps` writes it: escaped and spaced, so never less than what is sent) — dropped from the end."""
    paths = paths[:TREE_MAX_PATHS]
    room = TREE_BUDGET - 1 - len(json.dumps({**body, "paths": []}).encode())
    used = 0
    for i, path in enumerate(paths):
        used += len(json.dumps(path)) + (2 if i else 0)
        if used > room:
            return paths[:i]
    return paths


def tree_line(answer: dict, sha: str, total: int) -> str:
    """`tree: 779 files at 1a2b3c4 (sent)`; a cut tree says how much of it went."""
    count = int(answer.get("count") or 0)
    if answer.get("truncated"):
        return f"tree: {count} of {total} files at {sha[:7]} (sent — the rest does not fit one report)"
    return f"tree: {_plural(count, 'file')} at {sha[:7]} (sent)"


def _tree_part(cfg, root: Path, info: RepoInfo, repo: str, say) -> bool:
    """The default branch's file tree: sent when the server holds another commit; True when it was not sent for a
    reason the member can fix (no origin/HEAD, origin/<default> not fetched, git failed, a repo the server does not
    know). A newer tree already on the server is not a failure."""
    from flowmode.api_client import ApiError
    from flowmode.tasks import _client

    branch = info.default_branch
    if not branch:
        say(NO_HEAD)
        return True
    sha = local_head(root, branch)
    if sha is None:
        say(f"tree: not sent — origin/{branch} is not in this clone (git fetch origin)")
        return True
    with _client(cfg) as client:
        head = client.tree_head(repo)
        if head is not None and head.get("sha") == sha:
            mark(repo, tree_sha=sha)
            say(f"tree: unchanged at {sha[:7]}")
            return False
        exclude = load_repo_config(root).tree_exclude  # S14 F-14-05: the working tree's flowmode.toml
        listed = tree_paths(root, sha, exclude)
        committed = _git_bytes(root, "show", "-s", "--format=%cI", sha)
        log = _git_bytes(
            root,
            "log",
            "-z",
            "--first-parent",
            "--diff-merges=first-parent",
            "--name-only",
            f"--since={TREE_DAYS}.days",
            "--format=%x1e%H%x1f%cI%x1f%s",
            sha,
        )
        if listed is None or committed is None or log is None:
            say(f"tree: not sent — git could not list origin/{branch}")
            return True
        paths, skipped = listed
        body = {
            "repo": repo,
            "default_branch": branch,
            "sha": sha,
            "committed_at": committed.decode().strip(),
            "truncated": False,
            "total": len(paths),
            "changes": parse_changes(log, exclude),
        }
        if skipped:  # only when > 0: an S13 server refuses the key (extra="forbid")
            body["skipped"] = skipped
        sent = fit(body, paths)
        body.update(paths=sent, truncated=len(sent) < len(paths))
        try:
            answer = client.report_tree(body)
        except ApiError as exc:
            if exc.status != 409:
                raise
            mark(repo, tree_sha=sha)
            say(f"tree: not sent — the server has a newer commit ({terminal_safe(str(exc.body.get('kept'))[:7])})")
            return False
    if answer.get("ignored") == "repo":
        say(f"tree: not sent — the server does not know {repo} yet")
        return True
    mark(repo, tree_sha=sha)
    if answer.get("unchanged"):
        say(f"tree: unchanged at {sha[:7]}")
        return False
    say(tree_line(answer, sha, len(paths)))
    return False
