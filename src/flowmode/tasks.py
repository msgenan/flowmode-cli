"""`flowmode task start|list|take` and `flowmode handoff` (S4 §7), the S7 §5 assignment commands
`task new|inbox|accept|decline|resend|cancel|done` and the S8 §8 `pin` / `pins`: config → API → git → registry →
printed `key: value` lines. Local git first, server second; a server refusal rolls the local change back. GitHub
issue steps run the member's own gh (flowmode.github_cli) only on the checkout's own GitHub repo: before the server
step a gh problem stops the command, after it a gh problem is a warning (S7 §4)."""

import json
import re
import shlex
import shutil
import sys
from contextlib import contextmanager
from pathlib import Path

from flowmode.api_client import ApiClient, ApiError, ServerUnreachable
from flowmode.github_cli import (
    GhError,
    GhMissing,
    assign_to_me,
    github_repo_of,
    issue_view,
)
from flowmode.ids import now_iso
from flowmode.member_config import MemberConfig, load_member_config, old_token_hint
from flowmode.paths import symlink_on_the_way, write_no_follow
from flowmode.refs import printable, valid_ref_name
from flowmode.repo import RepoInfo, canonical_repo, find_repo, origin_url, relative_path
from flowmode.risky import DEFAULT_RISKY_PATTERNS, is_risky
from flowmode.shared import TASK_NAME_RE, parse_issue_url
from flowmode.task_registry import load_registry, register_worktree
from flowmode.worktrees import (
    FLOWMODE_SKILL_FILES,
    GitError,
    add_worktree,
    branch_exists,
    branch_state,
    default_worktree_dir,
    git_root,
    list_worktrees,
    main_root,
    push_hints,
    remote_branch_exists,
    remove_worktree,
    short_head,
    valid_branch_name,
)

__all__ = [
    "TASK_NAME_RE",
    "handoff_cmd",
    "pin_cmd",
    "pins_cmd",
    "slugify",
    "task_accept",
    "task_cancel",
    "task_decline",
    "task_done",
    "task_inbox",
    "task_list",
    "task_new",
    "task_resend",
    "task_start",
    "task_take",
]

# Written by `flowmode install`, usually untracked: copied into a new worktree so hooks, MCP and the skills (S11
# F-11-41) work there.
AGENT_CONFIG_FILES = (".claude/settings.json", ".mcp.json", ".codex/hooks.json", *FLOWMODE_SKILL_FILES)


class Failed(Exception):
    """A domain error: printed as `error: <message>` on stderr, exit 1."""


# S9 §15: Turkish letters become their ASCII base before the S7 rule (web/src/slug.ts has the same table)
TURKISH = str.maketrans("çğıİöşüÇĞÖŞÜ", "cgiiosuCGOSU")


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.translate(TURKISH).lower()).strip("-")


def slugify(text: str) -> str:
    """A task name from free text (S7 §5.1; the browser uses the same rule): always matches TASK_NAME_RE."""
    return _slug(text)[:64].rstrip("-.") or "task"


def _run(command, args) -> int:
    try:
        command(args)
    except Failed as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except GitError as exc:
        print(f"error: git: {exc}", file=sys.stderr)
        return 1
    return 0


def api_failure(exc: Exception, cfg: MemberConfig) -> Failed:
    """The §7 wording for a failed API call."""
    if isinstance(exc, ServerUnreachable):
        return Failed(f"could not reach {cfg.server_url} ({exc})")
    if isinstance(exc, ApiError) and exc.status == 401:
        return Failed(f"token rejected by {cfg.server_url}")
    return Failed(exc.detail if isinstance(exc, ApiError) else str(exc))


@contextmanager
def _client(cfg: MemberConfig):
    """An ApiClient whose failures become Failed with the §7 wording."""
    client = ApiClient(cfg.server_url, cfg.token, timeout=cfg.request_timeout_seconds)
    try:
        yield client
    except (ApiError, ServerUnreachable) as exc:
        raise api_failure(exc, cfg) from exc
    finally:
        client.close()


def _config() -> MemberConfig:
    cfg = load_member_config()
    if cfg is None:
        raise Failed("not configured (run flowmode login --server <url>)")
    if old := old_token_hint(cfg.server_url, cfg.token):  # S17 F-17-31: nothing is sent with it
        raise Failed(old)
    return cfg


def _repo_dir(arg: str) -> Path:
    """--repo as an absolute directory (find_repo walks up from it, so "." must become the real cwd)."""
    path = Path(arg).absolute()
    if not path.is_dir():
        raise Failed(f"{arg} is not a directory")
    return path


def _checkout(arg: str) -> tuple[Path, Path, str]:
    """(root of the work tree around --repo, the main checkout, repo identity)."""
    directory = _repo_dir(arg)
    if (info := find_repo(directory)).broken:  # S11 F-11-31 (a)
        raise Failed(info.repair_hint())
    try:
        root = git_root(directory)
    except GitError:
        raise Failed(f"{directory} is not a git repository")
    return root, main_root(root), find_repo(root).repo


def _copy_agent_config(src_root: Path, dest_root: Path) -> None:
    """Copy the member's agent config files that exist in `src_root` and not in `dest_root` (never overwrite). A
    symbolic link on either side — a committed dangling link in the branch, a linked file in the main checkout — is
    not followed: that file is not copied and is named on stderr (review P1a-R2-1)."""
    src_root, dest_root = Path(src_root).resolve(), Path(dest_root).resolve()
    for rel in AGENT_CONFIG_FILES:
        src, dest = src_root / rel, dest_root / rel
        if not (src.is_file() or src.is_symlink()) or dest.exists():
            continue
        if symlink_on_the_way(src_root, src) or symlink_on_the_way(dest_root, dest):
            print(f"warning: not copied {rel}: a symbolic link — flowmode does not write through one", file=sys.stderr)
            continue
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            write_no_follow(dest, src.read_bytes(), replace=False)
            shutil.copystat(src, dest, follow_symlinks=False)
        except OSError as exc:  # a link or a file made meanwhile: left as it is
            print(f"warning: not copied {rel}: {exc.strerror or exc}", file=sys.stderr)


def _new_dir_parents(path: Path) -> list[Path]:
    """Create the missing parents of `path`; returns them (outermost last) so a rollback can remove them."""
    missing = [p for p in path.parents if not p.exists()]
    path.parent.mkdir(parents=True, exist_ok=True)
    return missing


def _rollback(main: Path, path: Path, branch: str | None, parents: list[Path]) -> None:
    """Undo a just-created worktree (and branch); best effort, the original error is what the member sees."""
    try:
        remove_worktree(main, path, delete_branch=branch)
    except GitError as exc:
        print(f"warning: could not remove {path}: {exc}", file=sys.stderr)
    for parent in parents:
        try:
            parent.rmdir()
        except OSError:
            break


def _start(args) -> None:
    name = args.name
    if not TASK_NAME_RE.fullmatch(name):
        raise Failed(f"invalid task name '{name}' (use a-z, 0-9, . _ -; max 64 chars)")
    branch = args.branch if args.branch is not None else name
    if not valid_branch_name(branch):
        raise Failed(f"invalid branch name '{branch}'")
    cfg = _config()
    root, main, repo = _checkout(args.repo)
    with _client(cfg) as client:
        assigned = _assigned_to_start(client, repo, name)
    if assigned is not None and args.branch is None:
        branch = assigned["branch"]
        if not valid_branch_name(branch):
            raise Failed(f"invalid branch name '{branch}'")
    path = Path(args.path).expanduser().absolute() if args.path else default_worktree_dir(main, name)
    if path.exists():
        raise Failed(f"{path} already exists")
    task, path = start_in_worktree(
        cfg, (root, main, repo), name, branch, path, assigned, branch_arg=args.branch, base=args.base
    )
    print(f"task: {name}")
    print(f"branch: {branch}")
    print(f"worktree: {path}")
    print(f"next: cd {path} && claude   (or codex) — hooks and MCP config were copied from {root}")
    if task["issue"]:  # catches up an accept made in the browser
        _gh_after_server(
            task,
            (root, github_repo_of(repo)),
            assign_to_me,
            "could not assign {ref} to you on GitHub ({why}); the task is started",
        )


def start_in_worktree(
    cfg: MemberConfig,
    checkout: tuple[Path, Path, str],
    name: str,
    branch: str,
    path: Path,
    assigned: dict | None,
    *,
    branch_arg: str | None = None,
    base: str | None = None,
    reuse: bool = False,
    track_remote: bool = False,
) -> tuple[dict, Path]:
    """The shared body of `task start` and `flowmode work` (S11 F-11-39): the worktree at `path` (created on
    `branch`, or reused when `reuse`), then the server step — an assigned task goes active (S7 §5.4) with the
    worktree path (an already active one only records the path when it changed), else a new S4 task. A server
    refusal removes a worktree created here. Copies the agent config and registers the worktree; returns (the task,
    the resolved path)."""
    root, main, repo = checkout
    parents, created = [], False
    if not reuse:
        parents = _new_dir_parents(path)
        created = not branch_exists(main, branch)
        try:
            add_worktree(main, path, branch, base=base, track_remote=track_remote)
        except GitError:
            for parent in parents:
                try:
                    parent.rmdir()
                except OSError:
                    break
            raise
    where = str(path.resolve())
    try:
        with _client(cfg) as client:
            if assigned is None:
                task = client.create_task(name, repo, branch)
            elif assigned["status"] == "active" and assigned.get("worktree") == where:
                task = assigned
            else:
                task = client.start_task(assigned["id"], branch_arg, worktree=where)
    except Failed as exc:
        if not reuse:
            _rollback(main, path, branch if created else None, parents)
        cause = exc.__cause__
        if assigned is None and isinstance(cause, ApiError) and cause.status == 409:
            owner = (cause.body.get("task") or {}).get("owner", "?")
            raise Failed(
                f"task '{name}' already exists in {repo} (owner {owner}); run  flowmode task take {name}  "
                "if it was handed to you"
            ) from cause
        raise

    _copy_agent_config(root, path)
    path = path.resolve()
    old = load_registry().get(str(path), {}) if reuse else {}
    register_worktree(
        path,
        {
            "repo": repo,
            "root": str(main),
            "task": name,
            "task_id": task["id"],
            "branch": branch,
            "handoff_id": old.get("handoff_id"),
            "created_at": old.get("created_at") or now_iso(),
        },
    )
    return task, path


def _assigned_to_start(client: ApiClient, repo: str, name: str) -> dict | None:
    """S7 §5.4: the task `name` in `repo` when it is mine and not started yet (the start path), else None (S4 path)."""
    me = client.me()["name"]
    return next(
        (
            t
            for t in client.list_tasks(repo=repo, name=name)
            if t["owner"] == me and t["status"] in ("proposed", "accepted")
        ),
        None,
    )


def task_start(args) -> int:
    return _run(_start, args)


def _handoffs_for(handoffs: list[dict], me: str) -> list[dict]:
    return [h for h in handoffs if h["to_member"] in (None, me)]


def _local_worktree(task: dict, registry: dict[str, dict]) -> str | None:
    """The registered local worktree of `task`: by task_id, else by (repo, branch) — the registry's repo may be
    an older raw form (S11 F-11-26)."""
    by_id = next((path for path, e in registry.items() if e.get("task_id") == task["id"]), None)
    return by_id or next(
        (
            path
            for path, e in registry.items()
            if (canonical_repo(e.get("repo")), e.get("branch")) == (task["repo"], task["branch"])
        ),
        None,
    )


OPEN_FOR_WORK = ("proposed", "accepted", "active")  # the statuses `flowmode work` picks up


def work_line(name: str, worktree: str | None) -> str:
    """S11 F-11-38: `cd <worktree> && claude   (or codex)` when the worktree is on this machine, else the entry
    command that makes it."""
    if worktree:
        return f"cd {shlex.quote(str(worktree))} && claude   (or codex)"
    return f"flowmode work {name}"


def only_worktree(name: str) -> str:
    """The long form under a `next: flowmode work` line (the S7 command, kept for scripts and habits)."""
    return f"  or, only the worktree without an agent: flowmode task start {name}"


def _server_worktree_here(task: dict) -> str | None:
    """The worktree path the server knows for `task` (S11 F-11-39), when that directory exists on this machine."""
    path = task.get("worktree")
    return path if path and Path(path).is_dir() else None


def _list(args) -> None:
    cfg = _config()
    if not args.all and (info := find_repo(_repo_dir(args.repo))).broken:  # S11 F-11-31 (a)
        raise Failed(info.repair_hint())
    repo = None if args.all else find_repo(_repo_dir(args.repo)).repo
    with _client(cfg) as client:
        me = client.me()["name"]
        tasks = client.list_tasks(repo=repo)
        handoffs = _handoffs_for(client.list_handoffs(status="pending", repo=repo), me)
    registry = load_registry()
    tasks = [{**t, "worktree": _local_worktree(t, registry) or _server_worktree_here(t)} for t in tasks]
    if args.json:
        print(json.dumps({"repo": repo, "member": me, "tasks": tasks, "handoffs": handoffs}, indent=2))
        return
    print(f"Tasks ({len(tasks)}):")
    if not tasks:
        print("No tasks yet — flowmode task start <name>")
    for t in tasks:
        where = f" · worktree {t['worktree']}" if t["worktree"] else ""
        scope = f" · {t['repo']}" if repo is None else ""
        print(f"- {t['name']} · branch {t['branch']} · owner {t['owner']} · {t['status']}{scope}{where}")
        if t["owner"] == me and t["status"] in OPEN_FOR_WORK:  # S11 F-11-38: the one line to go on
            print(f"  next: {work_line(t['name'], t['worktree'])}")
    print(f"Handoffs for you ({len(handoffs)}):")
    for h in handoffs:
        summary = h["summary"].strip().splitlines()[0] if h["summary"].strip() else ""
        print(f"- {h['id']} · from {h['from_member']} · task {h['task'] or '-'} · {summary}")


def task_list(args) -> int:
    return _run(_list, args)


def _same_dir(a: str | None, b: Path) -> bool:
    """Both sides resolved: the hook may have registered the directory through a symlink, or the shell may stand in one."""
    try:
        return a is not None and Path(a).resolve() == b.resolve()
    except (OSError, RuntimeError):
        return False


def _push_asks_approval(client: ApiClient, branch: str) -> bool:
    try:
        patterns = client.config().get("risky_patterns") or DEFAULT_RISKY_PATTERNS
    except (ApiError, ServerUnreachable):
        patterns = DEFAULT_RISKY_PATTERNS
    try:
        return bool(is_risky(f"git push origin {branch}", patterns))
    except re.error:
        return True


def _push_hints_for(
    client: ApiClient, session_id: str, handoff: dict, root: Path | None, args, to: str | None
) -> list[tuple[str, str]]:
    """S9 §3.1: measured in the session's worktree when it is on this machine, else the checkout here. Best effort:
    the handoff already happened, so nothing here may fail the command."""
    branch = handoff.get("branch")
    if not branch:
        return []
    try:
        worktree = client.get_session(session_id).get("worktree")
    except (ApiError, ServerUnreachable):
        worktree = None
    place = Path(worktree) if worktree and Path(worktree).is_dir() else root
    if place is None:
        try:
            place = git_root(_repo_dir(args.repo))
        except (GitError, Failed):
            return []
    return push_hints(branch_state(place, branch, timeout=None), branch, to, _push_asks_approval(client, branch))


def _in_worktrees_of(root: Path, sessions: list[dict]) -> list[dict]:
    """S9 §2.3: the sessions (of this checkout's repo) that live in another worktree of the same main checkout."""
    try:
        paths = [w["path"] for w in list_worktrees(main_root(root))]
    except GitError:
        return []
    repo = find_repo(root).repo
    return [s for s in sessions if s["repo"] == repo and any(_same_dir(s["worktree"], p) for p in paths)]


def _handoff(args) -> None:
    cfg = _config()
    if not args.summary.strip():
        raise Failed("summary must not be empty")
    to = None if (args.to or "").strip() in ("", "unassigned") else args.to.strip()
    root = None if args.session else find_repo(_repo_dir(args.repo)).root
    with _client(cfg) as client:
        session_id = args.session
        if session_id is None:
            me = client.me()["name"]
            live = client.list_sessions(member=me, status="active")
            mine = [s for s in live if _same_dir(s["worktree"], root)]
            if not mine:
                mine = _in_worktrees_of(root, live)
                if len(mine) > 1:
                    where = ", ".join(sorted(s["branch"] or s["worktree"] or s["id"] for s in mine))
                    raise Failed(
                        f"no active Flowmode session in {root}, but {len(mine)} in its worktrees ({where});"
                        " pass --session <id>"
                    )
            if not mine:
                raise Failed(f"no active Flowmode session in {root} (pass --session <id>)")
            session_id = max(mine, key=lambda s: s["last_seen_at"])["id"]
        handoff = client.handoff(session_id, args.summary, to)
        hints = _push_hints_for(client, session_id, handoff, root, args, to)
    target = handoff["task"] or handoff["id"]
    who = f"{to} can run" if to else "anyone can run"
    print(f"handoff: {handoff['id']}")
    print(f"to: {to or 'unassigned'}")
    print(f"paths: {', '.join(handoff['paths']) or '(none)'}")
    for key, text in hints:
        print(f"{key}: {text}")
    print(f"next: {who}  flowmode task take {target}")


def handoff_cmd(args) -> int:
    return _run(_handoff, args)


def _resolve_handoff(client: ApiClient, target: str, repo: str, me: str) -> dict:
    """§7.3 step 2: by id, or the newest handoff of task `target` in `repo` that is pending for me or taken by me."""
    if target.startswith("hof_"):
        found = client.list_handoffs(id=target)
        if not found:
            raise Failed(f"handoff {target} not found")
        handoff = found[0]
    else:
        handoff = next(
            (
                h
                for h in client.list_handoffs(repo=repo)
                if h["task"] == target
                and (
                    (h["status"] == "pending" and h["to_member"] in (None, me))
                    or (h["status"] == "taken" and h["taken_by"] == me)
                )
            ),
            None,
        )
        if handoff is None:
            raise Failed(f"no pending handoff for task '{target}' in {repo}")
    hid = handoff["id"]
    if handoff["status"] == "taken" and handoff["taken_by"] != me:
        raise Failed(f"handoff {hid} already taken by {handoff['taken_by']}")
    if handoff["to_member"] not in (None, me):
        raise Failed(f"handoff {hid} is addressed to {handoff['to_member']}")
    if handoff["repo"] != repo:
        raise Failed(f"handoff {hid} is for repo {handoff['repo']}, run this inside a checkout of it")
    if not handoff["branch"]:
        raise Failed(f"handoff {hid} has no branch")
    return handoff


def _is_worktree_on(main: Path, path: Path, branch: str) -> bool:
    return any(w["branch"] == branch and w["path"].resolve() == path.resolve() for w in list_worktrees(main))


def _take(args) -> None:
    cfg = _config()
    root, main, repo = _checkout(args.repo)
    with _client(cfg) as client:
        me = client.me()["name"]
        handoff = _resolve_handoff(client, args.target, repo, me)
    path = (
        Path(args.path).expanduser().absolute()
        if args.path
        else default_worktree_dir(main, handoff["task"] or handoff["branch"])
    )
    handoff, _, path = take_into_worktree(cfg, (root, main, repo), handoff, path)
    summary = handoff["summary"].strip().splitlines()
    print(f"handoff: {handoff['id']}")
    print(f"from: {handoff['from_member']}")
    print(f"task: {handoff['task'] or '-'}")
    print(f"branch: {handoff['branch']}")
    print(f"worktree: {path}")
    print(f"summary: {summary[0] if summary else ''}")
    print(f"files: {', '.join(handoff['paths']) or '(none)'}")
    print(f"next: cd {path} && claude   (or codex)")


def check_handoff_branch(branch: str) -> None:
    """S12 F-12-15: a pre-S12 handoff row may carry any branch; refuse it before git sees it (no fetch, no worktree)."""
    if not valid_ref_name(branch or ""):
        raise Failed(f"handoff branch '{printable(branch or '')}' is not a valid branch name")


def take_into_worktree(
    cfg: MemberConfig, checkout: tuple[Path, Path, str], handoff: dict, path: Path
) -> tuple[dict, dict | None, Path]:
    """The shared body of `task take` and `flowmode work` (S11 F-11-39): the handoff's branch in the worktree at
    `path` (reused when it is already a worktree on that branch), then the server take; a refusal removes a worktree
    created here. Copies the agent config and registers the worktree; returns (the taken handoff, its task or None,
    the resolved path)."""
    root, main, repo = checkout
    hid, branch = handoff["id"], handoff["branch"]
    check_handoff_branch(branch)
    reused = path.exists()
    if reused and not _is_worktree_on(main, path, branch):
        raise Failed(f"{path} already exists")
    created_branch, parents = None, []
    if not reused:
        if branch_exists(main, branch):
            track = False
            busy = next((w["path"] for w in list_worktrees(main) if w["branch"] == branch), None)
            if busy is not None:
                raise Failed(
                    f"branch '{branch}' is checked out in {Path(busy).resolve()} — take it there, or ask "
                    f"{handoff['from_member']} to hand off a task branch"
                )
        elif remote_branch_exists(main, branch):
            track, created_branch = True, branch
        else:
            who = handoff["from_member"]
            raise Failed(
                f"branch '{branch}' is not in this clone: run  git fetch origin {branch}  and try again — if "
                f"origin does not have it, {who} has not pushed it yet (ask {who}: git push -u origin "
                f"{branch})"
            )
        parents = _new_dir_parents(path)
        add_worktree(main, path, branch, track_remote=track)

    try:
        with _client(cfg) as client:
            handoff = client.take_handoff(hid)["handoff"]
            task = next((t for t in client.list_tasks(repo=repo) if t["name"] == handoff["task"]), None)
    except Failed as exc:
        if not reused:
            _rollback(main, path, created_branch, parents)
        cause = exc.__cause__
        if isinstance(cause, ApiError) and cause.status == 409:
            raise Failed(f"handoff {hid} {cause.detail.removeprefix('handoff ')}") from cause
        raise

    _copy_agent_config(root, path)
    path = path.resolve()
    register_worktree(
        path,
        {
            "repo": repo,
            "root": str(main),
            "task": handoff["task"],
            "task_id": task["id"] if task else None,
            "branch": branch,
            "handoff_id": hid,
            "created_at": now_iso(),
        },
    )
    return handoff, task, path


def task_take(args) -> int:
    return _run(_take, args)


# --- S7 §5: the assignment lifecycle ------------------------------------------------------------------------------


def _assigner(task: dict) -> str:
    """Who assigned the task; a pre-S7 row (null) counts as its owner."""
    return task["assigned_by"] or task["owner"]


def _issue_ref(task: dict) -> str:
    issue = task["issue"]
    return f"{issue['repo']}#{issue['number']}" if issue else "-"


def _one_line(text: str | None) -> str:
    return " ".join((text or "").split()) or "-"


def _same_github_repo(checkout: str | None, issue_repo: str) -> bool:
    """GitHub owner and repo names are case-insensitive."""
    return checkout is not None and checkout.casefold() == issue_repo.casefold()


def _gh_checkout(repo_arg: str) -> tuple[Path, str | None]:
    """(root, [HOST/]OWNER/REPO) of the checkout around --repo; the GitHub repo is None outside of one or without a
    GitHub remote."""
    directory = Path(repo_arg).absolute()
    if not directory.is_dir():
        return directory, None
    info = find_repo(directory)
    return info.root, github_repo_of(info.repo)


def _gh_after_server(task: dict, checkout: tuple[Path, str | None], step, failure: str) -> bool:
    """§4: a gh step after the server answered (the server step stands). Runs only on the issue of the checkout's own
    GitHub repo; any gh problem is a warning. True when gh did it."""
    issue, (root, github) = task["issue"], checkout
    ref = f"{issue['repo']}#{issue['number']}"
    if not _same_github_repo(github, issue["repo"]):
        print(
            f"warning: not touching {ref} on GitHub: this checkout's GitHub remote is {github or 'none'}",
            file=sys.stderr,
        )
        return False
    try:
        step(issue, root)
    except (GhMissing, GhError) as exc:
        why = "gh not found" if isinstance(exc, GhMissing) else str(exc)
        print(f"warning: {failure.format(ref=ref, why=why, **issue)}", file=sys.stderr)
        return False
    return True


def _issue_for_new(number: int, root: Path, github: str | None) -> dict:
    """§5.1 step 3: issue #number as gh sees it in the checkout — {repo, number, url, title}; it must be open and in
    the checkout's own GitHub repo. Failed otherwise (nothing reached the server)."""
    try:
        view = issue_view(number, root)
    except GhMissing:
        raise Failed("gh not found (install GitHub CLI and run gh auth login, or leave out --issue)")
    except GhError as exc:
        raise Failed(f"gh: {exc}")
    try:
        link = parse_issue_url(str(view.get("url") or ""))
    except ValueError:
        raise Failed(f"gh: issue #{number} has no GitHub issue link ({view.get('url')})")
    if not _same_github_repo(github, link["repo"]):
        raise Failed(f"issue #{number} is in {link['repo']}, not in this checkout's {github or 'GitHub remote (none)'}")
    if str(view.get("state") or "").upper() != "OPEN":
        raise Failed(f"issue #{number} is closed")
    body = view.get("body") if isinstance(view.get("body"), str) else None
    return {**link, "title": str(view.get("title") or ""), "body": (body or "")[:8000] or None}


def _print_task(task: dict, *extra: tuple[str, str]) -> None:
    print(f"task: {task['name']}")
    print(f"id: {task['id']}")
    print(f"status: {task['status']}")
    for key, value in extra:
        print(f"{key}: {value}")


def _new(args) -> None:
    cfg = _config()
    info = find_repo(_repo_dir(args.repo))
    name = args.name
    if name is None and args.issue is None and args.title is not None and _slug(args.title):
        name = slugify(args.title)  # S9 §15: a task named by its title
    if name is None and args.issue is None:
        raise Failed("give a task name or --issue <number>")
    if name is not None and not TASK_NAME_RE.fullmatch(name):
        raise Failed(f"invalid task name '{name}' (use a-z, 0-9, . _ -; max 64 chars)")
    if args.branch is not None and not valid_branch_name(args.branch):
        raise Failed(f"invalid branch name '{args.branch}'")
    checkout = (info.root, github_repo_of(info.repo))
    issue, title = None, args.title
    if args.issue is not None:
        issue = _issue_for_new(args.issue, *checkout)
        name = name or slugify(f"{args.issue}-{issue['title']}")
        title = title if title is not None else issue["title"]
    if args.branch is None and not valid_branch_name(name):
        raise Failed(f"invalid branch name '{name}'")
    with _client(cfg) as client:
        to = args.to or client.me()["name"]
        task = client.assign_task(
            to,
            info.repo,
            name,
            title=title,
            note=args.note,
            branch=args.branch,
            issue_url=issue["url"] if issue else None,
            issue_body=issue.get("body") if issue else None,
        )  # S11 F-11-28
    print(f"task: {task['name']}")
    print(f"id: {task['id']}")
    print(f"to: {task['owner']}")
    print(f"status: {task['status']}")
    print(f"issue: {_issue_ref(task)}")
    if task["status"] == "accepted":
        print(f"next: flowmode work {task['name']}")  # S11 F-11-38
        print(only_worktree(task["name"]))
    else:
        print(f"next: {task['owner']} sees it in  flowmode task inbox  and accepts or declines it")
    if task["status"] == "accepted" and task["issue"]:
        _gh_after_server(
            task, checkout, assign_to_me, "could not assign {ref} to you on GitHub ({why}); the task is accepted"
        )


def task_new(args) -> int:
    return _run(_new, args)


def _inbox(args) -> None:
    cfg = _config()
    with _client(cfg) as client:
        me = client.me()["name"]
        inbox = client.list_tasks(owner=me, status="proposed")
        declined = client.list_tasks(assigned_by=me, status="declined")
    if args.json:
        print(json.dumps({"member": me, "inbox": inbox, "declined": declined}, indent=2))
        return
    print(f"Inbox ({len(inbox)}):")
    if not inbox:
        print("Nothing waiting for you.")
    for t in inbox:
        issue = f" · issue {_issue_ref(t)}" if t["issue"] else ""
        print(f"- {t['id']} · {t['name']} · from {_assigner(t)} · {t['repo']} · {t['title']}{issue}")
        print(f"  next: flowmode work {t['name']}")  # S11 F-11-38: accepts, opens the worktree, starts the agent
    print(f"Declined ({len(declined)}):")
    for t in declined:
        print(
            f"- {t['id']} · {t['name']} · declined by {t['owner']} · {t['repo']} · "
            f"reason: {_one_line(t['decline_reason'])}"
        )


def task_inbox(args) -> int:
    return _run(_inbox, args)


def _resolve_task(client: ApiClient, target: str, repo_arg: str) -> dict:
    """S7 §5 TARGET: a task id (never resolves --repo, works outside a checkout) or a task name in --repo's repo."""
    if target.startswith("tsk_"):
        found = client.list_tasks(id=target)
        if not found:
            raise Failed(f"task {target} not found")
        return found[0]
    repo = find_repo(_repo_dir(repo_arg)).repo
    found = client.list_tasks(repo=repo, name=target)
    if not found:
        raise Failed(f"no task '{target}' in {repo}")
    return found[0]


def _act(args, action) -> dict:
    """Resolve TARGET and run one lifecycle route on it (`action(client, task_id)`); the task after the change."""
    cfg = _config()
    with _client(cfg) as client:
        task = _resolve_task(client, args.target, args.repo)
        return action(client, task["id"])


def _accept(args) -> None:
    task = _act(args, lambda client, task_id: client.accept_task(task_id))
    _print_task(task, ("from", _assigner(task)), ("next", f"flowmode work {task['name']}"))
    print(only_worktree(task["name"]))
    if task["issue"]:
        _gh_after_server(
            task,
            _gh_checkout(args.repo),
            assign_to_me,
            "could not assign {ref} to you on GitHub ({why}); the task is accepted",
        )


def _decline(args) -> None:
    task = _act(args, lambda client, task_id: client.decline_task(task_id, args.reason))
    _print_task(task, ("to", _assigner(task)))


def _resend(args) -> None:
    task = _act(args, lambda client, task_id: client.resend_task(task_id, args.to))
    _print_task(task, ("to", task["owner"]))


def _cancel(args) -> None:
    _print_task(_act(args, lambda client, task_id: client.cancel_task(task_id)))


def _delete(args) -> None:
    """S11 F-11-34: ask first (unless --yes); anything but `y` keeps the task."""
    cfg = _config()
    with _client(cfg) as client:
        task = _resolve_task(client, args.target, args.repo)
        if not args.yes:
            prompt = (
                f"Delete task '{task['name']}' (owner {task['owner']})? It disappears for everyone; events keep"
                " the history. [y/N] "
            )
            try:
                answer = input(prompt)
            except EOFError:
                answer = ""
            if not sys.stdin.isatty():
                print()  # a piped answer is not echoed: end the prompt's line
            if answer.strip().lower() != "y":
                raise Failed("not deleted")
        client.delete_task(task["id"])
    print(f"deleted: {task['name']}")


def _done(args) -> None:
    """S12 F-12-14: the server step only — the issue stays open until the merge of its pull request closes it (the
    `Closes` line of `flowmode check --pr-text`); no gh call. --comment/--no-issue are accepted and ignored."""
    task = _act(args, lambda client, task_id: client.finish_task(task_id))
    _print_task(task)
    if args.comment is not None or args.no_issue:
        print(
            "note: --comment and --no-issue are ignored since S12: task done leaves the issue open, the merge of"
            " its pull request closes it",
            file=sys.stderr,
        )
    if not task["issue"]:
        return
    ref = _issue_ref(task)
    github = _gh_checkout(args.repo)[1]
    if _same_github_repo(github, task["issue"]["repo"]):
        print(f"issue: {ref} stays open (closes when its pull request is merged)")
        return
    print(f"issue: {ref} stays open")
    print(
        f"warning: not touching {ref} on GitHub: this checkout's GitHub remote is {github or 'none'}, so a pull"
        " request from here does not close it",
        file=sys.stderr,
    )


def task_accept(args) -> int:
    return _run(_accept, args)


def task_decline(args) -> int:
    return _run(_decline, args)


def task_resend(args) -> int:
    return _run(_resend, args)


def task_cancel(args) -> int:
    return _run(_cancel, args)


def task_delete(args) -> int:
    return _run(_delete, args)


def task_done(args) -> int:
    return _run(_done, args)


# --- S8 §8: pinned notes ------------------------------------------------------------------------------------------


def _pin_checkout() -> tuple[RepoInfo, Path]:
    """(the checkout around the current directory, the current directory); Failed outside one or without origin."""
    cwd = Path.cwd()
    info = find_repo(cwd)
    if not (info.root / ".git").exists():
        raise Failed(f"{cwd} is not inside a git checkout")
    if origin_url(info.root) is None:
        raise Failed(f"{info.root} has no origin remote (the team knows a repository by its origin URL)")
    return info, cwd


def _pin(args) -> None:
    cfg = _config()
    info, cwd = _pin_checkout()
    path = relative_path(info, cwd, args.path)
    if path is None:
        raise Failed(f"{args.path} is not a file inside {info.root}")
    if not args.text.strip():
        raise Failed("text must not be empty")
    try:
        commit = short_head(info.root)
    except GitError:
        commit = None  # a repository without a commit yet: the note is pinned without one
    with _client(cfg) as client:
        pin = client.create_pin(info.repo, path, args.text, commit)
    print(f"pinned {pin['path']} at {pin['commit']}" if pin.get("commit") else f"pinned {pin['path']}")


def pin_cmd(args) -> int:
    return _run(_pin, args)


def _pins(args) -> None:
    cfg = _config()
    info, _ = _pin_checkout()
    with _client(cfg) as client:
        pins = client.list_pins(repo=info.repo)
    for pin in pins:
        lines = pin["text"].strip().splitlines()
        state = "stale" if pin["stale"] else "ok"
        print(f"{pin['path']} · {state} · {pin['member']} · {lines[0] if lines else ''}")


def pins_cmd(args) -> int:
    return _run(_pins, args)
