"""`flowmode work [TASK]` (S11 F-11-39 + F-11-38): one command from a task to an agent working in its worktree.

Lists the member's tasks in this repo (in the inbox, accepted, in progress) and the pending handoffs for them, asks
which one (skipped when TASK is given) and which agent — every time, `--agent` skips the question and nothing is
stored (kickoff §1.4). A proposed task is accepted and started, an accepted one started, an active one reused, a
handoff taken (the `task start` / `task take` bodies in flowmode.tasks); the worktree is reused when one is on the
branch (the registry, else `git worktree list`), else created next to the main checkout. Then it prints `task:`,
`branch:`, `worktree:` and `launch:` and replaces itself with the agent, started in the worktree (`--no-launch` only
prints)."""

import os
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path

from flowmode.github_cli import assign_to_me, github_repo_of
from flowmode.refs import terminal_safe
from flowmode.task_registry import find_worktree, forget_worktree, load_registry
from flowmode.tasks import (
    OPEN_FOR_WORK,
    Failed,
    _checkout,
    _client,
    _config,
    _gh_after_server,
    _handoffs_for,
    _is_worktree_on,
    _run,
    check_handoff_branch,
    start_in_worktree,
    take_into_worktree,
)
from flowmode.worktrees import (
    branch_exists,
    default_worktree_dir,
    fetch_branch,
    list_worktrees,
    remote_branch_exists,
    valid_branch_name,
)

AGENTS = ("claude", "codex")
STATUS_WORDS = {"proposed": "in your inbox", "accepted": "accepted", "active": "in progress"}
NO_TASKS = "no tasks for you — ask a teammate to assign one or run  flowmode task new <name>"
FETCH_FAILED = (
    "note: could not fetch {branch} from origin — the fetch never asks (an ssh remote needs your key in"
    " ssh-agent and a known host: ssh-add, then ssh to it once)"
)
TRIES = 3  # a wrong answer is asked again this often before the command gives up
# The parser (help text, examples, common errors) lives in flowmode.cli, so a hook call never imports this module.


@dataclass
class Choice:
    """One line of the list: a task of mine (`task`) or a pending handoff for me (`handoff`)."""

    kind: str
    item: dict

    @property
    def name(self) -> str:
        if self.kind == "task":
            return self.item["name"]
        return self.item["task"] or self.item["branch"]

    def describe(self, me: str) -> str:
        item = self.item
        if self.kind == "task":
            title = f" · {item['title']}" if item["title"] and item["title"] != item["name"] else ""
            by = item["assigned_by"] or item["owner"]
            source = f" · from {by}" if by != me else ""
            return f"{item['name']}{title} · {STATUS_WORDS[item['status']]}{source}"
        lines = item["summary"].strip().splitlines()
        summary = f" · {lines[0][:80]}" if lines else ""
        to = "you" if item["to_member"] == me else "anyone"
        return f"{self.name}{summary} · handed off to {to} · from {item['from_member']}"

    def matches(self, target: str) -> bool:
        if self.kind == "task":
            return target in (self.item["name"], self.item["id"])
        return target in (self.item["id"], self.item["task"], self.item["branch"])


def _choices(client, repo: str, me: str) -> list[Choice]:
    """In the inbox, accepted, in progress (each newest first), then the handoffs for me or anyone that have a
    branch to open."""
    order = {status: i for i, status in enumerate(OPEN_FOR_WORK)}
    tasks = sorted(
        (t for t in client.list_tasks(repo=repo, owner=me) if t["status"] in order), key=lambda t: order[t["status"]]
    )
    handoffs = [h for h in _handoffs_for(client.list_handoffs(status="pending", repo=repo), me) if h["branch"]]
    return [Choice("task", t) for t in tasks] + [Choice("handoff", h) for h in handoffs]


def _ask(question: str) -> str:
    """One answer from stdin; Failed when stdin is closed. Without a terminal the answer is not echoed, so a newline
    keeps the next printed line on its own."""
    print(question, end=" ", flush=True)
    line = sys.stdin.readline()
    if not sys.stdin.isatty():
        print()
    if not line:
        raise Failed("no answer on stdin (give the task and --agent on the command line)")
    return line.strip()


def _pick(choices: list[Choice], me: str) -> Choice:
    print(f"Your tasks ({len(choices)}):")
    for i, choice in enumerate(choices, 1):
        print(f"  {i}  {terminal_safe(choice.describe(me), 2000)}")  # S20 F-20-90: titles, summaries
    for _ in range(TRIES):
        answer = _ask("Which task? [1]") or "1"
        if answer.isdigit() and 1 <= int(answer) <= len(choices):
            return choices[int(answer) - 1]
        found = next((c for c in choices if c.matches(answer)), None)
        if found is not None:
            return found
        print(f"answer with a number from 1 to {len(choices)}")
    raise Failed("no task chosen")


def _agent() -> str:
    for _ in range(TRIES):
        answer = _ask("Which agent? (claude/codex)").lower()
        if answer in AGENTS:
            return answer
        if answer in ("1", "2"):
            return AGENTS[int(answer) - 1]
        print("answer claude or codex")
    raise Failed("no agent chosen (or pass --agent claude|codex)")


def _choose_agent(args) -> str:
    """`--agent`, else the question; `--no-launch` starts nothing, so with no one to answer it is claude (walkthrough F25)."""
    if args.agent:
        return args.agent
    try:
        return _agent()
    except Failed:
        if args.no_launch:
            return "claude"
        raise


def _existing_worktree(main: Path, task_id: str | None, repo: str, branch: str, gone=None) -> Path | None:
    """A worktree of this main checkout on `branch` (never the main checkout itself): the registered one first.
    S12 F-12-31 (the F-11-34 leftover): `task delete` leaves the local registry entry, so an entry found for another
    task is asked about — `gone(task_id)` true (the server no longer has it) forgets the entry and goes on as if none
    was registered."""
    on_branch = [
        w["path"]
        for w in list_worktrees(main)
        if w["branch"] == branch and w["path"].is_dir() and w["path"].resolve() != main.resolve()
    ]
    registered = find_worktree(task_id, repo, branch)
    other = (load_registry().get(registered) or {}).get("task_id") if registered is not None else None
    if other and other != task_id and gone is not None and gone(other):
        forget_worktree(registered)
        registered = None
    if registered is not None and any(p.resolve() == Path(registered).resolve() for p in on_branch):
        return Path(registered)
    return on_branch[0] if on_branch else None


def _task_gone(cfg, task_id: str) -> bool:
    """The server answers and has no task `task_id` (deleted); unreachable or refused counts as still there."""
    try:
        with _client(cfg) as client:
            return client.list_tasks(id=task_id) == []
    except Failed:
        return False


def _open_task(cfg, checkout, task: dict) -> tuple[dict, Path]:
    root, main, repo = checkout
    branch = task["branch"]
    if not valid_branch_name(branch):
        raise Failed(f"invalid branch name '{branch}'")
    path = _existing_worktree(main, task["id"], repo, branch, gone=lambda gone_id: _task_gone(cfg, gone_id))
    reuse = path is not None
    if path is None:
        path = default_worktree_dir(main, task["name"])
        if path.exists():
            if not _is_worktree_on(main, path, branch):
                raise Failed(f"{path} already exists")
            reuse = True
    if (
        not reuse
        and task.get("pr_number") is not None
        and not branch_exists(main, branch)
        and not remote_branch_exists(main, branch)
        # S12 F-12-12: a fix task's branch is the pull request's, already pushed — fetch it first, never a fresh
        # branch of the same name off main (code-pr.md §10)
        and not fetch_branch(main, branch)
    ):
        raise Failed(f"branch {branch} is not on origin — ask {_branch_owner(cfg, task)} to push it")
    was = task["status"]
    started, path = start_in_worktree(
        cfg, checkout, task["name"], branch, path, task, reuse=reuse, track_remote=remote_branch_exists(main, branch)
    )
    if was != "active" and started["issue"]:  # as `task start`: the issue goes to the member on GitHub
        _gh_after_server(
            started,
            (root, github_repo_of(repo)),
            assign_to_me,
            "could not assign {ref} to you on GitHub ({why}); the task is started",
        )
    return started, path


def _branch_owner(cfg, task: dict) -> str:
    """Who pushes a fix task's branch: the owner of the pull request's own task (the server's PR row), else its
    author on GitHub, else "the pull request's author" (best effort: this is only the error's wording)."""
    try:
        with _client(cfg) as client:
            pull = client.get_pull(task["repo"], task["pr_number"])
            found = client.list_tasks(id=pull["task_id"]) if pull.get("task_id") else []
            if found:
                return found[0]["owner"]
            if pull.get("author_login"):
                return pull["author_login"]
    except Failed:
        pass
    return "the pull request's author"


def _open_handoff(cfg, checkout, handoff: dict, me: str) -> tuple[dict, Path]:
    _root, main, repo = checkout
    branch = handoff["branch"]
    check_handoff_branch(branch)  # before any git call that takes the name (fetch_branch below)
    path = _existing_worktree(
        main, None, repo, branch, gone=lambda gone_id: _task_gone(cfg, gone_id)
    ) or default_worktree_dir(main, handoff["task"] or branch)
    if (
        not path.exists()
        and not branch_exists(main, branch)
        and not remote_branch_exists(main, branch)
        and not fetch_branch(main, branch)  # the sender pushed it; without it the take below says what to do
    ):
        print(FETCH_FAILED.format(branch=branch), file=sys.stderr)
    handoff, task, path = take_into_worktree(cfg, checkout, handoff, path)
    if task is not None and task["owner"] == me and task["status"] == "active" and task.get("worktree") != str(path):
        try:  # best effort: the web shows the cd line only when the server knows the path
            with _client(cfg) as client:
                client.start_task(task["id"], worktree=str(path))
        except Failed as exc:
            print(f"warning: the worktree path was not recorded on the server ({exc})", file=sys.stderr)
    return handoff, path


def _work(args) -> None:
    cfg = _config()
    checkout = _checkout(args.repo)
    repo = checkout[2]
    with _client(cfg) as client:
        me = client.me()["name"]
        choices = _choices(client, repo, me)
    if not choices:
        raise Failed(NO_TASKS)
    if args.task is not None:
        choice = next((c for c in choices if c.matches(args.task)), None)
        if choice is None:
            raise Failed(f"'{args.task}' is not one of your tasks in {repo} — run  flowmode work  to see them")
    else:
        choice = _pick(choices, me)
    agent = _choose_agent(args)

    if choice.kind == "task":
        task, path = _open_task(cfg, checkout, choice.item)
        name, branch = task["name"], task["branch"]
    else:
        handoff, path = _open_handoff(cfg, checkout, choice.item, me)
        print(f"handoff: {terminal_safe(handoff['id'])}")  # S20 F-20-90: server text through the one filter
        print(f"from: {terminal_safe(handoff['from_member'])}")
        name, branch = handoff["task"] or "-", handoff["branch"]
    launch = f"cd {shlex.quote(str(path))} && {agent}"
    print(f"task: {terminal_safe(name)}")
    print(f"branch: {terminal_safe(branch)}")
    print(f"worktree: {terminal_safe(str(path), 2000)}")
    print(f"launch: {terminal_safe(launch, 2000)}")
    if args.no_launch:
        return
    sys.stdout.flush()  # exec replaces the process: what is still buffered would be lost
    sys.stderr.flush()
    os.chdir(path)
    _agent_env(cfg)
    try:
        os.execvp(agent, [agent])  # noqa: S606 — the agent the person chose replaces this process
    except OSError as exc:
        raise Failed(f"could not start {agent} ({exc.strerror or exc}): run  {launch}")


def _agent_env(cfg) -> None:
    """S17 F-17-12.f (D-3): the agent's hooks and MCP server (`${FLOWMODE_TOKEN}`) get this computer's server and
    device token from config.toml; a variable the shell already set wins. Never printed."""
    for name, value in (("FLOWMODE_SERVER_URL", cfg.server_url), ("FLOWMODE_TOKEN", cfg.token)):
        if not os.environ.get(name):
            os.environ[name] = value


def work_cmd(args) -> int:
    return _run(_work, args)
