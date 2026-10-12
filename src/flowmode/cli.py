"""`flowmode` command line. Exit codes: 0 ok, 1 domain error, 2 usage."""

import argparse
import importlib
import sys

from flowmode import __version__
from flowmode.shared import DEVICE_PAGE, DEVICE_TOKEN_PREFIX

INSTALLABLE_AGENTS = ["claude", "codex"]
# run by `server_cli`, which the client build does not ship (L-2); S19 adds `workspace`
SERVER_COMMANDS = ("serve", "member", "modules", "workspace")
REPO_HELP = "any directory inside the checkout (default: current directory)"
TARGET_HELP = "task id (tsk_…, works from any directory) or task name in the repo of --repo"
# S17 F-17-31 (D-7): `flowmode init` is gone; this is what is left of it
INIT_GONE = "flowmode init is gone: run flowmode login --server <url>"
WORK_DESCRIPTION = """\
Pick one of your tasks in this repository and start working on it: a task in your inbox is
accepted and started, an accepted one started, one in progress reused, a handoff for you taken.
Its worktree (<repo>-worktrees/<task> next to the main checkout) is reused or created, and the
agent you choose (claude or codex, asked every time unless --agent) starts inside it."""
WORK_EPILOG = """Examples:
  flowmode work                          list your tasks, ask which one and which agent
  flowmode work login-fix --agent codex  straight to one task with Codex
  flowmode work login-fix --no-launch    prepare the worktree, print the line that starts the agent

Common errors:
  no tasks for you                       nothing assigned to you here: ask a teammate, or  flowmode task new <name>
  '<name>' is not one of your tasks      a typo, someone else's task, or a task of another repository (--repo)
  branch '<b>' is not in this clone      the handoff's branch is not on origin yet: ask its sender to push it
  <path> already exists                  a directory that is not a worktree of the task's branch is in the way
  could not start <agent>                the agent is not on PATH: install it, or run the printed  launch:  line
"""
CHECK_DESCRIPTION = """\
Run the completion check of the task in this worktree before you push: every command of
`checks` in flowmode.toml (plus --also), each through the shell with a 10 min limit; the
issue's `- [ ]` lines are listed as criteria and `person_checks` as person items, both open.
A command that needs an approval (git push, curl, …) is not run. Each command's status and
exit code are stored on the task (never its output, which is printed here only) and shown on
the push approval card (never blocking). Only the task's owner stores them.
It also fetches the default branch (origin/HEAD, about 5 s at most) and names the files that
would conflict when it is merged in (git merge-tree: nothing in the checkout changes), and
prints the task's pull request as your own gh sees it (about 5 s at most), reporting its
facts to the task (flowmode pr does only that)."""
CHECK_EPILOG = """Examples:
  flowmode check                                  run the repo's checks in this task worktree
  flowmode check --also "uv run pytest tests/unit/test_export.py -q"
                                                  add the tests of the modules you touched, not the world
  flowmode check --pr-text                        also print the PR text: "Closes <issue>" (a task with an
                                                  issue: the merge closes it), then "What I verified"

Common errors:
  no checks: create flowmode.toml ...             the repo has no checks = [...] yet: add the file at its root
  not stored: no task for this worktree           run it in a task worktree (flowmode work <task>)
  check: <command> · failed (exit 1)              read the output tail printed under it, fix, run again
  check: <command> · refused — needs approval     a risky command: run it yourself, as its own command
  upload failed: … — not stored on the task       offline, or not your task: the results printed stand
  conflicts with main: <files> (origin/main)      after a yes, merge origin/main in (never rebase), run again
  pr: #<n> open · checks <n> failed · …           the pull request's own checks: fix, run again, ask to push
"""
# S11 F-11-34: the same fuller --help (what it does, Examples:, Common errors:) for the other everyday commands
# S14 F-14-13: sign a device in with GitHub (the device flow runs on the server), and out again
LOGIN_DESCRIPTION = """\
Sign this machine in with your GitHub account: the team server starts GitHub's device flow,
you open https://github.com/login/device and type the code shown here, and the server gives
this device its own token (fmd_…), written to $FLOWMODE_HOME/config.toml (the config it
replaces is kept beside it as config.toml.<UTC time>.bak). Your GitHub account must be on the
team. Each device's token can be revoked on its own (web: Profile, Devices; or flowmode logout).

With --code (the one-time code from the web page, "Connect this computer") it signs in at once,
without a browser or GitHub; the one line shown there installs Flowmode and runs this for you.

Without FLOWMODE_HOME (your real ~/.flowmode) a loopback or plain-http address needs --yes."""
LOGIN_EPILOG = """Examples:
  flowmode login --server https://flowmode.example.com
  flowmode login --server https://flowmode.example.com --code FM-ABCDE-FGHJK-LMNPQ-RSTUV
  flowmode login --name work-laptop                     again, on the server in config.toml
  flowmode login --server http://flowmode.lan:7420 --yes   plain http on purpose

Common errors:
  not on the team                         your GitHub account has no invitation: ask a team leader
  the code expired                        type the code on GitHub within 15 minutes: run flowmode login again
  the sign-in was denied on GitHub        Cancel was pressed on GitHub: run flowmode login again
  no GitHub sign-in on <server>           the server is not set up for it: ask the admin
  too many sign-ins; try again in <n> s   wait, then run flowmode login again
  GitHub did not answer                   GitHub, or the server's way to it, is down: try again later
"""
LOGOUT_DESCRIPTION = """\
Sign this device out: the server revokes this device's token (your other devices keep
theirs), then the token is removed from $FLOWMODE_HOME/config.toml (the old file is kept
beside it as a backup, without the token). Sign in again with flowmode login."""
LOGOUT_EPILOG = """Examples:
  flowmode logout

Common errors:
  not signed in on this device            config.toml holds no token: nothing to do
  this is an old member token: …          config.toml holds a retired fm_ token: run flowmode login --server <url>
  could not reach <server>                the token still works on the server: revoke the device on the web (Profile)
"""
REHEARSE_DESCRIPTION = """\
Make a harmless test approval (card 5): the server opens a test request with its own fixed
text, you approve or deny it on the web (signed in with GitHub), and this command prints
what you decided. Nothing runs, here or anywhere: the request only proves approvals reach you.
It waits approval_timeout_seconds from config.toml (the request itself expires in 10 minutes)."""
REHEARSE_EPILOG = """Examples:
  flowmode rehearse

Common errors:
  not configured                          sign this computer in first: flowmode login
  started from a computer ...             config.toml holds an old member token: run flowmode login
  Timed out.                              nobody decided in time: run flowmode rehearse again
"""
DOCTOR_DESCRIPTION = """\
Check this clone for card 3 and report it to the team server: origin is the team repo, an
agent (claude / codex) on PATH with its hooks, gh installed and signed in, and for a leader
the hook files committed. Each fact gets a check or a cross, and every cross its fix. The
report holds booleans, versions and the repo name only - no file contents, no paths.
A leader's first report sets the team repo; --team-repo makes this clone's origin the team repo."""
DOCTOR_EPILOG = """Examples:
  flowmode doctor                         in your clone of the team repo
  flowmode doctor --json                  card 3 as the server answered
  flowmode doctor --team-repo             (leader) this clone's origin becomes the team repo

Common errors:
  error: <repo problem>                   the repo's git data is broken: the message says how to repair it
  not in a git repo: cd into ...          run it inside your clone of the team repo
  report not sent: ...                    the server was not reached: the checks above still hold; run it again later

Exit status: 0 when card 3's rule is met and the report was sent; 1 otherwise.
"""
INSTALL_DESCRIPTION = """\
Write an agent's Flowmode hooks, MCP server entry and skills into a repository, so every
session of that agent in this checkout reports to the team server (claims, overlap warnings,
approvals of risky commands). Run it once per agent in the main checkout."""
INSTALL_EPILOG = """Examples:
  flowmode install claude                 in the checkout, for Claude Code
  flowmode install codex --repo ../app    for Codex, in another checkout
  flowmode install claude --force         also replace Flowmode skills you edited locally

Common errors:
  not configured                          run flowmode login --server <url> first
  skipped <file>: edited locally          your edit is kept; rerun with --force to replace it
  <file> is not a valid JSON object       fix or move the agent's settings file, run install again
  warning: flowmode is not on PATH        the hooks will not run: add the printed directory to PATH
"""
HANDOFF_DESCRIPTION = """\
Hand your agent session's work to a teammate (or to anyone): its claims move with it, its
task becomes handed off, and the receiver continues in their own worktree with
flowmode task take. First commit, and ask your person to push the branch so the receiver can
check it out."""
HANDOFF_EPILOG = """Examples:
  flowmode handoff "login form done, tests for the reset flow left" --to bob
  flowmode handoff "half of the export; see the plan" --session ses_…

Common errors:
  no active Flowmode session in <dir>     run it inside the worktree of a live agent session, or pass --session
  unknown member '<name>'                 a typo in --to: the member names are on the web UI's Team screen
  summary must not be empty               say what is done and what is left
"""
TASK_START_DESCRIPTION = """\
Create a git worktree on a new branch next to the main checkout and register it as a team
task. A task assigned to you with this name is started instead (its branch is used), and the
agent config (hooks, MCP) is copied into the new worktree."""
TASK_START_EPILOG = """Examples:
  flowmode task start login-fix           worktree <repo>-worktrees/login-fix on branch login-fix
  flowmode task start login-fix --branch fix/login --base origin/main

Common errors:
  task '<name>' already exists in <repo>  if it was handed to you:  flowmode task take <name>
  <path> already exists                   a directory is in the way: remove it or pass --path
  invalid task name '<name>'              use a-z, 0-9, . _ - (max 64 characters)
  not configured                          run flowmode login --server <url> first
"""
TASK_ACCEPT_DESCRIPTION = """\
Accept a task in your inbox (flowmode task inbox): the assigner sees it accepted, and a linked
GitHub issue is assigned to you (needs gh). Start it with flowmode work <name>."""
TASK_ACCEPT_EPILOG = """Examples:
  flowmode task accept login-fix          by name, in this checkout's repository
  flowmode task accept tsk_…              by id, from any directory

Common errors:
  no task '<name>' in <repo>              a typo, or a task of another repository: pass --repo or the id
  task is assigned to <member>            only the member it is assigned to accepts it
  task is accepted                        it is not in your inbox any more: flowmode work <name>
"""
TASK_DELETE_DESCRIPTION = """\
Delete a task for everyone, in any status (unlike cancel, which keeps it as cancelled). Asks
first unless --yes. Its events stay in the history; a live session on it loses its task
label. Only its assigner or its owner may delete it. The worktree and branch stay on disk."""
TASK_DELETE_EPILOG = """Examples:
  flowmode task delete old-spike          asks, then deletes the task old-spike of this repository
  flowmode task delete tsk_… --yes        by id, without asking

Common errors:
  not deleted                             the answer was not y: nothing changed
  only <assigner> or <owner> can delete   ask one of them
  no task '<name>' in <repo>              a typo, already deleted, or another repository: pass --repo or the id
"""

# S11 F-11-34 (review R3): the same fuller --help for every other command — (what it does, Examples: + Common errors:)
MORE_HELP: dict[str, tuple[str, str]] = {
    "env": (
        """\
Print shell export lines for FLOWMODE_SERVER_URL and FLOWMODE_TOKEN from your stored config,
for a shell or tool that should report as you. The token is printed: never paste the output
into a shared place.""",
        """Examples:
  eval "$(flowmode env)"                          in this shell only
  flowmode env                                    see what would be exported

Common errors:
  not configured                                  run flowmode login --server <url> first
""",
    ),
    "update": (
        """\
Install the client release the team server runs (the public client repo at the tag v<version>), then
re-run install for the agents that already have Flowmode hooks in this repo. The command is printed before it runs; off a terminal
it needs --yes.""",
        """Examples:
  flowmode update                                 show the command and ask
  flowmode update --yes                           run it without asking

Common errors:
  could not read the server's version             the server is down, or it did not answer with a version
""",
    ),
    "hook": (
        """\
Handle one agent hook event: read the hook's JSON on stdin, talk to the team server (claims,
overlap warnings, approvals) and answer the agent on stdout. The agent calls it through the
config that flowmode install wrote; you rarely run it by hand.""",
        """Examples:
  flowmode hook session-start < payload.json      what Claude Code runs when a session starts
  flowmode hook pre-tool-use --agent codex < payload.json

Common errors:
  Flowmode: not connected on this computer …    the hook allows the tool but records nothing
  Flowmode: could not reach <server>              offline: edits pass unrecorded, risky commands are denied
""",
    ),
    "watch": (
        """\
End this agent session when its agent process exits. The session-start hook starts it in the
background, one per session; it reads the session from the cache file and your token from
the config on disk, never from its command line. You do not run it by hand.""",
        """Examples:
  flowmode watch --pid 4242 --start "Mon Sep 28 10:00:00 2026" --cache ~/.flowmode/sessions/claude-<id>.json

Common errors:
  (none printed)                                  it leaves quietly when it cannot vouch for the session
  FLOWMODE_NO_WATCHER=1                           the session-start hook starts no watcher
""",
    ),
    "task list": (
        """\
List the team's tasks in this repository (owner, branch, status, your local worktree), the
next step for yours, and the handoffs waiting for you. --all lists every repository.""",
        """Examples:
  flowmode task list                              this checkout's repository
  flowmode task list --all --json                 every repository, as one JSON object

Common errors:
  not configured                                  run flowmode login --server <url> first
  No tasks yet — flowmode task start <name>       nothing is registered in this repository yet
""",
    ),
    "task take": (
        """\
Take a handoff: check out its branch in a new worktree next to the main checkout, copy the
agent config into it, and mark the handoff taken (its task becomes yours). The target is the
task name or the handoff id. A task released to the team (no handoff for you under that name,
or its tsk_… id) is taken on its page in the browser: the server refuses a device token, so
this prints the task's page and exits 1.""",
        """Examples:
  flowmode task take login-fix                    the pending handoff of task login-fix in this repository
  flowmode task take hof_…                        by handoff id
  flowmode task take tsk_…                        a released task, by id (prints its page)

Common errors:
  no pending handoff for task '<name>' in <repo>  nothing handed off under that name: flowmode task list
  handoff <id> is addressed to <member>           only that member (or anyone, for an unassigned one) takes it
  this task was released — take it on the site    not a handoff: open the printed page and press Take
  branch '<b>' is not in this clone               git fetch origin <b>, or ask the sender to push it
  <path> already exists                           a directory is in the way: remove it or pass --path
""",
    ),
    "task new": (
        """\
Assign a task to a member (yourself by default) in this checkout's repository. It waits in
their inbox until they accept it; with --issue N the title, body and link come from the
GitHub issue (needs gh).""",
        """Examples:
  flowmode task new login-fix --to bob --title "Fix the login crash"
  flowmode task new --issue 42 --to alice         name, title and body from issue #42

Common errors:
  give a task name or --issue <number>            one of the two is needed
  invalid task name '<name>'                      use a-z, 0-9, . _ - (max 64 characters)
  gh not found (install GitHub CLI …)             install gh and run gh auth login, or leave out --issue
  issue #<n> is closed                            reopen it on GitHub or pick another issue
""",
    ),
    "task inbox": (
        """\
Show the tasks assigned to you that wait for an answer (accept or decline), and the tasks you
assigned that were declined, with the reason.""",
        """Examples:
  flowmode task inbox
  flowmode task inbox --json                      one JSON object

Common errors:
  not configured                                  run flowmode login --server <url> first
  token rejected by <server>                      a revoked device: run flowmode login again
  you are no longer in workspace <name>           ask a leader for a new invitation, then flowmode login
""",
    ),
    "task decline": (
        """\
Decline a task in your inbox, optionally with a reason; the assigner sees it among their
declined tasks and may resend it.""",
        """Examples:
  flowmode task decline login-fix --reason "on holiday this week"
  flowmode task decline tsk_…                     by id, from any directory

Common errors:
  task is assigned to <member>                    only the member it is assigned to declines it
  task is accepted                                it left your inbox: ask the assigner to cancel it instead
  no task '<name>' in <repo>                      a typo, or another repository: pass --repo or the id
""",
    ),
    "task resend": (
        """\
Send a declined (or still waiting) task again, to the same member or with --to to someone
else; it goes back to their inbox. Only the member who assigned it resends it.""",
        """Examples:
  flowmode task resend login-fix                  to the same member again
  flowmode task resend login-fix --to carol

Common errors:
  only <assigner> can resend this task            ask the member who assigned it
  task is accepted                                it is being worked on: nothing to resend
  unknown member '<name>'                         a typo in --to: the names are on the Team screen
""",
    ),
    "task cancel": (
        """\
Cancel a task: it stays in the list as cancelled (flowmode task delete removes it). Its
assigner cancels it at any time; its owner once it is accepted (a waiting one is declined).""",
        """Examples:
  flowmode task cancel old-spike
  flowmode task cancel tsk_…                      by id, from any directory

Common errors:
  only <assigner> or <owner> can cancel …         ask one of them
  only <assigner> can cancel a <status> task      as its owner, decline it instead
  task is done                                    finished tasks stay as they are
""",
    ),
    "task release": (
        """\
Give a task back to the team: it stays yours (its owner) until any member takes it. Its owner or
a leader of the workspace releases it, on the task's page in the browser: the server refuses a
device token, so this prints the task's page and exits 1. A done task cannot be released.""",
        """Examples:
  flowmode task release login-fix --note "away until Monday"
  flowmode task release tsk_…                     by id, from any directory

Common errors:
  only the task's owner or a leader may release it   ask its owner or a leader
  task is done                                       finished tasks stay as they are
  task is already released                           it waits for a taker: flowmode task list
""",
    ),
    "task done": (
        """\
Mark an accepted or in-progress task done: its owner or whoever assigned it. A linked GitHub
issue stays open: the merge of the pull request closes it (flowmode check --pr-text writes the
closing line). No gh call; the worktree and branch stay on disk. --comment and --no-issue are
still accepted and ignored since S12.""",
        """Examples:
  flowmode task done login-fix                    done without a pull request

Common errors:
  task is assigned to <member>                    only its owner or its assigner marks it done
  task is proposed                                accept and start it first: flowmode work <name>
""",
    ),
    "chat": (
        """\
Write one message to the team chat, for people only (agents never read it). An @name
mentions that member; the printed mentions: line lists whom it reached.""",
        """Examples:
  flowmode chat "deploying the API at 15:00, hold your pushes"
  flowmode chat "@bob can you look at the export task?"

Common errors:
  text must not be empty                          say something
  not configured                                  run flowmode login --server <url> first
""",
    ),
    "pin": (
        """\
Pin a note to a file of this checkout for the whole team: agents see the repository's notes at
session start, people on the web UI. The note goes stale when an agent edits the file.""",
        """Examples:
  flowmode pin src/auth.py "the token refresh is racy, see #40 before changing it"
  flowmode pin docs/API.md "v2 endpoints only"

Common errors:
  <path> is not a file inside <root>              give the path relative to the current directory
  <root> has no origin remote                     the team knows a repository by its origin URL: add one
  text must not be empty                          write the note
""",
    ),
    "pins": (
        """\
List the pinned notes of this checkout's repository, newest first, stale ones marked.""",
        """Examples:
  flowmode pins
  cd ../app && flowmode pins                      another checkout

Common errors:
  <dir> is not inside a git checkout              run it inside a checkout
  <root> has no origin remote                     the team knows a repository by its origin URL: add one
""",
    ),
    "pr": (
        """\
Show the pull request of this task worktree's branch as your own gh sees it (state, checks,
review, whether it can be merged) and report those facts to the task: numbers, states and
the paths the branch changes against the default branch — never the diff, a title or a body.
A merged pull request marks the task done. Only the task's owner or assigner reports.

flowmode pr sync fills the team in on the whole repository: the pull requests updated in the
last 30 days (--days N, 1-30) and the open issues, as your own gh lists them — numbers, states,
titles and closing references, never a body. A merged pull request finishes its task when you
are the task's owner or assigner; anyone else's sync names the task instead. Session start runs
it by itself once a day in the background.""",
        """Examples:
  flowmode pr                                     in the task worktree
  flowmode pr --repo ../app-worktrees/login-fix
  flowmode pr sync                                in any checkout of the repository
  flowmode pr sync --days 7

Common errors:
  gh not found                                    install GitHub's CLI and run  gh auth login
  pr: none for <branch>                           no pull request yet: your person pushes, then gh pr create
  not reported: no task for this worktree         run it in a task worktree (flowmode work <task>)
  pulls: not sent — gh is not installed or not signed in (gh auth login)
                                                  install gh and sign in, then run flowmode pr sync again
  not reported: the server does not know <repo> yet (no task or live session)
                                                  start a task or an agent session in this repository first
""",
    ),
    "fix": (
        """\
Take the fix of a pull request that needs one (conflicts with main, failing checks, changes
requested). On your own task's pull request you continue that task; if you own a module it
touches you get a fix task on its branch at once; anyone else asks the task's owner, who
allows or denies it from Needs you (the branch stays theirs until they agree).""",
        """Examples:
  flowmode fix 12                                 in a checkout of the repository
  flowmode fix 12 --repo ../app

Common errors:
  pull request not found                          the server knows it from the webhook or  flowmode pr
  #<n> comes from a fork — fix it on GitHub       a fork's branch is not on origin
  pull request #<n> is not linked to a task       nobody to ask: its author runs  flowmode pr  first
  a request to take the fix on #<n> is already waiting for <owner>
                                                  wait for the owner's answer in Needs you
""",
    ),
    "review": (
        """\
A review session on a pull request before it is merged. `flowmode review 12` fetches the PR's
head, opens a detached worktree <repo>-worktrees/review-12 at it (your own task worktree may
keep the branch), writes the reviewer's prompt to $FLOWMODE_HOME/reviews/ and starts your agent
there. The reviewer judges first and edits nothing; it merges only after you say "merge". The
verdict is advice on the merge approval, never a lock. The verbs, in the review worktree:
verdict APPROVE|CHANGES records it, post comments it on the PR (after your yes), pass <member>
hands the review to a teammate, who answers with accept / decline; withdraw takes it back.
After the merge, followups reads the "## Follow-ups" drafts of the PR's description and lists
them; you decide the list with Open all on the site, then followups --open opens the approved
ones as issues with your gh.""",
        """Examples:
  flowmode review 12                              in a checkout of the repository
  flowmode review pay-retry --agent claude        by the task's name
  flowmode review 12 --to carol                   pass it to carol before opening it
  flowmode review verdict CHANGES --notes-file notes.md
  flowmode review post                            the verdict as a comment on the PR (your gh)
  flowmode review pass carol
  flowmode review accept 12                       a review passed to you
  flowmode review decline 12 --reason "out until Monday"
  flowmode review withdraw 12
  flowmode review followups                       after the merge: the drafts, proposed and listed
  flowmode review followups --open --label follow-up
  flowmode review followups --release <id>        a row left being opened with no issue on GitHub

Common errors:
  #<n> comes from a fork — review it on GitHub    a fork's branch is not on origin
  no pull request for <task> — push it and open the PR, or run  flowmode pr
                                                  the server and your gh know no PR yet
  the review of #<n> is with <member> — run  flowmode review accept <n>  if it was passed to you
                                                  only the holder (or a module owner) opens it
  not a review worktree                           run the verbs in the worktree flowmode review opened
  no merge yet                                    follow-ups are read only after the PR is merged
  nothing approved yet                            decide the list with Open all on the site first
""",
    ),
}


def _fuller(description: str, epilog: str) -> dict:
    """add_parser keywords for the fuller --help: the description, then Examples: and Common errors: as written."""
    return {"description": description, "epilog": epilog, "formatter_class": argparse.RawDescriptionHelpFormatter}


def _more(command: str) -> dict:
    return _fuller(*MORE_HELP[command])


def _server_cli():
    """The server's commands (`server_cli`), or None in the client build, which does not ship that module."""
    try:  # import_module, not `from flowmode import …`: that finds a module already imported even when it is hidden
        return importlib.import_module("flowmode.server_cli")
    except ModuleNotFoundError as error:
        if error.name != "flowmode.server_cli":  # a module that server_cli itself needs is missing: a real fault
            raise
        return None


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="flowmode")
    parser.add_argument("--version", action="version", version=f"flowmode {__version__}")
    parser.add_argument(  # S19 §4.4: a global option (dest apart from the server commands' own --workspace)
        "--workspace",
        dest="cli_workspace",
        metavar="ID",
        help="the workspace (an id from config.toml) this command is for, when the clone's origin does not say",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    login = commands.add_parser(
        "login",
        help="sign this device in with GitHub; its own token goes to $FLOWMODE_HOME",
        **_fuller(LOGIN_DESCRIPTION, LOGIN_EPILOG),
    )
    login.add_argument("--server", help="server URL (default: the one in config.toml)")
    login.add_argument("--name", help="this device's name on the Devices list (default: the short hostname)")
    login.add_argument("--yes", action="store_true", help="in your real home: accept a loopback or plain-http address")
    login.add_argument(
        "--code",
        help="the one-time code from the web page (Connect this computer): sign in without a browser or GitHub",
    )
    login.add_argument(
        "--approval-timeout", type=int, help="seconds a hook waits for an approval (default: keep the current one)"
    )
    commands.add_parser(
        "logout",
        help="revoke this device's token and remove it from $FLOWMODE_HOME",
        **_fuller(LOGOUT_DESCRIPTION, LOGOUT_EPILOG),
    )
    commands.add_parser(
        "rehearse",
        help="make a harmless test approval and wait for your decision on the web (runs nothing)",
        **_fuller(REHEARSE_DESCRIPTION, REHEARSE_EPILOG),
    )
    commands.add_parser("env", help="print shell exports for FLOWMODE_SERVER_URL and FLOWMODE_TOKEN", **_more("env"))
    doctor = commands.add_parser(
        "doctor",
        help="check this clone for card 3 (origin, hooks, gh) and report it to the team server",
        **_fuller(DOCTOR_DESCRIPTION, DOCTOR_EPILOG),
    )
    doctor.add_argument("--team-repo", action="store_true", help="(leader) make this clone's origin the team repo")
    doctor.add_argument("--json", action="store_true", help="print the server's answer as JSON")
    install = commands.add_parser(
        "install",
        help="write an agent's hook and MCP config into a repo",
        **_fuller(INSTALL_DESCRIPTION, INSTALL_EPILOG),
    )
    install.add_argument("agent", choices=INSTALLABLE_AGENTS)
    install.add_argument("--repo", default=".", help="repository directory (default: current directory)")
    install.add_argument("--force", action="store_true", help="replace Flowmode skills that were edited locally")
    update = commands.add_parser(
        "update", help="install the client release the server runs, then re-install the hooks here", **_more("update")
    )
    update.add_argument("--yes", action="store_true", help="run without asking (needed when not on a terminal)")
    update.add_argument(
        "--allow-downgrade", action="store_true", help="install the server's version even when it is older than this"
    )
    hook = commands.add_parser(
        "hook", help="handle one agent hook event (reads the hook JSON on stdin)", **_more("hook")
    )
    hook.add_argument("event", choices=["session-start", "pre-tool-use", "post-tool-use", "stop", "session-end"])
    hook.add_argument("--agent", choices=["claude", "codex"], default="claude")
    # S12 F-12-03: started by the session-start hook, detached; no token and no session id on its command line
    watch = commands.add_parser(
        "watch",
        help="end this session when its agent process exits (the session-start hook starts it; not for direct use)",
        **_more("watch"),
    )
    watch.add_argument("--pid", type=int, required=True, help="the agent process")
    watch.add_argument("--start", required=True, help="its start time (a reused pid is another process)")
    watch.add_argument("--cache", required=True, help="the hook's session cache file (names the session)")
    watch.add_argument("--every", type=float, default=5.0, help="seconds between checks (default 5)")
    task = commands.add_parser("task", help="git worktrees registered as team tasks")
    task_cmds = task.add_subparsers(dest="task_command", required=True)
    start = task_cmds.add_parser(
        "start",
        help="create a worktree on a new branch and register it as a task",
        **_fuller(TASK_START_DESCRIPTION, TASK_START_EPILOG),
    )
    start.add_argument("name")
    start.add_argument("--branch", help="branch name (default: the task name)")
    start.add_argument("--base", help="start point of a new branch (default: HEAD of the main checkout)")
    start.add_argument("--path", help="worktree directory (default: <repo>-worktrees/<name> next to the checkout)")
    start.add_argument("--repo", default=".", help="any directory inside the checkout (default: current directory)")
    listing = task_cmds.add_parser(
        "list", help="the team's tasks, handoffs waiting for you, your local worktrees", **_more("task list")
    )
    listing.add_argument("--repo", default=".", help="any directory inside the checkout (default: current directory)")
    listing.add_argument("--all", action="store_true", help="every repository, not only this one")
    listing.add_argument("--json", action="store_true", help="one JSON object instead of text")
    take = task_cmds.add_parser(
        "take", help="check out a handed-off branch in a new worktree and take the handoff", **_more("task take")
    )
    take.add_argument("target", help="task name, handoff id (hof_…) or released task id (tsk_…)")
    take.add_argument("--path", help="worktree directory (default: <repo>-worktrees/<name> next to the checkout)")
    take.add_argument("--repo", default=".", help="any directory inside the checkout (default: current directory)")
    _task_assignment_parsers(task_cmds)
    work = commands.add_parser(
        "work",
        help="pick one of your tasks and start your agent in its worktree",
        description=WORK_DESCRIPTION,
        epilog=WORK_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    work.add_argument("task", nargs="?", help="task name (or handoff id); default: choose from the list")
    work.add_argument("--agent", choices=INSTALLABLE_AGENTS, help="the agent to start (default: asked every time)")
    work.add_argument("--repo", default=".", help=REPO_HELP)
    work.add_argument("--no-launch", action="store_true", help="prepare the worktree and print the launch line only")
    handoff = commands.add_parser(
        "handoff",
        help="hand your agent session's work and claims to a member",
        **_fuller(HANDOFF_DESCRIPTION, HANDOFF_EPILOG),
    )
    handoff.add_argument("summary", help="what is done, what is left")
    handoff.add_argument("--to", default="unassigned", help="member name, or 'unassigned' (default) for anyone")
    handoff.add_argument("--session", help="session id (default: your live session in this worktree)")
    handoff.add_argument("--repo", default=".", help="any directory inside the worktree (default: current directory)")
    chat = commands.add_parser(
        "chat", help="write to the team chat (people only; agents never read it)", **_more("chat")
    )
    chat.add_argument("text")
    pin = commands.add_parser(
        "pin", help="pin a note to a file of this checkout (it goes stale when an agent edits the file)", **_more("pin")
    )
    pin.add_argument("path", help="the file, relative to the current directory")
    pin.add_argument("text", help="the note")
    commands.add_parser("pins", help="this checkout's pinned notes, newest first", **_more("pins"))
    check = commands.add_parser(
        "check",
        help="run the task's completion check (tests, criteria, person items)",
        description=CHECK_DESCRIPTION,
        epilog=CHECK_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    check.add_argument(
        "mode",
        nargs="?",
        choices=["commit-msg"],
        help="commit-msg <file>: the git hook's check — the message and author/committer name no agent (S20)",
    )
    check.add_argument("file", nargs="?", help=argparse.SUPPRESS)
    check.add_argument(
        "--repo", default=".", help="any directory inside the task worktree (default: current directory)"
    )
    check.add_argument(
        "--also",
        action="append",
        default=[],
        metavar="CMD",
        help="one more command to run (repeatable): the tests of the modules you touched",
    )
    check.add_argument(
        "--pr-text",
        action="store_true",
        help='also print the PR text: "Closes <issue>" (a task with an issue), "What I verified"',
    )
    pr = commands.add_parser(
        "pr", help="this task's pull request as your gh sees it; reports its facts to the task", **_more("pr")
    )
    pr.add_argument(
        "verb",
        nargs="?",
        choices=["sync"],
        help="sync: report the repository's pull requests of the last days and its open issues",
    )
    pr.add_argument("--repo", default=".", help="any directory inside the task worktree (default: current directory)")
    pr.add_argument("--days", type=_sync_days, help="pr sync: how many days back (1-30, default 30)")
    pr.add_argument("--auto", action="store_true", help=argparse.SUPPRESS)  # the detached child of session start
    fix = commands.add_parser(
        "fix", help="take the fix of a pull request (continue, a fix task, or ask its owner)", **_more("fix")
    )
    fix.add_argument("number", type=_pr_number, help="the pull request's number (12 or #12)")
    fix.add_argument("--repo", default=".", help=REPO_HELP)
    review = commands.add_parser(
        "review",
        help="a review session on a pull request before its merge; the verdict, passing it on, posting it",
        **_more("review"),
    )
    review.add_argument(
        "target",
        metavar="PR|TASK|VERB",
        help="the pull request (12 or #12) or the task name; or verdict, pass, accept, decline,"
        " withdraw, post, followups",
    )
    review.add_argument(
        "arg",
        nargs="?",
        help="verdict: APPROVE or CHANGES; pass: the member; accept / decline /"
        " withdraw: the pull request or task (default: this review worktree's)",
    )
    review.add_argument("--repo", default=".", help=REPO_HELP)
    review.add_argument("--agent", choices=INSTALLABLE_AGENTS, help="the agent to start (default: asked every time)")
    review.add_argument("--no-launch", action="store_true", help="prepare the worktree and print the launch line only")
    review.add_argument("--to", metavar="MEMBER", help="pass the review to a teammate instead of opening it")
    review.add_argument("--notes-file", metavar="FILE", help="verdict: the notes (at most 4000 characters)")
    review.add_argument(
        "--blocking-file",
        metavar="FILE",
        help="verdict CHANGES: what must be fixed before the merge, one item per line",
    )
    review.add_argument("--reason", help="decline: why")
    review.add_argument(
        "--open", action="store_true", help="followups: open the approved follow-ups as GitHub issues with your gh"
    )
    review.add_argument(
        "--label", action="append", metavar="LABEL", help="followups --open: a label for the issues (repeatable)"
    )
    review.add_argument(
        "--release",
        metavar="ID",
        help="followups: give back a follow-up left being opened when no issue for it is on GitHub (asks first)",
    )
    server = _server_cli()  # last, so --help lists the client commands first
    if server is not None:
        server.register(commands, _fuller)
    else:
        for name in SERVER_COMMANDS:  # listed so --help says why; `main` answers them before parsing (their options)
            commands.add_parser(name, help="a server command; not in the client build")
    return parser


def _task_assignment_parsers(task_cmds) -> None:
    """S7 §5: new, inbox, accept, decline, resend, cancel, done; S11 F-11-34: delete."""
    new = task_cmds.add_parser("new", help="assign a task to a member (default: yourself)", **_more("task new"))
    new.add_argument("name", nargs="?", help="task name (a-z, 0-9, . _ -)")
    new.add_argument("--to", help="member name (default: yourself)")
    new.add_argument("--title", help="one-line title (default: the task name)")
    new.add_argument("--note", help="free text for the assignee")
    new.add_argument("--branch", help="branch name (default: the task name)")
    new.add_argument(
        "--issue",
        type=int,
        metavar="N",
        help="GitHub issue number in this checkout's repo (needs gh): title and link come from it",
    )
    new.add_argument("--repo", default=".", help=REPO_HELP)
    inbox = task_cmds.add_parser(
        "inbox", help="tasks waiting for you and tasks you assigned that were declined", **_more("task inbox")
    )
    inbox.add_argument("--json", action="store_true", help="one JSON object instead of text")
    for command, help_text in (
        ("accept", "accept a task in your inbox"),
        ("decline", "decline a task in your inbox"),
        ("resend", "send a declined task again, or to someone else"),
        ("cancel", "cancel a task"),
        ("done", "mark a task done (its owner or its assigner)"),
        ("release", "give a task back to the team (its owner or a leader); any member takes it"),
        ("delete", "delete a task for everyone (asks first)"),
    ):
        fuller = {
            "accept": _fuller(TASK_ACCEPT_DESCRIPTION, TASK_ACCEPT_EPILOG),
            "delete": _fuller(TASK_DELETE_DESCRIPTION, TASK_DELETE_EPILOG),
        }.get(command) or _more(f"task {command}")
        sub = task_cmds.add_parser(command, help=help_text, **fuller)
        sub.add_argument("target", help=TARGET_HELP)
        sub.add_argument("--repo", default=".", help=REPO_HELP)
        if command == "delete":
            sub.add_argument("--yes", action="store_true", help="do not ask")
        if command == "decline":
            sub.add_argument("--reason", help="why (the assigner sees it)")
        if command == "resend":
            sub.add_argument("--to", help="member name (default: the same member again)")
        if command == "release":
            sub.add_argument("--note", help="why, for the team (rides the release event)")
        if command == "done":
            # S12 F-12-14: done never closes the issue; both options stay (the S7 parser pins), ignored with a note
            sub.add_argument("--comment", help="ignored since S12 (the merge of the pull request closes the issue)")
            sub.add_argument("--no-issue", action="store_true", help="ignored since S12 (the issue stays open)")


def _hook(args: argparse.Namespace) -> int:
    from flowmode.hooks import run_hook

    result = run_hook(args.event, args.agent, sys.stdin.read())
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    return result.exit_code


def _init_address_refusal(url: str) -> str | None:
    """F-12-01 / D-7 (`flowmode login`, kept from init): in the real home a loopback address (a test address?) or
    plain http needs --yes."""
    import ipaddress
    from urllib.parse import urlsplit

    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        host = ""
    loopback = host == "localhost" or host.endswith(".localhost")
    try:
        ip = ipaddress.ip_address(host)
        loopback = loopback or ip.is_loopback or ip.is_unspecified
    except ValueError:
        pass
    if loopback:
        return "loopback address in your real home — a test address? pass --yes to mean it"
    if url.startswith("http://"):
        return (
            f"plain http to {host or url} would send your token unencrypted — use https, or pass --yes to mean it"
            " (e.g. a private network address)"
        )
    return None


def _env_override_warning(cfg) -> str | None:
    """S10 F-10-17: FLOWMODE_SERVER_URL / FLOWMODE_TOKEN in this shell beat the file `flowmode login` just wrote.
    The token's value is never printed."""
    import os

    url = os.environ.get("FLOWMODE_SERVER_URL")
    token = os.environ.get("FLOWMODE_TOKEN")
    names, shown = [], []
    if url and url.rstrip("/") != cfg.server_url:
        names.append("FLOWMODE_SERVER_URL")
        shown.append(f"FLOWMODE_SERVER_URL={url}")
    if token and token != cfg.token:
        names.append("FLOWMODE_TOKEN")
        shown.append("FLOWMODE_TOKEN (another token)")
    if not names:
        return None
    return (
        f"warning: this shell sets {' and '.join(shown)}, not what login wrote; the environment overrides the"
        " file, so flowmode, its hooks and `install` would use it. Remove the old export from your shell"
        f" profile and open a new terminal, or run: unset {' '.join(names)}"
    )


def _terminal_safe(text: object) -> str:
    """S14 F-14-13 criterion 7: a server's string as it may reach the terminal (`refs.terminal_safe`, S20 F-20-90)."""
    from flowmode.refs import terminal_safe

    return terminal_safe(text)


LOGIN_HINT = (
    'If a shell or tool exported an older token, it still uses that one: run eval "$(flowmode env)" there again,'
    " or open a new terminal."
)
LOGIN_INTERVAL_MAX = 600
USER_CODE = r"[A-Za-z0-9-]{1,32}"
WORKSPACE_ID = r"[a-z0-9]{8}"  # S19 L-6: a workspace's public id


def _login_refusal(server: str, status: int, body: dict) -> str:
    """One sentence for an answer of `/auth/device/start` or `/auth/device/poll` other than going on."""
    word = body.get("status")
    if status == 403 and word == "not_invited":
        return "No project yet: start one or ask for an invite. This GitHub account is not on the team; ask a team leader to invite you."
    if status == 409 and word == "workspace_required":  # S19 §4.3: several memberships, the clone named none
        listed = body.get("workspaces") if isinstance(body.get("workspaces"), list) else []
        named = ", ".join(
            f"{_terminal_safe(w.get('id'))} ({_terminal_safe(w.get('name'))})" for w in listed if isinstance(w, dict)
        )
        return f"you are in several workspaces: run flowmode --workspace <id> login, one of: {named or '-'}"
    if status == 403 and word == "no_workspace":
        return "No project yet: start one or ask for an invite. This GitHub account is in no workspace on this server."
    if status == 404 and word == "not_found":
        return "no workspace with that id is yours on this server; run flowmode login without --workspace"
    if status == 410 and word == "denied":
        return "the sign-in was denied on GitHub; run flowmode login again"
    if status == 410:
        return "the code expired; run flowmode login again"
    if status == 404 and word == "unknown":
        return "the sign-in is no longer open on the server; run flowmode login again"
    if status == 404:
        return f"no GitHub sign-in on {server}; ask the admin"
    if status == 429:
        detail = body.get("detail")
        return _terminal_safe(detail) if isinstance(detail, str) else "too many sign-ins; try again in a minute"
    if status == 502:
        return "GitHub did not answer the server; try again later"
    return f"{server} answered {status}"


def _login(args: argparse.Namespace) -> int:
    """S14 F-14-13: the device flow through the server — start, show GitHub's page and code, poll at the server's
    interval, write the device token (the old config backed up first), then the `eval` hint (always) and the
    env-override warning (only when this shell's environment beats what was written)."""
    import os
    import re
    import socket
    import time

    from flowmode.api_client import ApiClient, ServerUnreachable
    from flowmode.member_config import read_config_file

    old = read_config_file()
    server = (args.server or str(old.get("server_url") or "")).rstrip("/")
    if not server:
        print("error: no server: pass --server https://… (config.toml names none)", file=sys.stderr)
        return 1
    if not server.startswith(("http://", "https://")):
        print("error: --server must start with http:// or https://", file=sys.stderr)
        return 1
    if args.approval_timeout is not None and not 1 <= args.approval_timeout <= 3600:
        print("error: --approval-timeout must be between 1 and 3600", file=sys.stderr)
        return 1
    if not os.environ.get("FLOWMODE_HOME") and not args.yes and (refusal := _init_address_refusal(server)):
        print(f"error: {refusal}", file=sys.stderr)  # before any request: a refused login never uses a code
        return 1
    flag = getattr(args, "cli_workspace", None)
    if flag is not None and not re.fullmatch(WORKSPACE_ID, flag):  # SR-12: before any request
        print("error: --workspace takes a workspace id (8 lowercase letters or digits)", file=sys.stderr)
        return 1
    name = args.name if args.name is not None else socket.gethostname().split(".")[0][:64]
    if args.code is not None:
        return _login_code(args, server, name, old)
    from pathlib import Path

    from flowmode.repo import find_repo
    from flowmode.shared import public_repo

    client = ApiClient(server, None, timeout=15.0)
    try:
        status, started = client.device_start(name, flag, public_repo(find_repo(Path.cwd()).origin))
        if status != 200:
            print(f"error: {_login_refusal(server, status, started)}", file=sys.stderr)
            return 1
        code, handle = started.get("user_code"), started.get("handle")
        if started.get("verification_uri") != DEVICE_PAGE:  # R-7: never send a person to another page
            print("error: the server named a sign-in page that is not GitHub's; tell the admin", file=sys.stderr)
            return 1
        if not isinstance(code, str) or not re.fullmatch(USER_CODE, code) or not isinstance(handle, str):
            print(f"error: {server} answered outside the device flow", file=sys.stderr)
            return 1
        print(f"Open {DEVICE_PAGE} and enter {code}", flush=True)
        interval = _login_interval(started.get("interval"), 5)
        deadline = time.monotonic() + _login_interval(started.get("expires_in"), 900, 900)
        while True:
            time.sleep(interval)
            status, answer = client.device_poll(handle)
            word = answer.get("status")
            if status == 200 and word == "ok":
                break
            if status == 200 and word in ("pending", "slow_down"):
                interval = _login_interval(answer.get("interval"), interval)
                if time.monotonic() > deadline:
                    print("error: the code expired; run flowmode login again", file=sys.stderr)
                    return 1
                continue
            print(f"error: {_login_refusal(server, status, answer)}", file=sys.stderr)
            return 1
    except ServerUnreachable as exc:
        print(f"error: could not reach {server} ({_terminal_safe(exc)})", file=sys.stderr)
        return 1
    finally:
        client.close()
    return _login_save(args, server, name, old, answer, with_login=True)


def _login_save(args: argparse.Namespace, server: str, name: str, old: dict, answer: dict, *, with_login: bool) -> int:
    """The tail both sign-ins share: check the device token, back the old config up, write the new one (0600), the
    `eval` hint and the env-override warning (the device flow's answer also names the GitHub login). S19 §4.4: the
    answer's `workspace` gets its `[workspaces.<id>]` entry, added or replaced; every other entry of the same server
    stays (a v0.18 file's token gets its own entry first, its workspace named by `/api/me`)."""
    from flowmode.member_config import (
        MemberConfig,
        backup_member_config,
        save_member_config,
        upsert_workspace,
        workspace_entries,
    )

    token, device = answer.get("token"), answer.get("device")
    if not isinstance(token, str) or not token.startswith(DEVICE_TOKEN_PREFIX) or not token.isascii():
        print(f"error: {server} answered without a device token", file=sys.stderr)
        return 1
    timeout = args.approval_timeout
    try:
        if timeout is None:
            timeout = int(old.get("approval_timeout_seconds", 300))
        cfg = MemberConfig(server_url=server, token=token, approval_timeout_seconds=timeout)
    except (TypeError, ValueError):
        cfg = MemberConfig(server_url=server, token=token)
    workspace = _named_workspace(answer.get("workspace"))
    same_server = str(old.get("server_url") or "").rstrip("/") == server  # another server's tokens do not carry over
    if workspace is None and same_server and workspace_entries(old):  # SR-13: never drop another entry
        print(f"error: {server} did not name the token's workspace; config.toml is unchanged", file=sys.stderr)
        return 1
    kept = _old_token_entry(server, old) if workspace is not None and same_server else {}
    backup = backup_member_config()
    path = upsert_workspace(cfg, *workspace, kept) if workspace is not None else save_member_config(cfg)
    device_label = _terminal_safe(device.get("name") if isinstance(device, dict) else name)
    member = _terminal_safe(answer.get("member"))
    who = f"@{_terminal_safe(answer.get('login'))} (member {member})" if with_login else f"member {member}"
    where = f" in workspace {_terminal_safe(workspace[1])} ({workspace[0]})" if workspace is not None else ""
    print(f"Signed in as {who} on device {device_label}{where}")
    print(f"config: {path}" + (f" (backup: {backup})" if backup is not None else ""))
    print(LOGIN_HINT)
    if warning := _env_override_warning(cfg):
        print(warning, file=sys.stderr)
    return 0


def _named_workspace(named: object) -> tuple[str, str, str | None] | None:
    """(id, name, repo) of a sign-in answer's or `/api/me`'s `workspace`; None when it names none (an older server)."""
    import re

    if (
        not isinstance(named, dict)
        or not isinstance(named.get("id"), str)
        or not re.fullmatch(WORKSPACE_ID, named["id"])
    ):
        return None
    name, repo = named.get("name"), named.get("repo")
    return named["id"], name if isinstance(name, str) else "", repo if isinstance(repo, str) and repo else None


def _old_token_entry(server: str, old: dict) -> dict:
    """S19 §4.4, K-7: a v0.18 file (a device token at the top, no workspace tables), or a file whose top-level token
    is an orphan (`orphan_token`: no entry holds it), with that token's own entry added first — `/api/me` names the
    workspace — so the next login keeps it chosen in its clones. A token the server rejects
    (401: revoked or unknown) is dropped, as a v0.18 login replaced it; anything else, or a server that does not
    answer, leaves `old` as it is (the token stays at the top level)."""
    from flowmode.api_client import ApiClient, ApiError, ServerUnreachable
    from flowmode.member_config import orphan_token, workspace_entries

    entries = workspace_entries(old)
    token = old.get("token") if not entries else orphan_token(old)
    if not isinstance(token, str) or not token.startswith(DEVICE_TOKEN_PREFIX):
        return old
    client = ApiClient(server, token, timeout=5.0)
    try:
        named = _named_workspace(client.me().get("workspace"))
    except ApiError as exc:
        return {**old, "token": ""} if exc.status == 401 else old
    except (ServerUnreachable, AttributeError):
        return old
    finally:
        client.close()
    if named is None:
        return old
    wid, name, repo = named
    if wid in entries:  # its workspace already has an entry: the orphan leaves the top level, that entry stays
        return {**old, "token": ""}
    return {**old, "workspaces": {wid: {"name": name, "repo": repo, "token": token}, **entries}}


def _login_code(args: argparse.Namespace, server: str, name: str, old: dict) -> int:
    """S17 F-17-11.g: `flowmode login --code`: one `POST /auth/connect/redeem` (no browser, no GitHub), then the same
    tail as the device flow. The code goes only in the JSON body; it is never printed."""
    from flowmode.api_client import ApiClient, ServerUnreachable

    code = args.code.strip()
    if not code or len(code) > 128:
        print("error: --code takes the code shown on the web page", file=sys.stderr)
        return 1
    client = ApiClient(server, None, timeout=15.0)
    try:
        status, answer = client.connect_redeem(code, name)
    except ServerUnreachable as exc:
        print(f"error: could not reach {server} ({_terminal_safe(exc)})", file=sys.stderr)
        return 1
    finally:
        client.close()
    if status == 404:
        print("error: that code is wrong, used or expired; get a new one on the web page", file=sys.stderr)
        return 1
    if status == 429:
        detail = answer.get("detail")
        print(f"error: {_terminal_safe(detail) if isinstance(detail, str) else 'too many attempts'}", file=sys.stderr)
        return 1
    if status != 200:
        print(f"error: {server} answered {status}", file=sys.stderr)
        return 1
    return _login_save(args, server, name, old, answer, with_login=False)


def _login_interval(value: object, default: int, most: int = LOGIN_INTERVAL_MAX) -> int:
    """A number of seconds from the server: a whole number from 1 to `most`, else `default`."""
    return value if isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= most else default


def _logout(args: argparse.Namespace) -> int:
    """S14 F-14-13 criterion 5: `DELETE /api/account/devices/current` with this device's token, then the token
    leaves config.toml (backup first, without the token). A server that cannot be reached does not keep the token
    here, and the CLI says the token still works there until it is revoked on the web."""
    from pathlib import Path

    from flowmode.api_client import ApiClient, ApiError, ServerUnreachable
    from flowmode.member_config import config_path, old_token_hint, pick_entry, read_config_file, remove_member_token
    from flowmode.repo import find_repo

    data = read_config_file()
    server = str(data.get("server_url") or "")
    # S19 §4.4: the entry of the chosen workspace (--workspace, the clone's origin, the only one) goes; others stay
    _wid, token = pick_entry(data, getattr(args, "cli_workspace", None), lambda: find_repo(Path.cwd()).origin)
    if not isinstance(token, str) or not token:
        print(f"error: not signed in on this device (no token in {config_path()})", file=sys.stderr)
        return 1
    if old := old_token_hint(server, token):  # S17 F-17-31.c: nothing changes, nothing is sent
        print(f"error: {old}", file=sys.stderr)
        return 1
    if not token.startswith(DEVICE_TOKEN_PREFIX):
        print("error: config.toml holds no device token; nothing changed (run flowmode login)", file=sys.stderr)
        return 1
    if not server.startswith(("http://", "https://")):
        print("error: config.toml names no server (http:// or https://); nothing changed", file=sys.stderr)
        return 1
    said = "Signed out: this device's token is revoked"
    client = ApiClient(server, token, timeout=5.0)
    try:
        client.revoke_current_device()
    except ApiError as exc:
        if exc.status != 401:
            print(f"error: {server} answered {exc.status}: {_terminal_safe(exc.detail)}", file=sys.stderr)
            return 1
        said = "Signed out: this device was already revoked on the server"
    except ServerUnreachable as exc:
        print(
            f"warning: could not reach {server} ({_terminal_safe(exc)}): this device's token is still valid on the"
            " server until you revoke it on the web (Profile, Devices)",
            file=sys.stderr,
        )
        said = "Signed out on this machine only: the token is still valid on the server; revoke it on the web"
    finally:
        client.close()
    backup = remove_member_token(token)
    print(said)
    kept = f" (backup, without the token: {backup})" if backup is not None else ""
    print(f"config: token removed from {config_path()}{kept}")
    return 0


def _env(args: argparse.Namespace) -> int:
    import shlex

    from flowmode.member_config import load_member_config, old_token_hint

    cfg = load_member_config()
    if cfg is None:
        print(
            "error: No project yet: start one or ask for an invite. Not configured (run flowmode login --server <url>)",
            file=sys.stderr,
        )
        return 1
    if old := old_token_hint(cfg.server_url, cfg.token):  # S17 F-17-31.c: never exported again
        print(f"error: {old}", file=sys.stderr)
        return 1
    print(f"export FLOWMODE_SERVER_URL={shlex.quote(cfg.server_url)}")
    print(f"export FLOWMODE_TOKEN={shlex.quote(cfg.token)}")
    return 0


CLIENT_REPO_URL = (
    "https://github.com/msgenan/flowmode-cli"  # the public client repo (the export allowlist has no config.py)
)


class _NotPrivate(Exception):
    """The update's source folder is not the member's own private folder (U-2)."""


def _private_source(version: str):
    """S20 F-20-90 (red team U-2): `$FLOWMODE_HOME/client-src/v<version>`, made for this run. uv's tool record names
    the folder it built from and a later `uv tool upgrade` rebuilds from it, so it must outlive the run and be the
    member's own: `client-src` is a real folder (no symlink) of this user, mode 0700, in a FLOWMODE_HOME of this user
    that nobody else may write; a leftover of the same version is removed first (git clones into a new folder)."""
    import contextlib
    import os
    import stat

    from flowmode.shared import flowmode_home

    home = flowmode_home()
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    base = home / "client-src"
    with contextlib.suppress(FileExistsError):  # an existing one is checked below
        base.mkdir(mode=0o700)
    for folder, closed, rule in ((home, 0o022, "no write for group or others"), (base, 0o077, "mode 0700")):
        info = os.lstat(folder)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & closed:
            raise _NotPrivate(
                f"{folder} must be a folder of yours that nobody else can change (not a symbolic link, {rule});"
                f" fix or remove it and run flowmode update again"
            )
    target = base / f"v{version}"
    _remove(target)
    return target


def _remove(path) -> None:
    """Remove one entry of the private source folder: a symbolic link itself, never what it points to."""
    import shutil

    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)


def _update(args: argparse.Namespace) -> int:
    """S20 L-10, SR-8: install the client release whose tag is the server's version, then re-install for this repo.
    F-20-90 (red team r1): the source stays in a private folder (U-2), a downgrade needs --allow-downgrade (U-4), the
    plan reaches a pipe before anything runs (U-5), only a git checkout is re-installed (U-6)."""
    import os
    import re
    import shlex
    import tempfile

    from flowmode.api_client import ApiClient, ApiError, ServerUnreachable
    from flowmode.member_config import load_member_config

    cfg = load_member_config()
    if cfg is None:
        print("error: Not configured (run flowmode login --server <url>)", file=sys.stderr)
        return 1
    try:
        answer = ApiClient(cfg.server_url, None).health()  # unauthenticated: no token sent
    except (ServerUnreachable, ApiError) as exc:
        print(f"error: could not read the server's version: {_terminal_safe(exc)}", file=sys.stderr)
        return 1
    version = answer.get("version") if isinstance(answer, dict) else None  # R2 U2-3: a list or text is no answer
    # fullmatch: `$` takes a "\n"; ASCII digits, bounded, so int() never meets thousands of digits (U2-3)
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}", version):
        print("error: the server did not give a plain X.Y.Z version; nothing was run", file=sys.stderr)
        return 1
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", __version__) and _parts(version) == _parts(__version__):  # "0.20.00" too
        print(f"Flowmode {__version__} is up to date.")
        return 0
    verb = "Updating"
    if re.fullmatch(r"\d+\.\d+\.\d+", __version__) and _parts(version) < _parts(__version__):  # U-4
        if not getattr(args, "allow_downgrade", False):
            print(
                f"error: the server runs {version}, older than this client {__version__}: nothing was run; to"
                f" install {version} anyway run flowmode update --allow-downgrade",
                file=sys.stderr,
            )
            return 1
        verb = "Downgrading"
    src = None
    with tempfile.TemporaryDirectory(prefix="flowmode-update-") as work:  # only the pins file: removed afterwards
        pins = f"{work}/pins.txt"
        if template := os.environ.get("FLOWMODE_UPDATE_CMD"):  # the test seam: one argv line instead of the steps
            steps = [[part.replace("{version}", version) for part in shlex.split(template)]]
        else:  # clone the tag, then setup.sh's pinned install line (client/setup.sh:109-112)
            try:
                src = _private_source(version)
            except (_NotPrivate, OSError) as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            steps = [
                ["git", "clone", "--depth", "1", "--branch", f"v{version}", CLIENT_REPO_URL, str(src)],
                [
                    "uv",
                    "export",
                    "--frozen",
                    "--no-dev",
                    "--no-emit-project",
                    "--no-hashes",
                    "--no-header",
                    "--quiet",
                    "--project",
                    str(src),
                    "-o",
                    pins,
                ],
                ["uv", "tool", "install", "--force", "--reinstall", "--constraints", pins, str(src)],
            ]
        print(f"{verb} {__version__} -> {version}. Commands:")
        for argv in steps:
            print(f"  {shlex.join(argv)}")
        sys.stdout.flush()  # U-5: off a terminal stdout is block-buffered; the plan must be out before a child runs
        if not args.yes and not sys.stdin.isatty():
            print("error: not a terminal: nothing was run; add --yes to run it", file=sys.stderr)
            return 1
        if not args.yes:
            try:
                answer = input("Run them? [y/N] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("\nCancelled: nothing was run.")
                return 1
            if answer not in ("y", "yes"):
                print("Nothing was run.")
                return 1
        code = _run_steps(steps, version)
        if code:
            if src is not None:
                _remove(src)  # the half-made folder; the version uv still points at stays
            return code
    if src is not None:  # installed from `src`: the older versions' folders are no longer named by uv
        for old in src.parent.iterdir():
            if old.name != src.name and re.fullmatch(r"v\d+\.\d+\.\d+", old.name):
                _remove(old)
    code = _reinstall_here()
    if code == 0:
        print(f"Updated to {version}. Restart your agent sessions to use it.")
    return code


def _parts(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def _run_steps(steps: list[list[str]], version: str) -> int:
    """Run the update's commands in order; the first failure's exit code (0 when all ran)."""
    import subprocess

    for number, argv in enumerate(steps):
        try:
            done = subprocess.run(argv, check=False)
        except OSError as exc:
            print(f"error: could not run {argv[0]}: {exc}", file=sys.stderr)
            return 1
        if done.returncode != 0:
            missing = f" (is the tag v{version} published in {CLIENT_REPO_URL}?)" if argv[0] == "git" else ""
            print(f"error: step {number + 1} failed ({done.returncode}){missing}", file=sys.stderr)
            return done.returncode
    return 0


def _reinstall_here() -> int:
    """Re-install the agents that have Flowmode hooks in the git checkout the update runs in; outside a checkout (e.g.
    HOME with user-level hooks) nothing (U-6: `install` there would write user-wide skills and `.mcp.json`)."""
    import subprocess
    from pathlib import Path

    from flowmode.doctor import _has_flowmode_hook, _json
    from flowmode.repo import find_repo, is_checkout

    info = find_repo(Path.cwd())
    if not is_checkout(info):
        print(
            f"{info.root} is not a git checkout: nothing re-installed here. In each repository that uses Flowmode run"
            " flowmode install claude (or codex) there."
        )
        return 0
    root = info.root
    servers = _json(root / ".mcp.json").get("mcpServers")  # a member may have cut the hooks out: the MCP entry stays
    claude = _has_flowmode_hook(root / ".claude/settings.json") or (
        isinstance(servers, dict) and isinstance(servers.get("flowmode"), dict)
    )
    hooked = [
        a for a, found in (("claude", claude), ("codex", _has_flowmode_hook(root / ".codex/hooks.json"))) if found
    ]
    if not hooked:
        print(
            f"No Flowmode hooks in {root}: nothing to re-install here (run flowmode install <agent> when you want them)."
        )
        return 0
    sys.stdout.flush()
    for agent in hooked:  # the NEW client does it: this process still holds the old modules in memory
        code = subprocess.run(
            [sys.executable, "-P", "-m", "flowmode", "install", agent, "--repo", str(root)], check=False
        )
        if code.returncode:
            return code.returncode
    return 0


def _install(args: argparse.Namespace) -> int:
    from pathlib import Path

    from flowmode.install import install, path_warning
    from flowmode.member_config import load_member_config

    cfg = load_member_config()
    if cfg is None:
        print(
            "error: No project yet: start one or ask for an invite. Not configured (run flowmode login --server <url>)",
            file=sys.stderr,
        )
        return 1
    repo = Path(args.repo)
    if not repo.is_dir():
        print(f"error: {repo} is not a directory", file=sys.stderr)
        return 1
    try:
        written, next_steps = install(args.agent, repo, cfg, force=args.force)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"server: {cfg.server_url}")  # S10 F-10-17: what the hooks will use (the environment beats the file)
    for path in written:
        print(f"wrote: {path}")
    for line in next_steps:
        print(line)
    if warning := path_warning():
        print(warning, file=sys.stderr)
    from flowmode.hooks import clone_form_note
    from flowmode.repo import find_repo

    info = find_repo(repo.resolve())
    if note := clone_form_note(info):  # S11 F-11-26
        print(note, file=sys.stderr)
    if info.origin and info.default_branch is None:  # S11 F-11-32
        print(
            "note: this clone does not know its default branch — run  git remote set-head origin -a  so edits on"
            " it are refused",
            file=sys.stderr,
        )
    from flowmode.doctor import send_after_install

    send_after_install(repo, cfg)  # S17 F-17-12.e: best effort, one line, never fails the install
    return 0


REHEARSAL_SAID = {"approved": "Approved: approvals reach you.", "denied": "Denied."}


def _rehearse(args: argparse.Namespace) -> int:
    """S17 F-17-13.e: create the rehearsal (the server fixes its text), print where to decide it, then long-poll
    until it is decided, expires or approval_timeout_seconds pass. Starts no process and opens no browser; exit 0
    only for an approval. The page address is the server's `public_url` (else the configured server)."""
    import time

    from flowmode.tasks import Failed, _client, _config, _run

    def rehearse(args) -> None:
        cfg = _config()
        with _client(cfg) as client:
            rehearsal = client.create_rehearsal()
            base = str(rehearsal.get("public_url") or cfg.server_url).rstrip("/")
            print(f"Open {_terminal_safe(base)}/start and approve the test request", flush=True)
            deadline = time.monotonic() + cfg.approval_timeout_seconds
            while rehearsal.get("status") == "pending" and (left := deadline - time.monotonic()) > 0:
                rehearsal = client.get_rehearsal(str(rehearsal["id"]), wait=min(30.0, left))
        said = REHEARSAL_SAID.get(str(rehearsal.get("status")))
        if said is None:
            print("Timed out.")
            raise Failed("nobody decided the test request in time; run flowmode rehearse again")
        print(said)
        if rehearsal["status"] != "approved":
            raise Failed("the test request was denied; run flowmode rehearse again to approve one")

    return _run(rehearse, args)


def _chat(args: argparse.Namespace) -> int:
    from flowmode.tasks import Failed, _client, _config, _run

    def post(args) -> None:
        cfg = _config()
        if not args.text.strip():
            raise Failed("text must not be empty")
        with _client(cfg) as client:
            chat = client.post_chat(args.text)
        print(f"chat: {_terminal_safe(chat['id'])}")  # S20 F-20-90: server text through the one filter
        print(f"mentions: {_terminal_safe(', '.join(chat['mentions'])) or '-'}")

    return _run(post, args)


def _closing_url(task: dict | None, origin: str | None) -> str | None:
    """S12 F-12-14: the issue `check --pr-text` opens with `Closes <url>` — only one in the checkout's own GitHub repo
    (a linked issue of another repo is not closed from here, S7 §4); None otherwise."""
    from flowmode.github_cli import github_repo_of
    from flowmode.tasks import _same_github_repo

    issue = (task or {}).get("issue") or {}
    if not issue.get("url") or not _same_github_repo(github_repo_of(origin), str(issue.get("repo") or "")):
        return None
    return issue["url"]


def _git_ident(var: str) -> str | None:
    """`git var GIT_AUTHOR_IDENT` / `GIT_COMMITTER_IDENT` in the current directory, without the date; None when git
    has no identity (or no git): that is not a finding."""
    import subprocess

    try:
        out = subprocess.run(["git", "var", var], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0 or not out.stdout.strip():
        return None
    ident = out.stdout.strip()
    end = ident.rfind(">")
    return ident[: end + 1] if end >= 0 else ident


def _git_comment() -> str | None:
    """The comment string git strips (core.commentString, else core.commentChar; default `#`); None for `auto`."""
    import subprocess

    for key in ("core.commentString", "core.commentChar"):
        try:
            out = subprocess.run(
                ["git", "config", "--get", key], capture_output=True, text=True, timeout=10, check=False
            )
        except (OSError, subprocess.SubprocessError):
            return "#"
        value = out.stdout.rstrip("\n")
        if out.returncode == 0 and value:
            return None if value == "auto" else value
    return "#"


def _git_cleanup() -> str | None:
    """commit.cleanup (None when unset or unreadable): which lines git strips from an edited message."""
    import subprocess

    try:
        out = subprocess.run(
            ["git", "config", "--get", "commit.cleanup"], capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return (out.stdout.strip() or None) if out.returncode == 0 else None


def _check_commit_msg(file: str | None) -> int:
    """S20 L-6 (c), §4.3: the git commit-msg hook's check — exit 1 with one line per agent marker in the message git
    may store (comment lines and `git commit -v`'s diff skipped only where git strips them, F-20-88) or agent
    author/committer git will store; 0 when clean."""
    from flowmode.risky import commit_msg_findings

    if not file:
        print("error: flowmode check commit-msg <file>: the commit message file is missing", file=sys.stderr)
        return 2
    try:
        with open(file, "rb") as f:
            message = f.read(1024 * 1024).decode("utf-8", errors="replace")
    except OSError as exc:
        print(f"error: cannot read {file}: {exc.strerror or exc}", file=sys.stderr)
        return 1
    idents = [
        (role, ident)
        for role, var in (("author", "GIT_AUTHOR_IDENT"), ("committer", "GIT_COMMITTER_IDENT"))
        if (ident := _git_ident(var)) is not None
    ]
    import os

    # F-20-88 (H1-2): git sets GIT_EDITOR=: for the hook when no editor ran (`-m`, `-F`, `--no-edit`)
    editor = os.environ.get("GIT_EDITOR") != ":"
    found = commit_msg_findings(message, idents, _git_comment(), editor=editor, cleanup=_git_cleanup())
    for item in found:
        print(
            f'flowmode: remove "{item}" — commits in this team never name an agent as author or co-author',
            file=sys.stderr,
        )
    return 1 if found else 0


def _check(args: argparse.Namespace) -> int:
    """S11 F-11-29: `flowmode check` — run the checks here, store them on the task of this worktree. The server gets
    each command's status and exit code only; its output tail is printed here and nowhere else (SPEC §3). A check the
    risky classifier flags is not run: a flowmode.toml line (team-reviewed) with the normal set plus the team's
    patterns, an ad hoc `--also` one with the strict-mode set plus the team's (F-11-29 check rules). Offline, or when
    the upload fails, the local results stand and the exit status is the checks' own."""
    from flowmode import checks
    from flowmode.api_client import ApiClient, ApiError, ServerUnreachable
    from flowmode.member_config import load_member_config, old_token_hint
    from flowmode.repo_config import FILE_NAME, load_repo_config
    from flowmode.risky import reason_for
    from flowmode.tasks import _checkout, _run, api_failure

    failed = False

    def run(args) -> None:
        nonlocal failed
        root, _main, repo = _checkout(args.repo)
        config = load_repo_config(root)
        also = [c for c in args.also if c.strip()]
        commands = config.checks + also
        if config.error:
            print(f"warning: {FILE_NAME} could not be read ({config.error})", file=sys.stderr)
        if not commands:
            print(
                f'no checks: create {FILE_NAME} at the repo root with checks = ["<your test command>"]'
                if not config.present
                else f"no checks: {FILE_NAME} has no checks = [...]"
            )
        cfg = load_member_config()
        old = old_token_hint(cfg.server_url, cfg.token) if cfg else None  # S17 F-17-31: nothing is sent with it
        client = ApiClient(cfg.server_url, cfg.token, timeout=cfg.request_timeout_seconds) if cfg and not old else None
        task, patterns, strict = None, checks.toml_patterns(), checks.check_patterns()
        unstored = old or (None if cfg else "not configured (run flowmode login --server <url>)")
        try:
            if client is not None:
                try:
                    team = client.config().get("risky_patterns")
                    team = team if isinstance(team, list) else None
                    patterns, strict = checks.toml_patterns(team), checks.check_patterns(team)
                    task = _worktree_task(client, root, repo)
                except (ApiError, ServerUnreachable) as exc:
                    unstored = str(api_failure(exc, cfg))
            rows = checks.rows_for(
                config.checks,
                root,
                task["issue_body"] if task else None,
                config.person_checks,
                risky_patterns=patterns,
                also=also,
                also_patterns=strict,
            )
            failed = any(r.status == "failed" for r in rows)
            for row in rows:
                if row.kind == "command":
                    _print_command(row, strict)  # the superset, normal set first: names a toml refusal too
            body = [r.as_body() for r in rows]
            stored = None
            if task is not None and body:
                try:
                    stored = client.report_checks(task["id"], body)
                except (ApiError, ServerUnreachable) as exc:
                    unstored = str(api_failure(exc, cfg))
            pr_lines = _pr_step(client, root, task, CHECK_GH_TIMEOUT, quiet=True) if task is not None else []
        finally:
            if client is not None:
                client.close()
        shown = stored if stored is not None else body
        for row in shown:
            if row["kind"] != "command":
                person_open = row["kind"] == "person" and row["status"] == "open"
                status = "person" if person_open else _terminal_safe(row["status"])
                print(
                    f"check: {_terminal_safe(row['name'])} · {status}"
                )  # S20 F-20-90: the stored rows are the server's
        _conflicts(root)
        for line in pr_lines:  # S12 F-12-10: the pull request as the member's gh sees it
            print(line)
        if unstored is not None:
            print(
                f"upload failed: {unstored} — not stored on the task; the results above are local only", file=sys.stderr
            )
        elif task is None:
            print("not stored: no task for this worktree (flowmode work <task> opens one)", file=sys.stderr)
        elif body:
            print(f"stored on task {_terminal_safe(task['name'])} ({_terminal_safe(task['id'])})")
        if args.pr_text and shown:
            print()
            print(checks.pr_text(shown, _closing_url(task, repo)), end="")

    def _print_command(row, patterns) -> None:
        """One command's line; a failed one with the last lines of its output (local only), a refused one with why."""
        if row.refused:
            why = reason_for(row.name, patterns) or "a risky command"
            print(f"check: {row.name} · refused — needs approval ({why}): run it yourself, as its own command")
            return
        state = row.status if row.status == "passed" else f"{row.status} ({row.detail})"
        print(f"check: {row.name} · {state}")
        if row.status == "failed" and row.tail:
            for line in row.tail.splitlines()[-5:]:
                print(f"  | {line}")

    def _conflicts(root) -> None:
        """S11 F-11-45: fetch the default branch (about 5 s at most) and name the files that conflict with it; a
        skipped comparison (offline, no origin/HEAD, no remote) says nothing. Never changes the exit status."""
        from flowmode.repo import find_repo

        found = checks.main_conflicts(root, find_repo(root).default_branch)
        if found is not None:
            checks.remember_conflicts(root, found)
            print(checks.conflicts_line(found))

    code = _run(run, args)
    return 1 if code == 0 and failed else code


def _worktree_task(client, root, repo) -> dict | None:
    """The task of this worktree: the registry's task id, else the task whose branch is checked out here."""
    from flowmode.repo import find_repo
    from flowmode.task_registry import lookup_worktree

    branch = find_repo(root).branch
    entry = lookup_worktree(root, repo, branch) or {}
    if entry.get("task_id"):
        found = client.list_tasks(id=entry["task_id"])
        if found:
            return found[0]
    return next(
        (
            t
            for t in client.list_tasks(repo=repo)
            if branch and t["branch"] == branch and t["status"] not in ("done", "cancelled", "declined")
        ),
        None,
    )


CHECK_GH_TIMEOUT = 5  # S12 F-12-10: `flowmode check` waits this long for gh (a hook 2 s; `flowmode pr` 20 s)
PR_GH_TIMEOUT = 20
MAX_TOUCHES = 200


def _touches(root, default_branch: str | None, extra=()) -> list[str]:
    """The paths the branch changes against the default branch (`git diff --name-only origin/<default>...HEAD`), at
    most 200 — paths only, never the diff (SPEC §3); secret-looking paths and the repo's `tree_exclude` globs `extra`
    stay on the machine (S14 F-14-05). [] when there is no default branch or git fails."""
    from flowmode.paths import secret_looking
    from flowmode.worktrees import GitError, _git

    if not default_branch:
        return []
    try:
        out = _git(root, "diff", "--name-only", "-z", f"origin/{default_branch}...HEAD", timeout=10, strip=False)
    except GitError:
        return []
    return [p for p in out.split("\0") if p and not secret_looking(p, extra)][:MAX_TOUCHES]


def _pr_step(client, root, task: dict, timeout: float, quiet: bool = False) -> list[str]:
    """S12 F-12-10: the pull request of the checkout's branch from the member's own gh, reported to `task` (facts
    only). The lines to print. With `quiet` (flowmode check) a missing gh, a gh error or a failed report says
    nothing: the check's own result stands; else they raise Failed."""
    from flowmode import github_cli
    from flowmode.api_client import ApiError, ServerUnreachable
    from flowmode.repo import find_repo
    from flowmode.repo_config import load_repo_config
    from flowmode.task_registry import lookup_worktree
    from flowmode.tasks import Failed

    info = find_repo(root)
    if quiet and not github_cli.gh_ready():  # flowmode check: a gh that cannot be logged in is not started
        return []
    branch, number = info.branch, None
    if not branch:  # F-12-13: a review worktree is detached at the PR's head; its registry entry names the PR
        entry = lookup_worktree(root) or {}
        if entry.get("kind") == "review":
            branch, number = entry.get("branch"), entry.get("pr")
    if not branch or github_cli.github_repo_of(info.repo) is None:
        if quiet:
            return []
        raise Failed("this checkout is on no branch or has no GitHub origin: no pull request to show")
    try:
        if isinstance(number, int):
            pr = github_cli.pr_view(number, root, timeout=timeout)
        else:
            pr = github_cli.pr_for_branch(branch, root, timeout=timeout)
    except (github_cli.GhMissing, github_cli.GhError) as exc:
        if quiet:
            return []
        why = (
            "gh not found: install GitHub's CLI and run  gh auth login"
            if isinstance(exc, github_cli.GhMissing)
            else f"gh: {exc}"
        )
        raise Failed(why) from exc
    if pr is None:
        return [] if quiet else [f"pr: none for {branch} (once your person has pushed:  gh pr create)"]
    exclude = load_repo_config(info.root).tree_exclude
    report = github_cli.pr_report(pr, _touches(root, info.default_branch, exclude))
    lines = [github_cli.pr_line(report, pr.get("baseRefName") or info.default_branch)]
    if task is None:
        return lines + ([] if quiet else ["not reported: no task for this worktree (flowmode work <task> opens one)"])
    try:
        answer = client.report_pr(task["id"], report)
    except (ApiError, ServerUnreachable) as exc:
        if quiet:
            return lines
        raise Failed(f"not reported: {exc.detail if isinstance(exc, ApiError) else exc}") from exc
    if answer.get("kept") == "webhook":
        return [*lines, f"reported: kept — GitHub's own record of #{report['number']} (webhook) is on the task"]
    done = (answer.get("task") or {}).get("status") == "done" and report["merged"] and not report["fork"]
    return lines + ([f"task: {task['name']} done (pull request #{report['number']} merged)"] if done else [])


def _sync_days(text: str) -> int:
    from flowmode.sync import days_arg

    return days_arg(text)


def _pr(args: argparse.Namespace) -> int:
    """S12 F-12-10: `flowmode pr` — the task's pull request from the member's own gh, reported as facts. S13
    F-13-01: `flowmode pr sync` — the repository's pull requests and open issues (flowmode.sync)."""
    from flowmode.tasks import _checkout, _client, _config, _run

    if args.verb == "sync":
        from flowmode import sync

        args.days = args.days or 30
        return sync.run(args)
    if args.days is not None or args.auto:
        print("error: --days and --auto go with `flowmode pr sync`", file=sys.stderr)
        return 2

    def run(args) -> None:
        cfg = _config()
        root, _main, repo = _checkout(args.repo)
        with _client(cfg) as client:
            task = _worktree_task(client, root, repo)
            for line in _pr_step(client, root, task, PR_GH_TIMEOUT):
                print(line)

    return _run(run, args)


def _pr_number(text: str) -> int:
    number = text.removeprefix("#")
    if not number.isdigit() or not 0 < int(number) < 10**10:
        raise argparse.ArgumentTypeError(f"not a pull request number: '{text}'")
    return int(number)


FIX_REQUESTED = "requested from {owner} — it appears in your My work when {owner} allows it"


def _fix(args: argparse.Namespace) -> int:
    """S12 F-12-12: `flowmode fix <PR#>` — POST /api/pulls/fix, then what to run next."""
    from flowmode.tasks import _checkout, _client, _config, _run

    def run(args) -> None:
        cfg = _config()
        _root, _main, repo = _checkout(args.repo)
        with _client(cfg) as client:
            answer = client.take_fix(repo, args.number)
        if answer["action"] == "requested":
            print(FIX_REQUESTED.format(owner=_terminal_safe(answer["request"]["owner"])))
            return
        task = answer["task"]
        if answer["action"] == "created":
            print(
                f"fix task: {_terminal_safe(task['name'])} on {_terminal_safe(task['branch'])} (#{args.number}, accepted)"
            )
        else:
            print(f"#{args.number} is your task {_terminal_safe(task['name'])}: continue it")
        print(f"next: flowmode work {_terminal_safe(task['name'])}")

    return _run(run, args)


def main(argv: list[str] | None = None) -> int:
    from flowmode.member_config import WorkspaceUnclear, choose_workspace

    choose_workspace(None)  # S19: no earlier in-process command's --workspace survives a parse error or --help
    first = (sys.argv[1:] if argv is None else argv)[:1]
    if first == ["init"]:  # S17 D-7: any `init …`, before argparse
        print(f"error: {INIT_GONE}", file=sys.stderr)
        return 2
    server = _server_cli()
    if server is None and first and first[0] in SERVER_COMMANDS:  # L-2: before argparse, which rejects their options
        print(f"flowmode {first[0]} is a server command; it is not in the client build", file=sys.stderr)
        return 2
    parser = _parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return int(e.code or 0)
    if server is not None and args.command in SERVER_COMMANDS:
        return server.run(args)
    choose_workspace(args.cli_workspace)
    try:
        return _client_command(parser, args)
    except WorkspaceUnclear as exc:  # S19 §4.4: raised before any request
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _client_command(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    if args.command == "login":
        return _login(args)
    if args.command == "logout":
        return _logout(args)
    if args.command == "rehearse":
        return _rehearse(args)
    if args.command == "env":
        return _env(args)
    if args.command == "install":
        return _install(args)
    if args.command == "update":
        return _update(args)
    if args.command == "doctor":
        from flowmode.doctor import doctor_cmd

        return doctor_cmd(args)
    if args.command == "hook":
        return _hook(args)
    if args.command == "watch":
        from pathlib import Path

        from flowmode.watcher import watch

        return watch(args.pid, args.start, Path(args.cache), args.every)
    if args.command == "chat":
        return _chat(args)
    if args.command in ("pin", "pins"):
        from flowmode.tasks import pin_cmd, pins_cmd

        return (pin_cmd if args.command == "pin" else pins_cmd)(args)
    if args.command == "check":
        if args.mode == "commit-msg":
            return _check_commit_msg(args.file)
        return _check(args)
    if args.command == "pr":
        return _pr(args)
    if args.command == "fix":
        return _fix(args)
    if args.command == "review":
        from flowmode.review import review_cmd

        return review_cmd(args)
    if args.command == "work":
        from flowmode.work import work_cmd

        return work_cmd(args)
    if args.command == "handoff":
        from flowmode.tasks import handoff_cmd

        return handoff_cmd(args)
    if args.command == "task":
        from flowmode import tasks

        return {
            "start": tasks.task_start,
            "list": tasks.task_list,
            "take": tasks.task_take,
            "new": tasks.task_new,
            "inbox": tasks.task_inbox,
            "accept": tasks.task_accept,
            "decline": tasks.task_decline,
            "resend": tasks.task_resend,
            "cancel": tasks.task_cancel,
            "delete": tasks.task_delete,
            "done": tasks.task_done,
            "release": tasks.task_release,
        }[args.task_command](args)
    parser.print_usage(sys.stderr)
    return 2
