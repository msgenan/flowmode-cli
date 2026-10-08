"""S18 F-18-01 (L-1): the rules both halves of Flowmode use — the client build ships this module, the server imports it.

The client modules import no server module (the export, `tools/export_client.py`, copies them alone), so whatever the
client needs from what used to live in `config`, `store`, `github`, `webhook` and `onboarding` lives here. Those
modules import the names back: every old import path keeps working, nothing was renamed. Pure Python — no sqlite, no
network, no third-party package; the only `flowmode` import is `repo` (a client module)."""

import os
import re
from pathlib import Path

from flowmode.repo import canonical_repo


def flowmode_home() -> Path:
    """$FLOWMODE_HOME, else $HOME/.flowmode — read at call time so tests can redirect it."""
    env = os.environ.get("FLOWMODE_HOME")
    return Path(env) if env else Path(os.environ.get("HOME") or Path.home()) / ".flowmode"


# --- devices (S14 F-14-13) ---------------------------------------------------------------------------------------------
DEVICE_TOKEN_PREFIX = "fmd_"  # noqa: S105 — a prefix, not a token
DEVICE_PAGE = "https://github.com/login/device"  # the only page a person is ever told to type a code into (R-7)

# --- task names and issue links (S7 §2.2) ------------------------------------------------------------------------------
TASK_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
ISSUE_URL_RE = re.compile(
    r"https://(?P<host>[A-Za-z0-9.-]+(:\d+)?)/(?P<owner>[A-Za-z0-9_.-]+)/(?P<name>[A-Za-z0-9_.-]+)"
    r"/issues/(?P<number>[1-9][0-9]*)/?([?#]\S*)?"
)
ISSUE_URL_HELP = "issue link must look like https://github.com/<owner>/<repo>/issues/<number>"
MAX_ISSUE_DIGITS = 10  # S10 F-10-02: GitHub numbers are far shorter; a huge one overflowed the INTEGER column (a 500)


def parse_issue_url(url: str) -> dict:
    """{repo, number, url} of a pasted GitHub issue link (S7 §2.2); the server never contacts GitHub.
    `repo` is OWNER/REPO on github.com, else HOST/OWNER/REPO (the form `gh --repo` takes). Raises ValueError."""
    m = ISSUE_URL_RE.fullmatch(url or "")
    if m is None or len(m["number"]) > MAX_ISSUE_DIGITS:  # S10 F-10-02: a longer number overflowed SQLite's INTEGER
        raise ValueError(ISSUE_URL_HELP)
    host, path = m["host"].lower(), f"{m['owner']}/{m['name']}"
    number = int(m["number"])
    return {
        "repo": path if host == "github.com" else f"{host}/{path}",
        "number": number,
        "url": f"https://{host}/{path}/issues/{number}",
    }


# --- the issues a pull request closes (S12 F-12-10) --------------------------------------------------------------------
# GitHub's closing keywords: `Fixes #7`, `closes acme/app#7`, `Resolves https://github.com/acme/app/issues/7`
CLOSING_RE = re.compile(
    r"\b(?:close|closes|closed|fix|fixes|fixed|resolve|resolves|resolved)\b:?\s+"
    r"(?:(?P<owner>[A-Za-z0-9_.-]+)/(?P<name>[A-Za-z0-9_.-]+)#(?P<qnum>\d{1,10})"
    r"|#(?P<num>\d{1,10})"
    r"|https://(?P<host>[A-Za-z0-9.-]+)/(?P<uowner>[A-Za-z0-9_.-]+)/(?P<uname>[A-Za-z0-9_.-]+)/issues/(?P<unum>\d{1,10}))",
    re.IGNORECASE,
)


def closing_refs(body: str | None) -> list[tuple[str | None, int]]:
    """The issues a PR body closes with GitHub's keywords, in order, once each: (repo or None for this repo, n)."""
    found: list[tuple[str | None, int]] = []
    for m in CLOSING_RE.finditer(body or ""):
        if m["num"]:
            ref = (None, int(m["num"]))
        elif m["qnum"]:
            ref = (f"{m['owner']}/{m['name']}", int(m["qnum"]))
        else:
            host = m["host"].lower()
            path = f"{m['uowner']}/{m['uname']}"
            ref = (path if host == "github.com" else f"{host}/{path}", int(m["unum"]))
        if ref not in found:
            found.append(ref)
    return found


# --- the follow-up drafts of a merged pull request (S12 F-12-13b) ------------------------------------------------------
# PR-body text: printable, capped — security.md R-10
MAX_FOLLOWUPS = 20
MAX_FOLLOWUP_TITLE = 200
MAX_FOLLOWUP_TEXT = 2000  # goal + acceptance together


def normal_text(text: str) -> str:
    """Casefolded, whitespace runs as one space: how a draft is compared with a blocking item (F-12-13b)."""
    return " ".join(str(text).casefold().split())


def blocking_hit(drafts: list[dict], items: list[str]) -> str | None:
    """The first blocking item that a draft's title or goal equals or contains (casefold, whitespace-normalised);
    None when no draft is one (F-12-13b criterion 4: a blocking item is fixed before the merge, never filed)."""
    for item in items:
        needle = normal_text(item)
        if needle and any(
            needle in normal_text(d.get("title") or "") or needle in normal_text(d.get("goal") or "") for d in drafts
        ):
            return item
    return None


def blocking_message(item: str) -> str:
    return f'blocking: "{item}" must be fixed before the merge, not filed'


def module_label(glob: str) -> str:
    """`src/payments/**` → `src/payments`: a module glob as the cards name it."""
    return re.sub(r"(/\*\*?)+$", "", glob) or glob


def module_owner(modules: list[dict], module: str) -> tuple[str, str] | None:
    """(member, module path) of the first `repo_modules` glob (by glob) that has `module` as a path segment (or run of
    segments): `payments` ↔ `src/payments/**` → ("carol", "src/payments"); None when no glob names it."""
    want = [p for p in module.split("/") if p]
    if not want:
        return None
    for m in modules:
        parts = m["glob"].split("/")
        if any(parts[i : i + len(want)] == want for i in range(len(parts) - len(want) + 1)):
            return m["member"], module_label(m["glob"])
    return None


# --- onboarding card 3: the repo report's rule (S17 F-17-12) -----------------------------------------------------------
# The card's stored id: ids stay when the cards are reordered (S18 D-2 a); `onboarding.REPO` is the same number.
REPO_CARD = 3
AGENTS = ("claude", "codex")
AGENT_NAMES = {"claude": "Claude Code", "codex": "Codex"}
AGENT_INSTALL = {"claude": "npm install -g @anthropic-ai/claude-code", "codex": "npm install -g @openai/codex"}
HOOK_FILES = {"claude": (".claude/settings.json", ".mcp.json"), "codex": (".codex/hooks.json",)}  # in the clone
NOT_SET = "The leader has not set the team repo yet"
NO_REPORT = "Run flowmode doctor in your clone of the team repo"
URL_PLACEHOLDER = "<the team repo's URL>"
# the canonical clone form (`repo.canonical_repo`) of a hosted repository: no user info, no local path
_HOSTED = re.compile(r"git@[a-z0-9.-]{1,253}:[A-Za-z0-9._~-]+(/[A-Za-z0-9._~-]+)+\.git")


def public_repo(url: str | None) -> str | None:
    """The canonical form of a hosted repository's clone URL (user info and port dropped); None for anything else (no
    origin, a local path, `file://`) — a report never carries a path outside the clone or a remote's user info."""
    canonical = canonical_repo(url) if url else ""
    return canonical if _HOSTED.fullmatch(canonical) else None


_SEMVER = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def client_outdated(version: str, latest: str) -> bool:
    """True only when both are plain `X.Y.Z` and `version` is the lower: anything else (two parts, a dev build) is
    never a reason to warn."""
    mine, newest = _SEMVER.fullmatch(version), _SEMVER.fullmatch(latest)
    return bool(mine and newest) and tuple(map(int, mine.groups())) < tuple(map(int, newest.groups()))


def same_repo(a: str | None, b: str | None) -> bool:
    """Lower-cased canonical forms: a case-only difference is the same repository (GitHub folds the case)."""
    return bool(a and b) and canonical_repo(a).lower() == canonical_repo(b).lower()


def clone_url(canonical: str) -> str:
    """`https://<host>/<path>.git` of a canonical `git@<host>:<path>.git`: the form the fix commands print."""
    host, _, path = canonical.removeprefix("git@").partition(":")
    return f"https://{host}/{path}"


def _fix(fact: str, text: str, command: str | None = None) -> dict:
    return {"fact": fact, "text": text, **({"command": command} if command else {})}


def repo_fixes(facts: dict, team_repo: str | None, leader: bool, *, team_known: bool = True) -> list[dict]:
    """Card 3's open items for one report, in order — `[{fact, text, command?}]`, `[]` when the rule is met (§6
    F-17-12.d): origin = the team repo, at least one agent on PATH with its hooks, `gh` installed and signed in, and
    for a leader the hook files tracked in git. The one mapping the API (`cards`, the facts route) and `flowmode
    doctor` use; `team_known=False` (a report that could not be sent) leaves the team repo out."""
    fixes = []
    url = clone_url(team_repo) if team_repo else URL_PLACEHOLDER
    if team_known and team_repo is None and not leader:
        fixes.append(_fix("origin", NOT_SET))
    if not facts.get("origin"):
        fixes.append(_fix("origin", "This clone has no origin", f"git remote add origin {url}"))
    elif facts.get("repo") is None:
        fixes.append(_fix("origin", "origin is not a hosted repository", f"git remote set-url origin {url}"))
    elif team_known and team_repo is not None and not same_repo(facts["repo"], team_repo):
        fixes.append(_fix("origin", f"origin is not the team repo ({team_repo})", f"git remote set-url origin {url}"))
    agents, hooks = facts.get("agents") or {}, facts.get("hooks") or {}
    ready = [agent for agent in AGENTS if agents.get(agent) and hooks.get(agent)]
    if not ready:
        on_path = [agent for agent in AGENTS if agents.get(agent)]
        if not on_path:
            fixes.append(_fix("agents.claude", "Install Claude Code (or Codex)", AGENT_INSTALL["claude"]))
        for agent in on_path or ["claude"]:
            text = f"Add flowmode's hooks for {AGENT_NAMES[agent]} (run in the clone)"
            fixes.append(_fix(f"hooks.{agent}", text, f"flowmode install {agent}"))
    gh = facts.get("gh") or {}
    if not (gh.get("installed") and gh.get("signed_in")):
        text = "Sign in to GitHub with gh" if gh.get("installed") else "Install the GitHub CLI, then sign in with it"
        fixes.append(_fix("gh", text, "gh auth login"))
    if leader and ready and not facts.get("hooks_tracked"):
        files = " ".join(path for agent in ready for path in HOOK_FILES[agent])
        command = f'git add {files} && git commit -m "Add flowmode hooks" && git push'
        fixes.append(_fix("hooks_tracked", "Commit the hook files once, for the whole team", command))
    return fixes
