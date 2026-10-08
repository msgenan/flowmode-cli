"""Risky-command classifier (S1 §8), shared by the server (/api/config) and the S2 hooks."""

import re

DEFAULT_RISKY_PATTERNS: list[str] = [
    # git push, also after global options (`git -C dir push`, `git -c k=v push`)
    r"\bgit\s+(-\S+(\s+[^-\s]\S*)?\s+)*push\b",
    r"\bgit\s+reset\s+--hard\b",
    r"\bgit\s+clean\s+(-\w+\s+)*-\w*f",
    r"(^|\s)--force(-with-lease)?\b",
    # rm with a recursive and a force flag, combined or separate, any case or long form (-rf, -Rf, -r -f, --recursive)
    r"\brm\s+(?=(-\S+\s+)*(-\w*[rR]|--recursive\b))(?=(-\S+\s+)*(-\w*f|--force\b))",
    r"\bcurl\b",
    r"\bwget\b",
    r"\bnpm\s+publish\b",
    r"\b(uv|twine|poetry|cargo|gem)\s+publish\b",
    r"\btwine\s+upload\b",
    r"\bgh\s+release\s+create\b",
    # S11 F-11-24: the push and merge bypasses seen or feared after the live test of 2026-09-27 (a free GitHub org has
    # no branch protection, so these are the only guard)
    r"\bgh\s+pr\s+create\b(?![^;&|]*--head\b)",  # without --head it pushes the branch
    (
        r"\bgh\s+api\b(?=[^;&|]*(\s-X\s*(?i:POST|PUT|PATCH|DELETE)\b|\s--method[ =](?i:POST|PUT|PATCH|DELETE)\b"
        r"|\s(-f|-F|--field|--raw-field|--input)[ =]))"
    ),  # a writing method, or fields (gh POSTs)
    r"""["']git["']\s*,\s*["']push["']""",  # ['git', 'push'] inside python -c
    r"\bgh\s+pr\s+merge\b",
    r"\bgh\s+pr\s+review\b(?=[^;&|]*(\s--approve\b|\s-a\b))",
    # S12 F-12-13b: an issue is opened only on the person's word (the follow-ups' Open all); `gh issue view/list` stay free
    r"\bgh\s+issue\s+create\b",
]


def is_risky(command: str, patterns: list[str] | None = None) -> str | None:
    """Return the first pattern that `re.search`es `command`, else None."""
    for pattern in DEFAULT_RISKY_PATTERNS if patterns is None else patterns:
        if re.search(pattern, command):
            return pattern
    return None


# --- S8 §6: approval modes per session ----------------------------------------------------------------------------

# where a command starts: the line start, after ; & | ( or after sudo/xargs ("grep docker" is not docker)
_AT_COMMAND = r"(^|[;&|(]\s*|\bsudo\s+|\bxargs\s+)"
# strict: also ask before installs, history writes, any delete and infra/remote commands
STRICT_PATTERNS: list[str] = [
    r"\b(npm|pnpm|yarn)\s+(i|install|add)\b",
    r"\bpip3?\s+install\b",
    r"\buv\s+(add|pip\s+install)\b",
    r"\bbrew\s+install\b",
    r"\bcargo\s+(add|install)\b",
    r"\bgo\s+get\b",
    r"\bgit\s+(-\S+(\s+[^-\s]\S*)?\s+)*(commit|merge|rebase|cherry-pick|revert|tag)\b",
    r"\bgit\s+branch\s+(-\w*[dD]\b|--delete\b)",
    r"\bgit\s+checkout\s+--(\s|$)",
    rf"{_AT_COMMAND}rm\s",
    r"(^|[;&|(]\s*)sudo\b",
    rf"{_AT_COMMAND}(docker|kubectl|terraform|helm)\b",
    rf"{_AT_COMMAND}(ssh|scp|rsync)\b",
]
# relaxed: network reads run without approval (only when the team patterns carry them verbatim)
RELAXED_EXEMPT: tuple[str, ...] = (r"\bcurl\b", r"\bwget\b")
MODES = ("strict", "normal", "relaxed")


def patterns_for(mode: str | None, team_patterns: list[str]) -> list[str]:
    """The risky patterns a session in `mode` asks approval for (normal = the team patterns)."""
    if mode == "strict":
        return [*team_patterns, *(p for p in STRICT_PATTERNS if p not in team_patterns)]
    if mode == "relaxed":
        return [p for p in team_patterns if p not in RELAXED_EXEMPT]
    return list(team_patterns)


# --- S8 §5: what an approval would touch -----------------------------------------------------------------------------

_SCOPES: tuple[tuple[str, re.Pattern], ...] = (
    ("network", re.compile(r"\b(curl|wget|ssh|scp|rsync)\b|https?://")),
    (
        "push",
        re.compile(
            r"\bgit\s+(-\S+(\s+[^-\s]\S*)?\s+)*push\b|\bgh\s+pr\s+create\b(?![^;&|]*--head\b)"
            r"""|["']git["']\s*,\s*["']push["']"""
        ),
    ),
    ("force", re.compile(r"(^|\s)--force(-with-lease)?\b|\bpush\b[^;&|]*\s-f\b")),
    (
        "publish",
        re.compile(
            r"\b(npm|pnpm|yarn)\s+publish\b|\b(uv|twine|poetry|cargo|gem)\s+publish\b"
            r"|\btwine\s+upload\b|\bgh\s+release\s+create\b|\bdocker\s+push\b"
        ),
    ),
    (
        "delete",
        re.compile(
            r"(^|[\s;&|(])rm\s|\bgit\s+clean\b|\bgit\s+reset\s+--hard\b|\bgit\s+branch\s+-D\b"
            r"|\bdrop\s+(table|database)\b",
            re.IGNORECASE,
        ),
    ),
    # S11 F-11-24: merging or approving a pull request lands on the default branch with no human step on GitHub
    ("merge", re.compile(r"\bgh\s+pr\s+merge\b|\bgh\s+pr\s+review\b[^;&|]*(\s--approve\b|\s-a\b)")),
    # S12 F-12-13b: a new GitHub issue (a follow-up is opened by `flowmode review followups --open`, never by hand)
    ("issue", re.compile(r"\bgh\s+issue\s+create\b")),
)


def scopes(command: str) -> list[str]:
    """What a command would reach, in a fixed order: network, push, force, publish, delete, merge, issue."""
    return [name for name, pattern in _SCOPES if pattern.search(command)]


# --- S9 §11: what a risky pattern means, in words ---------------------------------------------------------------------

_PUBLISH = "publish a package"
LABELS: dict[str, str] = dict(
    zip(
        DEFAULT_RISKY_PATTERNS,
        (
            "push to a remote",
            "discard local changes (git reset --hard)",
            "delete untracked files (git clean)",
            "force (--force)",
            "recursive delete (rm -rf)",
            "download (curl)",
            "download (wget)",
            _PUBLISH,
            _PUBLISH,
            _PUBLISH,
            "create a GitHub release",
            "create a pull request (may push the branch)",
            "write to GitHub through gh api",
            "push to a remote",
            "merge a pull request",
            "approve a pull request",
            "open a GitHub issue",
        ),
        strict=True,
    )
) | dict(
    zip(
        STRICT_PATTERNS,
        (
            "install packages",
            "install packages",
            "install packages",
            "install packages",
            "install packages",
            "install packages",
            "change git history",
            "delete a branch",
            "discard file changes",
            "delete files",
            "run as root (sudo)",
            "infrastructure command",
            "remote shell or copy",
        ),
        strict=True,
    )
)


def reason_for(command: str, patterns: list[str]) -> str | None:
    """The labels of every pattern in `patterns` that matches `command`, in pattern order, without repeats, joined by
    ", "; a pattern without a label reads `team rule <pattern>`. None when nothing matches."""
    labels: list[str] = []
    for pattern in patterns:
        if re.search(pattern, command):
            label = LABELS.get(pattern, f"team rule {pattern}")
            if label not in labels:
                labels.append(label)
    return ", ".join(labels) or None
