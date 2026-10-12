"""Risky-command classifier (S1 §8), shared by the server (/api/config) and the S2 hooks."""

import fnmatch
import functools
import os
import posixpath
import re
import shlex
import sys
from pathlib import Path

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


# S20 F-20-88 (H1-5): is_risky's answer for a command whose command word (or git/gh sub-command) is built at run time
# (`$(echo git) push`, `$X push`, a shell reading its script from stdin): what runs cannot be read, so it is asked
RUNTIME_COMMAND = "(command built at run time)"


def is_risky(command: str, patterns: list[str] | None = None) -> str | None:
    """The first pattern that `re.search`es `command` as written; else the first that matches the command as the shell
    runs it (`risk_views`: quotes removed, wrappers dropped, `sh -c`/`eval` strings parsed, plumbing push forms, git
    aliases defined in the command); else RUNTIME_COMMAND when a command word is built at run time and `patterns` is
    not empty; else None. Every raw-text decision is kept as it was."""
    patterns = DEFAULT_RISKY_PATTERNS if patterns is None else patterns
    for pattern in patterns:
        if re.search(pattern, command):
            return pattern
    views, runtime = _risk_analysis(command)
    for pattern in patterns:
        if any(re.search(pattern, view) for view in views[1:]):
            return pattern
    return RUNTIME_COMMAND if runtime and patterns else None


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
    """What a command would reach, in a fixed order: network, push, force, publish, delete, merge, issue — read on
    the command as written and as the shell runs it (`risk_views`)."""
    views = risk_views(command)
    return [name for name, pattern in _SCOPES if any(pattern.search(view) for view in views)]


# --- S9 §11: what a risky pattern means, in words ---------------------------------------------------------------------

_PUBLISH = "publish a package"
LABELS: dict[str, str] = (
    dict(
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
    )
    | dict(
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
    | {RUNTIME_COMMAND: "a command built at run time (cannot be read before it runs)"}
)


def reason_for(command: str, patterns: list[str]) -> str | None:
    """The labels of every pattern in `patterns` that matches `command`, in pattern order, without repeats, joined by
    ", "; a pattern without a label reads `team rule <pattern>`. None when nothing matches."""
    labels: list[str] = []
    views, runtime = _risk_analysis(command)
    for pattern in patterns:
        if any(re.search(pattern, view) for view in views):
            label = LABELS.get(pattern, f"team rule {pattern}")
            if label not in labels:
                labels.append(label)
    if runtime and patterns:
        labels.append(LABELS[RUNTIME_COMMAND])
    return ", ".join(labels) or None


# --- S20 L-6 (F-20-20): no agent as commit author or co-author ---------------------------------------------------------
# One shared check for the PreToolUse hook (a Bash command) and `flowmode check commit-msg` (the text git will store).
# Stdlib only: the server imports this module too.

ATTRIBUTION_REFUSAL = (
    "Flowmode: commits and PRs in this team never name an agent as author or co-author — remove {found} and try again."
)
AGENT_NAMES = frozenset(
    {
        "claude",
        "claude code",
        "codex",
        "chatgpt",
        "copilot",
        "github copilot",
        "cursor",
        "cursor agent",
        "devin",
        "gemini",
        "aider",
    }
)
MODEL_FAMILIES = ("opus", "sonnet", "haiku", "fable")
AGENT_DOMAINS = ("anthropic.com", "openai.com", "cursor.com", "cursor.sh")
_GITHUB_NOREPLY = "users.noreply.github.com"
_TRAILER = re.compile(r"co-authored-by[ \t]*[:=][ \t]*([^\n]*)", re.IGNORECASE)
_FOOTER_BODY = r"(?P<f>(?:🤖[ \t]*)?generated with[ \t]+\[?(?:claude code|claude|codex)\b\]?|🤖[ \t]*generated with)"
# a footer is a line: at a line start in a message; in a command also right after a quote, `=` or a flag (`-m `,
# `--title `), where a message starts — prose that mentions the footer mid-sentence passes
_FOOTER_LINE = re.compile(r"^[ \t]*" + _FOOTER_BODY, re.IGNORECASE | re.MULTILINE)
_FOOTER_CMD = re.compile(r"(?:^|[\n\"'=]|(?<!\S)-[\w-]*[ \t]+)[ \t]*" + _FOOTER_BODY, re.IGNORECASE)
_SESSION = re.compile(r"claude-session[ \t]*:[ \t]*[^\s\"'`)]*", re.IGNORECASE)
_PERSON = re.compile(r"\s*([^<\"'`\n]*?)\s*(?:<([^>\n]*)>|$|[\"'`\n])")
# commands that store a commit message or a pull request text (git's global options may come first); `commit`
# also covers `commit-tree` (plumbing: no hooks run), a merge commit's message comes from `merge`/`pull`; F-20-88
# (H1-3): `am`, `filter-branch`, `filter-repo`, `fast-import`, `replace` create commits without the commit-msg hook
_ATTRIBUTION_SCOPE = re.compile(
    r"\bgit\s+(-\S+(\s+[^-\s]\S*)?\s+)*(commit|merge|pull|am|filter-branch|filter-repo|fast-import|replace)\b"
    r"|\bgh\s+pr\s+(create|edit|merge)\b|\bgh\s+api\b[^;&|\n]*\bpulls\b"
)
_IDENT_ENV = re.compile(r"(GIT_(?:AUTHOR|COMMITTER)_(NAME|EMAIL))=(.*)", re.DOTALL)
_USER_KEY = re.compile(r"user\.(name|email)=(.*)", re.IGNORECASE | re.DOTALL)
_FILE_FLAGS = ("-F", "--file", "--body-file", "--input")
_FIELD_FLAGS = ("-F", "-f", "--field", "--raw-field")  # gh api: `key=@path` sends the file's text
_CUT_LINE = " " + "-" * 24 + " >8 " + "-" * 24
_AUTO_COMMENT = "#;@!$%^&|:"  # core.commentChar=auto picks one of these
_MAX_FOUND = 120
_MAX_FILE = 256 * 1024


def is_agent_name(name: str) -> bool:
    """Exactly (any case) one of AGENT_NAMES, or "Claude <model family> …"; "Claude Martin" and "Claudette" are not."""
    words = name.strip().strip("\"'").lower().split()
    if " ".join(words) in AGENT_NAMES:
        return True
    return len(words) >= 2 and words[0] == "claude" and words[1] in MODEL_FAMILIES


def is_agent_email(email: str) -> bool:
    """An address at an agent maker's domain, or a GitHub bot address (`…[bot]@users.noreply.github.com`, Copilot's);
    a person's `12345+name@users.noreply.github.com` is not."""
    local, at, domain = email.strip().strip("<>\"'").lower().rpartition("@")
    if not at:
        return False
    if any(domain == d or domain.endswith("." + d) for d in AGENT_DOMAINS):
        return True
    if domain == _GITHUB_NOREPLY:
        user = local.split("+", 1)[-1]
        return user.endswith("[bot]") or user == "copilot"
    return False


def is_agent_identity(name: str, email: str = "") -> bool:
    return is_agent_name(name) or (bool(email) and is_agent_email(email))


def _clip(found: str) -> str:
    found = found.strip().rstrip("\"'`)")
    return found if len(found) <= _MAX_FOUND else found[: _MAX_FOUND - 1] + "…"


def _parse_person(value: str) -> tuple[str, str, int]:
    """("Name", "email", length of the person text) from the start of `value` (`Name <email>` or a bare name)."""
    m = _PERSON.match(value)
    if m is None:
        return "", "", 0
    end = m.end(2) + 1 if m.group(2) is not None else m.end(1)
    return m.group(1), m.group(2) or "", end


def text_findings(text: str, command: bool = False) -> list[str]:
    """The agent markers in a commit message or PR text, in order, without repeats: a `Co-authored-by:` trailer naming
    an agent (a person's passes), a "Generated with [Claude Code]/Codex" or "🤖 Generated with" line, a
    `Claude-Session:` trailer. Prose that only mentions an agent is not a marker. `command`: `text` is a shell
    command, where a message line may also start after a quote, `=` or a flag."""
    found: list[tuple[int, str]] = []
    for m in _TRAILER.finditer(text):
        name, email, end = _parse_person(m.group(1))
        if is_agent_identity(name, email):
            found.append((m.start(), text[m.start() : m.start(1) + end]))
    found += [(m.start("f"), m.group("f")) for m in (_FOOTER_CMD if command else _FOOTER_LINE).finditer(text)]
    found += [(m.start(), m.group(0)) for m in _SESSION.finditer(text)]
    out: list[str] = []
    for _, item in sorted(found):
        clipped = _clip(item)
        if clipped and clipped not in out:
            out.append(clipped)
    return out


def _views(command: str) -> list[str]:
    """The command as written, without its quote characters (`"Cl"'aude'` → `Claude`), and with ANSI-C escapes
    decoded (`$'a\\nb'`); each also with backslash-newline continuations removed: quoting cannot hide a marker
    (SR-5)."""
    views = []
    for text in dict.fromkeys((command, command.replace("\\\n", ""))):
        bare = re.sub(r"[\"']", "", text.replace("$'", "'").replace('$"', '"'))
        decoded = bare.replace("\\n", "\n").replace("\\t", "\t").replace("\\", "")
        views += [text, bare, decoded]
    return list(dict.fromkeys(views))


def attribution_scope(command: str) -> bool:
    """The command may store a commit message, a commit identity or a pull request text."""
    return any(_ATTRIBUTION_SCOPE.search(view) for view in _views(command))


def _is_agent_value(kind: str, value: str) -> bool:
    if kind == "email":
        return is_agent_email(value)
    if kind == "name":
        return is_agent_name(value)
    name, email, _ = _parse_person(value)  # "Name <email>"
    return is_agent_identity(name, email)


# Shell words that only open a block before the command, and prefix commands that run the next words as the command:
# {name: (its options that take the next word as their value, positional words before the command)}
_OPENERS = frozenset({"(", "((", "{", "!", "if", "then", "else", "elif", "do", "while", "until", "coproc"})
_CLOSERS = frozenset({")", "))", "}"})
_ENDERS = frozenset({"}", ")", "))", "fi", "done", "esac"})  # a block's end that starts a segment (`; done > log`)
# shell words that, left in command position after the openers are dropped, mean grammar the hook does not extract
_RESERVED = frozenset(
    {"case", "coproc", "function", "esac", "in", "then", "do", "else", "elif", "fi", "done", "{", "}"}
)
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_WRAPPERS: dict[str, tuple[frozenset[str], int]] = {
    "sudo": (
        frozenset(
            {"-u", "-g", "-p", "-C", "-D", "-r", "-t", "-U", "-T", "-R", "--user", "--group", "--prompt", "--chdir"}
            | {"--close-from", "--role", "--type", "--other-user", "--command-timeout", "--chroot"}
        ),
        0,
    ),
    "doas": (frozenset({"-u", "-C"}), 0),
    "env": (frozenset({"-u", "-C", "-S", "--unset", "--chdir", "--split-string"}), 0),
    "nice": (frozenset({"-n", "--adjustment"}), 0),
    "nohup": (frozenset(), 0),
    "time": (frozenset({"-f", "-o", "--format", "--output"}), 0),
    "command": (frozenset(), 0),
    "exec": (frozenset({"-a"}), 0),
    "stdbuf": (frozenset({"-i", "-o", "-e", "--input", "--output", "--error"}), 0),
    "timeout": (frozenset({"-s", "-k", "--signal", "--kill-after"}), 1),
    "watch": (frozenset({"-n", "--interval", "-q", "--equexit"}), 0),
    "flock": (frozenset({"-w", "--timeout", "-E", "--conflict-exit-code"}), 1),
    "ionice": (frozenset({"-c", "-n", "-p", "-P", "-u", "--class", "--classdata", "--pid", "--pgid", "--uid"}), 0),
    "xargs": (
        frozenset({"-I", "-J", "-R", "-L", "-n", "-P", "-d", "-E", "-s", "-a", "--arg-file", "--delimiter"})
        | frozenset({"--max-args"})
        | frozenset({"--max-procs", "--max-lines", "--replace", "--eof", "--max-chars", "--process-slot-var"}),
        0,
    ),
}
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_MAX_DEPTH = 2  # nested strings (`sh -c`, `rebase --exec`) unwrapped this deep


def _plain_command(pairs: list[tuple[str, str]]) -> tuple[list[tuple[str, str]], list[tuple[str, list[str]]]]:
    """(the segment's [(raw, word)] as `VAR=…` assignments + the command run: subshell/group openers and closers,
    `if`/`then`/`do`/`!` and prefix commands with their own options dropped, [(each prefix command dropped, its
    option words)])."""
    pairs = list(pairs)
    while pairs and pairs[-1][0] in _CLOSERS:
        pairs.pop()
    if pairs and pairs[-1][0].endswith(")"):  # `(git commit -n)` — a quoted `"(x)"` ends with its quote
        raw, word = pairs[-1]
        pairs[-1] = (raw[:-1], word.removesuffix(")"))
    assigns: list[tuple[str, str]] = []
    wrappers: list[tuple[str, list[str]]] = []
    i, opened = 0, False
    while i < len(pairs):
        raw, word = pairs[i]
        if raw == "(":
            opened = True
        if (
            raw == "coproc"
            and i + 2 < len(pairs)
            and _NAME.fullmatch(pairs[i + 1][0])
            and (pairs[i + 2][0] == "{" or pairs[i + 2][0].startswith("("))
        ):
            i += 2  # `coproc NAME { …; }`, `coproc NAME (…)`
            continue
        if raw in _OPENERS or (raw and not raw.strip("(")) or (i == 0 and raw in _ENDERS):  # `(((`: subshell openers
            i += 1
            continue
        if raw.startswith("(") and raw.strip("("):
            pairs[i] = (raw.lstrip("("), word.lstrip("("))
            continue
        if raw == "case":  # `case WORD in PATTERN) cmd`: the arm's command
            at = next((k for k in range(i + 1, len(pairs)) if pairs[k][0] == "in"), None)
            if at is None:
                break
            i = at + 1
            continue
        if not opened and i + 2 < len(pairs) and pairs[i + 1][0] == ")":
            i += 2  # a case arm's pattern (`x)`, `a|b)` after the split); `(x) cmd` after a `(` reads `x` as a command
            continue
        if _ASSIGNMENT.match(word):
            assigns.append(pairs[i])
            i += 1
            continue
        spec = _WRAPPERS.get(os.path.basename(word))
        if spec is None:
            break
        value_opts, positionals = spec
        opts: list[str] = []
        i += 1
        while i < len(pairs) and pairs[i][1].startswith("-"):
            if pairs[i][1] == "--":
                i += 1
                break
            step = 2 if pairs[i][1] in value_opts else 1
            opts += [w for _, w in pairs[i : i + step]]
            i += step
        wrappers.append((os.path.basename(word), opts))
        i += positionals
    rest = [p for k, p in enumerate(pairs[i:], i) if p[0] != ")" or pairs[k - 1][0] == "("]  # `(rm f) 2>x`: the
    return assigns + rest, wrappers  # subshell's `)` goes, its redirections stay; a function's `()` stays


def _rebase_execs(words: list[str]) -> list[str]:
    """The command strings of `git rebase -x/--exec <cmd>` (any form), [] for any other command."""
    words = _command_words(words)
    if not words or os.path.basename(words[0]) != "git":
        return []
    i = 1
    while i < len(words) and words[i].startswith("-"):
        i += 2 if words[i] in _GIT_VALUE_OPTS else 1
    if i >= len(words) or words[i] != "rebase":
        return []
    out = []
    rest = words[i + 1 :]
    for k, word in enumerate(rest):
        if word in ("-x", "--exec") and k + 1 < len(rest):
            out.append(rest[k + 1])
        elif word.startswith("--exec="):
            out.append(word[len("--exec=") :])
        elif word.startswith("-x") and len(word) > 2:
            out.append(word[2:])
    return out


def _substitutions(text: str) -> tuple[list[str], bool]:
    """(the bodies of the outermost command substitutions in `text` — `$(…)` (not `$((` arithmetic, whose inner
    `$(…)` still count), backticks and, outside double quotes, `<(…)` / `>(…)`; in double quotes, `${…}` and the body
    of a heredoc whose delimiter is not quoted too —, whether one is left open or its end cannot be told: a `case`
    inside, whose arm `)` closes the shell's parenthesis count early). Read by `shellwrites.lex`, the one reader of
    quotes, comments, heredocs and arithmetic; nested substitutions are the caller's next level."""
    from flowmode.shellwrites import lex

    found = lex(text)
    return found.subs, found.broken


SUBSHELL_OPEN: list[tuple[str, str]] = [("(", "(")]  # `_segment_pairs(marks=True)`: a subshell starts / ends here
SUBSHELL_CLOSE: list[tuple[str, str]] = [(")", ")")]


def _segment_pairs(
    command: str, depth: int = 0, unresolved: list[str] | None = None, marks: bool = False
) -> list[list[tuple[str, str]]]:
    """Every segment as [(raw token, word as the shell sees it)], reduced to its assignments + the command it runs
    (`_plain_command`: openers, case arms, `coproc`, prefix commands dropped); backslash-newline continuations joined;
    a `sh -c '<string>'`, an `eval` string and a `git rebase --exec` string are parsed as segments too (`_MAX_DEPTH`
    deep); `echo a b | xargs cmd` gets `a b` appended (what xargs passes on). Wherever a git, gh, shell or
    write/remove word sits after the command word of a program not known to take only data (`_scan_starts`: an
    unknown wrapper, a function body), the words from there on are a segment too. `unresolved` (when given) collects
    what cannot be read before it runs: a string nested past `_MAX_DEPTH`, `xargs` running a risky or unknown git
    sub-command, gh or a shell, `sudo -s/-i`, shell grammar left in command position. Strings a program hands to a
    shell later (`_later_strings`) are parsed as segments too. `marks`: `SUBSHELL_OPEN` before a segment for each
    subshell `(` in it and `SUBSHELL_CLOSE` after it for each `)` (a `cd` inside one ends at its `)`)."""
    from flowmode.shellwrites import _tokens, _unwrap, join_continuations, segments

    def nested(text: str) -> list[list[tuple[str, str]]]:
        if depth < _MAX_DEPTH:
            return _segment_pairs(text, depth + 1, unresolved, marks)
        if unresolved is not None:
            unresolved.append("nested past the limit")
        return []

    lists: list[list[tuple[str, str]]] = []
    prev: list[str] = []

    def one(raw_pairs: list[tuple[str, str]], scan: bool) -> None:
        nonlocal prev
        pairs, wrappers = _plain_command(raw_pairs)
        at = next((n for n, (raw, _) in enumerate(pairs) if not _ASSIGNMENT.match(raw)), len(pairs))
        run_words = [w for _, w in pairs[at:]]  # a quoted `'a=b; …'` is a word, not an assignment
        if scan:
            starts = _scan_starts(pairs, at)
            for k, j in enumerate(starts):  # each later command word: its words on, as a command of its own
                end = len(pairs) if k < _MAX_SCANS else (starts[k + 1] if k + 1 < len(starts) else len(pairs))
                kept = prev
                one(pairs[j:end], False)
                prev = kept
            if len(starts) > _MAX_SCANS and unresolved is not None:
                unresolved.append("too many commands in one segment")
        if unresolved is not None and at < len(pairs) and _odd_grammar([r for r, _ in pairs[at:]]):
            unresolved.append("shell grammar the hook does not extract")
        xargs = any(name == "xargs" for name, _ in wrappers)
        if xargs and unresolved is not None and _runs_unread(run_words):
            unresolved.append("xargs runs git (a risky or unknown sub-command), gh or a shell")
        if xargs and unresolved is not None and run_words:
            marks = [m for name, opts in wrappers if name == "xargs" for m in _xargs_marks(opts)]
            if any(m in run_words[0] for m in marks):
                unresolved.append("xargs takes the command word from its input")
        for name, opts in wrappers:  # `env -S '<string>'`: env splits the string into the command it runs
            for text in _option_values(opts, "S", "--split-string") if name == "env" else []:
                lists.extend(nested(" ".join([text, shlex.join(run_words)])))
        if unresolved is not None and any(name == "sudo" and _sudo_shell(opts) for name, opts in wrappers):
            unresolved.append("sudo -s / -i runs its words in a shell")
        for text in _later_strings(run_words, [name for name, _ in wrappers]):
            lists.extend(nested(text))  # a string a program hands to a shell later (`trap`, `watch`, `script -c`, …)
        tokens, inner = _unwrap(pairs)
        if inner is not None:
            lists.extend(nested(inner))
            prev = []
            return
        if tokens is not pairs:  # Codex's joined `bash -lc a b c`
            tokens, _ = _plain_command(tokens)
        words = [w for _, w in tokens]
        run = _command_words(words)
        if run and run[0] == "eval":  # `eval "<string>"`: the shell parses the joined words again (F-20-88)
            lists.extend(nested(" ".join(run[1:])))
            prev = []
            return
        if xargs and prev and os.path.basename(prev[0]) in ("echo", "printf"):
            tokens = tokens + [(f"'{w}'", w) for w in prev[1:]]
        lists.append(tokens)
        for text in _rebase_execs(words):
            lists.extend(nested(text))
        prev = _command_words(words)

    command = join_continuations(command)
    for seg in segments(command):
        tokens = _tokens(seg)
        if not marks:
            one(tokens, True)
            continue
        raws = [raw for raw, _ in tokens]
        fn = {k for k in range(len(raws) - 1) if raws[k : k + 2] == ["(", ")"]}  # a function's `()`
        lists.extend(SUBSHELL_OPEN for k, raw in enumerate(raws) if raw == "(" and k not in fn)
        one(tokens, True)
        lists.extend(SUBSHELL_CLOSE for k, raw in enumerate(raws) if raw == ")" and k - 1 not in fn)
    bodies, broken = _substitutions(command)
    if broken and unresolved is not None:
        unresolved.append("a substitution the hook cannot read")
    for body in bodies:  # `$(…)`, backticks, `<(…)`, `>(…)`: commands of their own, after the segments (a `cd` in one
        prev = []  # stays in its subshell; the segments' `cd`s before them count)
        lists.extend(nested(body))
    return lists


# programs whose words after the command word are data, never a command they run: a git/gh/shell or write word among
# them is not looked at as a command (`brew install git`, `which bash`, `man git`, `echo rm x`)
_DATA_ARGS = frozenset(
    {"echo", "printf", "which", "type", "whereis", "whatis", "man", "info", "help", "apropos", "ls", "cat", "less"}
    | {"more", "head", "tail", "wc", "file", "stat", "grep", "egrep", "fgrep", "rg", "ag", "ack", "cd", "mkdir"}
    | {"brew", "apt", "apt-get", "dnf", "yum", "apk", "pip", "pip3", "git", "gh", "ssh", "scp", "test", "[", "[["}
    | {"read", "alias", "unalias", "hash", "history", "complete", "jq", "diff", "cmp", "sort", "uniq", "cut", "tr"}
    | {"export", "declare", "typeset", "readonly", "local"}
    | {"for", "select"}  # `for x in git rm`: the loop's words; its body is the next segment
    | {"docker", "podman", "kubectl"}  # what they run runs in a container (like ssh: another machine's shell)
)
# a word that runs (or writes) where it sits: git, gh, busybox, a shell, a write/remove/move/mode verb
_SCAN_WORDS = (
    frozenset({"git", "gh", "busybox", "dash", "ksh", "fish"})
    | frozenset({"sh", "bash", "zsh", "ash", "mksh", "csh", "tcsh"})
    | frozenset({"rm", "mv", "cp", "ln", "tee", "truncate", "dd", "install", "chmod", "chflags", "sed", "perl"})
    | frozenset({"unlink", "shred", "rsync", "tar", "unzip", "touch"})
)
_MAX_SCANS = 16  # later command words read in full per segment; past this, up to the next one (and asked)
_REDIRECT_OP = re.compile(r"[0-9&]*(?:<<<|<<-?|<>|<&|<|>>|>\||>&|>)")


def _scan_starts(pairs: list[tuple[str, str]], at: int) -> list[int]:
    """The indexes after the command word (`at`) where a `_SCAN_WORDS` word sits — a redirection's target and an
    option skipped — unless the command is known to take only data (`_DATA_ARGS`)."""
    if at >= len(pairs) or os.path.basename(pairs[at][1]) in _DATA_ARGS:
        return []
    out = []
    for j in range(at + 1, len(pairs)):
        word = pairs[j][1]
        if _REDIRECT_OP.fullmatch(pairs[j - 1][0]) or word.startswith("-"):
            continue
        if os.path.basename(word) in _SCAN_WORDS:
            out.append(j)
    return out


def _odd_grammar(raws: list[str]) -> bool:
    """Shell grammar left in command position that the hook does not extract: a reserved word other than a loop's
    head (`for NAME in …`, `select NAME in …`, `for ((…))`), or a `function` keyword (its body is scanned too)."""
    head = raws[0]
    if head in ("for", "select"):
        return not (raws[1:2] and (_NAME.fullmatch(raws[1]) or raws[1].startswith("((")))
    return head in _RESERVED


_XARGS_GIT_SAFE = frozenset({"add", "status", "diff", "log", "rm", "show", "blame", "grep", "ls-files", "check-ignore"})


def _runs_unread(words: list[str]) -> bool:
    """Under xargs / find -exec (they append words): the command runs a shell, busybox, gh, or git with a sub-command
    that is missing, built from the input (`{}`), aliased, or not an everyday read/stage one (`_XARGS_GIT_SAFE`)."""
    name = os.path.basename(words[0]) if words else ""
    if "{}" in name:  # `find -exec {} …`, `xargs -I{} {} …`: the command word is the input
        return True
    if name != "git":
        return name in _RUNS_TEXT
    sub = _git_sub_at(words)
    return sub is None or words[sub] not in _XARGS_GIT_SAFE or bool(_git_alias_views(words[:sub], None))


def _xargs_marks(opts: list[str]) -> list[str]:
    """The strings xargs replaces with an input line: `-I R`, `-J R`, `--replace[=R]`, `-i[R]` (`{}` by default)."""
    marks = _option_values(opts, "I", "--replace") + _option_values(opts, "J", "-J")
    marks += [o[2:] or "{}" for o in opts if o.startswith("-i")]
    marks += ["{}"] if "--replace" in opts else []
    return [m for m in marks if m]


def _sudo_shell(opts: list[str]) -> bool:
    return any(
        o in ("--shell", "--login") or (o[:1] == "-" and o[1:2] != "-" and bool(set(o[1:]) & {"s", "i"})) for o in opts
    )


def _option_values(args: list[str], short: str, long: str) -> list[str]:
    """The values of `-<short> V`, `-x<short>V` (a cluster), `--<long> V` and `--<long>=V` in `args`."""
    out: list[str] = []
    for k, arg in enumerate(args):
        nxt = args[k + 1 : k + 2]
        if arg == long:
            out += nxt
        elif arg.startswith(long + "="):
            out.append(arg[len(long) + 1 :])
        elif arg[:1] == "-" and arg[1:2] != "-" and short in arg[1:]:
            rest = arg[arg.index(short, 1) + 1 :]
            out += [rest] if rest else nxt
    return out


def _later_strings(words: list[str], wrappers: list[str]) -> list[str]:
    """The command strings a program hands to a shell later: `trap '<cmd>' SIG`, `watch <cmd…>`, `script -c`,
    `flock <file> -c`, `npx -c` / `npm exec --call`, `git submodule foreach <cmd…>`, `git bisect run <cmd…>`."""
    if "watch" in wrappers and words:
        return [" ".join(words)]
    if "flock" in wrappers and words[:1] in (["-c"], ["--command"]):
        return words[1:2]
    name = os.path.basename(words[0]) if words else ""
    args = words[1:]
    if name == "trap":
        ops = [a for a in args if a != "--"]
        return ops[:1] if len(ops) >= 2 and not ops[0].startswith("-") else []
    if name == "script":
        return _option_values(args, "c", "--command")
    if name in ("npx", "pnpx") or (name == "npm" and args[:1] == ["exec"]):
        return _option_values(args, "c", "--call")
    if name == "git" and (sub := _git_sub_at(words)) is not None:
        rest = words[sub + 1 :]
        if words[sub] == "submodule":
            rest = [w for w in rest if w not in ("--quiet", "-q", "--recursive")]
            return [" ".join(rest[1:])] if rest[:1] == ["foreach"] and rest[1:] else []
        if words[sub] == "bisect" and rest[:1] == ["run"] and rest[1:]:
            return [shlex.join(rest[1:])]
    return []


def _token_lists(command: str) -> list[list[str]]:
    """Every segment's words as the shell sees them, from the command it runs on (`_segment_pairs`)."""
    return [[w for _, w in pairs] for pairs in _segment_pairs(command)]


# --- S20 F-20-88 (H1-5): what the approval patterns read -----------------------------------------------------------------

# shells that read a script (from stdin when no script operand is named); `busybox sh` runs one too
_SHELL_NAMES = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash", "mksh", "fish", "csh", "tcsh"})
_RUNS_TEXT = _SHELL_NAMES | {"git", "gh", "busybox"}  # under xargs / find -exec / parallel: what runs cannot be read
_STDIN_SCRIPT = frozenset({"-", "/dev/stdin", "/dev/fd/0"})
_PUSH_PLUMBING = frozenset({"send-pack", "http-push"})  # they push without the word `push` after `git`
_PUSH_TOOLS = frozenset({"subtree", "lfs"})  # `git subtree push`, `git lfs push`
_SHELL_INFO = frozenset({"--version", "--help"})
_QUOTED = re.compile(r"'[^']*'|\"(?:[^\"\\]|\\.)*\"|\\.")
_BRACE_LIST = re.compile(r"\{[^{}]*(?:,|\.\.)[^{}]*\}")
_GIT_CONFIG_RUNTIME = re.compile(r"^GIT_CONFIG_(?:COUNT|KEY_\w*|VALUE_\w*|PARAMETERS)=")
_TEST_WORDS = frozenset({"[", "[["})
_FUNCTION_DEF = re.compile(r"[A-Za-z_][\w.:-]*\((?:\)\{?)?")
# settings and environment variables whose value git (or gh) hands to a shell later; a value that is one plain word
# (`core.pager=cat`, `GIT_EDITOR=vim`) names a program, anything else is a command line the hook does not read
_RUNS_LATER_KEY = re.compile(
    r"core\.(?:sshcommand|fsmonitor|pager|editor|askpass|gitproxy)|sequence\.editor|credential\.(?:.+\.)?helper"
    r"|diff\.(?:external|.+\.(?:textconv|command))|merge\..+\.driver|filter\..+|uploadpack\.packobjectshook|pager\..+"
    r"|gpg\.(?:.+\.)?program|remote\..+\.(?:receivepack|uploadpack)|interactive\.difffilter|(?:diff|merge)tool\..+\.cmd"
)
_RUNS_LATER_ENV = re.compile(
    r"(?:GIT_SSH_COMMAND|GIT_SSH|GIT_EDITOR|GIT_SEQUENCE_EDITOR|GIT_PAGER|PAGER|GIT_EXTERNAL_DIFF|GIT_ASKPASS"
    r"|SSH_ASKPASS|EDITOR|VISUAL|GH_EDITOR|GH_PAGER|GIT_PROXY_COMMAND)=(.*)",
    re.DOTALL,
)
_PLAIN_VALUE = re.compile(r"[\w./:@%+,=~-]*")
_DECLARE = frozenset({"export", "declare", "typeset", "readonly", "local"})
_SOURCE = frozenset({"source", "."})
_COPIERS = frozenset({"ln", "cp", "install", "rsync"})


def _built_at_run_time(raw: str) -> bool:
    """A raw word the shell completes when it runs: a `$` outside single quotes, or backticks."""
    return "`" in raw or ("$" in raw and not raw.startswith("'"))


def _expands(raw: str) -> bool:
    """A raw word the shell turns into other words when it runs: `$`/backticks (`_built_at_run_time`), or outside
    quotes a glob character or a brace list (`{a,b}`, `{1..3}`)."""
    if raw in _TEST_WORDS:
        return False
    bare = _QUOTED.sub("", raw)
    return _built_at_run_time(raw) or any(c in bare for c in _GLOB) or bool(_BRACE_LIST.search(bare))


def _unresolved_word(raw: str, name: str) -> bool:
    """The command word cannot be read before it runs (`_expands`). The one allowance: a path built from a variable
    to a literal program name (`$HOME/.local/bin/ruff`, `"$VIRTUAL_ENV/bin/python"`) that is not git, gh or a shell."""
    if not _expands(raw):
        return False
    slash = _last_slash(raw)  # a `/` inside `${x/a/b}`, `${x##*/}` or `$(…)` is not a folder's end
    return slash <= 0 or _expands(raw[slash + 1 :]) or name in _RUNS_TEXT


def _last_slash(raw: str) -> int:
    """The index of the last `/` in a raw word outside `${…}`, `$(…)` and backticks (escapes skipped), or -1."""
    depth, tick, last, i = 0, False, -1, 0
    while i < len(raw):
        c = raw[i]
        if c == "\\":
            i += 1
        elif c == "`":
            tick = not tick
        elif raw.startswith(("${", "$("), i):
            depth, i = depth + 1, i + 1
        elif depth and c in "})":
            depth -= 1
        elif c == "/" and not depth and not tick:
            last = i
        i += 1
    return last


def _git_sub_at(words: list[str]) -> int | None:
    """The index of git's sub-command in `words` (`words[0]` is git), after its global options."""
    i = 1
    while i < len(words) and words[i].startswith("-"):
        i += 2 if words[i] in _GIT_VALUE_OPTS else 1
    return i if i < len(words) else None


def _git_alias_views(words: list[str], sub: int | None) -> list[str]:
    """`git <value>` for each alias the git command defines: `-c alias.X=V` before the sub-command, or `git config …
    alias.X V` (a value starting with `!` is a shell command)."""
    values: list[str] = []
    for k in range(1, sub if sub is not None else len(words)):
        word, prev = words[k], words[k - 1]
        setting = word if prev == "-c" else word[2:] if word.startswith("-c") and word != "-c" else ""
        key, _, value = setting.partition("=")
        if key.lower().startswith("alias.") and value:
            values.append(value)
    if sub is not None and words[sub] == "config":
        rest = words[sub + 1 :]
        values += [rest[k + 1] for k in range(len(rest) - 1) if rest[k].lower().startswith("alias.")]
    return [v[1:] if v.startswith("!") else f"git {v}" for v in values]


def _segment_view(pairs: list[tuple[str, str]]) -> tuple[list[str], bool]:
    """(the texts the patterns read for one segment — its words joined, the command word by its program name,
    plumbing push forms as `git push`, aliases it defines —, whether the hook cannot resolve what it runs: a command
    word or git/gh sub-command that expands at run time (`_unresolved_word`), a shell function defined, a shell
    reading its script from stdin or a redirection, `find -exec`/`parallel` running git, gh or a shell, git
    configuration from `GIT_CONFIG_*` / `--config-env` / `-c alias.*`)."""
    if any(_GIT_CONFIG_RUNTIME.match(w) for _, w in pairs):
        return [], True
    k = 0
    while k < len(pairs) and _ASSIGNMENT.match(pairs[k][1]):
        k += 1
    declared = pairs[:k] + (pairs[k + 1 :] if k < len(pairs) and pairs[k][1] in _DECLARE else [])
    if any((m := _RUNS_LATER_ENV.fullmatch(w)) and not _PLAIN_VALUE.fullmatch(m.group(1)) for _, w in declared):
        return [], True  # `GIT_SSH_COMMAND='…' git fetch`, `export EDITOR='…'`: a command line run later
    if k >= len(pairs):
        return [], False
    raws = [r for r, _ in pairs[k:]]
    words = [re.sub(r"\s", "_", w) for _, w in pairs[k:]]  # a word with spaces stays one word (`-C "my dir"`)
    words[0] = os.path.basename(words[0]) or words[0]
    name = words[0]
    views = [" ".join(words)]
    unresolved = _unresolved_word(raws[0], name)
    if raws[0] == "function" or _FUNCTION_DEF.fullmatch(raws[0]) or raws[1:3] == ["(", ")"]:
        unresolved = True  # a function body runs with arguments only its call knows
    if name == "busybox" and len(words) > 1:
        name, words, raws = os.path.basename(words[1]), words[1:], raws[1:]
    unresolved = unresolved or _defines_or_sources(name, words, raws)
    unresolved = unresolved or (name not in _DATA_ARGS and _built_before_risky_sub(raws, words))
    if name in _COPIERS:  # a git, gh or shell binary under a new name (`ln -s /usr/bin/git g`) runs unseen
        operands = [w for w in words[1:] if not w.startswith("-")]
        sources = operands[:-1] if len(operands) > 1 else operands
        unresolved = unresolved or any(os.path.basename(w) in _RUNS_TEXT for w in sources)
    if name in _SHELL_NAMES:  # a shell with no script reads it from stdin (`… | sh`, `bash <<< …`, `sh /dev/stdin`)
        operands = [w for w in words[1:] if not w.startswith("-") or w in _SHELL_INFO]
        unresolved = unresolved or not operands or operands[0] in _STDIN_SCRIPT
        unresolved = unresolved or any(r.startswith("<") or (r[:1].isdigit() and "<" in r) for r in raws[1:])
    elif name == "git":
        sub = _git_sub_at(words)
        unresolved = unresolved or (sub is not None and _expands(raws[sub]))
        unresolved = unresolved or any(w.startswith("--config-env") for w in words[1:sub])
        if sub is not None and (
            words[sub] in _PUSH_PLUMBING or (words[sub] in _PUSH_TOOLS and "push" in words[sub + 1 : sub + 2])
        ):
            views.append("git push " + " ".join(words[sub + 1 :]))
        unresolved = unresolved or bool(_git_alias_views(words[:sub], None))  # `git -c alias.X=… X`
        unresolved = unresolved or _git_runs_later([w for _, w in pairs[k:]][:sub])  # `-c core.sshCommand='…'`
        views += _git_alias_views(words, sub)
    elif name == "gh":
        subs = [r for r, w in zip(raws[1:], words[1:], strict=False) if not w.startswith("-")][:2]
        subs = subs[:1] if subs[:1] == ["api"] else subs  # `gh api repos/{owner}/…`: an endpoint, not a command
        unresolved = unresolved or any(_expands(r) for r in subs)
    elif name == "find":
        execs = [k + 1 for k, w in enumerate(words[:-1]) if w in _FIND_EXEC]
        for k in execs:
            end = next((e for e in range(k, len(words)) if words[e] in (";", "+")), len(words))
            unresolved = unresolved or _runs_unread(words[k:end])
    elif name == "parallel":
        unresolved = unresolved or any(os.path.basename(w) in _RUNS_TEXT for w in words[1:])
    return views, unresolved


# git / gh sub-commands that change a remote or history: after a word built at run time (`setsid $(echo git) push`)
_RISKY_SUBS = frozenset(
    {"push", "send-pack", "http-push", "subtree", "lfs", "merge", "rebase", "reset", "clean", "commit", "tag", "am"}
    | {"cherry-pick", "pr", "release", "api", "issue"}
)


def _built_before_risky_sub(raws: list[str], words: list[str]) -> bool:
    """After the command word, a word built at run time (`$X`, `${X}`, `$(…)`, backticks; not `NAME=…`, not an option)
    whose next word — git's global options skipped — is a risky git/gh sub-command (`_RISKY_SUBS`): the word may be git
    or gh. A `$(…)` split into several raw words by its spaces counts as one."""
    k = 1
    while k < len(raws):
        raw = raws[k]
        if not _built_at_run_time(raw) or _ASSIGNMENT.match(raw) or words[k].startswith("-"):
            k += 1
            continue
        depth, ticks = raw.count("(") - raw.count(")"), raw.count("`") % 2
        while (depth > 0 or ticks) and k + 1 < len(raws):  # the rest of a `$(echo git)` the spaces split
            k += 1
            depth += raws[k].count("(") - raws[k].count(")")
            ticks = (ticks + raws[k].count("`")) % 2
        rest = ["git", *words[k + 1 :]]
        sub = _git_sub_at(rest)
        if sub is not None and rest[sub] in _RISKY_SUBS:
            return True
        k += 1
    return False


def _git_runs_later(options: list[str]) -> bool:
    """git's `-c key=value` options set a command line run later (`_RUNS_LATER_KEY` with a value not one plain word)."""
    for k in range(1, len(options)):
        word, prev = options[k], options[k - 1]
        setting = word if prev == "-c" else word[2:] if word.startswith("-c") and word != "-c" else ""
        key, _, value = setting.partition("=")
        if _RUNS_LATER_KEY.fullmatch(key.lower()) and not _PLAIN_VALUE.fullmatch(value):
            return True
    return False


def _defines_or_sources(name: str, words: list[str], raws: list[str]) -> bool:
    """The segment changes what a later word runs, or runs text the hook does not read: `alias X=…`, `hash -p`,
    `enable` with arguments, `gh alias set/import`, `su` (its string or stdin runs in a shell), `source`/`.` of anything
    but a plain file path (no operand, stdin, `/dev/fd/*`, `<(…)`, a path that expands)."""
    if name == "alias":
        return any("=" in w for w in words[1:])
    if name == "hash":
        return "-p" in words[1:]
    if name == "enable":
        return any(w not in ("-a", "-p", "-s") for w in words[1:])
    if name == "su":
        return True
    if name == "gh":
        subs = [w for w in words[1:] if not w.startswith("-")][:2]
        return subs[:1] == ["alias"] and subs[1:] != ["list"]
    if name in _SOURCE:
        if len(words) < 2:
            return True
        word, raw = words[1], raws[1]
        return (
            word in _STDIN_SCRIPT
            or word.startswith(("/dev/fd/", "/proc/"))
            or raw.startswith(("<(", ">("))
            or _unresolved_word(raw, os.path.basename(word))
        )
    return False


@functools.lru_cache(maxsize=16)
def _risk_analysis(command: str) -> tuple[tuple[str, ...], bool]:
    """((the command as written, its `_views`, each segment as the shell runs it), whether the hook cannot resolve
    what the command runs — `_segment_pairs`' and `_segment_view`'s fail-safe). Cached: `is_risky`, `reason_for`
    and `scopes` read one command several times. Never raises (a string the tokenizer cannot read keeps the written
    views)."""
    views = [command, *_views(command)]
    unresolved: list[str] = []
    local: dict[str, str] = {}
    try:
        for pairs in _segment_pairs(command, unresolved=unresolved):
            seg_views, seg_unresolved = _segment_view(pairs)
            views += seg_views
            if seg_unresolved or _unnamed_target(pairs, local):
                unresolved.append("segment")
            local.update(_assigned(pairs))
    except Exception:  # noqa: BLE001, S110 — the written views above still count
        pass
    return tuple(dict.fromkeys(views)), bool(unresolved)


def risk_views(command: str) -> tuple[str, ...]:
    """The texts the approval patterns read for `command`: as written first, then without quotes and as the shell
    runs each segment."""
    return _risk_analysis(command)[0]


def _message_files(words: list[str]) -> list[str]:
    """The message / PR text files one segment names, as written (`-` and `@-` = stdin): `-F`, `--file`,
    `--body-file`, `--input`, gh api's `-F`/`-f`/`--field`/`--raw-field key=@file`."""
    files: list[str] = []
    for i, word in enumerate(words):
        nxt = words[i + 1] if i + 1 < len(words) else None
        if word in _FIELD_FLAGS and nxt is not None and "=@" in nxt:
            files.append(nxt.split("=@", 1)[1])
        elif word.startswith(("--field=", "--raw-field=")) and "=@" in word.split("=", 1)[1]:
            files.append(word.split("=@", 1)[1])
        elif word in _FILE_FLAGS and nxt is not None and "=" not in nxt:
            files.append(nxt)
        elif word.startswith(("--file=", "--body-file=", "--input=")):
            files.append(word.split("=", 1)[1])
    return files


def _git_sub(words: list[str]) -> str | None:
    """git's sub-command in one segment (`git -C x am` → `am`), None for any other command."""
    words = _command_words(words)
    if not words or os.path.basename(words[0]) != "git":
        return None
    at = _git_sub_at(words)
    return words[at] if at is not None else None


def _command_identities_and_files(command: str) -> tuple[list[str], list[tuple[str, bool]]]:
    """([the agent identities the command sets: `--author`, `-c user.name/email`, `GIT_AUTHOR_*` / `GIT_COMMITTER_*`
    (also `export`ed), `git config user.*`], [(message file, read anywhere)]: a `git commit/merge/pull` file is read
    only inside the checkout (the commit-msg hook reads it too); a PR text or hook-less plumbing file anywhere
    (F-20-88, H1-3/H1-4); `git am` patches are read by `_am_findings`)."""
    found: list[str] = []
    files: list[tuple[str, bool]] = []
    for words in _token_lists(command):
        anywhere = _git_sub(words) not in ("commit", "merge", "pull")
        files += [(name, anywhere) for name in _message_files(words) if name not in ("-", "")]
        for i, word in enumerate(words):
            nxt = words[i + 1] if i + 1 < len(words) else None
            # (kind, value checked, text shown)
            hit: tuple[str, str, str] | None = None
            if m := _IDENT_ENV.match(word):
                hit = ("email" if m.group(2) == "EMAIL" else "name", m.group(3), word)
            elif word == "-c" and nxt is not None and (u := _USER_KEY.match(nxt)):
                hit = (u.group(1).lower(), u.group(2), nxt)
            elif word.startswith("-c") and (u := _USER_KEY.match(word[2:])):
                hit = (u.group(1).lower(), u.group(2), word[2:])
            elif word == "--author" and nxt is not None:
                hit = ("person", nxt, nxt)
            elif word.startswith("--author="):
                hit = ("person", word[len("--author=") :], word[len("--author=") :])
            elif word.lower() in ("user.name", "user.email") and "config" in words[:i] and nxt is not None:
                hit = (word.lower()[len("user.") :], nxt, f"{word} {nxt}")
            if hit is not None and _is_agent_value(hit[0], hit[1]) and hit[2] not in found:
                found.append(hit[2])
    return found, files


def _read_file(path: str, cwd: Path, root: Path | None = None, whole: bool = False) -> str | None:
    """The text of a file the command names (relative to `cwd`; a regular file only — never a FIFO or a device),
    read locally and never sent; None when it cannot be read, lies outside `root` (links resolved) when `root` is
    given, or (`whole`) is larger than the cap."""
    try:
        full = Path(os.path.realpath(os.path.join(str(cwd), os.path.expanduser(path))))
        if root is not None:
            full.relative_to(os.path.realpath(str(root)))
        if not full.is_file() or (whole and full.stat().st_size > _MAX_FILE):
            return None
        with full.open("rb") as f:
            return f.read(_MAX_FILE).decode("utf-8", errors="replace")
    except (OSError, ValueError):
        return None


# --- F-20-88 (H1-3): `git am` patches, and commit text an agent's hook cannot read ------------------------------------

_AM_STATE = frozenset(
    {"--continue", "--skip", "--abort", "--quit", "--resolved", "-r", "--show-current-patch", "--retry"}
)
_AM_VALUE_OPTS = frozenset(
    {"-p", "-C", "--exclude", "--include", "--directory", "--patch-format", "-S", "--whitespace"}
)
_MBOX_FROM = re.compile(r"^From \S+ .*$", re.MULTILINE)
_REDIRECT_WORD = re.compile(r"[0-9&]*(?:<<<|<<|<|>>|>\||>)")
_PATCH_END = re.compile(r"^(?:---[ \t]*$|diff --git |Index: )", re.MULTILINE)


def _am_patches(words: list[str]) -> list[str] | None:
    """The patch files of a `git am` segment ([] = stdin), None when it is no `git am` or only moves a running one."""
    words = _command_words(words)
    at = _git_sub_at(words) if words and os.path.basename(words[0]) == "git" else None
    if at is None or words[at] != "am" or any(w.split("=")[0] in _AM_STATE for w in words[at + 1 :]):
        return None
    out: list[str] = []
    rest = words[at + 1 :]
    i = 0
    while i < len(rest):
        word = rest[i]
        if word == "--":
            out += rest[i + 1 :]
            break
        if word.startswith("-"):
            i += 2 if word in _AM_VALUE_OPTS else 1
            continue
        if _REDIRECT_WORD.match(word):  # `git am < box`: stdin, not a patch file
            i += 1 if _REDIRECT_WORD.fullmatch(word) is None else 2
            continue
        out.append(word)
        i += 1
    return out


def _patch_findings(text: str) -> list[str]:
    """The markers in a mailbox of patches: each mail's `From:` (the author `git am` stores) and its message — the
    part before the `---` line or the diff; the diff itself is code."""
    found: list[str] = []
    for mail in _MBOX_FROM.split(text):
        head, _, body = mail.lstrip("\n").partition("\n\n")
        message = _PATCH_END.split(body, maxsplit=1)[0]
        for line in (head + "\n" + message).splitlines():
            if line.lower().startswith("from:"):
                name, email, _ = _parse_person(line[5:])
                if is_agent_identity(name, email):
                    found.append(f"From: {_clip(line[5:])}")
        found += text_findings(head + "\n" + message)
    return list(dict.fromkeys(found))


UNCHECKED_REFUSAL = (
    "Flowmode: an agent's commit or PR text must be one Flowmode can read — {why}. Put the text in the command or in a"
    " file, or ask a person to run it."
)
_FILTER_BRANCH_TEXT = ("--msg-filter", "--env-filter", "--commit-filter")
_FILTER_REPO_TEXT = (
    "--message-callback",
    "--replace-message",
    "--name-callback",
    "--email-callback",
    "--commit-callback",
    "--mailmap",
    "--use-mailmap",
)


def _unchecked_in(words: list[str], cwd: Path) -> str | None:
    sub = _git_sub(words)
    rest = words[words.index(sub) + 1 :] if sub is not None and sub in words else []
    if sub == "am":
        patches = _am_patches(words)
        if patches is not None and not patches:
            return "git am reads its patches from standard input; name the patch files"
        for name in patches or []:
            if _read_file(name, cwd, whole=True) is None:
                return f"git am cannot be checked: {_clip(name)} is not a readable file under 256 KiB"
    elif sub == "filter-branch" and any(w.split("=")[0] in _FILTER_BRANCH_TEXT for w in rest):
        return "git filter-branch runs a program that writes commit messages or authors"
    elif sub == "filter-repo" and any(w.split("=")[0] in _FILTER_REPO_TEXT for w in rest):
        return "git filter-repo runs code that writes commit messages or authors"
    elif sub == "fast-import":
        return "git fast-import reads commits from standard input"
    elif sub == "replace" and any(w in ("--edit", "-e") for w in rest):
        return "git replace --edit writes an object in an editor"
    elif sub == "commit-tree" and not any(w in ("-m", "-F") or w.startswith(("-m", "-F")) for w in rest):
        return "git commit-tree reads its message from standard input"
    for name in _message_files(words) if sub not in ("commit", "merge", "pull") else []:
        if name in ("-", ""):
            return "the text comes from standard input"
        if _read_file(name, cwd, whole=True) is None:
            return f"{_clip(name)} is not a readable file under 256 KiB"
    return None


def unchecked_commit_text(command: str, cwd: Path) -> str | None:
    """F-20-88 (H1-3, H1-4): why an agent's command stores a commit or PR text no check can read, or None —
    `git am` from stdin or an unreadable patch, `filter-branch`/`filter-repo` message or author programs,
    `fast-import`, `replace --edit`, `commit-tree` from stdin, a PR/plumbing text file that is stdin or unreadable.
    `git commit/merge/pull` pass (their commit-msg hook reads the text). Only the agent hook asks: a person keeps
    `git am`. Never raises."""
    try:
        if not attribution_scope(command):
            return None
        for words in _token_lists(command):
            if (why := _unchecked_in(words, Path(cwd))) is not None:
                return why
    except Exception:  # noqa: BLE001 — a string the tokenizer cannot read is no finding; the text checks still ran
        return None
    return None


def attribution_findings(command: str, cwd: Path, root: Path | None = None) -> list[str]:
    """What in a shell command would name an agent as commit author/co-author or in a PR text (L-6 (b)): markers in
    the command text (quoted, heredoc, ANSI-C — every view), identities set by flag, `-c` or environment, the text of
    `-F`/`--file` files of `git commit/merge/pull` inside `root` (default `cwd`), of PR text and plumbing files
    anywhere (F-20-88), and `git am` patches (author and message). [] for a command out of scope. Never raises: a
    part that cannot be read is skipped, the text markers still count."""
    if not attribution_scope(command):
        return []
    found: list[str] = []
    for view in _views(command):
        found += [f for f in text_findings(view, command=True) if f not in found]
    try:
        identities, files = _command_identities_and_files(command)
        found += [shown for shown in identities if shown not in found]
        for name, anywhere in files:
            text = _read_file(name, cwd, None if anywhere else (root or cwd))
            if text is not None:
                found += [f for f in text_findings(text) if f not in found]
        for words in _token_lists(command):
            for name in _am_patches(words) or []:
                if (text := _read_file(name, cwd)) is not None:
                    found += [f for f in _patch_findings(text) if f not in found]
    except Exception:  # noqa: BLE001, S110 — best effort: the markers found in the text above still refuse
        pass
    return found


def attribution_refusal(found: list[str]) -> str:
    return ATTRIBUTION_REFUSAL.format(found=", ".join(f'"{_clip(f)}"' for f in found))


# a line of `git commit -v`'s staged diff (after the cut line): a header, a hunk line, or a context/added/removed line
_DIFF_LINE = re.compile(r"diff --git |index |--- |\+\+\+ |@@ |[ +\-]|\\ No newline")
_STRIPPING = ("default", "strip")


def _message_git_stores(message: str, comment: str | None, editor: bool, cleanup: str | None) -> str:
    """The lines of the commit-msg hook's file git may store (F-20-88, H1-2; real git probed per mode: the hook sees the
    file before git's cleanup). Without an editor git's default cleanup is `whitespace`: every line is kept, so every
    line is checked (a `--cleanup` flag is not visible to the hook — when unsure, all lines). With an editor and the
    default/`strip` cleanup (`commit.cleanup`), comment lines go; nothing is cut at the scissors line unless `-v`, and
    `-v` puts the staged diff after it, so after the first cut line only diff lines (and stripped comments) are
    skipped. `comment`: core.commentChar/commentString; None = `auto`."""
    lines = message.splitlines()
    chars = [comment] if comment else list(_AUTO_COMMENT)
    cut = next((i for i, line in enumerate(lines) if any(line == c + _CUT_LINE for c in chars)), None)
    if cut is not None:
        comment = comment or lines[cut][0]
    comment = comment or "#"
    strips = editor and (cleanup or "default").lower() in _STRIPPING
    head, tail = (lines, []) if cut is None else (lines[:cut], lines[cut + 1 :])
    if editor:
        tail = [line for line in tail if not _DIFF_LINE.match(line)]
    return "\n".join(line for line in head + tail if not (strips and line.startswith(comment)))


def commit_msg_findings(
    message: str,
    idents: list[tuple[str, str]],
    comment: str | None = "#",
    *,
    editor: bool = True,
    cleanup: str | None = None,
) -> list[str]:
    """`flowmode check commit-msg`: the markers in the message git may store (`_message_git_stores`: `editor` — git
    ran an editor, i.e. GIT_EDITOR is not `:`; `cleanup` — commit.cleanup) and the author/committer identities
    [(role, "Name <email>")] that name an agent."""
    found = text_findings(_message_git_stores(message, comment, editor, cleanup))
    for role, ident in idents:
        name, email, _ = _parse_person(ident)
        if is_agent_identity(name, email):
            found.append(f"{role}: {_clip(ident)}")
    return found


# --- S20 L-6: an agent's commit keeps the team's git hooks on -----------------------------------------------------------

HOOKS_ON_REFUSAL = "Flowmode: agents commit with the team's git hooks on."
# git's global options that take the next word as their value (when written without `=`)
_GIT_VALUE_OPTS = frozenset({"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env", "--exec-path"})
# `git commit` options that take the next word as their value (when written without `=`)
_COMMIT_VALUE_OPTS = frozenset(
    {
        "-m",
        "--message",
        "-F",
        "--file",
        "-c",
        "--reedit-message",
        "-C",
        "--reuse-message",
        "-t",
        "--template",
        "--author",
        "--date",
        "--fixup",
        "--squash",
        "--trailer",
        "--cleanup",
        "--pathspec-from-file",
    }
)
_COMMIT_SHORT_WITH_VALUE = "mFcCtuS"  # in a cluster (`-am msg`), the rest of the word or the next word is the value


def _skips_hooks_in(words: list[str]) -> str | None:
    """The word in one `git … commit …` that turns the commit-msg hook off: `--no-verify` (or an unambiguous
    abbreviation), `-n` (also in a cluster like `-an`), `-c core.hooksPath=…` / `--config-env core.hooksPath=…`
    before `commit`, `GIT_CONFIG_*` naming core.hooksPath. None for any other command."""
    git = next((i for i, w in enumerate(words) if os.path.basename(w) == "git"), None)
    if git is None:
        return None
    for word in words[:git]:  # GIT_CONFIG_KEY_0=core.hooksPath / GIT_CONFIG_PARAMETERS="'core.hookspath'=…"
        if word.startswith("GIT_CONFIG_") and "core.hookspath" in word.lower():
            return word
    i = git + 1
    while i < len(words) and words[i].startswith("-"):
        word = words[i]
        value = words[i + 1] if word in _GIT_VALUE_OPTS and i + 1 < len(words) else word.partition("=")[2]
        if word in ("-c", "--config-env") or word.startswith(("-c", "--config-env=")):
            if word.startswith("-c") and word != "-c":
                value = word[2:]
            if value.lower().startswith("core.hookspath"):
                return f"{word} {value}" if word in _GIT_VALUE_OPTS else word
        i += 2 if word in _GIT_VALUE_OPTS else 1
    if i < len(words) and words[i] in ("merge", "pull"):  # their `-n` is --no-stat; only the full word skips hooks
        return next((w for w in words[i + 1 :] if w == "--no-verify"), None)
    if i >= len(words) or words[i] != "commit":
        return None
    i += 1
    while i < len(words):
        word = words[i]
        if word == "--":
            break
        if word.startswith("--"):
            name = word.partition("=")[0]
            if len(name) >= len("--no-veri") and "--no-verify".startswith(name):
                return word
            i += 2 if name in _COMMIT_VALUE_OPTS and "=" not in word else 1
            continue
        if word.startswith("-") and len(word) > 1:
            for k, ch in enumerate(word[1:], start=1):
                if ch == "n":
                    return word
                if ch in _COMMIT_SHORT_WITH_VALUE:
                    # a value glued to it (`-mfix`) or the next word (`-am fix`); `-u`/`-S` take only a glued one
                    i += 1 if k + 1 < len(word) or ch in "uS" else 2
                    break
            else:
                i += 1
            continue
        i += 1
    return None


def skips_git_hooks(command: str) -> str | None:
    """S20 L-6: the word in a `git commit` command that would skip the commit-msg check, or None. Git aliases are
    not expanded (the commit-msg layer catches what they create). Never raises."""
    try:
        for words in _token_lists(command):
            if (found := _skips_hooks_in(words)) is not None:
                return found
    except Exception:  # noqa: BLE001 — a string the tokenizer cannot read is no finding; the git hook still runs
        return None
    return None


# --- S20 part 2 F-20-81: an agent never switches the team's commit-msg check off -------------------------------------

HOOKS_GUARD_REFUSAL = (
    "Flowmode: the commit-msg check belongs to the team — an agent does not switch it off. Ask a person to change it"
    " from their own terminal."
)
# the first look, on the command without quotes and backslashes: none of these words, no finding (most commands)
# searched in the lower-cased command (a case-insensitive alternation is 4x slower on a long command)
_GUARD_HINT = re.compile(r"husky|pre.commit|alias\.|hooks|config|commit-msg|include|find")
_UNQUOTE = re.compile(r"[\"'\\]")
_GIT_CONFIG_ENV = re.compile(r"^GIT_CONFIG\w*=")
_GIT_CONFIG_FILE_ENV = re.compile(r"^GIT_CONFIG_(?:GLOBAL|SYSTEM)=(.+)", re.DOTALL)
_INCLUDE_KEY = re.compile(r"^(?:include|includeif\..+)\.path$", re.IGNORECASE)
# `git config` forms that only read
_CONFIG_READS = frozenset(
    {"--get", "--get-all", "--get-regexp", "--get-urlmatch", "--get-color", "--get-colorbool", "-l", "--list"}
)
_CONFIG_READ_VERBS = frozenset({"get", "list"})
# … and the ones that remove: core.hooksPath's removal is refused too (install skips its hook while hooksPath is set,
# so in a husky team removing it switches the check off)
_CONFIG_REMOVALS = frozenset(
    {"--unset", "--unset-all", "--remove-section", "--rename-section", "unset", "remove-section", "rename-section"}
)
_CONFIG_VALUE_OPTS = frozenset({"-f", "--file", "--blob", "--type", "--default", "--comment", "--value"})
_CONFIG_EDIT = "git config --edit"
_JS_RUNNERS = frozenset({"npx", "pnpx", "bunx", "pnpm", "yarn", "npm", "bun"})
_HUSKY = frozenset({"husky", "husky-init"})
_GIT_CONFIG_FILES = ("config", "config.worktree")


def _command_words(words: list[str]) -> list[str]:
    """The words from the command itself on: `VAR=…` assignments and runners (`sudo`, `env`, `exec`, …) dropped."""
    i = 0
    while i < len(words) and (("=" in words[i] and not words[i].startswith("-")) or words[i] in _RUNNERS):
        i += 1
    return words[i:]


def _alias_skips(value: str) -> bool:
    """An alias text that commits or merges without the hooks: `--no-verify` (or an abbreviation of it), or `-n` in a
    short-option word together with `commit` (`!git commit -n`, `commit -nm x`) — merge's `-n` is --no-stat."""
    from flowmode.shellwrites import split

    text = value.lstrip("!")
    try:
        words = split(text)
    except ValueError:
        words = text.split()
    for word in words:
        name = word.partition("=")[0]
        if len(name) >= len("--no-veri") and "--no-verify".startswith(name):
            return True
    short_n = any(w.startswith("-") and not w.startswith("--") and "n" in w[1:] for w in words)
    return short_n and "commit" in words


def _names_hooks_path(path: str, cwd: Path) -> bool:
    """The config file `path` (relative to `cwd`) exists and names hooksPath; `/dev/null` and a missing file do not."""
    try:
        full = Path(os.path.join(str(cwd), os.path.expanduser(path)))
        if not full.is_file():
            return False
        with full.open("rb") as f:
            return b"hookspath" in f.read(_MAX_FILE).lower()
    except OSError:
        return False


def _config_tamper(args: list[str]) -> str | None:
    """`git config <args>` that writes or removes core.hooksPath (or removes/renames the core section), writes an
    `include.path`/`includeIf.*.path`, or an alias that skips the hooks; `_CONFIG_EDIT` for the editor form (judged by
    the caller); None for reads and every other key."""
    flags: list[str] = []
    ops: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            ops += args[i + 1 :]
            break
        if arg.startswith("-") and len(arg) > 1:
            flags.append(arg.partition("=")[0])
            i += 2 if arg in _CONFIG_VALUE_OPTS else 1
            continue
        ops.append(arg)
        i += 1
    if any(f in _CONFIG_READS for f in flags) or (ops and ops[0] in _CONFIG_READ_VERBS):
        return None
    removal = next((f for f in flags if f in _CONFIG_REMOVALS), None)
    if ops and ops[0] in _CONFIG_REMOVALS:
        removal, ops = ops[0], ops[1:]
    if removal is not None:
        key = ops[0].lower() if ops else ""
        if key == ("core" if removal.endswith("section") else "core.hookspath"):
            return f"git config {removal} {ops[0]}"
        return None
    if "-e" in flags or "--edit" in flags or (ops and ops[0] == "edit"):
        return _CONFIG_EDIT
    if ops and ops[0] == "set":
        ops = ops[1:]
    if len(ops) < 2:  # `git config core.hooksPath` alone prints the value
        return None
    key = ops[0].lower()
    if (
        key == "core.hookspath"
        or _INCLUDE_KEY.match(key)
        or (key.startswith("alias.") and _alias_skips(" ".join(ops[1:])))
    ):
        return f"git config {ops[0]}"
    return None


def _git_tamper(words: list[str], cwd: Path) -> str | None:
    """One git command: `-c`/`--config-env` setting core.hooksPath (any sub-command), a hook-skipping alias or an
    include of a config file that names hooksPath, or `git config` writing one."""
    words = _command_words(words)
    if not words or os.path.basename(words[0]) != "git":
        return None
    i = 1
    while i < len(words) and words[i].startswith("-"):
        word = words[i]
        takes = word in _GIT_VALUE_OPTS
        value = words[i + 1] if takes and i + 1 < len(words) else word.partition("=")[2]
        if word.startswith("-c") and word != "-c":
            value = word[2:]
        if word in ("-c", "--config-env") or word.startswith(("-c", "--config-env=")):
            key, _, setting = value.partition("=")
            key = key.lower()
            if (
                key == "core.hookspath"
                or (key.startswith("alias.") and _alias_skips(setting))
                or (_INCLUDE_KEY.match(key) and _names_hooks_path(setting, cwd))
            ):
                return f"{word} {value}" if takes else word
        i += 2 if takes else 1
    if i < len(words) and words[i] == "config":
        return _config_tamper(words[i + 1 :])
    return None


def _husky(words: list[str]) -> str | None:
    """husky (`husky`, `husky install`, `npx husky init`, `pnpm dlx husky-init`, `yarn husky`): it sets core.hooksPath."""
    words = _command_words(words)
    if not words:
        return None
    if os.path.basename(words[0]).split("@")[0] in _HUSKY:
        return words[0]
    if os.path.basename(words[0]) not in _JS_RUNNERS:
        return None
    for word in words[1:]:
        if word.startswith("-") or word in ("exec", "dlx", "x"):
            continue
        return word if os.path.basename(word).split("@")[0] in _HUSKY else None
    return None


def _pre_commit_msg(words: list[str]) -> str | None:
    """`pre-commit install` taking the commit-msg hook (`-t commit-msg`, `--hook-type[=]commit-msg`); the plain
    install writes only the pre-commit hook and passes."""
    at = next((k for k, w in enumerate(words) if os.path.basename(w) in ("pre-commit", "pre_commit")), None)
    if at is None or "install" not in words[at + 1 :]:
        return None
    rest = words[at + 1 :]
    for k, word in enumerate(rest):
        if word in ("-t", "--hook-type") and k + 1 < len(rest) and rest[k + 1] == "commit-msg":
            return f"pre-commit install {word} commit-msg"
        if word in ("--hook-type=commit-msg", "-tcommit-msg"):
            return f"pre-commit install {word}"
    return None


def _is_git_dir(path: Path) -> bool:
    return path.name == ".git" or (
        (path / "HEAD").is_file() and ((path / "objects").is_dir() or (path / "commondir").is_file())
    )


_CASE_BLIND: dict[int, bool] = {}  # st_dev → the volume ignores case (asked once per volume)


def _existing(path: str) -> str:
    """`path` itself or its nearest ancestor that exists."""
    while not os.path.lexists(path) and os.path.dirname(path) != path:
        path = os.path.dirname(path)
    return path


def _case_blind(path: str | Path) -> bool:
    """F-20-107 (review round 2): the volume holding `path` (its nearest existing ancestor) treats `A` and `a` as one
    name — macOS's APFS by default. Asked once per volume: `pathconf(_PC_CASE_SENSITIVE)` on macOS, else the path with
    its letters' case swapped naming the same file. Never raises (an unknown volume counts as case-sensitive)."""
    try:
        probe = _existing(os.path.abspath(str(path)))
        dev = os.stat(probe).st_dev
        if dev not in _CASE_BLIND:
            try:
                if sys.platform != "darwin":
                    raise ValueError("no _PC_CASE_SENSITIVE")  # noqa: TRY301 — one fallback path
                blind = os.pathconf(probe, 11) == 0  # macOS _PC_CASE_SENSITIVE
            except (OSError, ValueError):
                swapped = probe.swapcase()
                blind = swapped != probe and os.path.exists(swapped) and os.path.samefile(swapped, probe)
            _CASE_BLIND[dev] = blind
        return _CASE_BLIND[dev]
    except OSError:
        return False


def _canon(path: str | Path) -> str:
    """`path` with its links resolved, and case-folded on a case-blind volume — the form two names of one file share
    there (`~/.CLAUDE/Settings.json` is `~/.claude/settings.json` on macOS). For comparing; the folded form still opens
    the file on such a volume."""
    real = os.path.realpath(path)
    return real.casefold() if _case_blind(real) else real


def _fold(word: str, where: str | Path | None) -> str:
    """A path word as letters, case-folded when the folder it is read from (`where`; `/` when unknown) is on a
    case-blind volume."""
    return word.casefold() if _case_blind(where if where is not None else os.sep) else word


_Spot = tuple[str, tuple[int, int] | None]


def _spot(path: str | Path) -> _Spot:
    """(`_canon(path)`, its (st_dev, st_ino) or None when it does not exist) — what `_inside` / `_is_spot` compare."""
    try:
        st = os.stat(path)
        ident = (st.st_dev, st.st_ino)
    except (OSError, ValueError):
        ident = None
    return _canon(path), ident


def _is_spot(path: str | Path, spots: list[_Spot]) -> bool:
    """`path` is one of `spots`: the same canonical name, or the same file."""
    canon, ident = _spot(path)
    return any(canon == c or (ident is not None and ident == i) for c, i in spots)


def _inside(path: str | Path, root: _Spot) -> bool:
    """`path` is the `root` spot or lies inside it — links resolved, case folded on a case-blind volume, and by file
    identity of `path`'s nearest existing ancestor and its parents, so no spelling of the folder gets past. Never
    raises."""
    try:
        top, want = root
        real = _canon(path)
        if real == top or real.startswith(top.rstrip(os.sep) + os.sep):
            return True
        if want is None:
            return False
        at = _existing(os.path.realpath(path))
        while True:
            st = os.stat(at)
            if (st.st_dev, st.st_ino) == want:
                return True
            if os.path.dirname(at) == at:
                return False
            at = os.path.dirname(at)
    except (OSError, ValueError):
        return False


def _same_path(a: str | Path | None, b: str | Path | None) -> bool:
    """`a` and `b` name one file or folder (links resolved, case folded on a case-blind volume, or the same inode)."""
    return a is not None and b is not None and _is_spot(a, [_spot(b)])


def _real(path: Path) -> Path:
    """The path with its folders' links resolved; the last part kept (a hook already linked to `true` is still the
    hook) — case-folded on a case-blind volume (`_canon`), so a name compares by what the disk opens."""
    parent = _canon(path.parent)
    return Path(parent) / (path.name.casefold() if _case_blind(parent) else path.name)


def _is_hook(path: Path) -> bool:
    return path.name == "commit-msg" and path.parent.name == "hooks" and _is_git_dir(path.parent.parent)


def _is_git_config(path: Path) -> bool:
    return path.name in _GIT_CONFIG_FILES and _is_git_dir(path.parent)


def _hooks_dir(cwd: Path) -> Path | None:
    """The folder git runs this checkout's hooks from (core.hooksPath honoured), links resolved; None when unknown.
    One local `git rev-parse` — called only for a `commit-msg` outside a git folder's `hooks` (rare)."""
    import subprocess

    try:
        out = subprocess.run(
            ["git", "-C", str(cwd), "rev-parse", "--git-path", "hooks"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    found = out.stdout.strip()
    if out.returncode != 0 or not found:
        return None
    return Path(os.path.realpath(os.path.join(str(cwd), found)))


_REMOVERS = frozenset({"rm", "unlink", "mv", "truncate", "shred", "trash", "rmtrash"})
_DESTRUCTIVE = _REMOVERS | {"cp", "ln", "install", "tee", "sed", "dd", "chmod"}
_INTO_OPS = frozenset({"tar -x", "unzip", "rsync", "cp -r"})  # what writes files into a folder (`-C`, `-d`, dest)
_DIR_OPS = frozenset({"rm", "mv", "chmod"}) | _INTO_OPS  # what takes a whole hooks folder away or rewrites it
_GLOB = "*?["
_DYNAMIC = "$`"
_CHMOD_FLAGS = set("RfvchHLP")
_CHMOD_CLAUSE = re.compile(r"([ugoa]*)((?:[-+=][rwxXstugo]*)+)")
_FIND_NAMES = frozenset({"-name", "-iname"})
_FIND_EXEC = frozenset({"-exec", "-execdir", "-ok", "-okdir"})
_MAX_BRACES = 64
_RSYNC_VALUE_OPTS = (
    "-e", "--rsh", "-f", "--filter", "--exclude", "--include", "--exclude-from", "--include-from", "--files-from",
    "-T", "--temp-dir", "--partial-dir", "--backup-dir", "--suffix", "--chmod", "--chown", "--log-file", "-M",
    "--remote-option", "--rsync-path", "--compare-dest", "--copy-dest", "--link-dest", "-B", "--block-size",
    "--timeout", "--port", "--password-file", "--bwlimit", "--max-size", "--min-size", "--out-format",
)  # fmt: skip
_URL = re.compile(r"[A-Za-z][\w+.-]*://")  # `s3://$B/`, `gs://…`: a remote target, not a local file
_VAR_REF = re.compile(r"\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)")
_DYNAMIC_PART = re.compile(r"\$\{[^}]*\}|\$\([^)]*\)?|`[^`]*`?|\$\w+|\$.?")


def _assigned(pairs: list[tuple[str, str]]) -> dict[str, str]:
    """The shell variables a segment sets for the segments after it: a segment of `NAME=value` words only, or
    `export`/`declare`/`local`/… `NAME=value`."""
    raws = [r for r, _ in pairs]
    if raws and all(_ASSIGNMENT.match(r) for r in raws):
        words = [w for _, w in pairs]
    elif raws and raws[0] in _DECLARE:
        words = [w for r, w in pairs[1:] if _ASSIGNMENT.match(r)]
    else:
        return {}
    return dict(w.split("=", 1) for w in words)


def _with_locals(word: str, local: dict[str, str]) -> str:
    """`word` with `$NAME` / `${NAME}` of the variables the command itself set (`D=.claude; rm $D/x`) filled in."""
    if "$" not in word or not local:
        return word
    return _VAR_REF.sub(lambda m: local.get(m.group(1) or m.group(2), m.group(0)), word)


def _could_name(base: str, names: tuple[str, ...]) -> bool:
    """A file name the hook cannot read (`$X`, `${X}.json`, backticks) whose literal tail could end one of `names`."""
    tail = _DYNAMIC_PART.split(base)[-1]
    return bool(tail) and any(n.endswith(tail) for n in names)


def _base(word: str) -> str:
    return posixpath.basename(word.rstrip("/")) or word


def _unnamed_target(pairs: list[tuple[str, str]], local: dict[str, str]) -> bool:
    """A write/remove/move target (redirection, `shellwrites._command_targets`, unlink/shred) whose own name the hook
    cannot read (`$F`, `"$OUT"`, backticks; variables the command set are filled in): it may be a protected file."""
    from flowmode.shellwrites import _command_targets, _operands, _redirections

    own, redirected = _redirections(pairs, every_fd=True)
    names = _command_words(own)
    targets = list(redirected)
    if names:
        targets += [t for t, _ in _command_targets(names)]
        if os.path.basename(names[0]) in ("unlink", "shred"):
            targets += _operands(names[1:])
    return any(c in _base(_with_locals(t, local)) for t in targets if not _URL.match(t) for c in _DYNAMIC)


def _braces(word: str) -> list[str]:
    """`a{,.off}` → [`a`, `a.off`] (bash brace expansion, enough of it to see the names a command touches)."""
    m = re.search(r"\{([^{}]*,[^{}]*)\}", word)
    if m is None:
        return [word]
    out: list[str] = []
    for part in m.group(1).split(","):
        out += _braces(word[: m.start()] + part + word[m.end() :])
    return out[:_MAX_BRACES]


def _chmod_parts(args: list[str]) -> tuple[str | None, list[str]]:
    """(the mode — None when `--reference` makes it unknown, the paths)."""
    ops: list[str] = []
    reference = False
    for arg in args:
        if arg.startswith("--"):
            reference = reference or arg.startswith("--reference")
            continue
        if not ops and len(arg) > 1 and arg[0] == "-" and set(arg[1:]) <= _CHMOD_FLAGS:
            continue
        ops.append(arg)
    if reference:
        return None, ops
    return (ops[0] if ops else ""), ops[1:]


def _chmod_removes_x(mode: str | None) -> bool:
    """The mode can take the owner's executable bit away (`-x`, `a=r`, `644`, unknown); adding it (`+x`, `755`) is
    the repair of a hook that is not executable, never a tamper."""
    if mode is None:
        return True
    if re.fullmatch(r"[0-7]{1,4}", mode):
        return not int(mode.zfill(4)[1]) & 1
    for clause in mode.split(","):
        m = _CHMOD_CLAUSE.fullmatch(clause)
        if m is None:
            return True
        who = m.group(1) or "a"
        if "u" not in who and "a" not in who:
            continue
        for op, perms in re.findall(r"([-+=])([rwxXstugo]*)", m.group(2)):
            has_x = "x" in perms or "X" in perms
            if (op == "-" and has_x) or (op == "=" and not has_x):
                return True
    return False


def _find_split(args: list[str]) -> tuple[list[str], list[str]]:
    """(the start folders, the expression) of a `find`'s arguments."""
    i = 0
    while i < len(args) and not args[i].startswith(("-", "(", "!")):
        i += 1
    return args[:i] or ["."], args[i:]


def _find_execs(expr: list[str]) -> list[list[str]]:
    """The commands of a find's `-exec`/`-execdir`/`-ok`/`-okdir` actions."""
    out: list[list[str]] = []
    for k, word in enumerate(expr):
        if word in _FIND_EXEC:
            cmd = []
            for x in expr[k + 1 :]:
                if x in (";", "+"):
                    break
                cmd.append(x)
            out.append(cmd)
    return out


def _find_destructive(expr: list[str], agent: bool = False) -> bool:
    """`-delete`, or an `-exec` that removes, moves, re-modes (git: only an x-removing chmod) or rewrites the files it
    finds; for the agent hooks (`agent`) also a copy, link or install onto `{}`, chflags, a shell (`sh -c '…'`, its
    text unread) and a `sed -i`."""
    from flowmode.shellwrites import _sed_targets

    if "-delete" in expr:
        return True
    for cmd in _find_execs(expr):
        verb = os.path.basename(cmd[0]) if cmd else ""
        if verb in _REMOVERS or (verb == "sed" and bool(_sed_targets([*cmd[1:], "{}"]))):
            return True
        if verb == "gio" and cmd[1:2] == ["trash"]:
            return True
        if verb == "chmod" and (agent or _chmod_removes_x(_chmod_parts(cmd[1:])[0])):
            return True
        if agent and (
            verb in ("chflags", "tee", "dd", "sh", "bash", "zsh", "dash", "ksh")
            or (verb in ("cp", "ln", "install", "rsync") and cmd[-1:] == ["{}"])
        ):
            return True
    return False


_FIND_PATHS = frozenset({"-path", "-wholename", "-ipath", "-iwholename"})
_FIND_REGEX = frozenset({"-regex", "-iregex"})
_FIND_TESTS = _FIND_NAMES | _FIND_PATHS | _FIND_REGEX


def _find_reaches(expr: list[str], starts: list[str], bases: tuple[str, ...], rels: tuple[str, ...]) -> bool:
    """A find's name tests can pick a file named one of `bases` at `<start>/<rel>` (or deeper): a `-name`/`-iname`
    glob matching the name (case-folded for `-iname`), a `-path`/`-wholename` glob matching the path or whose last
    part matches the name, a `-regex` matching the path; a negated, `$`-built or unreadable test counts; no test at
    all picks everything."""
    tests = [(k, expr[k], expr[k + 1]) for k in range(len(expr) - 1) if expr[k] in _FIND_TESTS]
    if not tests:
        return True
    for k, test, raw in tests:
        fold = test.startswith("-i")
        pat = raw.lower() if fold else raw
        if any(c in pat for c in _DYNAMIC) or (k > 0 and expr[k - 1] in ("!", "-not")):
            return True
        if test in _FIND_NAMES:
            if any(fnmatch.fnmatchcase(b, pat) for b in bases):
                return True
            continue
        paths = [posixpath.join(s, sub, r) for s in starts for r in rels for sub in ("", "x")]
        paths = [x.lower() for x in paths] if fold else paths
        if test in _FIND_PATHS:
            last = pat.rsplit("/", 1)[-1]
            if any(fnmatch.fnmatchcase(b, last) for b in bases) or any(fnmatch.fnmatchcase(x, pat) for x in paths):
                return True
        else:
            if any(t in pat for t in ("\\(", "\\)", "\\|", "\\{")):
                return True  # emacs/basic regex grammar: not read, so it may match
            try:
                rx = re.compile(pat, re.IGNORECASE if fold else 0)
            except re.error:
                return True
            if any(rx.fullmatch(x) for x in paths):
                return True
    return False


def _find_targets(args: list[str]) -> tuple[list[tuple[str, str]], bool]:
    """(what a `find … -delete` / `-exec rm …` takes away, whether its name tests can pick `commit-msg`); ([], False)
    for a find that only lists or adds the executable bit."""
    starts, expr = _find_split(args)
    names = [expr[k + 1] for k in range(len(expr) - 1) if expr[k] in _FIND_NAMES]
    if not _find_destructive(expr):
        return [], False
    named = _find_reaches(expr, starts, ("commit-msg",), (".git/hooks/commit-msg", ".husky/commit-msg"))
    if not names:
        return [(s, "rm") for s in starts], named and any(w in _FIND_TESTS for w in expr)  # the whole folder goes
    return [(posixpath.join(s, n), "find") for s in starts for n in names], named


_FIND_WALK = 2000  # folders a find's start is searched for `.claude`/`.codex` before it counts as holding one


def _find_start_holds_agent(start: str, eff: Path | None, maxdepth: int | None, walked: dict) -> bool:
    """A destructive find from `start` could reach an agent hooks file: the folder cannot be read (`$`, a glob, an
    unknown `cd`), it is a `.claude`/`.codex` folder, or one lies below it within `maxdepth` (searched on the disk,
    `.git` and `node_modules` skipped; a tree larger than `_FIND_WALK` folders counts as holding one; each folder
    searched once per command, `walked`)."""
    from flowmode.shellwrites import _resolve

    if any(c in start for c in _GLOB + _DYNAMIC):
        return True
    path = _resolve(eff, start)
    if path is None:
        return True
    real = Path(_canon(path))
    if real.name in _AGENT_FOLDERS:
        return True
    if not real.is_dir():
        return False
    if any((real / f).exists() for f in _AGENT_FOLDERS) and (maxdepth is None or maxdepth >= 2):
        return True
    if (real, maxdepth) not in walked:
        walked[(real, maxdepth)] = _walk_holds_agent(real, maxdepth)
    return walked[(real, maxdepth)]


def _walk_holds_agent(real: Path, maxdepth: int | None) -> bool:
    seen = 0
    for top, dirs, _ in os.walk(real):
        depth = len(Path(top).relative_to(real).parts)
        if maxdepth is not None and depth + 2 > maxdepth:
            dirs[:] = []
            continue
        if any(d in _AGENT_FOLDERS for d in dirs):
            return True
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
        seen += 1
        if seen > _FIND_WALK:
            return True
    return False


def _find_reaches_agent_hooks(args: list[str], eff: Path | None, walked: dict) -> str | None:
    """A destructive find (`_find_destructive`) whose name tests can pick an agent hooks file (`_find_reaches`) from
    a start folder that holds (or may hold) a `.claude`/`.codex` folder: `find . -name settings.json -delete`."""
    starts, expr = _find_split(args)
    if not _find_destructive(expr, agent=True):
        return None
    if not _find_reaches(expr, starts, _AGENT_FILE_NAMES, _AGENT_PATHS):
        return None
    depth = next((expr[k + 1] for k in range(len(expr) - 1) if expr[k] == "-maxdepth"), None)
    maxdepth = int(depth) if depth is not None and depth.isdigit() else None
    for start in starts:
        if _find_start_holds_agent(start, eff, maxdepth, walked):
            return f"find {start}"
    return None


def _destructive_targets(names: list[str], dynamic: bool) -> list[tuple[str, str]]:
    """The paths a removal/write/mode verb in one segment acts on, beyond `shellwrites._command_targets`: unlink,
    shred, chmod (only a mode that can remove x), ln, `<dest>/<source name>` of cp/mv/install/ln; in a segment with a
    `$(…)`/backticks, every word with a `/` or `hooks` in it (the substitution split the path into words)."""
    from flowmode.shellwrites import _TAKES_ARG, _operands

    head, args = os.path.basename(names[0]), names[1:]
    out: list[tuple[str, str]] = []
    if head in ("unlink", "shred"):
        out = [(a, head) for a in _operands(args, ("-n", "-s", "--iterations", "--size", "--random-source"))]
    elif head in ("trash", "rmtrash") or (head == "gio" and args[:1] == ["trash"]):
        out = [(a, "rm") for a in _operands(args[1:] if head == "gio" else args, ())]  # into the bin: gone too
    elif head == "chmod":
        mode, paths = _chmod_parts(args)
        if not _chmod_removes_x(mode):
            return []
        out = [(p, "chmod") for p in paths]
    elif head in ("cp", "mv", "install", "ln"):
        ops = _operands(args, _TAKES_ARG.get(head, ("-t", "--target-directory", "-S", "--suffix")))
        if len(ops) >= 2:
            out = [(posixpath.join(ops[-1], posixpath.basename(s.rstrip("/"))), head) for s in ops[:-1]]
            out += [(ops[-1], head)] if head == "ln" else []
        elif head == "ln" and ops:
            out = [(posixpath.basename(ops[0]), "ln")]
        recursive = any(
            a in ("--recursive", "--archive") or (a[:1] == "-" and a[1:2] != "-" and bool(set(a[1:]) & set("rRa")))
            for a in args
        )
        out += [(ops[-1], "cp -r")] if head == "cp" and recursive and len(ops) >= 2 else []
    elif head == "rsync":
        ops = _operands(args, _RSYNC_VALUE_OPTS)
        if len(ops) >= 2:
            dest = ops[-1]
            out = [(dest, "rsync")] + [(posixpath.join(dest, _base(s)), "rsync") for s in ops[:-1] if s[-1:] != "/"]
    elif head == "tar" and _tar_extracts(args):
        out = [(d, "tar -x") for d in _option_values(args, "C", "--directory")]
    elif head == "unzip":
        out = [(d, "unzip") for d in _option_values(args, "d", "-d")]
    elif head == "git":
        out = _git_path_targets(names)
    if dynamic and head in _DESTRUCTIVE:
        out += [(w, head) for w in args if "/" in w or "hooks" in w]
    return out


_CHECKOUT_VALUE_OPTS = frozenset({"-b", "-B", "--orphan", "--conflict", "-s", "--source", "--pathspec-from-file"})


def _git_path_targets(names: list[str]) -> list[tuple[str, str]]:
    """The paths `git checkout [<tree-ish>] [--] <paths…>` and `git restore [-s <tree-ish>] <paths…>` rewrite from
    another version (any git global options before the sub-command). Every operand counts — a branch name is never a
    hooks file, so a protected name decides without telling a revision from a path."""
    sub = _git_sub_at(names)
    if sub is None or names[sub] not in ("checkout", "restore"):
        return []
    from flowmode.shellwrites import _operands

    op = f"git {names[sub]}"
    out: list[tuple[str, str]] = []
    for word in _operands(names[sub + 1 :], tuple(_CHECKOUT_VALUE_OPTS)):
        spec = _pathspec(word) if word else None
        # the whole tree passes: an agent's everyday discard (lead, round 5). A documented limit like `git reset
        # --hard`: it can revert an uncommitted hook install in a tracked `.claude/settings.json`
        if spec is None or spec == ".":
            continue
        out.append((spec, op))
        if any(c in spec for c in _GLOB):  # git matches a pathspec glob itself, quoted or not, `*` across folders
            out += [(path, op) for path in _AGENT_PATHS if fnmatch.fnmatchcase(path, spec)]
    return out


def _pathspec(word: str) -> str | None:
    """A git pathspec's path with its magic dropped (`:(top,glob)x` → `x`, `:/x` → `x`, `./x` → `x`; the whole tree →
    `.`), None for an exclusion (`:!x`, `:^x`, `:(exclude)x`). `:/` and `:(top)` are read from the current folder."""
    if word.startswith(":("):
        magic, close, rest = word[2:].partition(")")
        if not close or "exclude" in magic.lower():
            return None
    elif word.startswith(":"):
        i = 1
        while i < len(word) and word[i] in "/!^":
            i += 1
        if set(word[1:i]) & {"!", "^"}:
            return None
        rest = word[i + 1 :] if word[i : i + 1] == ":" else word[i:]
    else:
        rest = word
    while rest.startswith("./"):
        rest = rest[2:]
    return rest if rest not in ("", ".") else "."


def _tar_extracts(args: list[str]) -> bool:
    first = args[0] if args else ""
    return (bool(first) and first[0] != "-" and "x" in first) or any(
        a in ("--extract", "--get") or (a[:1] == "-" and a[1:2] != "-" and "x" in a[1:]) for a in args
    )


def _target_hits(word: str, op: str, eff: Path | None, dynamic: bool, hooks_dir) -> bool:
    """`word` names the commit-msg hook (git's hooks folder, or the core.hooksPath folder — `hooks_dir()`, asked
    only when such a folder holds a commit-msg) or, for rm/mv/chmod, the hooks folder itself. A path that can be
    resolved is resolved (links in folders followed); one with `$`, backticks, a glob or an unknown directory is
    judged by its letters: `…/hooks/commit-msg`, `…/hooks/<glob matching commit-msg>` next to `$`/`.git`, `.git/hooks`."""
    from flowmode.shellwrites import _resolve

    text = _fold(word.rstrip(")").rstrip("/") or word, eff)  # F-20-107: `.GIT/HOOKS/COMMIT-MSG` on macOS
    parent, base = posixpath.split(text)
    pname = posixpath.basename(parent)
    moving = dynamic or any(c in text for c in _DYNAMIC)
    hook_name = fnmatch.fnmatchcase("commit-msg", base)
    if base == "commit-msg" and pname == "hooks" and (moving or eff is None):
        return True
    if base == "commit-msg" and (moving or (eff is None and not posixpath.isabs(text))):
        return True  # `rm $H/commit-msg`, `cd "$D" && rm commit-msg`: the folder cannot be read
    if any(c in base for c in _DYNAMIC) and _could_name(base, ("commit-msg",)):
        return True  # `rm .git/hooks/${N}msg`
    if moving and hook_name and fnmatch.fnmatchcase("hooks", pname):
        return True
    if op in _DIR_OPS and ((base == "hooks" and pname == ".git") or (moving and fnmatch.fnmatchcase("hooks", base))):
        return True
    if any(c in parent for c in _GLOB + _DYNAMIC):
        return False
    pdir = _resolve(eff, parent or ".")
    if pdir is None:
        return False
    real_parent = Path(_canon(pdir))
    if hook_name and (
        (real_parent.name == "hooks" and _is_git_dir(real_parent.parent))
        or (os.path.lexists(real_parent / "commit-msg") and _same_path(hooks_dir(), real_parent))
    ):
        return True
    if op in _DIR_OPS and not any(c in base for c in _GLOB + _DYNAMIC):
        full = Path(_canon(real_parent / base))
        if full.name == "hooks" and _is_git_dir(full.parent):
            return True
        if full.is_dir() and os.path.lexists(full / "commit-msg") and _same_path(hooks_dir(), full):
            return True
    return False


def _segment_targets(command: str, cwd: Path):
    """Per segment of the command, from the command each one runs, the last fixed `cd` known: (the paths it writes,
    removes, links or re-modes as [(word, op)] — redirections, `shellwrites._command_targets`, unlink/shred/chmod/ln,
    cp/mv/install destinations, tar `-C`/unzip `-d`/rsync/`cp -r` folders, `find … -delete|-exec` —, the directory
    then (None when unknown), whether the segment has `$(…)`/backticks, whether a `find` in it names `commit-msg`, the
    segment's command words, the variables earlier segments set)."""
    from flowmode.shellwrites import _cd_target, _command_targets, _is_glob_or_var, _redirections

    eff: Path | None = Path(cwd)
    local: dict[str, str] = {}
    outer: list[Path | None] = []
    redirected: list[str] = []
    made: set[Path] = set()
    for pairs in _segment_pairs(command, marks=True):
        if pairs is SUBSHELL_OPEN:
            outer.append(eff)
            continue
        if pairs is SUBSHELL_CLOSE:
            eff = outer.pop() if outer else eff
            if redirected:  # `(cd x; …) > f`: `f` opens in the folder outside the subshell
                yield [(p, ">") for p in redirected], eff, False, False, [], dict(local)
            continue
        own, redirected = _redirections(pairs, every_fd=True)
        names = [x for w in _command_words(own) for x in _braces(w)]
        if names and names[0] in ("pushd", "popd"):
            eff = None
            continue
        if names and names[0] == "cd":
            if redirected:  # `cd . > f`: the shell opens `f` (in the folder it was in) before `cd` runs
                yield [(p, ">") for p in redirected], eff, False, False, names, dict(local)
            target = _cd_target(names)
            target = _with_locals(target, local) if target is not None else None
            eff = None if target is None or target == "-" or _is_glob_or_var(target) else _enterable(eff, target, made)
            continue
        if names and os.path.basename(names[0]) == "mkdir" and eff is not None:
            made |= _made_folders(names[1:], eff)
        dynamic = any(c in raw for raw, _ in pairs for c in ("$(", "`"))
        targets = [(p, ">") for p in redirected]  # a bare `> hook` (no command word) truncates it too
        if names:
            targets += _command_targets(names) + _destructive_targets(names, dynamic)
        named = False
        if names and os.path.basename(names[0]) == "find":
            found, named = _find_targets(names[1:])
            targets += found
        yield targets, eff, dynamic, named, names, dict(local)
        local.update(_assigned(pairs))


def _enterable(eff: Path | None, target: str, made: set[Path] | frozenset[Path] = frozenset()) -> Path | None:
    """The folder `cd target` moves to from `eff`, or None (unknown) when it is not a folder one can enter now: a
    `cd` that fails leaves the shell where it was, and the next command after a `;` still runs there. A folder an
    earlier `mkdir` of the command makes (`_made_folders`) counts as one: `mkdir -p out && cd out`."""
    from flowmode.shellwrites import _resolve

    path = _resolve(eff, target)
    if path is not None and path in made:
        return path
    return path if path is not None and os.path.isdir(path) and os.access(path, os.X_OK) else None


def _made_folders(args: list[str], eff: Path) -> set[Path]:
    """The folders `mkdir args` run in `eff` makes: each operand (and, for `-p`, its missing parents) that does not
    exist yet, under a folder one can write in, and is not and lies not in a `.claude`/`.codex` folder."""
    from flowmode.shellwrites import _operands, _resolve

    out: set[Path] = set()
    for word in _operands(args, ("-m", "--mode", "-Z", "--context")):
        path = _resolve(eff, word)
        if path is None or any(c in word for c in _GLOB + _DYNAMIC):
            continue
        new = [path]
        while not os.path.lexists(new[-1].parent) and new[-1].parent != new[-1]:
            new.append(new[-1].parent)
        top = new[-1].parent
        if os.path.lexists(path) or not (top.is_dir() and os.access(top, os.W_OK | os.X_OK)):
            continue
        parts = Path(_canon(top)).parts + Path(_fold(str(path.relative_to(top)), top)).parts
        if any(part in _AGENT_FOLDERS for part in parts):
            continue
        out.update(new)
    return out


def _hook_file_target(command: str, cwd: Path, names_hooks_path: bool) -> str | None:
    """A shell write, removal, link or x-removing chmod of the commit-msg hook (git's, or the core.hooksPath
    folder's; literal names, globs, braces and `$(…)` paths too), of its hooks folder, or a write of a git config
    file by a command that names hooksPath (`_segment_targets`)."""
    from flowmode.shellwrites import _is_glob_or_var, _resolve

    hooks_dir = functools.cache(lambda: _hooks_dir(cwd))
    for targets, eff, dynamic, named, _, local in _segment_targets(command, cwd):
        if named:
            return "find -name commit-msg"
        for raw_word, op in targets:
            for word in dict.fromkeys((raw_word, _with_locals(raw_word, local))):
                if _target_hits(word, op, eff, dynamic, hooks_dir):
                    return f"{op} {raw_word}"
            word = _with_locals(raw_word, local)
            if names_hooks_path and not _is_glob_or_var(word):
                path = _resolve(eff, word)
                if path is not None and _is_git_config(_real(path)):
                    return f"{op} {word}"
    return None


def tampers_with_git_hooks(command: str, cwd: Path) -> str | None:
    """`_parsed_git_tamper`, then the lexer-free net (`hook_file_net`) over the commit-msg hook names."""
    return _parsed_git_tamper(command, cwd) or hook_file_net(command, _NET_GIT_NAMES)


def _parsed_git_tamper(command: str, cwd: Path) -> str | None:
    """S20 part 2 (owner answer 4): what in an agent's shell command would switch the commit-msg check off, or None —
    core.hooksPath set or removed by `git config` (any scope, `--file`, `set`/`unset`), by `-c`/`--config-env` on any
    git command, by `GIT_CONFIG_*` (also `export`ed) or by a `GIT_CONFIG_GLOBAL/SYSTEM` / `-c include.path` file that
    names it; an `include.path` written; husky; `pre-commit install -t commit-msg`; an alias hiding `--no-verify`/`-n`;
    a write, removal, x-removing chmod or link of the commit-msg hook (any git folder: worktrees share the common one;
    the core.hooksPath folder's); hooksPath written into a git config file. Subshells, groups and prefix commands
    (`sudo`, `env`, `nice`, `timeout`, `xargs`, …) are seen through, `sh -c` and `rebase --exec` strings parsed. Text
    that only mentions the setting passes. Never raises."""
    try:
        bare = _UNQUOTE.sub("", command).lower()
        if not _GUARD_HINT.search(bare):
            return None
        names_hooks_path = "hookspath" in bare
        for words in _token_lists(command):
            for word in words:
                if _GIT_CONFIG_ENV.match(word) and "hookspath" in _UNQUOTE.sub("", word).lower():
                    return word
                if (m := _GIT_CONFIG_FILE_ENV.match(word)) and _names_hooks_path(m.group(1), Path(cwd)):
                    return word
            found = _git_tamper(words, Path(cwd)) or _husky(words) or _pre_commit_msg(words)
            if found == _CONFIG_EDIT and not names_hooks_path:
                found = None
            if found:
                return found
        return _hook_file_target(command, Path(cwd), names_hooks_path)
    except Exception:  # noqa: BLE001 — a string the tokenizer cannot read is no finding; doctor and the session say "off"
        return None


def file_edit_tampers(path: str, cwd: Path, new_text: str) -> str | None:
    """An Edit/Write/MultiEdit/NotebookEdit or apply_patch of the commit-msg hook (git's, or the core.hooksPath
    folder's — asked of git only for a file named commit-msg) or of a git config file whose new text names hooksPath;
    None otherwise. Never raises."""
    try:
        full = _real(Path(os.path.normpath(os.path.join(str(cwd), os.path.expanduser(path)))))
        if _is_hook(full) or (_is_git_config(full) and "hookspath" in new_text.lower()):
            return path
        if full.name == "commit-msg" and full.parent.is_dir() and _same_path(_hooks_dir(full.parent), full.parent):
            return path
    except Exception:  # noqa: BLE001 — never a broken hook
        return None
    return None


# --- S20 F-20-88 (H1-6): an agent never removes or switches off Flowmode's agent hooks -----------------------------------

AGENT_HOOKS_REFUSAL = (
    "Flowmode: the agent hooks belong to the team — an agent does not remove or switch them off. Ask a person to"
    " change them from their own terminal."
)
_AGENT_HOOK_PREFIX = "flowmode hook "  # agents/claude.py HOOK_PREFIX (that module imports hooks.py: not imported here)
_AGENT_HOOKS_HINT = re.compile(
    r"settings|hooks\.json|config\.toml|\.claude|\.codex|uninstall|disableallhooks|checkout|restore|find|[*?\[$`]"
)
_MAX_SETTINGS = 1_000_000  # doctor's MAX_CONFIG_BYTES: a larger file is not ours


def _agent_hooks_kind(path: Path) -> str | None:
    """`claude` for `.claude/settings.json` / `settings.local.json` (any folder: the project's or the home's), `codex`
    for `.codex/hooks.json`, `codex-config` for `config.toml` in a `.codex` folder or in $CODEX_HOME; else None."""
    parent = path.parent.name
    if path.name in ("settings.json", "settings.local.json") and parent == ".claude":
        return "claude"
    if path.name == "hooks.json" and parent == ".codex":
        return "codex"
    if path.name == "config.toml":
        home = os.environ.get("CODEX_HOME") or os.path.join(os.path.expanduser("~"), ".codex")
        if parent == ".codex" or _same_path(path.parent, home):
            return "codex-config"
    return None


def _hooks_state(kind: str, text: str) -> tuple[frozenset, bool] | None:
    """(Flowmode's hook entries in the file's text — (event, matcher, hook) for JSON hooks files, `features.hooks`
    for a Codex config —, whether the text switches every hook off: `disableAllHooks`, `[features] hooks = false`);
    None when the text does not parse (the agent would lose the hooks with it)."""
    if kind == "codex-config":
        import tomllib

        try:
            features = tomllib.loads(text).get("features")
        except (tomllib.TOMLDecodeError, ValueError):
            return None
        hooks = features.get("hooks") if isinstance(features, dict) else None
        return frozenset({"features.hooks"} if hooks is True else ()), hooks is False
    import json

    try:
        data = json.loads(text or "{}")
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    entries = set()
    hooks = data.get("hooks")
    for event, groups in hooks.items() if isinstance(hooks, dict) else ():
        for group in groups if isinstance(groups, list) else ():
            inner = group.get("hooks") if isinstance(group, dict) else None
            for hook in inner if isinstance(inner, list) else ():
                if isinstance(hook, dict) and str(hook.get("command", "")).startswith(_AGENT_HOOK_PREFIX):
                    entries.add((event, json.dumps(group.get("matcher")), json.dumps(hook, sort_keys=True)))
    return frozenset(entries), kind == "claude" and bool(data.get("disableAllHooks"))


def _current_text(path: Path) -> str:
    try:
        if not path.is_file() or path.stat().st_size > _MAX_SETTINGS:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _loses_hooks(kind: str, old_text: str, new_text: str | None) -> bool:
    """The new text drops or changes one of Flowmode's entries the old text has, or switches every hook off; an
    unknown or unparsable new text loses them when the old one has them."""
    old = _hooks_state(kind, old_text) or (frozenset(), False)
    new = _hooks_state(kind, new_text) if new_text is not None else None
    if new is None:
        return bool(old[0]) or (new_text is not None and "disableallhooks" in new_text.lower())
    return new[1] or not old[0] <= new[0]


def _edited(old_text: str, edits: list) -> str | None:
    """Edit/MultiEdit's result on `old_text` ([{old_string, new_string, replace_all}]); None when an edit does not
    apply (the tool fails too)."""
    text = old_text
    for edit in edits:
        if not isinstance(edit, dict):
            return None
        old, new = edit.get("old_string"), edit.get("new_string")
        if not isinstance(old, str) or not isinstance(new, str) or old not in text:
            return None
        text = text.replace(old, new) if edit.get("replace_all") else text.replace(old, new, 1)
    return text


_PATCH_FILE = re.compile(r"^\*\*\* (Add File|Update File|Delete File|Move to): (.+?)\s*$")


def _patched(old_text: str, lines: list[str]) -> str | None:
    """An apply_patch `Update File` section's hunks applied to `old_text`; None when a hunk does not apply."""
    out = old_text.split("\n")
    at = 0
    hunks: list[list[str]] = [[]]
    for line in lines:
        if line.startswith("@@"):
            hunks.append([])
        elif line[:1] in (" ", "-", "+") or line == "":
            hunks[-1].append(line)
    for hunk in (h for h in hunks if h):
        before = [ln[1:] for ln in hunk if ln[:1] in (" ", "-", "")]
        after = [ln[1:] for ln in hunk if ln[:1] in (" ", "+", "")]
        k = next((i for i in range(at, len(out) - len(before) + 1) if out[i : i + len(before)] == before), None)
        if k is None:
            return None
        out[k : k + len(before)] = after
        at = k + len(after)
    return "\n".join(out)


def _patch_sections(text: str) -> list[tuple[str, str, list[str]]]:
    """[(action, path, the section's lines)] of an apply_patch text."""
    sections: list[tuple[str, str, list[str]]] = []
    for line in text.splitlines():
        if m := _PATCH_FILE.match(line):
            sections.append((m.group(1), m.group(2), []))
        elif line.startswith("*** "):
            continue
        elif sections:
            sections[-1][2].append(line)
    return sections


def agent_hooks_change(tool: str | None, tool_input: dict, cwd: Path) -> str | None:
    """F-20-88 (H1-6): the agent-hooks file an agent's file tool would leave without Flowmode's hook entries (removed,
    changed, the file deleted, moved or no longer parsable) or with every hook switched off (`disableAllHooks`,
    Codex `[features] hooks = false`), or None. An edit that keeps the entries passes. Never raises."""
    try:
        changes: list[tuple[Path, str, str | None]] = []  # (file, old text, new text; None = gone or unknown)
        if tool == "apply_patch":
            text = "\n".join(v for v in tool_input.values() if isinstance(v, str))
            moving: Path | None = None
            for action, name, lines in _patch_sections(text):
                path = Path(os.path.normpath(os.path.join(str(cwd), os.path.expanduser(name))))
                if action == "Move to" and moving is not None:
                    changes.append((moving, _current_text(moving), None))
                    continue
                moving = path if action == "Update File" else None
                old = _current_text(path)
                if action == "Delete File":
                    changes.append((path, old, None))
                elif action == "Add File":
                    changes.append((path, old, "\n".join(ln[1:] for ln in lines if ln.startswith("+"))))
                else:
                    changes.append((path, old, _patched(old, lines)))
        else:
            name = tool_input.get("file_path") or tool_input.get("notebook_path")
            if not isinstance(name, str):
                return None
            path = Path(os.path.normpath(os.path.join(str(cwd), os.path.expanduser(name))))
            old = _current_text(path)
            if tool == "Write":
                new = tool_input.get("content") if isinstance(tool_input.get("content"), str) else None
            elif tool == "Edit":
                new = _edited(old, [tool_input])
            elif tool == "MultiEdit":
                edits = tool_input.get("edits")
                new = _edited(old, edits) if isinstance(edits, list) else None
            else:
                new = None
            changes.append((path, old, new))
        for path, old, new in changes:
            kind = _agent_hooks_kind(_real(path))
            if kind is not None and _loses_hooks(kind, old, new):
                return str(path)
    except Exception:  # noqa: BLE001 — never a broken hook; doctor says when the hooks are gone
        return None
    return None


def _uninstall_in(words: list[str]) -> bool:
    at = _flowmode_at(words)
    if at is None:
        return False
    rest = [w for w in words[at + 1 :] if not w.startswith("-")]
    return bool(rest) and rest[0] == "uninstall"


def _expanded(word: str, eff: Path | None) -> list[Path]:
    """The paths a target word names from `eff`: `~` and environment variables expanded, a glob matched against the
    disk (at most 64), else the word itself — joined to `eff`, or as written when the directory is unknown (its
    folder names still tell a hooks file)."""
    import glob

    word = os.path.expandvars(os.path.expanduser(word))
    full = word if eff is None else os.path.join(str(eff), word)
    if any(c in word for c in _GLOB):
        return [Path(p) for p in glob.glob(full, include_hidden=True)[:64]]
    return [Path(os.path.normpath(full))]


def _hooks_files_under(folder: Path) -> list[Path]:
    return [folder / n for n in ("settings.json", "settings.local.json", "hooks.json", "config.toml")] + [
        folder / sub / n for sub in (".claude", ".codex") for n in ("settings.json", "hooks.json", "config.toml")
    ]


_AGENT_FILE_NAMES = ("settings.json", "settings.local.json", "hooks.json", "config.toml")
_AGENT_FOLDERS = (".claude", ".codex")
_AGENT_PATHS = (".claude/settings.json", ".claude/settings.local.json", ".codex/hooks.json", ".codex/config.toml")


def _agent_extra_targets(names: list[str]) -> list[tuple[str, str]]:
    """Agent-hooks-only targets of one segment: chmod (any mode) and chflags paths — an unreadable or frozen file is
    lost to `flowmode install` too —, `git rm` paths, `git mv` sources, destination and `<dest>/<source name>`."""
    head, args = os.path.basename(names[0]), names[1:]
    if head == "chmod":
        return [(p, "chmod") for p in _chmod_parts(args)[1]]
    if head == "chflags":
        return [(p, "chflags") for p in [a for a in args if not a.startswith("-")][1:]]
    sub = _git_sub_at(names) if head == "git" else None
    if sub is None or names[sub] not in ("rm", "mv"):
        return []
    ops = [w for w in names[sub + 1 :] if not w.startswith("-")]
    op = f"git {names[sub]}"
    if names[sub] == "mv" and len(ops) >= 2:
        return [(w, op) for w in ops] + [(posixpath.join(ops[-1], _base(w)), op) for w in ops[:-1]]
    return [(w, op) for w in ops]


def _agent_target_by_name(word: str, op: str, eff: Path | None) -> bool:
    """Refused by its letters alone: a `.claude`/`.codex` folder word with `$`/glob inside, a file name the hook
    cannot read whose literal tail could end a hooks file name (`${N}.json`), a hooks file name under a folder that
    expands or after a `cd` to an unknown folder, a folder copy/extraction into a `.claude`/`.codex` folder."""
    word = _fold(word, eff)  # F-20-107: `.CLAUDE/Settings.json` on macOS
    if _names_agent_folder(word):
        return True
    base, parent = _base(word), posixpath.dirname(word.rstrip("/"))
    if any(c in base for c in _DYNAMIC):
        return _could_name(base, _AGENT_FILE_NAMES + _AGENT_FOLDERS)
    if base in _AGENT_FILE_NAMES and (
        any(c in parent for c in _DYNAMIC) or (eff is None and not os.path.isabs(os.path.expanduser(word)))
    ):
        return True
    return op in _INTO_OPS and any(part in _AGENT_FOLDERS for part in posixpath.normpath(word).split("/"))


def _names_agent_folder(word: str) -> bool:
    """A target word the shell completes at run time (`$F`, backticks, a glob) inside a `.claude` / `.codex`
    folder, or naming one: the file it writes cannot be told, so it counts as a hooks file."""
    return any(c in word for c in _GLOB + _DYNAMIC) and bool(re.search(r"(^|/)\.(claude|codex)(/|$)", word))


def removes_agent_hooks(command: str, cwd: Path) -> str | None:
    """`_parsed_agent_hooks_removal`, then the lexer-free net (`hook_file_net`) over the agent hooks file names."""
    return _parsed_agent_hooks_removal(command, cwd) or hook_file_net(command, _NET_AGENT_NAMES)


def _parsed_agent_hooks_removal(command: str, cwd: Path) -> str | None:
    """F-20-88 (H1-6, review round 1 items 6-7): what in an agent's shell command would remove or rewrite the agent
    hooks files, or None — `flowmode uninstall`; ANY shell write, removal, link, copy or move onto a Claude
    `settings.json`/`settings.local.json`, a Codex `hooks.json` or a Codex `config.toml` (`>`, tee, cp, mv, ln,
    install, dd, sed -i, rm, truncate, chmod, chflags, rsync, tar -C, unzip -d, `git rm`/`mv`/`checkout`/`restore`,
    a `.claude`/`.codex` folder, globs, `$F` in such a folder, a name read by `_agent_target_by_name`) —
    the hook cannot read the text a shell writes, so the file need not hold Flowmode's entries today. Agents change
    these files with the File tools, which `agent_hooks_change` reads. Quotes and backslashes inside words do not hide
    them. Reading or copying them away passes. Never raises."""
    try:
        if not _AGENT_HOOKS_HINT.search(_UNQUOTE.sub("", command).lower()):
            return None
        for words in _token_lists(command):
            if _uninstall_in(words):
                return "flowmode uninstall"
        found: list[tuple[str, str, Path | None]] = []
        walked: dict = {}
        for targets, eff, _, _, names, local in _segment_targets(command, cwd):
            find = names and os.path.basename(names[0]) == "find"
            if find and (hit := _find_reaches_agent_hooks(names[1:], eff, walked)):
                return hit
            extra = _agent_extra_targets(names) if names else []
            for raw_word, op in targets + extra:
                found += [(word, op, eff) for word in dict.fromkeys((raw_word, _with_locals(raw_word, local)))]
        for word, op, eff in found:
            if _agent_target_by_name(word, op, eff):
                return f"{op} {word}"
            if any(c in _base(word) for c in _DYNAMIC):
                continue  # asked (`is_risky`: a target the hook cannot name), not refused
            if op in ("git checkout", "git restore") and _pathspec(word) == ".":
                continue  # the whole tree: an everyday discard, a documented limit (see `_git_path_targets`)
            for path in _expanded(word, eff):
                real = _real(path) if path.is_absolute() else path
                if real.name in _AGENT_FOLDERS:
                    return f"{op} {word}"
                if op in ("rm", "mv", "git rm", "git checkout", "git restore") and real.is_dir():
                    files = [f for f in _hooks_files_under(real) if f.exists()]
                else:
                    files = [real]
                if any(_agent_hooks_kind(file) is not None for file in files):
                    return f"{op} {word}"
    except Exception:  # noqa: BLE001 — never a broken hook; doctor says when the hooks are gone
        return None
    return None


# The lexer-free net (F-20-88 round 7, lead's decision): the hook files' names and the words that write or remove a
# file, found in the command's letters with quotes and backslashes dropped — no shell grammar read, so no lexer
# mistake (a comment, a heredoc, a quote read wrong) can hide them.
_NET_AGENT_NAMES = (".claude/settings.json", ".claude/settings.local.json", ".codex/hooks.json", ".codex/config.toml")
_NET_GIT_NAMES = ("hooks/commit-msg", ".husky/commit-msg", "core.hookspath")
_NET_VERBS = "rm|mv|cp|ln|tee|truncate|dd|install|chmod|chflags|unlink|shred|rsync|tar|unzip|trash|rmtrash"
_NET_VERB = re.compile(rf"(?<![\w.-])(?:{_NET_VERBS})(?![\w.-])|>")
_NET_AT_COMMAND = re.compile(
    rf"(?:^|[;&|(){{}}`\n]|\$\()\s*(?:(?:sudo|command|exec|env|nohup)\s+)*(?:{_NET_VERBS})(?![\w.-])"
)
_NET_GIT = re.compile(r"(?<![\w.-])git(?![\w.-])")
_NET_GIT_SUB = re.compile(r"(?<![\w.-])(?:config|mv|rm|checkout|restore)(?![\w.-])")
_NET_SED = re.compile(r"(?<![\w.-])sed(?![\w.-])")
_NET_SED_I = re.compile(r"\s-(?:-in-place|[a-z]*i)")
_NET_SIMPLE = re.compile(r"[^$`\\#<\n()!]*")  # no expansion, escape, comment, heredoc, line or subshell: read whole
# programs that only read their files (and print): with only these, a name and a verb in the same text are data
_NET_READERS = frozenset(
    {"cat", "jq", "grep", "egrep", "fgrep", "head", "tail", "ls", "stat", "wc", "file", "diff", "cmp", "echo"}
    | {"printf", "test", "[", "[[", "cd", "true", ":", "md5", "md5sum", "shasum", "sha256sum", "readlink"}
    | {"realpath", "basename", "dirname"}
)
_NET_GIT_READS = frozenset(
    {"status", "diff", "log", "show", "blame", "grep", "ls-files", "check-ignore", "rev-parse", "cat-file", "ls-tree"}
)


def _net_verbs(text: str) -> list[str]:
    """The write/remove words in `text` (already unquoted and lowercased): `rm`, `>`, …, `git config|mv|rm|checkout|
    restore` (a sub-command word anywhere after a `git` word), `sed` with an `-i` option after it."""
    verbs = _NET_VERB.findall(text)
    git = _NET_GIT.search(text)
    if git and (sub := _NET_GIT_SUB.search(text, git.end())):
        verbs.append("git " + sub.group())
    sed = _NET_SED.search(text)
    if sed and _NET_SED_I.search(text, sed.end()):
        verbs.append("sed -i")
    return verbs


def _net_reader(words: list[str]) -> bool:
    """A command that only reads: `_NET_READERS`, a git read sub-command, `git config --get/--list/get/list`."""
    name = os.path.basename(words[0])
    if name in _NET_READERS:
        return True
    sub = _git_sub_at(words) if name == "git" else None
    if sub is None:
        return False
    args = words[sub + 1 :]
    if words[sub] == "config":
        flags = [a.partition("=")[0] for a in args]
        return not any(f in _CONFIG_REMOVALS for f in args) and (
            any(f in _CONFIG_READS for f in flags) or args[:1] in (["get"], ["list"])
        )
    return words[sub] in _NET_GIT_READS


def _net_only_reads(command: str, text: str, names: list[str], verbs: list[str]) -> bool:
    """The parser read the whole command as reads: nothing it cannot resolve, every segment a reader
    (`_net_reader`) whose redirections write no hooks file, and every name and verb the letters hold is among the words
    it read (none dropped as a comment or a heredoc body) — with no verb right after a command separator."""
    from flowmode.shellwrites import _redirections

    if _NET_AT_COMMAND.search(text):
        return False
    unresolved: list[str] = []
    lists = _segment_pairs(command, unresolved=unresolved)
    if unresolved:
        return False
    seen: list[str] = []
    for pairs in lists:
        own, redirected = _redirections(pairs, every_fd=True)
        words = _command_words(own)
        if words and not _net_reader(words):
            return False
        if any(c in _base(r) for r in redirected for c in _GLOB + _DYNAMIC) or any(
            name in r.lower() for r in redirected for name in names
        ):
            return False
        seen += [w for _, w in pairs]
    parsed = _UNQUOTE.sub("", " ".join(seen)).lower()
    return all(parsed.count(name) >= text.count(name) for name in names) and all(
        _net_verbs(parsed).count(v) >= verbs.count(v) for v in set(verbs)
    )


def hook_file_net(command: str, names: tuple[str, ...]) -> str | None:
    """A crude net under the parsed guards (lead, round 7): the command's letters, quotes and backslashes dropped,
    name one of `names` and hold a write/remove word (`_net_verbs`) → refused — unless the text has none of `$`,
    backticks, backslashes, `#`, `<` or newlines (then the parser reads it whole and its answer stands) or the
    parser proved it only reads (`_net_only_reads`: `cat .claude/settings.json > /tmp/x`, `git config --get
    core.hooksPath`). It trusts no lexer, so it also refuses some data: a heredoc commit message naming a hooks
    file and a verb, a comment like `# rm .claude/settings.json`. Never raises."""
    try:
        text = _UNQUOTE.sub("", command).lower()
        found = [name for name in names if name in text]
        if not found:
            return None
        verbs = _net_verbs(text)
        if not verbs or _NET_SIMPLE.fullmatch(command):
            return None
        if _net_only_reads(command, text, found, verbs):
            return None
        return f"{verbs[0]} … {found[0]}"
    except Exception:  # noqa: BLE001 — the net itself never breaks the hook; a failure to prove a read refuses
        return f"{names[0]} (unread)"


# --- S20 F-20-107 (H2-1/H2-2): an agent never writes Flowmode's own folder ($FLOWMODE_HOME) -----------------------------

FLOWMODE_HOME_REFUSAL = (
    "Flowmode: its own folder (the session state, config and tokens) belongs to the person — an agent does not write,"
    " move or remove anything there. Reading it is fine; ask a person to run the flowmode command from their own"
    " terminal."
)
_HOME_REMOVALS = frozenset({"rm", "mv", "git rm", "git mv"})  # ops that take a folder above the home with them
_EDITORS = frozenset({"vi", "vim", "nvim", "ex", "view", "ed", "sponge"})  # run unseen, they write their operands


def _flowmode_home() -> str:
    from flowmode.shared import flowmode_home

    return str(flowmode_home())


def under_flowmode_home(name: str, cwd: Path) -> bool:
    """A file tool's path (relative to `cwd`, `~` expanded, links resolved, any case on a case-blind volume, by file
    identity) is $FLOWMODE_HOME or inside it. Never raises."""
    try:
        return _inside(os.path.join(str(cwd), os.path.expanduser(name)), _spot(_flowmode_home()))
    except (OSError, ValueError):
        return False


def _home_writers(names: list[str]) -> list[tuple[str, str]]:
    """Writers only the home guard reads (review round 2): `sponge FILE`, an editor run on files (`vim -es`, `ex`,
    `ed`), `awk -i inplace`, `ruby -i` — every operand counts."""
    head, args = os.path.basename(names[0]), names[1:]
    operands = [a for a in args if not a.startswith(("-", "+"))]
    if head in _EDITORS:
        return [(w, head) for w in operands]
    if head in ("awk", "gawk") and ("inplace" in args or "--include=inplace" in args or "-iinplace" in args):
        return [(w, f"{head} -i inplace") for w in operands]
    if head == "ruby" and any(a.startswith("-") and not a.startswith("--") and "i" in a[1:] for a in args):
        return [(w, "ruby -i") for w in operands]
    return []


def writes_flowmode_home(command: str, cwd: Path) -> str | None:
    """What in an agent's shell command would write, remove, move, link or re-mode a path under $FLOWMODE_HOME (or
    remove/move a folder above it), or None — the targets `_segment_targets` reads (`~`, variables and globs expanded
    against the disk, links resolved, a `cd` followed) and `_home_writers`, compared by `_inside` (any case, file
    identity), then the lexer-free net (`hook_file_net`) over the folder's name and real path. Reads pass. Never
    raises."""
    try:
        home = _flowmode_home()
        spot = _spot(home)
        for targets, eff, _, _, names, local in _segment_targets(command, cwd):
            extra = _agent_extra_targets(names) + _home_writers(names) if names else []
            for raw_word, op in targets + extra:
                for word in dict.fromkeys((raw_word, _with_locals(raw_word, local))):
                    found = [(p, op in _HOME_REMOVALS) for p in _expanded(word, eff)]
                    if (cut := next((i for i, c in enumerate(word) if c in _GLOB), None)) is not None:
                        # a glob that matches nothing yet still names its folder (never a folder above the home)
                        found += [(p, False) for p in _expanded(posixpath.dirname(word[:cut]) or ".", eff)]
                    for path, above in found:
                        if not path.is_absolute():
                            continue  # after a `cd` to an unknown folder: the net below reads the letters
                        if _inside(path, spot) or (above and _inside(home, _spot(path))):
                            return f"{op} {word}"
        return hook_file_net(command, tuple(dict.fromkeys((".flowmode", os.path.realpath(home).lower()))))
    except Exception:  # noqa: BLE001 — never a broken hook
        return None


TASK_HANDS_REFUSAL = "Flowmode: a person takes or releases tasks — on the site, from the task's page."
_TASK_HANDS = ("take", "release")


_RUNNERS = frozenset(
    {"uv", "uvx", "pipx", "sudo", "env", "exec", "command", "builtin", "nohup", "time", "nice", "xargs"}
)


def _flowmode_at(words: list[str]) -> int | None:
    """The index of the word that runs the flowmode CLI: `flowmode` by any path as the command (after `VAR=…`
    assignments, or behind a runner such as `uv run`, `sudo`, `env`), or the module after `-m` (`python -m flowmode`).
    None when the segment runs something else (`echo flowmode task take` is text, not a take)."""
    i = 0
    while i < len(words) and "=" in words[i] and not words[i].startswith("-"):
        i += 1
    if i >= len(words):
        return None
    head = os.path.basename(words[i])
    if head == "flowmode":
        return i
    if head in _RUNNERS:
        found = next((k for k in range(i + 1, len(words)) if os.path.basename(words[k]) == "flowmode"), None)
    elif head.startswith("python"):
        found = next((k + 1 for k in range(i + 1, len(words) - 1) if words[k] == "-m"), None)
        found = found if found is not None and words[found] in ("flowmode", "flowmode.cli") else None
    else:
        return None
    return found


def _task_hand_in(words: list[str]) -> str | None:
    at = _flowmode_at(words)
    if at is None:
        return None
    i = at + 1
    while i < len(words) and words[i].startswith("-"):  # global options; `--workspace X` (or an abbreviation)
        word = words[i]
        takes_value = "=" not in word and len(word) > 2 and "--workspace".startswith(word)
        i += 2 if takes_value else 1
    if i >= len(words) or words[i] != "task":
        return None
    i += 1
    while i < len(words) and words[i].startswith("-"):
        i += 1
    if i < len(words) and words[i] in _TASK_HANDS:
        return f"flowmode task {words[i]}"
    return None


def takes_or_releases_task(command: str) -> str | None:
    """S20 L-7: `flowmode task take|release` in any segment of an agent's shell command (global options, a path or
    `uv run` before it; a `sh -c` string unwrapped once), or None. Never raises."""
    try:
        for words in _token_lists(command):
            if (found := _task_hand_in(words)) is not None:
                return found
    except Exception:  # noqa: BLE001 — a string the tokenizer cannot read is no finding (the server still checks rights)
        return None
    return None
