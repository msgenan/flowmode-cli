"""S11 F-11-37 (the fixed lines): which files a shell command writes to, by parsing — best effort.

`write_targets(command, cwd)` names the paths a command changes through redirections (`>`, `>>`, `&>`), `tee`,
`sed -i`, `perl -pi`, `cp`/`mv`/`install` destinations (and `mv` sources), `git checkout -- p`, `git restore p`,
`rm p`, `touch p`, `truncate p`, `dd of=p` and `patch p`, resolved against the directory a leading `cd <dir>` (or
`git -C <dir>`) moved to. A nested shell string (`sh -c "…"`, and Codex's `bash -lc …`) is unwrapped once. A quoted
`'>'` is an argument, not a redirection; a heredoc body is skipped. Blind spots by design: scripts (`bash x.sh`),
`python -c` code, pipes into interpreters, `xargs`, `find -exec`, variables and globs in paths, `git apply`/`am`/
`stash pop`/`merge`/`rebase`/`checkout <branch>`/`reset` — the skills and the docs say so. Never raises."""

import os
import re
import shlex
from pathlib import Path

SHELLS = ("bash", "sh", "zsh", "dash")
_SKIP_TARGETS = ("/dev/null", "/dev/stdout", "/dev/stderr", "&1", "&2")
_PREFIXES = ("sudo", "command", "exec", "nohup", "time", "env")
_REDIR_OUT = ("&>", "&>>", ">|", ">>", ">", "1>", "1>>")
_HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
# options that take an argument, per command (an option not listed here never swallows a path)
_TAKES_ARG = {
    "cp": ("-t", "--target-directory", "--suffix", "-S"),
    "mv": ("-t", "--target-directory", "--suffix", "-S"),
    "install": ("-t", "--target-directory", "-m", "-o", "-g", "-S", "--suffix", "--mode", "--owner", "--group"),
    "rm": (),
    "touch": ("-d", "-r", "-t", "--date", "--reference"),
    "truncate": ("-s", "--size", "-r", "--reference"),
    "patch": ("-p", "-d", "-i", "-o", "-r", "-B", "-z", "--directory", "--input", "--output"),
    "tee": (),
    "perl": ("-e", "-E", "-M", "-m", "-I"),
    "restore": ("-s", "--source"),
}


def _strip_heredocs(command: str) -> str:
    """The command without its heredoc bodies (the `cat > file <<'EOF' … EOF` body lines are data, not commands)."""
    lines = command.split("\n")
    out, i = [], 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        m = _HEREDOC.search(line)
        if m and not _in_quotes(line, m.start()):
            word = m.group(2)
            i += 1
            while i < len(lines) and lines[i].strip() != word:
                i += 1
        i += 1
    return "\n".join(out)


def _in_quotes(text: str, at: int) -> bool:
    quote = None
    for ch in text[:at]:
        if quote:
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
    return quote is not None


def segments(command: str) -> list[str]:
    """Split on unquoted `;`, `&&`, `||`, `|` and newlines; heredoc bodies are dropped first."""
    command = _strip_heredocs(command)
    parts, cur, quote, i = [], [], None, 0
    while i < len(command):
        ch = command[i]
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            elif ch == "\\" and quote == '"' and i + 1 < len(command):
                cur.append(command[i + 1])
                i += 1
        elif ch in ("'", '"'):
            quote = ch
            cur.append(ch)
        elif ch == "\\" and i + 1 < len(command):
            cur.append(ch)
            cur.append(command[i + 1])
            i += 1
        elif command.startswith(("&&", "||"), i):
            parts.append("".join(cur))
            cur = []
            i += 2
            continue
        elif ch in (";", "\n", "|"):
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


def _tokens(segment: str) -> list[tuple[str, str]]:
    """[(raw token with its quotes, the token as the shell sees it)]; a quoting error → whitespace split."""
    try:
        raw, posix = shlex.split(segment, posix=False), shlex.split(segment, posix=True)
    except ValueError:
        words = segment.split()
        return [(w, w) for w in words]
    if len(raw) != len(posix):  # the two tokenisers disagree (odd escapes): no redirection is guessed
        return [(f'"{p}"', p) for p in posix]
    return list(zip(raw, posix, strict=False))


def _unwrap(tokens: list[tuple[str, str]]) -> tuple[list[tuple[str, str]], str | None]:
    """`sh -c '<string>'` → the inner string (parsed again); Codex's joined `bash -lc a b c` → the tokens after."""
    if len(tokens) >= 3 and os.path.basename(tokens[0][1]) in SHELLS:
        for i in range(1, min(len(tokens) - 1, 4)):
            opt = tokens[i][1]
            if opt.startswith("-") and not opt.startswith("--") and "c" in opt[1:]:
                rest = tokens[i + 1 :]
                if len(rest) == 1:
                    return [], rest[0][1]
                return rest, None
            if not opt.startswith("-"):
                break
    return tokens, None


def _strip_prefix(tokens: list[tuple[str, str]]) -> tuple[list[tuple[str, str]], str | None]:
    """Drop env assignments and `sudo`/`env`/… in front of the real command; `git -C <dir>` gives the directory."""
    i = 0
    while i < len(tokens):
        tok = tokens[i][1]
        if (
            "=" in tok and not tok.startswith("-") and tok.split("=", 1)[0].replace("_", "a").isalnum()
        ) or tok in _PREFIXES:
            i += 1
        else:
            break
    tokens = tokens[i:]
    if len(tokens) >= 3 and tokens[0][1] == "git" and tokens[1][1] == "-C":
        return [tokens[0], *tokens[3:]], tokens[2][1]
    return tokens, None


def _redirections(tokens: list[tuple[str, str]]) -> tuple[list[str], list[str]]:
    """(the command's own tokens, the paths written by `>`-style redirections). Only a bare, unquoted operator
    counts: `grep '>' f` keeps its argument."""
    own, targets, i = [], [], 0
    while i < len(tokens):
        raw, tok = tokens[i]
        quoted = raw[:1] in ("'", '"')
        if not quoted and tok in _REDIR_OUT:
            if i + 1 < len(tokens):
                targets.append(tokens[i + 1][1])
            i += 2
            continue
        if not quoted and tok in ("2>", "2>>", "<", "<<", "<<<", "<<-"):
            i += 2
            continue
        if not quoted and tok.startswith(("2>", "<")):
            i += 1
            continue
        if not quoted and tok.startswith((">", "&>", "1>")):
            rest = tok.lstrip("&1").lstrip(">").lstrip("|")
            if rest:
                targets.append(rest)
            i += 1
            continue
        if not quoted and ">" in tok and not tok.startswith("-"):  # `echo x>f`
            head, _, tail = tok.partition(">")
            tail = tail.lstrip(">").lstrip("|")
            if head:
                own.append(head)
            if tail:
                targets.append(tail)
            i += 1
            continue
        own.append(tok)
        i += 1
    return own, [t for t in targets if t not in _SKIP_TARGETS and not t.startswith("&")]


def _operands(args: list[str], taking_arg: tuple[str, ...] = ()) -> list[str]:
    """Arguments that are not options; an option in `taking_arg` swallows the next token; `--` ends the options."""
    out, i = [], 0
    while i < len(args):
        tok = args[i]
        if tok == "--":
            out.extend(args[i + 1 :])
            break
        if tok.startswith("-") and len(tok) > 1:
            if tok in taking_arg:
                i += 2
                continue
        else:
            out.append(tok)
        i += 1
    return out


def _sed_targets(args: list[str]) -> list[str]:
    if not any(
        a == "-i"
        or a.startswith(("-i", "--in-place"))
        or (a.startswith("-") and not a.startswith("--") and "i" in a[1:] and "e" not in a[1:])
        for a in args
    ):
        return []
    ops, i, has_e = [], 0, False
    while i < len(args):
        a = args[i]
        if a in ("-e", "--expression", "-f", "--file"):
            has_e = True
            i += 2
            continue
        if a == "-i" and i + 1 < len(args) and args[i + 1] == "":
            i += 2
            continue
        if a.startswith("-") and len(a) > 1:
            if "e" in a[1:] and not a.startswith("--"):
                has_e = True
                i += 2
                continue
            i += 1
            continue
        ops.append(a)
        i += 1
    if not has_e and ops:
        ops = ops[1:]  # the first operand is the script
    return ops


def _command_targets(tokens: list[str]) -> list[tuple[str, str]]:
    """The paths the command itself writes to, with the operator that does it."""
    if not tokens:
        return []
    name = os.path.basename(tokens[0])
    args = tokens[1:]
    if name == "tee":
        return [(p, "tee") for p in _operands(args)]
    if name == "sed":
        return [(p, "sed -i") for p in _sed_targets(args)]
    if name == "perl":
        if not any(a.startswith("-") and "i" in a[1:] and not a.startswith("--") for a in args):
            return []
        return [(p, "perl -i") for p in _operands(args, _TAKES_ARG["perl"])]
    if name in ("cp", "mv", "install"):
        ops = _operands(args, _TAKES_ARG[name])
        if len(ops) < 2:
            return []
        targets = [(ops[-1], name)]
        if name == "mv":  # moving a file away changes it too
            targets = [(p, "mv") for p in ops[:-1]] + targets
        return targets
    if name == "git" and args:
        sub = args[0]
        if sub == "checkout" and "--" in args:
            return [(p, "git checkout --") for p in args[args.index("--") + 1 :]]
        if sub == "restore":
            return [(p, "git restore") for p in _operands(args[1:], _TAKES_ARG["restore"])]
        return []
    if name == "dd":
        return [(a[3:], "dd") for a in args if a.startswith("of=") and len(a) > 3]
    if name in ("rm", "touch", "truncate", "patch"):
        return [(p, name) for p in _operands(args, _TAKES_ARG[name])]
    return []


def _is_glob_or_var(path: str) -> bool:
    return any(ch in path for ch in "*?[$`")


def _cd_target(tokens: list[str]) -> str | None:
    return next((t for t in tokens[1:] if not t.startswith("-")), None)


def _resolve(base: Path | None, target: str) -> Path | None:
    target = os.path.expanduser(target)
    if os.path.isabs(target):
        return Path(os.path.normpath(target))
    if base is None:
        return None
    return Path(os.path.normpath(os.path.join(str(base), target)))


def effective_dir(command: str, cwd: Path) -> Path | None:
    """The directory the command's last `cd` moved to (resolved against `cwd`); `cwd` without one; None when a
    `cd` without a fixed target (`cd -`, `cd` alone, `pushd`) makes it unknown."""
    eff: Path | None = Path(cwd)
    for seg in segments(command):
        tokens, inner = _unwrap(_tokens(seg))
        if inner is not None:
            tokens = _tokens(inner)
        tokens, _ = _strip_prefix(tokens)
        names = [t for _, t in tokens]
        if not names:
            continue
        if names[0] in ("pushd", "popd"):
            eff = None
        elif names[0] == "cd":
            target = _cd_target(names)
            eff = None if target is None or target == "-" or _is_glob_or_var(target) else _resolve(eff, target)
    return eff


def write_targets(command: str, cwd: Path) -> list[tuple[Path, str]]:
    """[(absolute path, operator)] for every file the command writes to, in order, without repeats. Relative paths
    count only while the effective directory is known; globs and variables are never guessed."""
    found: list[tuple[Path, str]] = []
    seen: set[Path] = set()
    eff: Path | None = Path(cwd)
    try:
        for seg in segments(command):
            tokens, inner = _unwrap(_tokens(seg))
            if inner is not None:
                for path, op in write_targets(inner, eff if eff is not None else cwd):
                    if path not in seen:
                        seen.add(path)
                        found.append((path, op))
                continue
            own, redirected = _redirections(tokens)
            own_tokens, git_dir = _strip_prefix([(t, t) for t in own])
            names = [t for _, t in own_tokens]
            if names and names[0] in ("pushd", "popd"):
                eff = None
                continue
            if names and names[0] == "cd":
                target = _cd_target(names)
                eff = None if target is None or target == "-" or _is_glob_or_var(target) else _resolve(eff, target)
                continue
            base = _resolve(eff, git_dir) if git_dir else eff
            for path, op in [(p, ">") for p in redirected] + _command_targets(names):
                if not path or _is_glob_or_var(path):
                    continue
                full = (
                    _resolve(base if op.startswith("git") else eff, path)
                    if op.startswith("git")
                    else _resolve(eff, path)
                )
                if full is None or full in seen:
                    continue
                seen.add(full)
                found.append((full, op))
    except Exception:  # noqa: BLE001 — best effort, never a broken hook
        return found
    return found
