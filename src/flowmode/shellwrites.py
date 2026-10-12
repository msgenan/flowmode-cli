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
from pathlib import Path
from typing import NamedTuple

SHELLS = ("bash", "sh", "zsh", "dash")
_SKIP_TARGETS = ("/dev/null", "/dev/stdout", "/dev/stderr", "&1", "&2")
_PREFIXES = ("sudo", "command", "exec", "nohup", "time", "env")
# a write redirection token: `[n|{name}|&]` then `>`, `>>`, `>|` or `>&`, then the target when glued on
_FD = r"[0-9]+|\{[A-Za-z_][A-Za-z0-9_]*\}"
_REDIR_WRITE = re.compile(rf"(?P<fd>{_FD}|&)?(?P<op>>>|>\||>&|>)(?P<rest>.*)", re.DOTALL)
_REDIR_READ = re.compile(rf"(?:{_FD})?(?:<<<|<<-|<<|<>|<&|<)(?P<rest>.*)", re.DOTALL)
_DUP = re.compile(r"[0-9]*-?")
# a heredoc operator (not a `<<<` here-string) and its delimiter word, quotes and all (`<<E"OF"` ends at `EOF`)
_HEREDOC = re.compile(
    r"<<(?!<)(-?)[ \t]*((?:'[^'\n]*'|\"(?:[^\"\\\n]|\\.)*\"|\\.|\$\{(?:[^{}'\"\\]|\\.|'[^']*'|\"(?:[^\"\\]|\\.)*\")*\}"
    r"|\$\([^()]*\)|`[^`]*`|[^\s;&|<>()'\"\\`])+)"
)  # `${x:- #}`, `$(…)` and backticks are part of the word, spaces and all
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


def heredoc_at(text: str, i: int) -> tuple[int, str, bool, bool] | None:
    """At a `<<` / `<<-` in `text` (the caller has ruled out a `<<<` here-string): (the index after its word, the
    delimiter as bash compares it — the word without its quotes —, whether `<<-` strips leading tabs, whether the
    body is literal: a quoted or escaped word, so no `$(…)` and no continuations in it), else None."""
    m = _HEREDOC.match(text, i)
    if m is None:
        return None
    word = m.group(2)
    try:  # a space inside `${x:- #}` stays in the word (split would end the word there)
        delim = "".join(split(word.replace(" ", "\0"), sh=True)).replace("\0", " ")
    except ValueError:
        delim = word
    return m.end(), delim, m.group(1) == "-", any(q in word for q in "'\"\\")


# a frame on the lexer's stack: S `$(…)`, P `<(…)` / `>(…)`, B a backtick, p a plain `(` inside S or P (these and the
# top level are code); d `"…"`; b `${…}` (and a plain `{` inside one); a `$((…))` / `((…))` parenthesis; k `$[…]`
_LEX_SPECIAL = "\\$'\"`#<>(){}[]\n"
_LEX_PLAIN = re.compile(r"[^\\$'\"`#<>(){}\[\]\n]+")
_WORD_END = " \t\n;&|()<>"
_CASE_WORD = re.compile(r"(?:^|[\s;&|(])case\s")
_TICK_ESCAPE = re.compile(r"\\([\\`$])")


class Lexed(NamedTuple):
    """What bash's reader finds in a command (`lex`)."""

    joins: list[int]  # the backslashes bash drops: before a newline (a continuation), and a lone one at the end
    drops: list[tuple[int, int]]  # comments, and heredoc bodies with their delimiter lines, in order
    subs: list[str]  # the bodies of the outermost `$(…)`, backticks (unescaped) and `<(…)` / `>(…)`
    broken: bool  # a substitution left open, or one whose end cannot be told (a `case` arm's `)` inside)


def lex(text: str, body: bool = False) -> Lexed:
    """Read `text` as bash reads it, in one pass with a stack of nested frames (`$(…)`, backticks, `<(…)`, `"…"`,
    `${…}`, arithmetic). A `#` starts a comment only at a word's start in code (the top level, a substitution: not
    inside `${…}`, quotes or arithmetic); inside backticks it ends at the closing backtick. A `<<` is a heredoc only in
    code (not a `<<<` here-string, not a shift in `$((…))`, `((…))`, `$[…]`); its body runs to the line that is
    exactly the delimiter (`<<-`: after its tabs). A backslash-newline is joined outside single and ANSI-C quotes,
    comments and quoted heredoc bodies; a lone backslash at the end is dropped. `body`: an unquoted heredoc's body,
    where quotes are text and only expansions count. Linear in the text."""
    joins: list[int] = []
    joined: set[int] = set()
    drops: list[tuple[int, int]] = []
    subs: list[str] = []
    stack: list[str] = []
    pending: list[tuple[str, bool, bool]] = []  # heredocs opened on this line: (delimiter, <<-, quoted)
    broken, nsub, start, tick = False, 0, 0, -1
    base = "h" if body else ""
    i, n = 0, len(text)

    def opens(kind: str, at: int) -> None:
        nonlocal nsub, start
        if not nsub:
            start = at
        nsub += 1
        stack.append(kind)

    def closes(end: int) -> None:
        nonlocal nsub, broken
        kind = stack.pop()
        nsub -= 1
        if not nsub:
            found = text[start:end]
            if kind == "B":
                found = _TICK_ESCAPE.sub(r"\1", found)
            else:
                broken = broken or bool(_CASE_WORD.search(found))
            subs.append(found)

    def word_start(at: int) -> bool:
        p = at - 1
        while p > 0 and text[p] == "\n" and p - 1 in joined:
            p -= 2  # a joined continuation is not there for bash
        if p >= 0 and text[p] in _WORD_END:  # … unless that space or operator is escaped (`\\ #` is a word)
            q = p
            while q > 0 and text[q - 1] == "\\":
                q -= 1
            return (p - q) % 2 == 0
        return p < 0 or p == tick

    while i < n:
        c = text[i]
        if c not in _LEX_SPECIAL:
            i = _LEX_PLAIN.match(text, i).end()
            continue
        top = stack[-1] if stack else base
        if c == "\\":
            if i + 1 == n or text[i + 1] == "\n":
                joins.append(i)
                joined.add(i)
            i += 2
        elif c == "$":
            if text.startswith("$$", i):
                i += 2
            elif text.startswith("$((", i):
                stack += ["a", "a"]
                i += 3
            elif text.startswith("$(", i):
                opens("S", i + 2)
                i += 2
            elif text.startswith("${", i) or text.startswith("$[", i):
                stack.append("b" if text[i + 1] == "{" else "k")
                i += 2
            elif text.startswith("$'", i) and top not in ("d", "h"):
                end = _ANSI_C_BODY.match(text, i + 2).end()
                if end >= n or text[end] != "'":
                    break  # left open: the rest is quoted
                i = end + 1
            elif text.startswith('$"', i) and top not in ("d", "h"):
                stack.append("d")
                i += 2
            else:
                i += 1
        elif c == "`":
            if top == "B":
                closes(i)
            else:
                opens("B", i + 1)
                tick = i
            i += 1
        elif top in ("d", "h"):
            if c == '"' and top == "d":
                stack.pop()
            i += 1
        elif c == "'":
            end = text.find("'", i + 1)
            if end < 0:
                break  # left open: the rest is quoted
            i = end + 1
        elif c == '"':
            stack.append("d")
            i += 1
        elif top == "b":
            if c == "{":
                stack.append("b")
            elif c == "}":
                stack.pop()
            i += 1
        elif top == "k":
            if c == "[":
                stack.append("k")
            elif c == "]":
                stack.pop()
            i += 1
        elif top == "a":
            if c == "(":
                stack.append("a")
            elif c == ")":
                stack.pop()
            i += 1
        elif c == "#" and word_start(i):  # code from here on
            end = text.find("\n", i)
            end = n if end < 0 else end
            if "B" in stack:
                close = text.find("`", i)
                end = end if close < 0 else min(end, close)
            drops.append((i, end))
            i = end
        elif c == "(":
            if text.startswith("((", i) and (i == 0 or text[i - 1] not in "<>"):
                stack += ["a", "a"]
                i += 2
                continue
            if top in ("S", "P", "p"):
                stack.append("p")
            i += 1
        elif c == ")":
            if top == "p":
                stack.pop()
            elif top in ("S", "P"):
                closes(i)
            i += 1
        elif c in "<>" and text.startswith("(", i + 1):
            opens("P", i + 2)
            i += 2
        elif text.startswith("<<<", i):  # a here-string: its word is read as usual
            i += 3
        elif text.startswith("<<", i) and (op := heredoc_at(text, i)):
            pending.append((op[1], op[2], op[3]))
            i = op[0]
        elif c == "\n" and pending:
            i += 1
            for delim, strip, literal in pending:  # each body runs to its delimiter line
                begin = i
                while i < n:
                    end = text.find("\n", i)
                    line = text[i:] if end < 0 else text[i:end]
                    while not literal and end >= 0 and (len(line) - len(line.rstrip("\\"))) % 2:
                        joins.append(end - 1)  # an unquoted body joins its continuations too
                        nxt = text.find("\n", end + 1)
                        line = line[:-1] + (text[end + 1 :] if nxt < 0 else text[end + 1 : nxt])
                        end = nxt
                    i = n if end < 0 else end + 1
                    if (line.lstrip("\t") if strip else line) == delim:
                        break
                drops.append((begin, i))
                if not literal and not nsub:  # `cat <<EOF` expands `$(…)` in its body
                    inner = lex(text[begin:i], body=True)
                    subs += inner.subs
                    broken = broken or inner.broken
            pending = []
        else:
            i += 1
    return Lexed(sorted(joins), drops, subs, broken or nsub > 0)


def _cut(text: str, spans: list[tuple[int, int]]) -> str:
    """`text` without the (sorted, disjoint) spans."""
    out, kept = [], 0
    for start, end in spans:
        out.append(text[kept:start])
        kept = end
    out.append(text[kept:])
    return "".join(out)


def join_continuations(command: str) -> str:
    """The command with the backslash-newline continuations bash joins, and a lone backslash at its end, removed
    (`lex`): a backslash at the end of a comment, in single quotes or in a quoted heredoc's body is text, and its
    newline still ends the line."""
    if "\\\n" not in command and not command.endswith("\\"):
        return command
    return _cut(command, [(j, j + 2) for j in lex(command).joins])


def _strip_data(command: str) -> str:
    """The command without its comments and heredoc bodies (the `cat > file <<'EOF' … EOF` body lines are data, not
    commands), found as bash finds them (`lex`)."""
    if "<<" not in command and "#" not in command:
        return command
    return _cut(command, lex(command).drops)


# `>&`, `<&`, `&>` are redirections (`2>&1`, `<&3`, `&> f`), `|&` a pipe; a lone `&` sends the command to the background
_SEGMENT_PIECE = re.compile(
    r"""\$\$|\$'(?:[^'\\]+|\\.)*'?|'[^']*'?|"(?:[^"\\]+|\\.)*"?|\\.|>\||>&|<&|&&|&>\||&>|\|&|\|\||[;\n|&]"""
    r"""|[^'"\\&|;\n<>$]+|.""",
    re.DOTALL,
)
_SEPARATORS = ("&&", "||", ";", "\n", "|", "|&", "&")


def segments(command: str) -> list[str]:
    """Split on unquoted `;`, `&&`, `||`, `|`, `|&`, a background `&` and newlines (not the `|` of a `>|` clobber nor
    the `&` of `2>&1`, `<&3`, `&> f`); comments and heredoc bodies are dropped first. One regex pass (a quoted
    string, an escaped character, a separator or a run of plain characters per match), linear in the command."""
    parts, cur = [], []
    for m in _SEGMENT_PIECE.finditer(_strip_data(command)):
        piece = m.group()
        if piece in _SEPARATORS:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(piece)
    parts.append("".join(cur))
    return [p.strip(" \t\n") for p in parts if p.strip(" \t\n")]  # a `\r` is part of a word in bash


_WORD_RUN = re.compile(r"[^ \t\r\n'\"\\]+")
_SH_WORD_RUN = re.compile(r"(?:[^ \t\n'\"\\$]+|\$\$|\$(?!['\"]))+")  # stops before `$'` / `$"`; `\r` is a letter
_ANSI_C_BODY = re.compile(r"(?:[^'\\]+|\\.)*", re.DOTALL)
_ANSI_C_ESCAPE = re.compile(r"\\(?:x[0-9A-Fa-f]{1,2}|u[0-9A-Fa-f]{1,4}|U[0-9A-Fa-f]{1,8}|[0-7]{1,3}|c.|.)", re.DOTALL)
_ANSI_C_CHARS = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}
_ANSI_C_CHARS |= {"v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}


def _ansi_c_char(m: re.Match) -> str:
    """One `$'…'` escape as bash decodes it; an unknown one keeps its backslash (`\\q` → `\\q`)."""
    esc = m.group()[1:]
    if esc[0] in "xuU" and len(esc) > 1:
        return chr(min(int(esc[1:], 16), 0x10FFFF))
    if esc[0] in "01234567":
        return chr(int(esc, 8) & 0xFF)
    if esc[0] == "c" and len(esc) == 2:
        return chr(ord(esc[1].upper()) & 0x1F)
    return _ANSI_C_CHARS.get(esc, "\\" + esc)


_RAW_RUN = re.compile(r"[^ \t\r\n]+")
_DQUOTE_RUN = re.compile(r'[^"\\]*')
_SPACE = " \t\r\n"
_SH_SPACE = " \t\n"  # bash's blanks (and the newline it ends a command at): a `\r` stays in the word


def split(text: str, posix: bool = True, spans: bool = False, sh: bool = False) -> list:
    """`shlex.split(text, posix=posix)` word for word (same tokens, same ValueError), in linear time: shlex grows each
    token one character at a time on an attribute, which is quadratic in a word's length (a 100 kB word took 0.24 s,
    and this runs in the PreToolUse hook on every agent Bash call). `spans` (posix only): [(the word as written, with
    its quotes, the word)] — `'.claude'/settings.json` is one word, as the shell reads it. `sh` (posix only): bash's
    ANSI-C `$'…'` (backslash escapes, `\\'` included, decoded) and locale `$"…"` quotes too, which shlex lacks."""
    out: list = []
    n, i, blanks = len(text), 0, _SH_SPACE if sh else _SPACE
    while True:
        while i < n and text[i] in blanks:
            i += 1
        if i >= n:
            return out
        ch = text[i]
        if not posix:  # a quote opens a token that ends at the same quote; any other word runs to whitespace
            if ch in "'\"":
                end = text.find(ch, i + 1)
                if end < 0:
                    raise ValueError("No closing quotation")
                out.append(text[i : end + 1])
                i = end + 1
            else:
                m = _RAW_RUN.match(text, i)
                out.append(m.group())
                i = m.end()
            continue
        start, parts = i, []
        while i < n and (ch := text[i]) not in blanks:
            if sh and text.startswith("$'", i):
                end = _ANSI_C_BODY.match(text, i + 2).end()
                if end >= n or text[end] != "'":  # the text's end, or a lone backslash before it
                    raise ValueError("No closing quotation")
                parts.append(_ANSI_C_ESCAPE.sub(_ansi_c_char, text[i + 2 : end]))
                i = end + 1
            elif sh and text.startswith('$"', i):
                i += 1  # a locale string reads as a double-quoted one
            elif ch == "'":
                end = text.find("'", i + 1)
                if end < 0:
                    raise ValueError("No closing quotation")
                parts.append(text[i + 1 : end])
                i = end + 1
            elif ch == '"':
                i += 1
                while True:
                    m = _DQUOTE_RUN.match(text, i)
                    parts.append(m.group())
                    i = m.end()
                    if i >= n:
                        raise ValueError("No closing quotation")
                    if text[i] == '"':
                        i += 1
                        break
                    if i + 1 >= n:
                        raise ValueError("No escaped character")
                    nxt = text[i + 1]
                    if nxt not in ('\\"$`\n' if sh else '\\"'):  # shlex keeps it before all but `\\` and `"`
                        parts.append("\\")
                    if not (sh and nxt == "\n"):  # bash drops a backslash-newline in double quotes
                        parts.append(nxt)
                    i += 2
            elif ch == "\\":
                if i + 1 >= n:
                    if sh:  # bash drops a lone backslash at the end
                        if i == start:
                            return out
                        i = n
                        break
                    raise ValueError("No escaped character")
                if not (sh and text[i + 1] == "\n"):  # bash joins a backslash-newline
                    parts.append(text[i + 1])
                i += 2
            else:
                m = (_SH_WORD_RUN if sh else _WORD_RUN).match(text, i)
                parts.append(m.group())
                i = m.end()
        out.append((text[start:i], "".join(parts)) if spans else "".join(parts))


def _tokens(segment: str) -> list[tuple[str, str]]:
    """[(raw token with its quotes, the token as the shell sees it)] — word boundaries as the shell draws them, so
    mixed quoting (`'.claude'/settings.json`) stays one word, an unquoted `(` or `)` outside `$(…)`, `$((…))`, `<(…)`,
    `>(…)`, `${…}` and backticks is a token of its own (`(rm f) 2>x`, `!(rm f)`, `time(rm f)`: bash ends a word
    there; an array `a=(x y)` stays one word), and a glued redirection is a token of its own (`f&>/dev/null`, `f<in`,
    `f>>log` → `f` and the redirection); a quoting error → whitespace split."""
    try:
        pairs = split(segment, posix=True, spans=True, sh=True)
    except ValueError:
        words = segment.split()
        return [(w, w) for w in words]
    out: list[tuple[str, str]] = []
    nest: list[str] = []  # the closers still open, carried across words: `$(echo a b)` is split at its blanks
    array: list[str] = []  # the raw words of an `a=(x y)` assignment being read
    for raw, word in pairs:
        pieces = _paren_pieces(raw, nest)
        if array or (len(pieces) == 1 and nest and _ARRAY_START.match(raw)):
            array.append(raw)
            if not nest:
                joined = " ".join(array)
                out.append((joined, joined))
                array = []
            continue
        for piece in pieces:
            if piece in ("(", ")"):
                out.append((piece, piece))
            else:
                out += _redirect_pieces(piece, word if piece == raw else None)
    if array:
        joined = " ".join(array)
        out.append((joined, joined))
    return out


_ARRAY_START = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=\(")
_OPENS = {"$(": ")", "<(": ")", ">(": ")", "${": "}"}


def _paren_pieces(raw: str, nest: list[str]) -> list[str]:
    """`raw` cut at its unquoted `(` / `)` outside any substitution (each one a piece of its own); `nest` holds the
    closers open from earlier words of the segment (`$(`, `<(`, `>(`, `$((`, `${`, a backtick, an array's `=(`) and
    is updated in place."""
    pieces, at, i, n, quote = [], 0, 0, len(raw), ""
    while i < n:
        c = raw[i]
        if quote:
            if c == "\\" and quote != "'":
                i += 1
            elif c == quote[-1]:
                quote = ""
        elif c == "\\":
            i += 1
        elif nest and nest[-1] == "`":
            if c == "`":
                nest.pop()
        elif raw.startswith("$'", i):
            quote, i = "$'", i + 1
        elif c in "'\"":
            quote = c
        elif c == "`":
            nest.append("`")
        elif raw[i : i + 2] in _OPENS:
            nest.append(_OPENS[raw[i : i + 2]])
            i += 1
        elif c == "(" and (nest or _ARRAY_START.fullmatch(raw, 0, i + 1)):
            nest.append(")")
        elif nest and c == nest[-1]:
            nest.pop()
        elif not nest and c in "()":
            pieces += [raw[at:i], c] if i > at else [c]
            at = i + 1
        i += 1
    if at < n:
        pieces.append(raw[at:])
    return pieces


def _redirect_pieces(raw: str, word: str | None) -> list[tuple[str, str]]:
    """One word as [(raw, word)], a glued redirection cut off as a token of its own; `word` None: read from `raw`."""
    try:
        if word is None:
            word = "".join(split(raw, sh=True))
        cuts, at = [], _redirect_at(raw) if "<" in raw or ">" in raw else -1
        while at >= 0:
            if at and not (not cuts and _FD_WORD.fullmatch(raw[:at])):
                cuts.append(at)
            op = _GLUED_OP.match(raw, at)
            at = _redirect_at(raw, op.end() + 1) if op else -1  # the next one after this one's target
        if not cuts:
            return [(raw, word)]
        pieces = [raw[a:b] for a, b in zip([0, *cuts], [*cuts, len(raw)], strict=True)]
        return [(p, "".join(split(p, sh=True))) for p in pieces]
    except ValueError:
        return [(raw, word if word is not None else raw)]


_FD_WORD = re.compile(rf"{_FD}")
_GLUED_OP = re.compile(r"&>>|&>\||&>|>>|>\||>&|>|<<<|<<-|<<|<>|<&|<")


def _redirect_at(raw: str, i: int = 0) -> int:
    """The index in a raw word, from `i`, where a redirection glued to it starts — a `<` or `>` (or the `&` of `&>`)
    outside quotes, escapes and `$(…)` / `${…}` / backticks / `<(…)` —, or -1."""
    depth, tick, quote, n = 0, False, "", len(raw)
    while i < n:
        c = raw[i]
        if quote:
            if c == "\\" and quote != "'":
                i += 1
            elif c == quote[-1]:
                quote = ""
        elif c == "\\":
            i += 1
        elif raw.startswith("$'", i):
            quote, i = "$'", i + 1
        elif c in "'\"":
            quote = c
        elif c == "`":
            tick = not tick
        elif raw.startswith(("$(", "${", "<(", ">("), i):
            depth, i = depth + 1, i + 1
        elif depth and c in ")}":
            depth -= 1
        elif not depth and not tick and (c in "<>" or raw.startswith("&>", i)):
            return i
        i += 1
    return -1


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


def _redirections(tokens: list[tuple[str, str]], every_fd: bool = False) -> tuple[list[str], list[str]]:
    """(the command's own tokens, the paths written by `>`-style redirections). Only a bare, unquoted operator
    counts: `grep '>' f` keeps its argument. Stdout writes (`>`, `>>`, `>|`, `1>…`, `&>`, `&>>`, `&>|`, `>& file`)
    are targets; other descriptors (`2>`, `3>`, `{fd}>`) only with `every_fd` (the hooks guard: any of them
    truncates the hook; claims leave stderr logs out)."""
    own, targets, i = [], [], 0
    while i < len(tokens):
        raw, tok = tokens[i]
        at = _redirect_at(raw)
        quoted = not (at == 0 or (at > 0 and _FD_WORD.fullmatch(raw[:at])))  # `'>'`, `$'>'`: an argument
        out = None if quoted else _REDIR_WRITE.fullmatch(tok)
        if out:
            fd, op, target = out.group("fd"), out.group("op"), out.group("rest")
            if not target:
                target = tokens[i + 1][1] if i + 1 < len(tokens) else ""
                i += 1
            i += 1
            if op == ">&" and _DUP.fullmatch(target):
                continue  # `>&2`, `2>&1`, `3>&-`: a descriptor, not a file
            if every_fd or fd in (None, "1", "&"):
                targets.append(target)
            continue
        read = None if quoted else _REDIR_READ.fullmatch(tok)
        if read:
            i += 1 if read.group("rest") else 2
            continue
        own.append(tok)
        i += 1
    return own, [t for t in targets if t and t not in _SKIP_TARGETS and not t.startswith("&")]


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


def _parts(tokens: list[tuple[str, str]]):
    """A segment's tokens cut at its subshell parentheses: ("(", []), (")", []) or ("", the tokens of a command)."""
    cur: list[tuple[str, str]] = []
    for pair in tokens:
        if pair[0] in ("(", ")"):
            if cur:
                yield "", cur
            yield pair[0], []
            cur = []
        else:
            cur.append(pair)
    if cur:
        yield "", cur


def _enter_or_leave(paren: str, eff: Path | None, outer: list[Path | None]) -> Path | None:
    """At a subshell's `(` the folder is kept for its `)`; at the `)` the folder before it comes back."""
    if paren == "(":
        outer.append(eff)
        return eff
    return outer.pop() if outer else eff


def effective_dir(command: str, cwd: Path) -> Path | None:
    """The directory the command's last `cd` moved to (resolved against `cwd`); `cwd` without one; None when a
    `cd` without a fixed target (`cd -`, `cd` alone, `pushd`) makes it unknown. A `cd` in a subshell ends at its `)`."""
    eff: Path | None = Path(cwd)
    outer: list[Path | None] = []
    for seg in segments(command):
        for paren, part in _parts(_tokens(seg)):
            if paren:
                eff = _enter_or_leave(paren, eff, outer)
                continue
            tokens, inner = _unwrap(part)
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
    count only while the effective directory is known; globs and variables are never guessed; a `cd` in a subshell
    ends at its `)`."""
    found: list[tuple[Path, str]] = []
    seen: set[Path] = set()
    eff: Path | None = Path(cwd)
    outer: list[Path | None] = []
    try:
        for seg in segments(command):
            for paren, part in _parts(_tokens(seg)):
                if paren:
                    eff = _enter_or_leave(paren, eff, outer)
                    continue
                tokens, inner = _unwrap(part)
                if inner is not None:
                    for path, op in write_targets(inner, eff if eff is not None else cwd):
                        if path not in seen:
                            seen.add(path)
                            found.append((path, op))
                    continue
                own, redirected = _redirections(tokens)
                own_tokens, git_dir = _strip_prefix([(t, t) for t in own if t != "!"])
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
                    full = _resolve(base if op.startswith("git") else eff, path)
                    if full is None or full in seen:
                        continue
                    seen.add(full)
                    found.append((full, op))
    except Exception:  # noqa: BLE001 — best effort, never a broken hook
        return found
    return found
