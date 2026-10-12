"""S12 F-12-15: branch names and outside text, checked in pure Python (no git subprocess).

`valid_ref_name` holds git's `check-ref-format --branch` rules and is a little stricter than git: a bare `@`, a name
of 256 characters or more and any Unicode whitespace or C1 control character are refused too. Every branch field
on the server goes through it (`store._check_branch`, `server.TaskIn`/`SessionIn`), and so does a handoff's branch
before `flowmode work` / `task take` fetch it. `printable` makes GitHub-sourced text safe to print on a terminal;
`display_safe` (S13 F-13-01) also drops the invisible format characters a title could hide or reorder text with;
`terminal_safe` (S20 F-20-90) is the one filter for any server-provided text the CLI prints."""

import re
import unicodedata

MAX_REF_LEN = 255
FORBIDDEN = set("~^:?*[\\")


def _control(ch: str) -> bool:
    code = ord(ch)
    return code < 0x20 or 0x7F <= code <= 0x9F


def valid_ref_name(name: str) -> bool:
    """True when `name` may be a branch: git's rules (no `..`, `@{`, `//`, control characters, space, `~^:?*[\\`;
    no component starting with `.` or ending in `.lock`; not starting with `-` or `/`, not ending in `/` or `.`;
    not `HEAD`) plus Flowmode's own refusals (a bare `@`, 256+ characters, any whitespace)."""
    if not isinstance(name, str) or not name or len(name) > MAX_REF_LEN:
        return False
    if name in ("@", "HEAD") or name.startswith("-") or name.endswith("."):
        return False
    if ".." in name or "@{" in name:
        return False
    if any(ch in FORBIDDEN or ch.isspace() or _control(ch) for ch in name):
        return False
    # a leading or trailing `/` and `//` leave an empty component
    return all(part and not part.startswith(".") and not part.endswith(".lock") for part in name.split("/"))


def printable(text: str) -> str:
    """`text` without control characters (`\\x00-\\x1f`, `\\x7f-\\x9f`); a tab becomes a space."""
    return "".join(ch for ch in text.replace("\t", " ") if not _control(ch))


INVISIBLE = frozenset({"Cf", "Zl", "Zp"})  # format (bidi overrides, zero-width), line and paragraph separators


def display_safe(text: str) -> str:
    """S13 F-13-01: `printable(text)` without Unicode format characters (`Cf`: bidi overrides and isolates,
    zero-width spaces and joiners, the BOM) and line/paragraph separators (`Zl`, `Zp`) — for GitHub titles and labels
    shown on every member's screen. `printable` is unchanged."""
    return "".join(ch for ch in printable(text) if unicodedata.category(ch) not in INVISIBLE)


MAX_TERMINAL_TEXT = 500
# whole escape sequences, so no remnant (`[2J`, `52;c;…`) is left: OSC/DCS/SOS/PM/APC strings up to BEL, ST or the end
# (7-bit `ESC ] P X ^ _` and their C1 forms), CSI (`ESC [`, C1 `\x9b`), then any other ESC with its intermediates
ESCAPES = re.compile(
    r"(?:\x1b[\]PX^_]|[\x90\x98\x9d\x9e\x9f]).*?(?:\x07|\x1b\\|\x9c|$)"
    r"|(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]?"
    r"|\x1b[ -/]*[0-~]?",
    re.DOTALL,
)


def terminal_safe(text: object, limit: int = MAX_TERMINAL_TEXT) -> str:
    """S20 F-20-90 (red team U-3): server-provided text as it may reach a terminal — whole ESC/CSI/OSC/DCS sequences
    (an OSC 52 clipboard write, a screen clear, a window title) and their C1 forms removed, a newline, tab or carriage
    return made one space (no faked second line), every other C0/C1 control and the invisible format characters
    (`display_safe`) dropped, at most `limit` characters (the last one `…` when cut)."""
    raw = str(text)[: limit * 16]  # a huge body costs no more than this; a sequence cut here is removed whole
    flat = re.sub(r"[\n\t\r]+", " ", ESCAPES.sub("", raw))
    shown = display_safe(flat).strip()
    return shown if len(shown) <= limit else shown[: limit - 1] + "…"
