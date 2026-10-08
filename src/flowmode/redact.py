"""S14 F-14-05 (SEC-2, D-14, CODE-18): the one place that masks secrets inside a text Flowmode sends or stores — a
risky command waiting for approval (the hook, and again the server for an old CLI), a check's one-line detail, a
review prompt. Each secret becomes `[redacted]`; what the text does (the tool, the host, the path) stays readable.

The table below is regular expressions only: no secret-shaped literal lives in this file (the secret scan runs over
`src/`). Order matters: a header (`Authorization:`, `Bearer`) is masked before the token shapes it may carry, and the
longer prefix (`sk-ant-`) before the shorter one (`sk-`)."""

import re

REDACTED = "[redacted]"
# the characters that end an unquoted value: a space, a quote, and every shell operator (`;` `&` `|` `<` `>` `(` `)`
# `$` and the backtick) — a mask never swallows the next command, so the approver reads the command that runs
_WORD = r"""[^\s"'`;&|<>()$]"""
# one shell word: single-quoted, double-quoted without a substitution in it (`"$(…)"` still runs: left readable), or
# unquoted up to the next space, quote or operator
_VALUE = rf"""(?:"[^"$`]*"|'[^']*'|{_WORD}+)"""
_B64 = r"[A-Za-z0-9._~+/=-]"  # the characters of a bearer token (RFC 6750 b64token)

# (pattern, replacement): a replacement keeps the named part (\1) that says what the secret was for
_RULES: tuple[tuple[re.Pattern, str], ...] = (
    # a header value: `Authorization: Bearer x`, `Authorization: token x`, `Authorization: x`
    (
        re.compile(rf"(?i)\b(authorization:\s*)(?:(?:bearer|basic|token|digest|bot)\s+)?{_WORD}+"),
        r"\1" + REDACTED,
    ),
    (re.compile(rf"(?i)\b(bearer\s+){_B64}{{8,}}"), r"\1" + REDACTED),
    # user:password inside a URL
    (re.compile(r"""(?i)\b([a-z][a-z0-9+.-]{0,30}://)[^/@\s"'`;&|<>()$]+@"""), r"\1" + REDACTED + "@"),
    # `--password=x`, `--password x` (and `--passwd`)
    (re.compile(rf"(--passw(?:or)?d(?:=|\s+)){_VALUE}"), r"\1" + REDACTED),
    # `mysql -p<x>` (the MySQL tools take the password glued to -p; `-p` alone prompts for it)
    (re.compile(rf"(\bmysql\w*\b[^\n;&|]{{0,300}}?\s-p){_WORD}+"), r"\1" + REDACTED),
    # `NAME=value` where NAME ends in TOKEN, SECRET, PASSWORD, PASSWD, KEY or APIKEY (not `KEY_COUNT=3`): an
    # upper-case name (`DEPLOY_TOKEN`, `MYKEY`), or any case when the word stands alone or after `_`/`-` (`api_key`,
    # `--password`, `token` in a query) — so `monkey=1` stays
    (
        re.compile(
            r"(?<![\w.-])((?:[A-Z_][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|KEY)"
            rf"|(?i:(?:[\w-]*[_-])?(?:api)?(?:token|secret|password|passwd|key)))=){_VALUE}"
        ),
        r"\1" + REDACTED,
    ),
    # token shapes: Anthropic, OpenAI, AWS access key id, Slack, GitHub, Flowmode (agent, approver, device)
    (re.compile(r"\bsk-ant-[A-Za-z0-9_-]{8,}"), REDACTED),
    # `sk-` then optional words (`proj-`) and one run of 20+ with a digit: never a branch like `sk-rotate-keys-2`
    (re.compile(r"\bsk-(?:[A-Za-z]{1,20}-){0,3}(?=[A-Za-z_]*\d)[A-Za-z0-9_]{20,}[A-Za-z0-9_-]*"), REDACTED),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), REDACTED),
    (re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"), REDACTED),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"), REDACTED),
    (re.compile(r"\bgh[opsur]_[A-Za-z0-9]{20,}"), REDACTED),
    (re.compile(r"\bfm[ad]?_[A-Za-z0-9_-]{8,}"), REDACTED),
)


def redact_secrets(text: str | None) -> str | None:
    """`text` with every secret of the table replaced by `[redacted]`; idempotent (a masked text stays as it is);
    None and "" pass through. Pure."""
    if not text:
        return text
    for pattern, replacement in _RULES:
        text = pattern.sub(replacement, text)
    return text
