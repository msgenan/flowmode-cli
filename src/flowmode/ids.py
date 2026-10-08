"""Id and timestamp helpers."""

import secrets
from datetime import UTC, datetime


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


def now_iso() -> str:
    """UTC ISO-8601 with milliseconds, e.g. 2026-09-23T10:00:00.123+00:00 (string order == time order)."""
    return datetime.now(UTC).isoformat(timespec="milliseconds")
