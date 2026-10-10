"""Id and timestamp helpers."""

import secrets
import string
from datetime import UTC, datetime

WORKSPACE_ID_ALPHABET = string.ascii_lowercase + string.digits


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


def new_workspace_id() -> str:
    """S19 L-6: a workspace's public id, 8 random characters [a-z0-9] (the integer `workspaces.id` stays internal)."""
    return "".join(secrets.choice(WORKSPACE_ID_ALPHABET) for _ in range(8))


def now_iso() -> str:
    """UTC ISO-8601 with milliseconds, e.g. 2026-09-23T10:00:00.123+00:00 (string order == time order)."""
    return datetime.now(UTC).isoformat(timespec="milliseconds")
