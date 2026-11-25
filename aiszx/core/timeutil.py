"""UTC time helpers. Every timestamp Aiszx stores is UTC ISO-8601 with a trailing ``Z``."""

from __future__ import annotations

import re
from datetime import date, datetime, time, timezone

from aiszx.core.errors import ValidationError

_DATE_ONLY = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt: datetime | None = None) -> str:
    dt = utcnow() if dt is None else dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value: str) -> datetime:
    """Parse a stored or user-supplied timestamp; naive values are treated as UTC."""
    dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_bound(value: str | None, *, end: bool) -> str | None:
    """Parse a validity bound. A bare date means start of day (``end=False``) or end of day (``end=True``)."""
    if value is None or not value.strip():
        return None
    v = value.strip()
    try:
        if _DATE_ONLY.fullmatch(v):
            dt = datetime.combine(date.fromisoformat(v), time(23, 59, 59) if end else time(0, 0, 0), tzinfo=timezone.utc)
        else:
            dt = parse_iso(v)
    except ValueError:
        raise ValidationError(f"invalid date/time {value!r}; use YYYY-MM-DD or ISO-8601 (e.g. 2026-11-25T16:00:00Z)") from None
    return iso(dt)
