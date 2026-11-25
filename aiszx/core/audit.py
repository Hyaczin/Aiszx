"""Audit trail: who changed scope, registered or removed targets, and when."""

from __future__ import annotations

import json
from typing import Any

from aiszx.core.timeutil import iso
from aiszx.db.connection import Database


def record_event(
    db: Database,
    action: str,
    *,
    actor: str,
    engagement_id: str | None = None,
    target_id: str | None = None,
    **detail: Any,
) -> None:
    db.execute(
        "INSERT INTO audit_events (ts, actor, engagement_id, target_id, action, detail_json) VALUES (?, ?, ?, ?, ?, ?)",
        (iso(), actor, engagement_id, target_id, action, json.dumps(detail, sort_keys=True, default=str)),
    )
