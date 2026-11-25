"""Persist inventory results: SQLite rows (current state) and JSON snapshots (history)."""

from __future__ import annotations

import json
from pathlib import Path

from aiszx.core.fsutil import atomic_write_text
from aiszx.db.connection import Database
from aiszx.tools.dependency_checker import CapabilityStatus
from aiszx.tools.inventory import Inventory


def save_inventory(db: Database, inventory: Inventory) -> None:
    with db.transaction():
        for t in inventory.tools.values():
            db.execute(
                "INSERT INTO tool_inventory (name, status, path, version, source, package, launch_json, detail_json, checked_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT (name) DO UPDATE SET status = excluded.status, path = excluded.path,"
                " version = excluded.version, source = excluded.source, package = excluded.package,"
                " launch_json = excluded.launch_json, detail_json = excluded.detail_json, checked_at = excluded.checked_at",
                (t.name, t.status, t.path, t.version, t.source, t.package, json.dumps(t.launch),
                 json.dumps({"installations": [i.to_dict() for i in t.installations], "problems": t.problems,
                             "notes": t.notes, **t.detail}, sort_keys=True),
                 inventory.checked_at),
            )
        if inventory.complete:
            names = list(inventory.tools)
            marks = ",".join("?" * len(names))
            db.execute(f"DELETE FROM tool_inventory WHERE name NOT IN ({marks})", names)


def save_capabilities(db: Database, capabilities: list[CapabilityStatus], checked_at: str) -> None:
    with db.transaction():
        db.execute("DELETE FROM dependency_status")
        for cap in capabilities:
            for req in cap.requirements:
                db.execute(
                    "INSERT INTO dependency_status (capability, tool_name, requirement, status, state, message, checked_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (cap.name, req.tool, req.requirement, req.status, cap.state, cap.message, checked_at),
                )


def write_snapshot(data_dir: Path, inventory: Inventory, capabilities: list[CapabilityStatus] | None) -> Path:
    """Keep a timestamped JSON snapshot so tool changes over time can be compared."""
    out_dir = data_dir / "global" / "tools"
    payload = inventory.to_dict()
    if capabilities is not None:
        payload["capabilities"] = [c.to_dict() for c in capabilities]
    text = json.dumps(payload, indent=2, sort_keys=True)
    stamp = inventory.checked_at.replace(":", "").replace("-", "")
    path = out_dir / f"inventory-{stamp}.json"
    atomic_write_text(path, text)
    atomic_write_text(out_dir / "latest.json", text)
    return path


def load_saved(db: Database) -> list[dict]:
    rows = db.query("SELECT * FROM tool_inventory ORDER BY name")
    return [{**dict(r), "launch": json.loads(r["launch_json"]), "detail": json.loads(r["detail_json"])} for r in rows]
