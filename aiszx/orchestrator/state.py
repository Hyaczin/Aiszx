"""Persistence of executions, unit states, attempts, evidence, approvals and lifecycle logs.

All writes happen on the orchestrator's main thread (single SQLite writer).
"""

from __future__ import annotations

import json
from typing import Any

from aiszx.core.ids import new_id
from aiszx.core.timeutil import iso
from aiszx.db.connection import Database
from aiszx.modules.registry import ModuleRegistry

PENDING, RUNNING, COMPLETED, FAILED, SKIPPED, INTERRUPTED, RECOVERY_REQUIRED = (
    "PENDING", "RUNNING", "COMPLETED", "FAILED", "SKIPPED", "INTERRUPTED", "RECOVERY_REQUIRED")
UNIT_STATES = (PENDING, RUNNING, COMPLETED, FAILED, SKIPPED, INTERRUPTED, RECOVERY_REQUIRED)
TERMINAL = {COMPLETED, FAILED, SKIPPED, INTERRUPTED, RECOVERY_REQUIRED}

EXEC_RUNNING, EXEC_COMPLETED, EXEC_PARTIAL, EXEC_FAILED, EXEC_INTERRUPTED = (
    "RUNNING", "COMPLETED", "PARTIAL", "FAILED", "INTERRUPTED")

_JSON_COLUMNS = {"inputs_json", "depends_on_json", "tools_json", "outputs_json", "summary_json",
                 "commands_json", "context_json", "config_snapshot"}


def _encode(fields: dict[str, Any]) -> dict[str, Any]:
    return {k: (json.dumps(v, sort_keys=True, default=str) if k in _JSON_COLUMNS and not isinstance(v, str) else v)
            for k, v in fields.items()}


class ExecutionStore:
    def __init__(self, db: Database) -> None:
        self.db = db

    def _update(self, table: str, row_id: str, fields: dict[str, Any]) -> None:
        if not fields:
            return
        enc = _encode(fields)
        sets = ", ".join(f"{k} = ?" for k in enc)
        self.db.execute(f"UPDATE {table} SET {sets} WHERE id = ?", [*enc.values(), row_id])

    def _insert(self, table: str, fields: dict[str, Any]) -> None:
        enc = _encode(fields)
        cols = ", ".join(enc)
        marks = ", ".join("?" * len(enc))
        self.db.execute(f"INSERT INTO {table} ({cols}) VALUES ({marks})", list(enc.values()))

    # -- catalogue -----------------------------------------------------------
    def sync_modules(self, registry: ModuleRegistry) -> None:
        now = iso()
        with self.db.transaction():
            for mid, mod in registry.modules.items():
                m = mod.meta
                self.db.execute(
                    "INSERT INTO modules (id, version, stage, safety_class, categories_json, description, updated_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO UPDATE SET version = excluded.version,"
                    " stage = excluded.stage, safety_class = excluded.safety_class,"
                    " categories_json = excluded.categories_json, description = excluded.description,"
                    " updated_at = excluded.updated_at",
                    (mid, m.version, m.stage.value, m.safety.value, json.dumps(list(m.categories)), m.description, now),
                )

    # -- executions ----------------------------------------------------------
    def create_execution(self, **fields: Any) -> str:
        eid = new_id()
        self._insert("executions", {"id": eid, **fields})
        return eid

    def update_execution(self, eid: str, **fields: Any) -> None:
        self._update("executions", eid, fields)

    def execution(self, eid: str):
        return self.db.query_one("SELECT * FROM executions WHERE id = ?", (eid,))

    def executions_for_target(self, target_id: str) -> list:
        return self.db.query("SELECT * FROM executions WHERE target_id = ? ORDER BY started_at DESC, run_id DESC",
                             (target_id,))

    def find_run(self, target_id: str, run_id: str | None, commands: tuple[str, ...] | None = None):
        if run_id:
            return self.db.query_one("SELECT * FROM executions WHERE target_id = ? AND run_id = ?", (target_id, run_id))
        sql, params = "SELECT * FROM executions WHERE target_id = ?", [target_id]
        if commands:
            sql += f" AND command IN ({','.join('?' * len(commands))})"
            params += list(commands)
        return self.db.query_one(sql + " ORDER BY started_at DESC, run_id DESC LIMIT 1", params)

    # -- units ---------------------------------------------------------------
    def insert_unit(self, **fields: Any) -> str:
        uid = new_id()
        self._insert("module_executions", {"id": uid, **fields})
        return uid

    def update_unit(self, uid: str, **fields: Any) -> None:
        self._update("module_executions", uid, fields)

    def units(self, eid: str) -> list:
        return self.db.query("SELECT * FROM module_executions WHERE execution_id = ? ORDER BY rowid", (eid,))

    def state_counts(self, eid: str) -> dict[str, int]:
        rows = self.db.query("SELECT state, COUNT(*) AS n FROM module_executions WHERE execution_id = ? GROUP BY state",
                             (eid,))
        return {r["state"]: r["n"] for r in rows}

    # -- attempts ------------------------------------------------------------
    def start_attempt(self, uid: str, attempt: int, output_dir: str) -> str:
        aid = new_id()
        self._insert("module_attempts", {"id": aid, "module_execution_id": uid, "attempt": attempt,
                                         "status": "running", "output_dir": output_dir, "started_at": iso()})
        return aid

    def finish_attempt(self, aid: str, **fields: Any) -> None:
        self._update("module_attempts", aid, {"ended_at": iso(), **fields})

    def attempts(self, uid: str) -> list:
        return self.db.query("SELECT * FROM module_attempts WHERE module_execution_id = ? ORDER BY attempt", (uid,))

    # -- evidence / approvals / logs -----------------------------------------
    def add_evidence(self, **fields: Any) -> str:
        evid = "EV-" + new_id()[:16]
        self.db.execute(
            "INSERT INTO evidence (id, execution_id, target_id, module_execution_id, attempt, tool, kind, rel_path,"
            " sha256, size_bytes, sensitive, description, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT (execution_id, rel_path) DO UPDATE SET sha256 = excluded.sha256,"
            " size_bytes = excluded.size_bytes, description = COALESCE(excluded.description, evidence.description)",
            (evid, fields["execution_id"], fields.get("target_id"), fields.get("module_execution_id"),
             fields.get("attempt"), fields.get("tool"), fields["kind"], fields["rel_path"], fields.get("sha256"),
             fields.get("size_bytes"), int(fields.get("sensitive", False)), fields.get("description"), iso()),
        )
        return evid

    def evidence_count(self, eid: str) -> int:
        return int(self.db.query_one("SELECT COUNT(*) FROM evidence WHERE execution_id = ?", (eid,))[0])

    def record_approval(self, *, execution_id: str, target_id: str, action: str, safety: str, approved: bool,
                        actor: str, note: str | None = None) -> None:
        self._insert("approvals", {"id": new_id(), "execution_id": execution_id, "target_id": target_id,
                                   "action": action, "safety_class": safety,
                                   "decision": "approved" if approved else "denied",
                                   "decided_by": actor, "decided_at": iso(), "note": note})

    def log(self, eid: str | None, level: str, event: str, message: str, *, unit_id: str | None = None,
            **ctx: Any) -> None:
        self._insert("execution_logs", {"execution_id": eid, "module_execution_id": unit_id, "ts": iso(),
                                        "level": level, "event": event, "message": message, "context_json": ctx})
