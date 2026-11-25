"""Crash recovery and resume decisions.

Startup reconciliation (runs before every orchestrated command)
    Executions still marked RUNNING whose owner process is gone (dead pid, different boot,
    or stale heartbeat from another host) become INTERRUPTED, together with their running
    units and attempts. Stale locks are released.

Resume decision for each unit of the run being resumed
    =====================  =============================================  ==================
    previous state         check                                          decision
    =====================  =============================================  ==================
    COMPLETED              outputs present + hashes match, module output  reuse
                           validation OK, same input/config fingerprint,
                           same module version
    COMPLETED              output files missing or modified               recover (re-run,
                                                                          RECOVERY_REQUIRED
                                                                          until confirmed)
    COMPLETED              inputs/config/module version changed           rerun (reason shown)
    FAILED/INTERRUPTED/…   (resumable modules get the previous attempt)   rerun
    SKIPPED                now runnable?                                  run / skip
    (not in old plan)      –                                              run
    =====================  =============================================  ==================
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

from aiszx.core.timeutil import iso, parse_iso, utcnow
from aiszx.db.connection import Database
from aiszx.orchestrator.fingerprint import file_sha256
from aiszx.orchestrator.locks import LockManager
from aiszx.orchestrator.planner import PlannedUnit
from aiszx.orchestrator.procutil import Owner
from aiszx.orchestrator.state import (
    COMPLETED,
    EXEC_INTERRUPTED,
    EXEC_RUNNING,
    INTERRUPTED,
    PENDING,
    RECOVERY_REQUIRED,
    RUNNING,
    SKIPPED,
)


def reconcile(db: Database, owner: Owner, stale_after: int) -> list[str]:
    messages: list[str] = []
    for ex in db.query("SELECT * FROM executions WHERE status = ?", (EXEC_RUNNING,)):
        if ex["owner_pid"] == owner.pid and ex["owner_host"] == owner.host:
            continue
        alive = owner.is_alive(ex["owner_pid"], ex["owner_host"], ex["boot_id"])
        if alive is None:
            beat = ex["heartbeat_at"] or ex["started_at"]
            alive = utcnow() - parse_iso(beat) < timedelta(seconds=stale_after)
        if alive:
            continue
        now = iso()
        with db.transaction():
            n = db.execute(
                "UPDATE module_executions SET state = ?, ended_at = ?, error_class = 'interrupted',"
                " error_message = 'the Aiszx process ended while this unit was running' WHERE execution_id = ? AND state = ?",
                (INTERRUPTED, now, ex["id"], RUNNING)).rowcount
            db.execute(
                "UPDATE module_attempts SET status = 'interrupted', ended_at = ? WHERE status = 'running'"
                " AND module_execution_id IN (SELECT id FROM module_executions WHERE execution_id = ?)",
                (now, ex["id"]))
            db.execute("UPDATE executions SET status = ?, ended_at = ? WHERE id = ?", (EXEC_INTERRUPTED, now, ex["id"]))
        messages.append(f"run {ex['run_id']} was interrupted (process {ex['owner_pid']} on {ex['owner_host']} is gone); "
                        f"{n} running unit(s) marked INTERRUPTED. Continue it with `resume`.")
    stale = LockManager(db, owner, stale_after).reap_stale()
    if stale:
        messages.append(f"released {len(stale)} stale lock(s)")
    return messages


def verify_outputs(run_dir: Path, outputs: list[dict]) -> list[str]:
    """Compare recorded output files with what is on disk."""
    problems = []
    for item in outputs:
        path = run_dir / item["path"]
        if not path.is_file():
            problems.append(f"missing {item['path']}")
            continue
        try:
            if file_sha256(path) != item["sha256"]:
                problems.append(f"modified {item['path']}")
        except OSError as exc:
            problems.append(f"unreadable {item['path']}: {exc.strerror}")
    return problems


def decide(pu: PlannedUnit, row, run_dir: Path) -> None:
    """Set pu.decision / pu.state for resume based on the previous unit row (None if new)."""
    if row is None:
        if pu.state != SKIPPED:
            pu.decision, pu.decision_reason = "run", "not part of the previous plan"
        return
    pu.row_id = row["id"]
    pu.attempts_done = row["attempt"]
    prev = row["state"]

    if prev == COMPLETED:
        outputs = json.loads(row["outputs_json"] or "[]")
        problems = verify_outputs(run_dir, outputs)
        if not problems and row["output_dir"]:
            problems = pu.module.validate_outputs(pu.unit, run_dir / row["output_dir"])
        changes = []
        if row["input_fingerprint"] != pu.input_fp:
            changes.append("inputs changed")
        if row["config_fingerprint"] != pu.config_fp:
            changes.append("configuration changed")
        if row["module_version"] != pu.module.meta.version:
            changes.append(f"module version {row['module_version']} -> {pu.module.meta.version}")
        if problems:
            pu.decision, pu.decision_reason = "recover", "; ".join(problems)
            pu.state = RECOVERY_REQUIRED if pu.state != SKIPPED else SKIPPED
        elif changes:
            if pu.state == SKIPPED:
                pu.decision, pu.decision_reason = "skip", f"{'; '.join(changes)}, but cannot re-run: {pu.skip_reason}"
            else:
                pu.decision, pu.decision_reason, pu.state = "rerun", "; ".join(changes), PENDING
        else:
            pu.decision, pu.decision_reason, pu.state = "reuse", "outputs verified", COMPLETED
        return

    if pu.state == SKIPPED:
        pu.decision, pu.decision_reason = "skip", pu.skip_reason or "skipped"
        return
    pu.state = PENDING
    if prev == SKIPPED:
        pu.decision, pu.decision_reason = "run", "previously skipped; now runnable"
    elif prev == PENDING:
        pu.decision, pu.decision_reason = "run", "never started"
    else:
        pu.decision, pu.decision_reason = "rerun", f"previously {prev}" + (
            f": {row['error_message']}" if row["error_message"] else "")
        if pu.module.meta.resumable and row["output_dir"]:
            pu.previous_attempt_dir = run_dir / row["output_dir"]
