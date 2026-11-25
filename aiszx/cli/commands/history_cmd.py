"""``history TARGET [--run RUN_ID]``: past runs of a target and the details of one run.

Run-to-run comparison (`compare`) is added in Milestone 8.
"""

from __future__ import annotations

import argparse
import json

from aiszx.app import AppContext
from aiszx.cli.commands import engagement_slug
from aiszx.cli.output import emit_json, kv, table
from aiszx.core.errors import NotFoundError
from aiszx.orchestrator.state import ExecutionStore


def register(sub: argparse._SubParsersAction, common: argparse.ArgumentParser) -> None:
    h = sub.add_parser("history", parents=[common], help="list a target's runs, or show one run in detail")
    h.add_argument("target")
    h.add_argument("--run", dest="run_id", metavar="RUN_ID", help="show this run's units, attempts and evidence")
    h.add_argument("--json", action="store_true")
    h.set_defaults(handler=cmd_history)


def _counts(row) -> str:
    summary = json.loads(row["summary_json"] or "{}")
    return ", ".join(f"{n} {s.lower()}" for s, n in sorted(summary.items())) or "-"


def cmd_history(ctx: AppContext, args: argparse.Namespace) -> int:
    eng = ctx.engagements().get(engagement_slug(ctx, args))
    target = ctx.targets().get(eng, args.target)
    store = ExecutionStore(ctx.db)
    if not args.run_id:
        rows = store.executions_for_target(target.id)
        if args.json:
            emit_json([{k: r[k] for k in ("run_id", "command", "profile", "status", "started_at", "ended_at",
                                          "pinned_address", "workspace_path")} | {"units": json.loads(r["summary_json"])}
                       for r in rows])
            return 0
        if not rows:
            print(f"No runs yet for {target.canonical}. Start one with `run {target.canonical} -m core.connectivity`.")
            return 0
        print(f"Runs of {target.canonical} (engagement {eng.slug})")
        print(table([(r["run_id"], r["command"], r["profile"], r["status"], _counts(r), r["started_at"],
                      r["ended_at"] or "-") for r in rows],
                    ("RUN", "COMMAND", "PROFILE", "STATUS", "UNITS", "STARTED", "ENDED")))
        return 0

    ex = store.find_run(target.id, args.run_id)
    if ex is None:
        raise NotFoundError(f"run {args.run_id} not found for {target.canonical}")
    units = store.units(ex["id"])
    if args.json:
        emit_json({"run": {k: ex[k] for k in ex.keys() if k not in ("config_snapshot",)}
                   | {"config": json.loads(ex["config_snapshot"])},
                   "units": [dict(u) | {"attempts": [dict(a) for a in store.attempts(u["id"])]} for u in units]})
        return 0
    snapshot = json.loads(ex["config_snapshot"])
    print(f"Run {ex['run_id']} of {target.canonical}: {ex['status']}")
    print(kv([
        ("command", f"{ex['command']} -m {' -m '.join(snapshot['modules'])}"), ("profile", ex["profile"]),
        ("safety ceiling", snapshot.get("ceiling")), ("address", ex["pinned_address"]),
        ("started", ex["started_at"]), ("ended", ex["ended_at"]),
        ("workspace", ctx.config.data_dir / ex["workspace_path"]),
        ("evidence files", store.evidence_count(ex["id"])), ("units", _counts(ex)),
    ]))
    rows = []
    for u in units:
        detail = u["summary"] or u["error_message"] or u["skip_reason"] or ""
        rows.append((u["module_id"], u["unit_key"], u["state"], u["attempt"], detail[:110]))
    print(table(rows, ("MODULE", "UNIT", "STATE", "ATTEMPTS", "DETAIL"), indent="  "))
    return 0
