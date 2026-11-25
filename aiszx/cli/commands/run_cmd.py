"""``run`` (new run of selected modules) and ``resume`` (continue an interrupted or partial run)."""

from __future__ import annotations

import argparse
import sys
from typing import Any

from aiszx.app import AppContext
from aiszx.cli.commands import engagement_slug
from aiszx.cli.output import confirm, table
from aiszx.orchestrator.orchestrator import RunReport
from aiszx.orchestrator.planner import PlannedUnit
from aiszx.orchestrator.state import EXEC_COMPLETED, EXEC_INTERRUPTED

EXIT = {EXEC_COMPLETED: 0, EXEC_INTERRUPTED: 130}


def register(sub: argparse._SubParsersAction, common: argparse.ArgumentParser) -> None:
    r = sub.add_parser(
        "run", parents=[common], help="run selected modules against a registered target (creates a new run)",
        description="Creates a new run directory, plans the selected modules (safety ceiling, tool checks), "
                    "and executes them. Every command is checked against scope before it starts. "
                    "Ctrl+C stops cleanly; continue later with `resume`.",
    )
    r.add_argument("target")
    r.add_argument("-m", "--module", dest="modules", action="append", required=True, metavar="MODULE",
                   help="module id, family (e.g. 'core') or service category; repeatable")
    r.add_argument("--profile", help="execution profile (default: orchestrator.default_profile)")
    r.add_argument("--approve", action="append", default=[], metavar="MODULE",
                   help="pre-approve an INTRUSIVE module for this run (otherwise you are asked interactively)")
    r.set_defaults(handler=cmd_run)

    rs = sub.add_parser(
        "resume", parents=[common], help="resume the last (or a given) run of a target",
        description="Re-checks scope, verifies the outputs of completed units (presence, SHA-256, inputs, "
                    "configuration, module version), shows what will be reused or re-run, and continues.",
    )
    rs.add_argument("target")
    g = rs.add_mutually_exclusive_group()
    g.add_argument("--run", dest="run_id", metavar="RUN_ID", help="run to resume (see `history TARGET`)")
    g.add_argument("--last-run", action="store_true", help="resume the most recent run (the default)")
    rs.add_argument("--approve", action="append", default=[], metavar="MODULE")
    rs.set_defaults(handler=cmd_resume)


def _approver(args: argparse.Namespace):
    def approve(pu: PlannedUnit) -> bool:
        if pu.module.meta.id in args.approve:
            print(f"  approved by --approve: {pu.label}")
            return True
        if not sys.stdin.isatty():
            print(f"  not approved (no terminal; use --approve {pu.module.meta.id}): {pu.label}")
            return False
        print(f"\nINTRUSIVE module {pu.label}: {pu.module.meta.description}")
        # --yes deliberately does not approve intrusive modules.
        return confirm("Approve running it against this target now?", assume_yes=False)
    return approve


def _plan_rows(units: list[PlannedUnit]) -> list[tuple]:
    rows = []
    for pu in units:
        note = pu.decision_reason if pu.decision != "run" or pu.state == "SKIPPED" else ""
        if pu.needs_approval and pu.state != "SKIPPED":
            note = (note + "; " if note else "") + "needs approval"
        rows.append((pu.module.meta.id, pu.unit.key, pu.module.meta.safety.value, pu.decision, note))
    return rows


def _announce(units: list[PlannedUnit], info: dict[str, Any]) -> None:
    if info.get("layer", 0) == 0:
        verb = "Run" if info.get("new_run", True) else "Resuming run"
        print(f"{verb} {info['run_id']}: {info['target']} (engagement {info['engagement']}, profile {info['profile']})")
        print(f"  address   : {info['address']}")
        print(f"  workspace : {info['run_dir']}")
    if units:
        stage = units[0].module.meta.stage.value
        print(f"\n  stage {stage}:")
        print(table(_plan_rows(units), ("MODULE", "UNIT", "SAFETY", "ACTION", "NOTE"), indent="  "))


def _finish(report: RunReport, ctx: AppContext, args: argparse.Namespace) -> int:
    for msg in report.messages:
        print(f"note: {msg}")
    counts = report.counts
    parts = ", ".join(f"{n} {s.lower()}" for s, n in sorted(counts.items()))
    print(f"\nRun {report.run_id}: {report.status} ({parts})")
    if not any(counts.get(s) for s in ("COMPLETED", "FAILED", "INTERRUPTED")):
        print("Nothing was executed: every unit was skipped (reasons above).")
    eng = engagement_slug(ctx, args)
    prefix = "python3 pentest.py" + ("" if eng == ctx.config.default_engagement else f" -e {eng}")
    print(f"Details: {prefix} history {args.target} --run {report.run_id}")
    if report.status == EXEC_INTERRUPTED:
        print(f"Continue with: {prefix} resume {args.target}")
    return EXIT.get(report.status, 1)


def cmd_run(ctx: AppContext, args: argparse.Namespace) -> int:
    orch = ctx.orchestrator(approve=_approver(args), progress=print, announce=_announce)
    report = orch.start(engagement_slug(ctx, args), args.target, args.modules, profile=args.profile)
    return _finish(report, ctx, args)


def cmd_resume(ctx: AppContext, args: argparse.Namespace) -> int:
    def confirm_plan(units: list[PlannedUnit]) -> bool:
        print("Resume plan:")
        print(table(_plan_rows(units), ("MODULE", "UNIT", "SAFETY", "ACTION", "REASON"), indent="  "))
        recover = [pu for pu in units if pu.decision == "recover"]
        if recover:
            print(f"\n{len(recover)} completed unit(s) have missing or modified outputs and will be re-run "
                  "(the previous attempt directories are kept).")
        return confirm("Continue?", assume_yes=ctx.assume_yes)

    orch = ctx.orchestrator(approve=_approver(args), progress=print, confirm=confirm_plan,
                            announce=lambda u, i: _announce(u, i) if i.get("layer", 0) > 0 and u else None)
    report = orch.resume(engagement_slug(ctx, args), args.target, run_id=args.run_id)
    if any(m.startswith(("nothing to resume", "resume cancelled")) for m in report.messages):
        for msg in report.messages:
            print(msg)
        return 0
    return _finish(report, ctx, args)
