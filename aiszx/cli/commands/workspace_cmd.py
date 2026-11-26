"""``workspace verify [--repair]``."""

from __future__ import annotations

import argparse

from aiszx.app import AppContext
from aiszx.cli.commands import engagement_slug, help_handler


def register(sub: argparse._SubParsersAction, common: argparse.ArgumentParser) -> None:
    p = sub.add_parser("workspace", help="verify and repair workspace directory structure")
    p.set_defaults(handler=help_handler(p))
    wsub = p.add_subparsers(dest="workspace_action", metavar="ACTION")
    v = wsub.add_parser("verify", parents=[common], help="check engagement and target workspaces",
                        description="Checks that every expected directory exists. --repair recreates missing "
                                    "directories and tightens protected-directory permissions; file content is never touched.")
    v.add_argument("target", nargs="?", help="limit to one target")
    v.add_argument("--repair", action="store_true")
    v.set_defaults(handler=cmd_verify)

    s = wsub.add_parser("stats", parents=[common], help="disk usage per engagement, target and run (read-only)",
                        description="Shows where disk space goes. Nothing is deleted: Aiszx never removes evidence "
                                    "automatically. Remove old runs yourself only after a `backup` if you need space.")
    s.add_argument("--all", action="store_true", help="all engagements (default: the selected engagement)")
    s.add_argument("--top", type=int, default=10, help="number of largest runs to list (default 10)")
    s.add_argument("--json", action="store_true")
    s.set_defaults(handler=cmd_stats)


def cmd_stats(ctx: AppContext, args: argparse.Namespace) -> int:
    from aiszx.cli.output import emit_json, table
    from aiszx.maintenance.stats import human, workspace_stats

    stats = workspace_stats(ctx, None if args.all else engagement_slug(ctx, args), top=max(1, args.top))
    if args.json:
        emit_json(stats)
        return 0
    rows = []
    for e in stats["engagements"]:
        for t in sorted(e["targets"], key=lambda t: -t["bytes"]):
            rows.append((e["engagement"], t["target"], t["runs"], t["files"], human(t["bytes"])))
        if e.get("range_runs_bytes"):
            rows.append((e["engagement"], "(range discovery runs)", "-", "-", human(e["range_runs_bytes"])))
    print(table(rows, ("ENGAGEMENT", "TARGET", "RUNS", "FILES", "SIZE")) if rows else "No targets.")
    if stats["largest_runs"]:
        print("\nLargest runs")
        print(table([(r["run_id"], r["target"], r["command"], r["status"], human(r["bytes"]))
                     for r in stats["largest_runs"]], ("RUN", "TARGET", "COMMAND", "STATUS", "SIZE"), indent="  "))
    print(f"\ndatabase {human(stats['database_bytes'])}, logs {human(stats['log_bytes'])}, "
          f"total {human(stats['total_bytes'])}")
    return 0


def cmd_verify(ctx: AppContext, args: argparse.Namespace) -> int:
    eng = ctx.engagements().get(engagement_slug(ctx, args))
    manager = ctx.targets()
    targets = [manager.get(eng, args.target)] if args.target else manager.list(eng, include_archived=True)

    reports = [("engagement " + eng.slug, ctx.layout.verify_engagement(eng.slug, repair=args.repair))]
    reports += [(f"target {t.canonical}", ctx.layout.verify_target(eng.slug, t.slug, repair=args.repair)) for t in targets]

    known = {t.slug for t in manager.list(eng, include_archived=True)}
    orphans = [d for d in ctx.layout.list_target_dirs(eng.slug) if d not in known]

    failures = 0
    for label, report in reports:
        if report.ok:
            status = f"ok (repaired {len(report.repaired)})" if report.repaired else "ok"
        else:
            failures += 1
            status = f"{len(report.missing) - len(report.repaired)} missing, {len(report.problems)} problem(s)"
        print(f"{label}: {status}")
        for m in report.missing:
            print(f"    {'repaired' if m in report.repaired else 'missing'}: {m}")
        for problem in report.problems:
            print(f"    problem: {problem}")
    if not args.target:
        for orphan in orphans:
            print(f"warning: directory targets/{orphan} has no matching registered target (left untouched)")
    if failures and not args.repair:
        print("Run again with --repair to recreate missing directories.")
    return 0 if failures == 0 else 6
