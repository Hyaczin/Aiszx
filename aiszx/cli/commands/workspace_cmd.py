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
