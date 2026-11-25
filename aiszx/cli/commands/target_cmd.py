"""``target add|list|show|remove``."""

from __future__ import annotations

import argparse
import sys

from aiszx.app import AppContext
from aiszx.cli.commands import engagement_slug, help_handler
from aiszx.cli.output import emit_json, format_decision, kv, table
from aiszx.targets.engagements import ACTIVE


def register(sub: argparse._SubParsersAction, common: argparse.ArgumentParser) -> None:
    p = sub.add_parser("target", help="register, list, inspect and remove targets")
    p.set_defaults(handler=help_handler(p))
    tsub = p.add_subparsers(dest="target_action", metavar="ACTION")

    a = tsub.add_parser("add", parents=[common], help="register a target (IP address or hostname)",
                        description="Register a target in the engagement. It must be in scope.")
    a.add_argument("target", help="IPv4/IPv6 address or hostname")
    a.add_argument("--scope", dest="add_to_scope", action="store_true",
                   help="if out of scope, add an include rule for exactly this target (recorded in the audit log)")
    a.add_argument("--no-resolve", action="store_true", help="do not resolve hostnames now")
    a.add_argument("--notes", help="free-text notes")
    a.set_defaults(handler=cmd_add)

    ls = tsub.add_parser("list", parents=[common], help="list targets in the engagement")
    ls.add_argument("--all", action="store_true", help="include archived targets")
    ls.add_argument("--json", action="store_true")
    ls.set_defaults(handler=cmd_list)

    sh = tsub.add_parser("show", parents=[common], help="show target details, addresses, scope and workspace")
    sh.add_argument("target")
    sh.add_argument("--json", action="store_true")
    sh.set_defaults(handler=cmd_show)

    rm = tsub.add_parser("remove", parents=[common], help="archive a target (default) or permanently purge it",
                         description="Archiving hides the target but keeps its workspace and history; "
                                     "`target add` reactivates it. --purge deletes the workspace and all records.")
    rm.add_argument("target")
    rm.add_argument("--purge", action="store_true", help="permanently delete records and workspace (irreversible)")
    rm.add_argument("--confirm", metavar="TARGET", help="non-interactive purge confirmation: repeat the target exactly")
    rm.set_defaults(handler=cmd_remove)


def cmd_add(ctx: AppContext, args: argparse.Namespace) -> int:
    result = ctx.targets().add(
        engagement_slug(ctx, args), args.target, add_to_scope=args.add_to_scope,
        resolve=False if args.no_resolve else None, notes=args.notes,
    )
    t = result.target
    verb = "Registered" if result.created else ("Reactivated" if result.reactivated else "Refreshed")
    print(f"{verb} {t.canonical} in engagement '{t.engagement.slug}'")
    pairs = [("kind", t.kind), ("workspace", ctx.layout.target_dir(t.engagement.slug, t.slug))]
    if t.kind == "hostname":
        pairs.append(("addresses", ", ".join(t.current_addresses) or ("(not resolved)" if result.resolved else "(resolution skipped)")))
    if result.scope_rule_added:
        pairs.append(("scope rule added", result.scope_rule_added))
    print(kv(pairs))
    print(format_decision(result.decision))
    validity = t.engagement.validity()
    if validity != ACTIVE:
        print(f"warning: engagement '{t.engagement.slug}' is {validity}; testing will be refused outside its validity window",
              file=sys.stderr)
    return 0


def cmd_list(ctx: AppContext, args: argparse.Namespace) -> int:
    manager = ctx.targets()
    eng = ctx.engagements().get(engagement_slug(ctx, args))
    targets = manager.list(eng, include_archived=args.all)
    decisions = {t.id: manager.decide(t) for t in targets}
    if args.json:
        emit_json([{**t.to_dict(), "scope": decisions[t.id].to_dict()} for t in targets])
        return 0
    if not targets:
        print(f"No targets in engagement '{eng.slug}'. Register one with `target add <ip|hostname>`.")
        return 0
    rows = [
        (t.canonical, t.kind, t.status, ", ".join(t.current_addresses) if t.kind == "hostname" else "",
         "in" if decisions[t.id].in_scope else "OUT", t.created_at)
        for t in targets
    ]
    print(f"Engagement '{eng.slug}'")
    print(table(rows, ("TARGET", "KIND", "STATUS", "ADDRESSES", "SCOPE", "REGISTERED")))
    return 0


def cmd_show(ctx: AppContext, args: argparse.Namespace) -> int:
    manager = ctx.targets()
    eng = ctx.engagements().get(engagement_slug(ctx, args))
    t = manager.get(eng, args.target)
    decision = manager.decide(t)
    workspace = ctx.layout.target_dir(eng.slug, t.slug)
    report = ctx.layout.verify_target(eng.slug, t.slug)
    runs_dir = ctx.layout.target_runs_dir(eng.slug, t.slug)
    runs = sorted(p.name for p in runs_dir.iterdir() if p.is_dir()) if runs_dir.is_dir() else []
    if args.json:
        emit_json({**t.to_dict(), "scope": decision.to_dict(), "workspace": str(workspace),
                   "workspace_ok": report.ok, "workspace_missing": [str(m) for m in report.missing], "runs": runs})
        return 0
    print(f"Target {t.canonical}")
    print(kv([
        ("engagement", eng.slug), ("kind", t.kind), ("status", t.status), ("source", t.source), ("notes", t.notes),
        ("registered", t.created_at), ("updated", t.updated_at), ("archived", t.archived_at),
        ("workspace", workspace),
        ("workspace state", "ok" if report.ok else f"{len(report.missing)} missing dir(s), {len(report.problems)} problem(s)"
                            " — run `workspace verify --repair`"),
        ("runs", len(runs)),
    ]))
    if t.addresses:
        print("  addresses:")
        print(table([(a.address, a.source, "in" if a.in_scope else "OUT", a.first_seen, a.last_seen) for a in t.addresses],
                    ("ADDRESS", "SOURCE", "SCOPE", "FIRST SEEN", "LAST SEEN"), indent="    "))
    print("  scope:")
    print(format_decision(decision, indent="    "))
    return 0


def cmd_remove(ctx: AppContext, args: argparse.Namespace) -> int:
    manager = ctx.targets()
    eng = ctx.engagements().get(engagement_slug(ctx, args))
    if not args.purge:
        t, changed = manager.archive(eng, args.target)
        print(f"Archived {t.canonical} (workspace kept at {ctx.layout.target_dir(eng.slug, t.slug)})" if changed
              else f"{t.canonical} is already archived")
        return 0

    t = manager.get(eng, args.target)
    workspace = ctx.layout.target_dir(eng.slug, t.slug)
    print(f"PURGE {t.canonical}: permanently deletes all records and the workspace {workspace}", file=sys.stderr)
    if args.confirm is not None:
        ok = args.confirm.strip().lower() == t.canonical
    elif sys.stdin.isatty():
        try:
            ok = input(f"Type '{t.canonical}' to confirm: ").strip().lower() == t.canonical
        except EOFError:
            ok = False
    else:
        ok = False
        print("refusing: no interactive terminal; pass --confirm <target>", file=sys.stderr)
    if not ok:
        print("Purge cancelled.", file=sys.stderr)
        return 1
    manager.purge(eng, t.canonical)
    print(f"Purged {t.canonical}")
    return 0
