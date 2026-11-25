"""``engagement add|list|show``."""

from __future__ import annotations

import argparse
from pathlib import Path

from aiszx.app import AppContext
from aiszx.cli.commands import help_handler
from aiszx.cli.output import emit_json, kv, table


def register(sub: argparse._SubParsersAction, common: argparse.ArgumentParser) -> None:
    p = sub.add_parser("engagement", help="create and inspect engagements (scope + target groupings)")
    p.set_defaults(handler=help_handler(p))
    esub = p.add_subparsers(dest="engagement_action", metavar="ACTION")

    a = esub.add_parser("add", parents=[common], help="create an engagement")
    a.add_argument("slug", help="short name used on disk and with -e (a-z, 0-9, '-', '_')")
    a.add_argument("--name", help="descriptive name")
    a.add_argument("--description")
    a.add_argument("--auth-ref", dest="authorisation_ref", help="authorisation reference (contract, ticket, lab name)")
    a.add_argument("--valid-from", help="start of the testing window (YYYY-MM-DD or ISO-8601, UTC)")
    a.add_argument("--valid-until", help="end of the testing window (a bare date means end of that day, UTC)")
    a.add_argument("--scope-file", type=Path, help="import scope rules from a YAML file (see config/templates/scope.example.yaml)")
    a.set_defaults(handler=cmd_add)

    ls = esub.add_parser("list", parents=[common], help="list engagements")
    ls.add_argument("--all", action="store_true", help="include archived engagements")
    ls.add_argument("--json", action="store_true")
    ls.set_defaults(handler=cmd_list)

    up = esub.add_parser("update", parents=[common], help="change metadata, validity window or rules of engagement")
    up.add_argument("slug", nargs="?", help="engagement (default: -e or the default engagement)")
    up.add_argument("--name")
    up.add_argument("--description")
    up.add_argument("--auth-ref", dest="authorisation_ref")
    up.add_argument("--valid-from")
    up.add_argument("--valid-until")
    up.add_argument("--max-safety", choices=("passive", "active_safe", "active_noisy", "intrusive"),
                    help="rules of engagement: most aggressive module safety class allowed (lowers any profile)")
    up.add_argument("--clear", action="append", default=[], choices=("valid_from", "valid_until", "max_safety"),
                    help="remove a setting; repeatable")
    up.set_defaults(handler=cmd_update)

    sh = esub.add_parser("show", parents=[common], help="show one engagement")
    sh.add_argument("slug", nargs="?", help="engagement (default: -e or the default engagement)")
    sh.add_argument("--json", action="store_true")
    sh.set_defaults(handler=cmd_show)


def cmd_add(ctx: AppContext, args: argparse.Namespace) -> int:
    store = ctx.engagements()
    eng = store.create(
        args.slug, name=args.name, description=args.description, authorisation_ref=args.authorisation_ref,
        valid_from=args.valid_from, valid_until=args.valid_until,
    )
    print(f"Created engagement '{eng.slug}'")
    print(kv([("workspace", ctx.layout.engagement_dir(eng.slug)), ("validity", eng.validity())]))
    if args.scope_file:
        scope = ctx.scope()
        result = scope.import_file(eng, args.scope_file)
        scope.write_mirror(eng)
        print(f"Imported {len(result.added)} scope rule(s) from {args.scope_file}")
    print(f"Use it with: python3 pentest.py -e {eng.slug} target add <host>")
    return 0


def cmd_update(ctx: AppContext, args: argparse.Namespace) -> int:
    slug = args.slug or args.engagement or ctx.config.default_engagement
    eng = ctx.engagements().update(
        slug, name=args.name, description=args.description, authorisation_ref=args.authorisation_ref,
        valid_from=args.valid_from, valid_until=args.valid_until, max_safety=args.max_safety,
        clear=tuple(args.clear),
    )
    print(f"Engagement '{eng.slug}'")
    print(kv([("validity", eng.validity()), ("valid from", eng.valid_from), ("valid until", eng.valid_until),
              ("max safety (RoE)", eng.roe.get("max_safety")), ("authorisation", eng.authorisation_ref)]))
    return 0


def cmd_list(ctx: AppContext, args: argparse.Namespace) -> int:
    engagements = ctx.engagements().list(include_archived=args.all)
    manager, scope = ctx.targets(), ctx.scope()
    rows = []
    payload = []
    for eng in engagements:
        n_targets = len(manager.list(eng))
        n_rules = len(scope.rules(eng))
        rows.append((eng.slug, eng.name, eng.validity(), n_rules, n_targets, eng.authorisation_ref))
        payload.append({**eng.to_dict(), "scope_rules": n_rules, "active_targets": n_targets})
    if args.json:
        emit_json(payload)
    else:
        print(table(rows, ("ENGAGEMENT", "NAME", "VALIDITY", "RULES", "TARGETS", "AUTH REF")))
    return 0


def cmd_show(ctx: AppContext, args: argparse.Namespace) -> int:
    slug = args.slug or args.engagement or ctx.config.default_engagement
    eng = ctx.engagements().get(slug)
    rules = ctx.scope().rules(eng)
    targets = ctx.targets().list(eng, include_archived=True)
    if args.json:
        emit_json({**eng.to_dict(), "scope_rules": [r.to_dict() for r in rules],
                   "targets": [t.canonical for t in targets], "workspace": str(ctx.layout.engagement_dir(eng.slug))})
        return 0
    print(f"Engagement '{eng.slug}'")
    print(kv([
        ("name", eng.name), ("description", eng.description), ("authorisation", eng.authorisation_ref),
        ("valid from", eng.valid_from), ("valid until", eng.valid_until), ("validity", eng.validity()),
        ("max safety (RoE)", eng.roe.get("max_safety")),
        ("scope rules", len(rules)),
        ("targets", f"{sum(t.status == 'active' for t in targets)} active, {sum(t.status == 'archived' for t in targets)} archived"),
        ("workspace", ctx.layout.engagement_dir(eng.slug)), ("created", eng.created_at),
    ]))
    return 0
