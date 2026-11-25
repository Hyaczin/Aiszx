"""``scope show|add|remove|check|import``."""

from __future__ import annotations

import argparse
from pathlib import Path

from aiszx.app import AppContext
from aiszx.cli.commands import engagement_slug, help_handler
from aiszx.cli.output import emit_json, format_decision, kv, table
from aiszx.targets.engagements import Engagement
from aiszx.targets.identity import normalise_target
from aiszx.targets.scope import EXCLUDE, INCLUDE


def register(sub: argparse._SubParsersAction, common: argparse.ArgumentParser) -> None:
    p = sub.add_parser("scope", help="manage and check the engagement's authorised scope")
    p.set_defaults(handler=help_handler(p))
    ssub = p.add_subparsers(dest="scope_action", metavar="ACTION")

    sh = ssub.add_parser("show", parents=[common], help="show scope rules, or the scope decision for a registered target")
    sh.add_argument("target", nargs="?")
    sh.add_argument("--json", action="store_true")
    sh.set_defaults(handler=cmd_show)

    for name, helptext in (("add", "add a rule"), ("remove", "remove a rule")):
        sp = ssub.add_parser(name, parents=[common], help=helptext,
                             description="VALUE is an IP, CIDR (10.10.10.0/24), hostname or *.domain (subdomains only).")
        sp.add_argument("value")
        sp.add_argument("--exclude", action="store_true", help="operate on an exclude rule (exclusions always win)")
        if name == "add":
            sp.add_argument("--note")
        sp.set_defaults(handler=cmd_add if name == "add" else cmd_remove)

    ck = ssub.add_parser("check", parents=[common], help="check whether an IP/hostname is in scope (no registration)")
    ck.add_argument("value")
    ck.add_argument("--no-resolve", action="store_true")
    ck.add_argument("--json", action="store_true")
    ck.set_defaults(handler=cmd_check)

    im = ssub.add_parser("import", parents=[common], help="import rules from a YAML scope file")
    im.add_argument("file", type=Path)
    im.add_argument("--replace", action="store_true", help="delete existing rules first (asks for confirmation)")
    im.set_defaults(handler=cmd_import)


def _after_change(ctx: AppContext, eng: Engagement) -> None:
    ctx.scope().write_mirror(eng)
    out = [(t, d) for t, d in ctx.targets().refresh_scope_flags(eng) if not d.in_scope]
    for t, d in out:
        print(f"warning: registered target {t.canonical} is now OUT of scope: {'; '.join(d.reasons)}")


def cmd_show(ctx: AppContext, args: argparse.Namespace) -> int:
    eng = ctx.engagements().get(engagement_slug(ctx, args))
    if args.target:
        manager = ctx.targets()
        t = manager.get(eng, args.target)
        decision = manager.decide(t)
        if args.json:
            emit_json({"engagement": eng.slug, "validity": eng.validity(), **decision.to_dict()})
        else:
            print(f"Scope decision in engagement '{eng.slug}' (validity: {eng.validity()})")
            print(format_decision(decision))
        return 0 if decision.in_scope else 3

    rules = ctx.scope().rules(eng)
    if args.json:
        emit_json({"engagement": eng.slug, "validity": eng.validity(), "valid_from": eng.valid_from,
                   "valid_until": eng.valid_until, "rules": [r.to_dict() for r in rules]})
        return 0
    print(f"Scope for engagement '{eng.slug}'")
    print(kv([("validity", eng.validity()), ("valid from", eng.valid_from), ("valid until", eng.valid_until),
              ("hostname resolution", "strict" if ctx.config.scope.strict_hostname_resolution else "lenient")]))
    if rules:
        print(table([(r.action, r.rule_type, r.value, r.note) for r in rules], ("ACTION", "TYPE", "VALUE", "NOTE")))
    else:
        print("No scope rules: nothing is in scope. Add one with `scope add <ip|cidr|hostname>`.")
    return 0


def cmd_add(ctx: AppContext, args: argparse.Namespace) -> int:
    eng = ctx.engagements().get(engagement_slug(ctx, args))
    result = ctx.scope().add(eng, args.value, EXCLUDE if args.exclude else INCLUDE, args.note)
    if result.normalisation:
        print(f"note: {result.normalisation}")
    print(f"{'Added' if result.created else 'Already present'}: {result.rule.describe()}")
    if result.created:
        _after_change(ctx, eng)
    return 0


def cmd_remove(ctx: AppContext, args: argparse.Namespace) -> int:
    eng = ctx.engagements().get(engagement_slug(ctx, args))
    rule = ctx.scope().remove(eng, args.value, EXCLUDE if args.exclude else INCLUDE)
    print(f"Removed: {rule.describe()}")
    _after_change(ctx, eng)
    return 0


def cmd_check(ctx: AppContext, args: argparse.Namespace) -> int:
    eng = ctx.engagements().get(engagement_slug(ctx, args))
    identity = normalise_target(args.value)
    addresses: list[str] = []
    if not identity.is_ip and not args.no_resolve and ctx.config.scope.resolve_hostnames:
        from aiszx.targets import resolver
        addresses = resolver.resolve_host(identity.canonical)
    decision = ctx.scope().policy(eng).evaluate(identity, addresses)
    if args.json:
        emit_json({"engagement": eng.slug, "validity": eng.validity(), **decision.to_dict()})
    else:
        print(f"Engagement '{eng.slug}' (validity: {eng.validity()})")
        print(format_decision(decision))
    return 0 if decision.in_scope else 3


def cmd_import(ctx: AppContext, args: argparse.Namespace) -> int:
    from aiszx.cli.output import confirm

    eng = ctx.engagements().get(engagement_slug(ctx, args))
    if args.replace and not confirm(f"Replace ALL scope rules of engagement '{eng.slug}'?", assume_yes=ctx.assume_yes):
        print("Import cancelled.")
        return 1
    result = ctx.scope().import_file(eng, args.file, replace=args.replace)
    print(f"Imported from {args.file}: {len(result.added)} added, {len(result.existing)} already present"
          + (f", {result.removed} removed first" if args.replace else ""))
    _after_change(ctx, eng)
    return 0
