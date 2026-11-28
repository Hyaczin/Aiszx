"""``hints list|accept|remove``: host names seen for a target, and the virtual hosts accepted for it."""

from __future__ import annotations

import argparse

from aiszx.app import AppContext
from aiszx.cli.commands import engagement_slug, help_handler
from aiszx.cli.output import confirm, emit_json, table
from aiszx.core.errors import ValidationError
from aiszx.targets.identity import normalise_hostname


def register(sub: argparse._SubParsersAction, common: argparse.ArgumentParser) -> None:
    p = sub.add_parser("hints", help="host names seen for a target; accept them as virtual hosts",
                       description="Host names found in certificates, redirects, NTLM/LDAP/SMB information, DNS answers "
                                   "and virtual-host discovery. Nothing uses them until you accept them: an accepted "
                                   "name is sent as Host header / SNI to the target's in-scope address in every later "
                                   "run (/etc/hosts is never edited).")
    p.set_defaults(handler=help_handler(p))
    hsub = p.add_subparsers(dest="hints_action", metavar="ACTION")

    ls = hsub.add_parser("list", parents=[common], help="list host-name hints and accepted virtual hosts")
    ls.add_argument("target")
    ls.add_argument("--json", action="store_true")
    ls.set_defaults(handler=cmd_list)

    ac = hsub.add_parser("accept", parents=[common], help="accept names as virtual hosts of the target (asks first)",
                         description="Each name must be in scope when presented to the target's address. Names do not "
                                     "have to appear in the hints (for names you learned elsewhere).")
    ac.add_argument("target")
    ac.add_argument("names", nargs="+", metavar="NAME")
    ac.set_defaults(handler=cmd_accept)

    rm = hsub.add_parser("remove", parents=[common], help="stop using accepted virtual hosts")
    rm.add_argument("target")
    rm.add_argument("names", nargs="+", metavar="NAME")
    rm.set_defaults(handler=cmd_remove)


def _context(ctx: AppContext, args: argparse.Namespace):
    eng = ctx.engagements().get(engagement_slug(ctx, args))
    target = ctx.targets().get(eng, args.target)
    prefix = "python3 pentest.py" + ("" if eng.slug == ctx.config.default_engagement else f" -e {eng.slug}")
    return eng, target, prefix


def hints_for(ctx: AppContext, target):
    from aiszx.assessment.hints import collect
    from aiszx.assessment.knowledge import gather

    k = gather(ctx.db, ctx.config.data_dir, target.id, target.canonical)
    return collect(k, exclude=[target.canonical])


def cmd_list(ctx: AppContext, args: argparse.Namespace) -> int:
    _, target, prefix = _context(ctx, args)
    mgr = ctx.targets()
    accepted = {v["name"]: v for v in mgr.vhosts(target)}
    hints = hints_for(ctx, target)
    rows = []
    for name in sorted(set(accepted) | {h.name for h in hints}):
        hint = next((h for h in hints if h.name == name), None)
        decision = mgr.vhost_decision(target, name)
        status = "accepted" if name in accepted else ("in scope" if decision.in_scope else "OUT OF SCOPE")
        rows.append({"name": name, "status": status, "in_scope": decision.in_scope,
                     "sources": hint.sources if hint else [], "accepted": accepted.get(name)})
    if args.json:
        emit_json({"target": target.canonical, "addresses": target.current_addresses, "hints": rows})
        return 0
    print(f"Host names for {target.canonical} (presented to {', '.join(target.current_addresses) or '?'})")
    if not rows:
        print("  none seen yet: run `enumerate` (or `full`) first")
        return 0
    print(table([(r["name"], r["status"], "; ".join(r["sources"])[:90] or ("accepted manually" if r["accepted"] else "-"))
                 for r in rows], ("NAME", "STATUS", "SEEN IN")))
    new = [r["name"] for r in rows if r["status"] == "in scope"]
    if new:
        print(f"\nAccept: {prefix} hints accept {target.canonical} {' '.join(new[:5])}")
    if any(r["status"] == "OUT OF SCOPE" for r in rows):
        print("Out-of-scope names cannot be accepted; change the scope only if the engagement authorises it.")
    return 0


def cmd_accept(ctx: AppContext, args: argparse.Namespace) -> int:
    _, target, prefix = _context(ctx, args)
    mgr = ctx.targets()
    names = []
    for raw in args.names:
        try:
            name = normalise_hostname(raw)
        except Exception as exc:
            raise ValidationError(f"{raw!r} is not a valid host name: {exc}") from None
        if name == target.canonical:
            raise ValidationError(f"{name} is the target itself")
        if name not in names:
            names.append(name)
    sources = {h.name: "; ".join(h.sources) for h in hints_for(ctx, target)}
    refused = []
    for name in names:
        decision = mgr.vhost_decision(target, name)
        if not decision.in_scope:
            refused.append(name)
            print(f"refused: {name} is out of scope ({'; '.join(decision.reasons)})")
        for w in decision.warnings:
            print(f"  note ({name}): {w}")
    ok = [n for n in names if n not in refused]
    if not ok:
        return 1
    addresses = ", ".join(target.current_addresses)
    print(f"Accepting for {target.canonical}: {', '.join(ok)}")
    print(f"  Every later run sends these names as Host header / SNI to {addresses}; nothing else is contacted.")
    if not confirm("Accept?", assume_yes=args.yes):
        print("nothing accepted")
        return 1
    added = mgr.accept_vhosts(target, {n: sources.get(n, "manual") for n in ok})
    already = [n for n in ok if n not in added]
    if added:
        print(f"accepted: {', '.join(added)}")
    if already:
        print(f"already accepted: {', '.join(already)}")
    print(f"Next: {prefix} enumerate {target.canonical}   (or `full`): the names are included automatically")
    return 1 if refused else 0


def cmd_remove(ctx: AppContext, args: argparse.Namespace) -> int:
    _, target, _ = _context(ctx, args)
    names = [n.strip().rstrip(".").lower() for n in args.names]
    removed = ctx.targets().remove_vhosts(target, names)
    missing = [n for n in names if n not in removed]
    if removed:
        print(f"removed: {', '.join(removed)}")
    if missing:
        print(f"not accepted for {target.canonical}: {', '.join(missing)}")
    return 0 if removed else 1
