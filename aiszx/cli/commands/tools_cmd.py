"""``tools inventory|check|missing|show|install|nmap-caps``."""

from __future__ import annotations

import argparse
import sys

from aiszx.app import AppContext
from aiszx.cli.commands import help_handler
from aiszx.cli.output import confirm, emit_json, kv, table
from aiszx.core.audit import record_event
from aiszx.core.errors import AiszxError
from aiszx.tools import dependency_checker, nmap_privileges, store
from aiszx.tools.installer import Installer, InstallOutcome, InstallPlan
from aiszx.tools.inventory import BROKEN, INCOMPATIBLE, MISSING, OK, Inventory, ToolStatus
from aiszx.tools.registry import ToolRegistry


def register(sub: argparse._SubParsersAction, common: argparse.ArgumentParser) -> None:
    p = sub.add_parser("tools", help="detect, check and install the security tools Aiszx uses")
    p.set_defaults(handler=help_handler(p))
    tsub = p.add_subparsers(dest="tools_action", metavar="ACTION")

    inv = tsub.add_parser("inventory", parents=[common], help="detect installed tools, versions and install sources")
    inv.add_argument("names", nargs="*", metavar="TOOL", help="limit to these tools")
    inv.add_argument("--json", action="store_true")
    inv.set_defaults(handler=cmd_inventory)

    chk = tsub.add_parser("check", parents=[common], help="health of all tools and readiness of each capability")
    chk.add_argument("--json", action="store_true")
    chk.set_defaults(handler=cmd_check)

    mis = tsub.add_parser("missing", parents=[common], help="missing/broken/outdated tools: why, what needs them, how to install")
    mis.add_argument("--json", action="store_true")
    mis.set_defaults(handler=cmd_missing)

    sh = tsub.add_parser("show", parents=[common], help="details of one tool")
    sh.add_argument("name", metavar="TOOL")
    sh.add_argument("--json", action="store_true")
    sh.set_defaults(handler=cmd_show)

    ins = tsub.add_parser(
        "install", parents=[common], help="install missing tools after confirming each one",
        description="Builds an install plan (APT > pipx > Go > git by default) and asks before each tool. "
                    "Never uses sudo pip and never runs third-party install scripts.",
    )
    ins.add_argument("names", nargs="*", metavar="TOOL", help="tools to install (default: every missing/broken/outdated tool)")
    ins.add_argument("--interactive", action="store_true", help="confirm each tool (the default; kept for compatibility)")
    ins.add_argument("--dry-run", action="store_true", help="show the plan only")
    ins.set_defaults(handler=cmd_install)

    caps = tsub.add_parser(
        "nmap-caps", parents=[common], help="show or set nmap raw-socket capabilities (one-time setup)",
        description="Without root or capabilities nmap can only run TCP connect scans. --apply grants "
                    f"'{nmap_privileges.CAPABILITY_SET}' to the nmap binary via sudo setcap, after confirmation.",
    )
    g = caps.add_mutually_exclusive_group()
    g.add_argument("--apply", action="store_true", help="grant capabilities (asks for confirmation; uses sudo)")
    g.add_argument("--remove", action="store_true", help="remove the capabilities again")
    caps.set_defaults(handler=cmd_nmap_caps)


# --- shared ----------------------------------------------------------------------

def _detect(ctx: AppContext, names: list[str] | None = None) -> tuple[ToolRegistry, Inventory, list]:
    registry = ctx.tool_registry()
    inventory = ctx.tool_inventory(registry).detect(names)
    store.save_inventory(ctx.db, inventory)
    caps = []
    if inventory.complete:
        caps = dependency_checker.evaluate(registry, inventory)
        store.save_capabilities(ctx.db, caps, inventory.checked_at)
        store.write_snapshot(ctx.config.data_dir, inventory, caps)
    return registry, inventory, caps


def _summary(inventory: Inventory) -> str:
    counts = {s: len(inventory.by_status(s)) for s in (OK, MISSING, BROKEN, INCOMPATIBLE)}
    return ", ".join(f"{n} {s}" for s, n in counts.items())


def _tool_rows(tools: list[ToolStatus]) -> list[tuple]:
    return [(t.name, t.status, t.version or "-", t.source or "-", t.path or "-") for t in tools]


def _privileges_line(inventory: Inventory) -> str | None:
    nmap = inventory.tools.get("nmap")
    priv = nmap.detail.get("privileges") if nmap else None
    return f"nmap privileges: {priv['mode']}: {priv['message']}" if priv else None


# --- commands --------------------------------------------------------------------

def cmd_inventory(ctx: AppContext, args: argparse.Namespace) -> int:
    _, inventory, _ = _detect(ctx, args.names or None)
    if args.json:
        emit_json(inventory.to_dict())
        return 0
    print(f"Tool inventory ({inventory.checked_at}): {_summary(inventory)}")
    print(table(_tool_rows(list(inventory.tools.values())), ("TOOL", "STATUS", "VERSION", "SOURCE", "PATH")))
    if inventory.interpreters:
        print("\nPython interpreters:")
        print(table([(i.kind, i.version, i.path) for i in inventory.interpreters], ("KIND", "VERSION", "PATH"), indent="  "))
    notes = [(t.name, n) for t in inventory.tools.values() for n in t.notes]
    if notes:
        print("\nNotes:")
        for name, note in notes:
            print(f"  {name}: {note}")
    line = _privileges_line(inventory)
    if line:
        print(f"\n{line}")
    if not inventory.dpkg_available:
        print("\nwarning: dpkg-query not found; APT package detection was skipped")
    if inventory.by_status(MISSING, BROKEN, INCOMPATIBLE):
        print("\nRun `python3 pentest.py tools missing` for reasons and install recommendations.")
    return 0


def cmd_check(ctx: AppContext, args: argparse.Namespace) -> int:
    _, inventory, caps = _detect(ctx)
    unhealthy = inventory.by_status(BROKEN, INCOMPATIBLE)
    if args.json:
        emit_json({"checked_at": inventory.checked_at, "summary": _summary(inventory),
                   "capabilities": [c.to_dict() for c in caps],
                   "problems": {t.name: t.problems for t in unhealthy},
                   "nmap_privileges": (inventory.tools.get("nmap").detail.get("privileges")
                                       if inventory.tools.get("nmap") else None)})
        return 1 if unhealthy else 0
    print(f"Tool health ({inventory.checked_at}): {_summary(inventory)}\n")
    print(table([(c.name, c.state, c.message or "-") for c in caps], ("CAPABILITY", "STATE", "DETAIL")))
    if unhealthy:
        print("\nProblems:")
        for t in unhealthy:
            for problem in t.problems:
                print(f"  {t.name} [{t.status}]: {problem}")
    line = _privileges_line(inventory)
    if line:
        print(f"\n{line}")
    return 1 if unhealthy else 0


def _plan_lines(plan: InstallPlan, registry: ToolRegistry, st: ToolStatus) -> list[str]:
    lines = [f"{plan.tool}: {plan.current_status}", f"  {registry.tools[plan.tool].description}"]
    lines += [f"  why       : {r}" for r in plan.reasons]
    lines.append(f"  needed by : {', '.join(st.capabilities) or '(no capability; utility)'}")
    if plan.chosen:
        verb = {"install": "install", "upgrade": "upgrade", "repair": "repair"}.get(plan.action, plan.action)
        for cmd in plan.chosen.commands():
            lines.append(f"  {verb:<10}: {cmd}   [{plan.chosen.method}: {plan.chosen.reason}]")
        lines += [f"  then      : {m}" for m in plan.chosen.manual]
    else:
        lines.append("  install   : no automatic method available")
    for alt in plan.alternatives:
        state = "; ".join(alt.commands()) if alt.available else f"unavailable: {alt.reason}"
        lines.append(f"  alt {alt.method:<6}: {state}")
    return lines


def cmd_missing(ctx: AppContext, args: argparse.Namespace) -> int:
    registry, inventory, _ = _detect(ctx)
    installer = Installer(registry, ctx.runner(), ctx.host(), inventory)
    plans = installer.plan()
    if args.json:
        emit_json([{**p.to_dict(), "capabilities": inventory.tools[p.tool].capabilities} for p in plans])
        return 0
    if not plans:
        print("All registered tools are installed and working.")
        return 0
    print(f"{len(plans)} tool(s) need attention:\n")
    for plan in plans:
        print("\n".join(_plan_lines(plan, registry, inventory.tools[plan.tool])))
        print()
    print("Install with confirmation: python3 pentest.py tools install [TOOL ...]")
    return 0


def cmd_show(ctx: AppContext, args: argparse.Namespace) -> int:
    registry = ctx.tool_registry()
    spec = registry.get(args.name)
    _, inventory, _ = _detect(ctx, [spec.name])
    t = inventory.tools[spec.name]
    if args.json:
        emit_json(t.to_dict())
        return 0
    print(f"Tool {t.name}: {t.status}")
    print(kv([
        ("description", spec.description), ("version", t.version), ("version source", t.detail.get("version_source")),
        ("minimum", spec.min_version), ("path", t.path), ("source", t.source), ("package", t.package),
        ("command", " ".join(t.launch) if t.launch else None), ("capabilities", ", ".join(t.capabilities)),
        ("install sources", ", ".join(f"{m}={spec.source_for(m)}" for m in spec.install_preference)),
        ("notes", spec.notes),
    ]))
    for inst in t.installations:
        extra = f", commit {inst.commit}" if inst.commit else ""
        print(f"  installation: {inst.path} -> {inst.real_path} ({inst.source}"
              f"{', ' + inst.package if inst.package else ''}{extra}{', on PATH' if inst.on_path else ''})")
    for problem in t.problems:
        print(f"  problem: {problem}")
    for note in t.notes:
        print(f"  note: {note}")
    priv = t.detail.get("privileges")
    if priv:
        print(f"  privileges: {priv['mode']}: {priv['message']}")
    return 0


def cmd_install(ctx: AppContext, args: argparse.Namespace) -> int:
    registry, inventory, _ = _detect(ctx)
    installer = Installer(registry, ctx.runner(), ctx.host(), inventory)
    plans = [p for p in installer.plan(args.names or None) if p.action != "none"]
    for name in args.names:
        spec = registry.get(name)
        if inventory.tools[spec.name].status == OK:
            print(f"{spec.name} is already installed and working ({inventory.tools[spec.name].path})")
    if not plans:
        if not args.names:
            print("Nothing to install: all registered tools are installed and working.")
        return 0
    print("Install plan:\n")
    for plan in plans:
        print("\n".join(_plan_lines(plan, registry, inventory.tools[plan.tool])))
        print()
    if args.dry_run:
        print("Dry run: nothing was executed.")
        return 0
    if not ctx.assume_yes and not sys.stdin.isatty():
        raise AiszxError("installation needs confirmation: run in an interactive terminal (or pass --yes)")

    def ask(plan: InstallPlan) -> bool:
        cmds = "\n".join(f"    {c}" for c in plan.chosen.commands())
        warn = " (uses sudo: you may be asked for your password)" if plan.chosen.privileged else ""
        print(f"\n{plan.action} {plan.tool} via {plan.chosen.method}{warn}:\n{cmds}")
        return confirm(f"Run this for {plan.tool}?", assume_yes=ctx.assume_yes)

    def audit(plan: InstallPlan, outcome: InstallOutcome) -> None:
        record_event(ctx.db, f"tools.{plan.action}", actor=ctx.actor, tool=plan.tool,
                     method=plan.chosen.method if plan.chosen else None,
                     commands=plan.chosen.commands() if plan.chosen else [], result=outcome.result,
                     detail=outcome.detail)

    outcomes = installer.execute(plans, ask, audit)
    done = [o.tool for o in outcomes if o.result == "installed"]
    print()
    for o in outcomes:
        print(f"{o.tool}: {o.result}{' — ' + o.detail if o.detail else ''}")
    if done:
        _, after, _ = _detect(ctx, done)
        print("\nRe-check:")
        print(table(_tool_rows([after.tools[n] for n in done]), ("TOOL", "STATUS", "VERSION", "SOURCE", "PATH")))
        manual = [m for p in plans if p.tool in done and p.chosen for m in p.chosen.manual]
        for m in manual:
            print(f"manual step: {m}")
    return 1 if any(o.result == "failed" for o in outcomes) else 0


def cmd_nmap_caps(ctx: AppContext, args: argparse.Namespace) -> int:
    _, inventory, _ = _detect(ctx, ["nmap"])
    nmap = inventory.tools["nmap"]
    if nmap.status in (MISSING, BROKEN) or nmap.primary is None:
        raise AiszxError(f"nmap is {nmap.status}; install it first (`python3 pentest.py tools install nmap`)")
    real = nmap.primary.real_path
    priv = nmap_privileges.check(ctx.runner(), ctx.host(), real)
    print(f"nmap binary : {real}")
    print(f"mode        : {priv.mode}")
    print(f"capabilities: {', '.join(priv.capabilities) or '-'}{' (' + priv.flags + ')' if priv.flags else ''}")
    print(f"             {priv.message}")
    if not (args.apply or args.remove):
        return 0
    if priv.mode == nmap_privileges.MODE_ROOT:
        print("Running as root; capabilities are not needed for this session.")
        return 0
    if nmap_privileges.find_getcap(ctx.host()) is None:
        raise AiszxError("getcap/setcap not found; install them first: sudo apt-get install libcap2-bin")
    if args.apply and priv.mode == nmap_privileges.MODE_CAPS:
        print("Capabilities are already set; nothing to do.")
        return 0
    if args.remove and not priv.capabilities:
        print("No capabilities are set; nothing to remove.")
        return 0

    argv = nmap_privileges.apply_command(real) if args.apply else nmap_privileges.remove_command(real)
    action = "apply" if args.apply else "remove"
    print(f"\nWill run: {' '.join(argv)}")
    if args.apply:
        print(f"Security note: {nmap_privileges.SECURITY_NOTE}")
        print("Note: an `apt upgrade` of nmap removes the capabilities; `tools check` will tell you to re-apply.")
    if not confirm(f"{action.capitalize()} nmap capabilities?", assume_yes=ctx.assume_yes):
        record_event(ctx.db, f"tools.nmap_caps.{action}", actor=ctx.actor, path=real, result="declined")
        print("Cancelled.")
        return 1
    rc = ctx.runner().run_interactive(argv)
    after = nmap_privileges.check(ctx.runner(), ctx.host(), real)
    record_event(ctx.db, f"tools.nmap_caps.{action}", actor=ctx.actor, path=real, result="ok" if rc == 0 else "failed",
                 exit_code=rc, mode_after=after.mode)
    print(f"\nsetcap exited with {rc}; nmap mode is now: {after.mode}")
    _detect(ctx, ["nmap"])  # refresh the stored inventory row
    expected = nmap_privileges.MODE_CAPS if args.apply else nmap_privileges.MODE_UNPRIVILEGED
    return 0 if rc == 0 and after.mode == expected else 1
