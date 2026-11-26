"""``recon``, ``full``, ``services`` and ``discover``."""

from __future__ import annotations

import argparse
import json

from aiszx.app import AppContext
from aiszx.cli.commands import engagement_slug
from aiszx.cli.commands.run_cmd import _announce, _approver, _finish
from aiszx.cli.output import confirm, emit_json, kv, table
from aiszx.core.errors import AiszxError, NotFoundError
from aiszx.orchestrator.state import EXEC_FAILED, EXEC_INTERRUPTED, EXEC_PARTIAL, ExecutionStore
from aiszx.recon.store import ReconStore

RECON_MODULES = ["core.connectivity", "recon"]


def register(sub: argparse._SubParsersAction, common: argparse.ArgumentParser) -> None:
    r = sub.add_parser(
        "recon", parents=[common], help="reconnaissance of a target: host discovery, TCP ports, services, UDP",
        description="Runs core.connectivity, recon.host_discovery, recon.tcp_ports, recon.service_id and recon.udp "
                    "(per profile) in a new run. If the last recon run of the target was interrupted or partial, "
                    "you are pointed to `resume` unless --force is given.",
    )
    _target_args(r)
    r.set_defaults(handler=cmd_recon, command_name="recon")

    f = sub.add_parser(
        "full", parents=[common], help="full workflow: reconnaissance, enumeration of what it finds, assessment",
        description="Runs reconnaissance and enumeration in one run: enumeration modules are planned from the "
                    "services identified moments earlier; findings are then assessed. Write the report with `report`.",
    )
    _target_args(f)
    f.add_argument("--vhost", action="append", default=[], metavar="NAME", help="virtual host to test; repeatable")
    f.set_defaults(handler=cmd_recon, command_name="full")

    s = sub.add_parser("services", parents=[common], help="show discovered ports and services of a target")
    s.add_argument("target")
    s.add_argument("--run", dest="run_id", metavar="RUN_ID", help="a specific run (default: latest with services)")
    s.add_argument("--json", action="store_true")
    s.set_defaults(handler=cmd_services)

    d = sub.add_parser(
        "discover", parents=[common], help="find live hosts in an in-scope network range (nmap -sn)",
        description="The whole range must be in scope; scope exclusions are passed to nmap. Live hosts are only "
                    "listed: --register asks before registering each as a target. Nothing else is scanned.",
    )
    d.add_argument("network", nargs="?", help="CIDR range, e.g. 10.10.10.0/24")
    d.add_argument("--profile")
    d.add_argument("--register", action="store_true", help="offer to register each live host as a target")
    d.add_argument("--list", action="store_true", help="list previous discovery runs of the engagement")
    d.set_defaults(handler=cmd_discover)


def _target_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("target")
    p.add_argument("--profile", help="conservative | standard | comprehensive (see config/profiles.yaml)")
    p.add_argument("--force", action="store_true", help="start a new run even if the last one should be resumed")
    p.add_argument("--approve", action="append", default=[], metavar="MODULE")


def cmd_recon(ctx: AppContext, args: argparse.Namespace) -> int:
    eng = ctx.engagements().get(engagement_slug(ctx, args))
    target = ctx.targets().get(eng, args.target)
    prefix = "python3 pentest.py" + ("" if eng.slug == ctx.config.default_engagement else f" -e {eng.slug}")
    last = ExecutionStore(ctx.db).find_run(target.id, None, commands=("recon", "full"))
    if (last is not None and not args.force and last["command"] in ("recon", "full")
            and last["status"] in (EXEC_INTERRUPTED, EXEC_PARTIAL, EXEC_FAILED)):
        raise AiszxError(f"the last {last['command']} run {last['run_id']} is {last['status']}; continue it with "
                         f"`{prefix} resume {target.canonical}` or start a new run with --force")
    orch = ctx.orchestrator(approve=_approver(args), progress=print, announce=_announce)
    tokens, run_params = list(RECON_MODULES), {}
    if args.command_name == "full":
        from aiszx.cli.commands.enum_cmd import enumeration_modules, vhost_list
        tokens += enumeration_modules(ctx)
        run_params = {"vhosts": vhost_list(args.vhost)}
    report = orch.start(eng.slug, args.target, tokens, profile=args.profile, command=args.command_name,
                        run_params=run_params)
    code = _finish(report, ctx, args)
    if report.counts.get("COMPLETED"):
        print(f"Services: {prefix} services {target.canonical}")
        if args.command_name == "full":
            print(f"Web results: {prefix} web {target.canonical}")
    if args.command_name == "full" and report.status != "INTERRUPTED":
        from aiszx.assessment.engine import Assessor
        from aiszx.cli.commands.assess_cmd import print_report

        print("\n=== Assessment ===")
        print_report(Assessor(ctx).run(eng.slug, target.canonical), target.canonical, prefix)
        print(f"Report: {prefix} report {target.canonical}")
    return code


def cmd_services(ctx: AppContext, args: argparse.Namespace) -> int:
    eng = ctx.engagements().get(engagement_slug(ctx, args))
    target = ctx.targets().get(eng, args.target)
    recon = ReconStore(ctx.db)
    if args.run_id:
        ex = ExecutionStore(ctx.db).find_run(target.id, args.run_id)
        if ex is None:
            raise NotFoundError(f"run {args.run_id} not found for {target.canonical}")
        eid, run_id, services = ex["id"], ex["run_id"], recon.services_for_execution(ex["id"])
    else:
        snap = recon.latest_services(target.id)
        eid, run_id, services = snap.execution_id, snap.run_id, snap.services
    if eid is None:
        print(f"No services known for {target.canonical} yet. Run `recon {target.canonical}` first.")
        return 0
    ports = recon.ports_for_execution(eid)
    hosts = recon.hosts_for_execution(eid)
    uncertain = sorted({(p["protocol"], p["port"]) for p in ports if p["state"] == "open|filtered"})
    os_guess = next((json.loads(h["os_json"]) for h in hosts if json.loads(h["os_json"] or "[]")), [])
    if args.json:
        emit_json({"target": target.canonical, "run_id": run_id, "services": [s.to_dict() for s in services],
                   "open_filtered": [f"{p}/{n}" for p, n in uncertain], "os_matches": os_guess,
                   "hosts": [dict(h) for h in hosts]})
        return 0
    print(f"Services of {target.canonical} (run {run_id})")
    if os_guess:
        print(kv([("OS guess", "; ".join(f"{m['name']} ({m['accuracy']}%)" for m in os_guess[:3]))]))
    rows = [(s.key, s.state, s.name or "?", s.banner or "-", ", ".join(s.categories) +
             (f" ({s.category_confidence})" if s.category_confidence and s.category_confidence != "high" else ""))
            for s in services]
    if rows:
        print(table(rows, ("PORT", "STATE", "SERVICE", "VERSION", "CATEGORY")))
    else:
        print("  no open services recorded")
    if uncertain:
        print(f"\nUncertain (UDP open|filtered: no reply, could be open or filtered): "
              f"{', '.join(f'{n}/{p}' for p, n in uncertain)}")
    scripts = [(s.key, sid, out) for s in services for sid, out in sorted(s.scripts.items())]
    if scripts:
        print("\nNSE script output (summary; full output in the run's raw/ files):")
        for key, sid, out in scripts[:40]:
            print(f"  {key:<9} {sid}: {script_summary(out)}")
    return 0


def script_summary(output: str, width: int = 110) -> str:
    """Compact one-line view of multi-line NSE output: non-empty lines joined with ' | '."""
    lines = [ln.strip() for ln in output.splitlines() if ln.strip()]
    text = " | ".join(lines)
    return text if len(text) <= width else text[: width - 3] + "..."


def cmd_discover(ctx: AppContext, args: argparse.Namespace) -> int:
    from aiszx.recon.range_discovery import RangeDiscovery

    disc = RangeDiscovery(ctx, progress=print)
    slug = engagement_slug(ctx, args)
    if args.list or not args.network:
        runs = disc.history(slug)
        if not runs:
            print("No discovery runs yet. Example: python3 pentest.py discover 10.10.10.0/24")
            return 0
        print(table([(r["run_id"], r["network"], r["status"], len(r["hosts"]), len(r["registered"]),
                      ", ".join(r["hosts"][:6]) + (" ..." if len(r["hosts"]) > 6 else "")) for r in runs],
                    ("RUN", "NETWORK", "STATUS", "LIVE", "REGISTERED", "HOSTS")))
        return 0
    result = disc.run(slug, args.network, profile=args.profile)
    print(f"\nDiscovery run {result.run_id}: {result.status}, {len(result.hosts)} live host(s) in {result.network}")
    for lim in result.limitations:
        print(f"note: {lim}")
    if result.hosts:
        registered = {t.canonical for t in ctx.targets().list(ctx.engagements().get(slug))}
        print(table([(h.address, h.reason or "-", ", ".join(h.hostnames) or "-",
                      "yes" if h.address in registered else "no") for h in result.hosts],
                    ("ADDRESS", "REASON", "HOSTNAMES", "REGISTERED")))
    if args.register and result.hosts:
        todo = [h.address for h in result.hosts if h.address not in registered]
        chosen = [a for a in todo if confirm(f"Register {a} as a target?", assume_yes=ctx.assume_yes)]
        done = disc.register(slug, result.execution_id, chosen)
        print(f"Registered {len(done)} target(s)" + (f": {', '.join(done)}" if done else ""))
    elif result.hosts:
        print("Register hosts with `target add <address>` or rerun with --register.")
    return 0 if result.status == "COMPLETED" else (130 if result.status == EXEC_INTERRUPTED else 1)

