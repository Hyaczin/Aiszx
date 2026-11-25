"""``enumerate`` (service enumeration of known services) and ``web`` (web results of a target)."""

from __future__ import annotations

import argparse
import json

from aiszx.app import AppContext
from aiszx.cli.commands import engagement_slug
from aiszx.cli.commands.run_cmd import _announce, _approver, _finish
from aiszx.cli.output import emit_json, table
from aiszx.core.errors import AiszxError, NotFoundError
from aiszx.modules.base import Stage
from aiszx.orchestrator.state import ExecutionStore
from aiszx.recon.store import ReconStore
from aiszx.targets.identity import normalise_hostname


def enumeration_modules(ctx: AppContext) -> list[str]:
    return [mid for mid, m in ctx.module_registry().modules.items() if m.meta.stage is Stage.ENUMERATION]


def vhost_list(values: list[str]) -> list[str]:
    out = []
    for v in values:
        h = normalise_hostname(v)
        if h not in out:
            out.append(h)
    return out


def _clip(text: str, width: int) -> str:
    """Shorten a comma-separated list at an item boundary, marking the cut with '…'."""
    if len(text) <= width:
        return text
    kept: list[str] = []
    for item in text.split(", "):
        candidate = ", ".join([*kept, item])
        if len(candidate) + 2 > width:  # room for " …"
            break
        kept.append(item)
    return ", ".join(kept) + " …" if kept else text[: width - 2] + " …"


def register(sub: argparse._SubParsersAction, common: argparse.ArgumentParser) -> None:
    e = sub.add_parser(
        "enumerate", parents=[common], help="enumerate the target's known services (run `recon` first)",
        description="Plans enumeration modules from the services found by the latest reconnaissance and runs them "
                    "in a new run. --module restricts to a family (e.g. http) or module id. Virtual hosts given "
                    "with --vhost are sent as Host header/SNI to the target's in-scope address.",
    )
    e.add_argument("target")
    e.add_argument("-m", "--module", dest="modules", action="append", default=[], metavar="MODULE",
                   help="module id or family (default: all enumeration modules)")
    e.add_argument("--vhost", action="append", default=[], metavar="NAME", help="virtual host to test; repeatable")
    e.add_argument("--profile")
    e.add_argument("--approve", action="append", default=[], metavar="MODULE")
    e.set_defaults(handler=cmd_enumerate)

    w = sub.add_parser("web", parents=[common], help="show web endpoints, technologies, paths and hints of a target")
    w.add_argument("target")
    w.add_argument("--run", dest="run_id", metavar="RUN_ID")
    w.add_argument("--json", action="store_true")
    w.set_defaults(handler=cmd_web)


def cmd_enumerate(ctx: AppContext, args: argparse.Namespace) -> int:
    eng = ctx.engagements().get(engagement_slug(ctx, args))
    target = ctx.targets().get(eng, args.target)
    snap = ReconStore(ctx.db).latest_services(target.id)
    if not snap.services:
        raise AiszxError(f"no services known for {target.canonical}; run `recon {target.canonical}` first")
    print(f"Using services from run {snap.run_id}: " + ", ".join(f"{s.key} {s.name or '?'}" for s in snap.services))
    tokens = args.modules or enumeration_modules(ctx)
    orch = ctx.orchestrator(approve=_approver(args), progress=print, announce=_announce)
    report = orch.start(eng.slug, args.target, tokens, profile=args.profile, command="enumerate",
                        run_params={"vhosts": vhost_list(args.vhost)})
    code = _finish(report, ctx, args)
    prefix = "python3 pentest.py" + ("" if eng.slug == ctx.config.default_engagement else f" -e {eng.slug}")
    print(f"Web results: {prefix} web {target.canonical}")
    return code


def cmd_web(ctx: AppContext, args: argparse.Namespace) -> int:
    eng = ctx.engagements().get(engagement_slug(ctx, args))
    target = ctx.targets().get(eng, args.target)
    store = ReconStore(ctx.db)
    if args.run_id:
        ex = ExecutionStore(ctx.db).find_run(target.id, args.run_id)
        if ex is None:
            raise NotFoundError(f"run {args.run_id} not found for {target.canonical}")
        found = (ex["id"], ex["run_id"])
    else:
        found = store.latest_web_execution(target.id)
    if not found:
        print(f"No web results for {target.canonical} yet. Run `enumerate {target.canonical}` first.")
        return 0
    eid, run_id = found
    web = store.web_for_execution(eid)
    techs: dict[str, list[str]] = {}
    for t in web["technologies"]:
        techs.setdefault(t["endpoint_url"], []).append(t["name"] + (f" {t['version']}" if t["version"] else ""))
    units = {u["module_id"]: u for u in ExecutionStore(ctx.db).units(eid)}
    hints, observations = set(), []
    for u in ExecutionStore(ctx.db).units(eid):
        if u["module_id"] != "http.probe" or not u["output_dir"]:
            continue
        try:
            data = json.loads((ctx.config.data_dir / ExecutionStore(ctx.db).execution(eid)["workspace_path"]
                               / u["output_dir"] / "parsed" / "result.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        hints.update(data.get("artifacts", {}).get("hostname_hints", []))
        observations += [o for o in data.get("observations", []) if o["key"] != "http.hostname_hints"]
    if args.json:
        emit_json({"run_id": run_id, "endpoints": [dict(r) for r in web["endpoints"]],
                   "resources": [dict(r) for r in web["resources"]], "technologies": [dict(r) for r in web["technologies"]],
                   "hostname_hints": sorted(hints), "observations": observations})
        return 0
    print(f"Web results of {target.canonical} (run {run_id})")
    print(table([(e["url"], e["status_code"] or "-", (e["title"] or "-")[:40], (e["server"] or "-")[:30],
                  _clip(", ".join(techs.get(e["url"], [])), 60) or "-") for e in web["endpoints"]],
                ("URL", "STATUS", "TITLE", "SERVER", "TECHNOLOGIES")))
    if web["resources"]:
        print("\nPaths:")
        print(table([(r["url"], r["status_code"] or "-", r["content_length"] or "-", r["redirect"] or "",
                      r["source_tool"]) for r in web["resources"][:80]],
                    ("URL", "STATUS", "SIZE", "REDIRECT", "SOURCE"), indent="  "))
        if len(web["resources"]) > 80:
            print(f"  ... {len(web['resources']) - 80} more (use --json)")
    if observations:
        print("\nObservations (for manual review; assessed in Milestone 7):")
        for o in observations[:30]:
            print(f"  {o['key']}: {json.dumps(o['value'])[:120]} ({o.get('url', '')})")
    if hints:
        print(f"\nHost name hints (not tested yet): {', '.join(sorted(hints))}")
        print(f"  add to scope (`scope add <name>`), then `enumerate {target.canonical} --vhost <name>`")
    shot = units.get("http.screenshots")
    if shot and shot["output_dir"]:
        report = (ctx.config.data_dir / ExecutionStore(ctx.db).execution(eid)["workspace_path"] / shot["output_dir"]
                  / "raw" / "eyewitness" / "report.html")
        if report.is_file():
            print(f"\nScreenshots: {report}")
    return 0
