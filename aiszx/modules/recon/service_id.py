"""recon.service_id: service/version identification on the open TCP ports (nmap -sV [-sC] [-O]).

Ports come from recon.tcp_ports in the same run; when run on its own, from the target's most
recent known services. Ports are part of the unit inputs, so a changed port list on resume
triggers a re-run instead of reusing stale results.
"""

from __future__ import annotations

from aiszx.modules.base import (
    Command,
    ModuleMeta,
    ModuleResult,
    PlanContext,
    RetryPolicy,
    RunContext,
    Safety,
    Stage,
    ToolRequirement,
    WorkUnit,
)
from aiszx.modules.records import HostRecord, ServiceRecord
from aiszx.modules.recon._nmap_base import NmapModule
from aiszx.recon import nmap

NAME = "services"


def tcp_ports_from(ctx: PlanContext) -> list[int]:
    results = ctx.upstream.get("recon.tcp_ports")
    if results:
        return sorted({p["port"] for r in results for p in r.get("ports", []) if p["protocol"] == "tcp"})
    return sorted({s.port for s in ctx.services if s.protocol == "tcp" and s.state == "open"})


class ServiceId(NmapModule):
    output_name = NAME
    meta = ModuleMeta(
        id="recon.service_id",
        version="1",
        description="Service/version identification, default NSE scripts and optional OS detection on open TCP ports",
        stage=Stage.RECON,
        safety=Safety.ACTIVE_SAFE,
        timeout_seconds=2400,
        tools=(ToolRequirement("nmap", min_version="7.80"),),
        depends_on=("recon.tcp_ports",),
        retry=RetryPolicy(max_attempts=2, backoff_seconds=10),
        profile_sections=("nmap",),
    )

    def plan(self, ctx: PlanContext) -> list[WorkUnit]:
        return [WorkUnit(self.meta.id, "host", {"target": ctx.target.canonical, "address": ctx.address,
                                                "ports": tcp_ports_from(ctx)})]

    def build_commands(self, unit: WorkUnit, ctx: RunContext) -> list[Command]:
        ports = unit.inputs["ports"]
        if not ports:
            return []
        address = unit.inputs["address"]
        p = nmap.params(ctx.profile_params)
        flags, raw, _ = nmap.privileges(ctx.tool_details)
        argv = ["-Pn", "-sV"]
        if p["scripts"]:
            argv.append("-sC")
        if p["version_all"]:
            argv.append("--version-all")
        if p["os_detection"] and raw:
            argv.append("-O")
        argv += ["-p", ",".join(map(str, ports)), *nmap.rate_args(p), *nmap.common(p, flags, address),
                 *nmap.outputs(ctx.attempt_dir, NAME), address]
        return [Command("services", argv, tool="nmap", targets=[address])]

    def parse(self, unit: WorkUnit, results, ctx: RunContext) -> ModuleResult:
        address, ports = unit.inputs["address"], unit.inputs["ports"]
        if not ports:
            return ModuleResult(summary="no open TCP ports to identify", artifacts={"services": []})
        run = self.load(ctx)
        res = ModuleResult(limitations=self.completeness(run), evidence_descriptions={
            f"{NAME}.xml": "nmap service identification (XML)", f"{NAME}.nmap": "nmap service identification (normal)"})
        p = nmap.params(ctx.profile_params)
        _, raw, _ = nmap.privileges(ctx.tool_details)
        if p["os_detection"] and not raw:
            res.limitations.append("OS detection skipped: needs raw sockets (`tools nmap-caps --apply`)")
        host = run.host(address)
        if host is None:
            res.limitations.append("nmap returned no result for the host")
            res.summary = "no service information returned"
            return res
        for port in host.ports:
            if port.protocol != "tcp" or port.state != "open":
                continue
            s = port.service
            res.services.append(ServiceRecord(
                address=address, protocol="tcp", port=port.port, state=port.state,
                name=s.name if s else None, product=s.product if s else None, version=s.version if s else None,
                extrainfo=s.extrainfo if s else None, tunnel=s.tunnel if s else None, cpes=s.cpes if s else [],
                confidence=s.conf if s else None, method=s.method if s else None, scripts=port.scripts,
            ))
        missing = sorted(set(ports) - {s.port for s in res.services})
        if missing:
            res.limitations.append(f"port(s) {', '.join(map(str, missing))} were not open during identification")
        res.hosts.append(HostRecord(address, "up", "nmap -sV", host.reason, host.hostnames, host.os_matches[:5]))
        res.artifacts = {"services": [s.to_dict() for s in res.services], "os_matches": host.os_matches[:5],
                         "complete": run.complete}
        shown = "; ".join(f"{s.key} {s.name or '?'}{' ' + s.banner if s.banner else ''}" for s in res.services[:8])
        more = f" (+{len(res.services) - 8} more)" if len(res.services) > 8 else ""
        res.summary = f"{len(res.services)} service(s): {shown}{more}" if res.services else "no services identified"
        return res
