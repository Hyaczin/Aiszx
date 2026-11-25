"""recon.udp: UDP discovery of the most common ports (nmap -sU --top-ports N -sV).

UDP is slow and ambiguous: a silent port is reported ``open|filtered`` and stored as such.
It is never counted as open. Requires raw sockets; disabled when the profile's
``udp_top_ports`` is 0.
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
from aiszx.modules.records import PortRecord, ServiceRecord
from aiszx.modules.recon._nmap_base import NmapModule
from aiszx.recon import nmap

NAME = "udp"


class Udp(NmapModule):
    output_name = NAME
    meta = ModuleMeta(
        id="recon.udp",
        version="1",
        description="UDP scan of the most common ports (count set by the profile); open|filtered kept as uncertain",
        stage=Stage.RECON,
        safety=Safety.ACTIVE_SAFE,
        timeout_seconds=2400,
        tools=(ToolRequirement("nmap", min_version="7.80"),),
        retry=RetryPolicy(max_attempts=1),
        profile_sections=("nmap",),
    )

    def unavailable_reason(self, ctx: PlanContext) -> str | None:
        if int(nmap.params(ctx.profile_params)["udp_top_ports"]) <= 0:
            return "UDP scanning is disabled in this profile (udp_top_ports: 0)"
        _, raw, mode = nmap.privileges(ctx.tool_details)
        if not raw:
            return f"UDP scanning needs raw sockets (nmap mode '{mode}'); run `tools nmap-caps --apply`"
        return None

    def build_commands(self, unit: WorkUnit, ctx: RunContext) -> list[Command]:
        address = unit.inputs["address"]
        p = nmap.params(ctx.profile_params)
        flags, _, _ = nmap.privileges(ctx.tool_details)
        argv = ["-Pn", "-sU", "--top-ports", str(int(p["udp_top_ports"])), "-sV", "--version-intensity", "0",
                "--max-retries", "1", *nmap.common(p, flags, address), *nmap.outputs(ctx.attempt_dir, NAME), address]
        return [Command("udp", argv, tool="nmap", targets=[address])]

    def parse(self, unit: WorkUnit, results, ctx: RunContext) -> ModuleResult:
        address = unit.inputs["address"]
        run = self.load(ctx)
        res = ModuleResult(limitations=self.completeness(run), evidence_descriptions={
            f"{NAME}.xml": "nmap UDP scan (XML)", f"{NAME}.nmap": "nmap UDP scan (normal output)"})
        host = run.host(address)
        opened, uncertain = [], []
        for port in (host.ports if host else []):
            if port.protocol != "udp" or port.state not in ("open", "open|filtered"):
                continue
            res.ports.append(PortRecord(address, "udp", port.port, port.state, port.reason))
            if port.state == "open":
                s = port.service
                opened.append(port)
                res.services.append(ServiceRecord(
                    address=address, protocol="udp", port=port.port, state="open",
                    name=s.name if s else None, product=s.product if s else None, version=s.version if s else None,
                    extrainfo=s.extrainfo if s else None, cpes=s.cpes if s else [], confidence=s.conf if s else None,
                    method=s.method if s else None, scripts=port.scripts))
            else:
                uncertain.append(port)
        top = int(nmap.params(ctx.profile_params)["udp_top_ports"])
        res.artifacts = {"open": [p.port for p in opened], "open_filtered": [p.port for p in uncertain],
                         "top_ports": top, "complete": run.complete}
        if uncertain:
            res.limitations.append(f"{len(uncertain)} UDP port(s) are open|filtered: no reply, so open vs filtered is unknown")
        named = ", ".join(f"{p.port}/{p.service.name if p.service and p.service.name else '?'}" for p in opened)
        parts = [f"{len(opened)} open" + (f" ({named})" if opened else "")]
        if uncertain:
            parts.append(f"{len(uncertain)} open|filtered (uncertain)")
        res.summary = f"UDP top {top}: " + ", ".join(parts)
        return res
