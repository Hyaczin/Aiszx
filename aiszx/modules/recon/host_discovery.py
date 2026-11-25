"""recon.host_discovery: is the host responding to discovery probes? (nmap -sn)

A non-responding host is not treated as down for later stages: HTB and Windows hosts often
drop ICMP, so port scans always use -Pn. The result is recorded as an observation.
"""

from __future__ import annotations

from aiszx.modules.base import (
    Command,
    ModuleMeta,
    ModuleResult,
    RetryPolicy,
    RunContext,
    Safety,
    Stage,
    ToolRequirement,
    WorkUnit,
)
from aiszx.modules.records import HostRecord
from aiszx.modules.recon._nmap_base import NmapModule
from aiszx.recon import nmap


class HostDiscovery(NmapModule):
    output_name = "discovery"
    meta = ModuleMeta(
        id="recon.host_discovery",
        version="1",
        description="Host discovery probes (nmap -sn); informational, port scans always use -Pn",
        stage=Stage.RECON,
        safety=Safety.ACTIVE_SAFE,
        timeout_seconds=300,
        tools=(ToolRequirement("nmap", min_version="7.80"),),
        retry=RetryPolicy(max_attempts=2, backoff_seconds=5),
        profile_sections=("nmap",),
    )

    def build_commands(self, unit: WorkUnit, ctx: RunContext) -> list[Command]:
        p = nmap.params(ctx.profile_params)
        flags, raw, _ = nmap.privileges(ctx.tool_details)
        probes = list(p["discovery_probes"]) if raw else []  # ICMP/raw probes need privileges
        address = unit.inputs["address"]
        argv = ["-sn", *probes, *nmap.common(p, flags, address), *nmap.outputs(ctx.attempt_dir, self.output_name),
                address]
        return [Command("discovery", argv, tool="nmap", targets=[address])]

    def parse(self, unit: WorkUnit, results, ctx: RunContext) -> ModuleResult:
        address = unit.inputs["address"]
        run = self.load(ctx)
        res = ModuleResult(limitations=self.completeness(run), evidence_descriptions={
            "discovery.xml": "nmap host discovery (XML)", "discovery.nmap": "nmap host discovery (normal output)"})
        _, raw, mode = nmap.privileges(ctx.tool_details)
        if not raw:
            res.limitations.append(f"nmap privileges '{mode}': only TCP connect probes were used")
        host = run.host(address)
        status = host.status if host else "down"
        reason = host.reason if host else "no response"
        res.hosts.append(HostRecord(address, status if status in ("up", "down") else "unknown",
                                    "nmap -sn", reason, host.hostnames if host else []))
        res.artifacts = {"status": status, "reason": reason, "args": run.args}
        res.observations.append({"key": "host.discovery_response", "value": status == "up"})
        if status == "up":
            res.summary = f"host responded to discovery probes ({reason})"
        else:
            res.summary = ("no response to discovery probes; common for HTB/Windows hosts that drop ICMP. "
                           "Port scans use -Pn regardless")
        return res
