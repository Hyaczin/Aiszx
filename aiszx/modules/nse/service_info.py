"""nse.service_info: service metadata via *information-only* NSE scripts, per service category.

Covers services without a dedicated module: MSSQL, MySQL, RDP, SMTP, NFS/rpcbind, VNC, plus SMB
protocol/security-mode and FTP details. The script list comes from the module options; names that
look like brute force, DoS, exploitation, fuzzing or vulnerability checks are refused.
"""

from __future__ import annotations

import re

from aiszx.modules import _svc
from aiszx.modules.base import (
    Command,
    Module,
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
from aiszx.parsers.nmap_xml import parse_nmap_xml_file
from aiszx.recon import nmap

DEFAULT_SCRIPTS = {
    "mssql": ["ms-sql-info", "ms-sql-ntlm-info"],
    "mysql": ["mysql-info"],
    "rdp": ["rdp-enum-encryption", "rdp-ntlm-info"],
    "smtp": ["smtp-commands", "smtp-ntlm-info"],
    "nfs": ["nfs-showmount", "rpcinfo"],
    "smb": ["smb-protocols", "smb2-security-mode", "smb-os-discovery"],
    "ftp": ["ftp-anon", "ftp-syst"],
    "vnc": ["vnc-info"],
    "postgresql": [],
}
FORBIDDEN = re.compile(r"brute|dos|exploit|fuzz|flood|vuln|-enum-users|backdoor", re.IGNORECASE)
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")


def scripts_for(categories, mapping) -> list[str]:
    out: list[str] = []
    for cat in categories:
        for s in mapping.get(cat, []):
            if s not in out:
                out.append(s)
    return out


class ServiceInfo(Module):
    meta = ModuleMeta(
        id="nse.service_info",
        version="1",
        description="Information-only NSE scripts per service (MSSQL, MySQL, RDP, SMTP, NFS, SMB, FTP, VNC)",
        stage=Stage.ENUMERATION,
        safety=Safety.ACTIVE_SAFE,
        timeout_seconds=300,
        tools=(ToolRequirement("nmap", min_version="7.80"),),
        categories=("other", "mssql", "mysql", "rdp", "smtp", "nfs", "smb", "ftp", "vnc", "postgresql"),
        retry=RetryPolicy(max_attempts=2, backoff_seconds=5),
        max_parallel=2,
        config_defaults={"scripts": DEFAULT_SCRIPTS},
        profile_sections=("nmap",),
    )

    def unavailable_reason(self, ctx: PlanContext) -> str | None:
        for cat, names in (ctx.options.get("scripts") or {}).items():
            for name in names:
                if not NAME_RE.fullmatch(name) or FORBIDDEN.search(name):
                    return f"script '{name}' ({cat}) is not an information-only NSE script; remove it from the options"
        return None

    def plan(self, ctx: PlanContext) -> list[WorkUnit]:
        mapping = ctx.options["scripts"]
        units = []
        for svc in ctx.services:
            if svc.state != "open":
                continue
            scripts = scripts_for(svc.categories, mapping)
            if scripts:
                units.append(WorkUnit(self.meta.id, svc.key, {**_svc.service_inputs(ctx, svc), "scripts": scripts}))
        return units

    def build_commands(self, unit: WorkUnit, ctx: RunContext) -> list[Command]:
        a = unit.inputs["address"]
        p = nmap.params(ctx.profile_params)
        flags, raw, _ = nmap.privileges(ctx.tool_details)
        argv = ["-Pn", "-p", str(unit.inputs["port"]), "--script", ",".join(unit.inputs["scripts"])]
        if unit.inputs["protocol"] == "udp":
            if not raw:
                return []
            argv.append("-sU")
        argv += [*nmap.common(p, flags, a), *nmap.outputs(ctx.attempt_dir, "nse"), a]
        return [Command("nse", argv, tool="nmap", targets=[a])]

    def parse(self, unit: WorkUnit, results, ctx: RunContext) -> ModuleResult:
        res = ModuleResult(evidence_descriptions={"nse.xml": "nmap NSE output (XML)", "nse.nmap": "nmap NSE output"})
        if not results:
            res.limitations.append("UDP NSE scripts need raw sockets (`tools nmap-caps --apply`)")
            res.summary = "skipped (no raw sockets for UDP)"
            return res
        run = parse_nmap_xml_file(ctx.attempt_dir / "raw" / "nse.xml")
        host = run.host(unit.inputs["address"])
        port = next((p for p in (host.ports if host else []) if p.port == int(unit.inputs["port"])), None)
        scripts = dict(port.scripts) if port else {}
        res.artifacts = {"scripts": scripts, "requested": unit.inputs["scripts"]}
        url = f"{unit.inputs['protocol']}://{unit.inputs['address']}:{unit.inputs['port']}"
        for sid, output in scripts.items():
            res.observations.append({"key": f"nse.{sid}", "value": output.strip()[:4000], "url": url})
        if not run.complete:
            res.limitations.append("nmap did not finish cleanly")
        missing = [s for s in unit.inputs["scripts"] if s not in scripts]
        if missing:
            res.limitations.append(f"no output from: {', '.join(missing)} (not applicable or not answered)")
        res.summary = (f"{len(scripts)} script result(s): " + ", ".join(sorted(scripts))) if scripts else "no script output"
        return res
