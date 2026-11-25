"""recon.tcp_ports: TCP port discovery (nmap -Pn -sS/-sT, all ports by default).

Resumable: if a previous attempt was interrupted, its grepable output is copied into the new
attempt (with the output paths rewritten) and the scan continues with ``nmap --resume``.
"""

from __future__ import annotations

import shutil

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
from aiszx.modules.records import PortRecord
from aiszx.modules.recon._nmap_base import NmapModule
from aiszx.parsers.nmap_xml import parse_gnmap_ports, parse_nmap_xml_file
from aiszx.recon import nmap

NAME = "tcp"


class TcpPorts(NmapModule):
    output_name = NAME
    meta = ModuleMeta(
        id="recon.tcp_ports",
        version="1",
        description="TCP port discovery (all ports by default; SYN scan with raw sockets, else connect scan)",
        stage=Stage.RECON,
        safety=Safety.ACTIVE_SAFE,
        timeout_seconds=3600,
        tools=(ToolRequirement("nmap", min_version="7.80"),),
        retry=RetryPolicy(max_attempts=2, backoff_seconds=10),
        resumable=True,
        profile_sections=("nmap",),
    )

    def _resume_from(self, ctx: RunContext):
        prev = ctx.previous_attempt_dir
        if prev is None:
            return None
        gnmap = prev / "raw" / f"{NAME}.gnmap"
        if not gnmap.is_file() or parse_nmap_xml_file(prev / "raw" / f"{NAME}.xml").complete:
            return None
        return prev

    def build_commands(self, unit: WorkUnit, ctx: RunContext) -> list[Command]:
        address = unit.inputs["address"]
        prev = self._resume_from(ctx)
        if prev is not None:
            # Prepare this attempt's own copies; nmap --resume reuses the original -oA base path,
            # so rewrite it to point into the new attempt (the previous attempt stays untouched).
            old_base, new_base = str(prev / "raw" / NAME), str(ctx.attempt_dir / "raw" / NAME)
            for ext in ("gnmap", "nmap", "xml"):
                src = prev / "raw" / f"{NAME}.{ext}"
                if src.is_file():
                    text = src.read_text(encoding="utf-8", errors="replace").replace(old_base, new_base)
                    (ctx.attempt_dir / "raw" / f"{NAME}.{ext}").write_text(text, encoding="utf-8")
            shutil.copyfile(prev / "raw" / f"{NAME}.gnmap", ctx.attempt_dir / "raw" / "resumed-from.gnmap")
            return [Command("tcp", ["--resume", f"{new_base}.gnmap"], tool="nmap", targets=[address])]

        p = nmap.params(ctx.profile_params)
        flags, raw, _ = nmap.privileges(ctx.tool_details)
        argv = ["-Pn", "-sS" if raw else "-sT", *nmap.tcp_port_args(p["tcp_ports"]), *nmap.rate_args(p),
                *nmap.common(p, flags, address), *nmap.outputs(ctx.attempt_dir, NAME), address]
        return [Command("tcp", argv, tool="nmap", targets=[address])]

    def parse(self, unit: WorkUnit, results, ctx: RunContext) -> ModuleResult:
        address = unit.inputs["address"]
        run = self.load(ctx)
        res = ModuleResult(limitations=self.completeness(run), evidence_descriptions={
            f"{NAME}.xml": "nmap TCP port scan (XML)", f"{NAME}.nmap": "nmap TCP port scan (normal output)",
            f"{NAME}.gnmap": "nmap TCP port scan (grepable output)"})
        resumed = (ctx.attempt_dir / "raw" / "resumed-from.gnmap").is_file()
        host = run.host(address)
        open_ports = sorted({p.port for p in (host.ports if host else []) if p.protocol == "tcp" and p.state == "open"})
        if resumed or (not run.complete and not open_ports):
            gnmap = ctx.attempt_dir / "raw" / f"{NAME}.gnmap"
            if gnmap.is_file():
                fallback = parse_gnmap_ports(gnmap.read_text(encoding="utf-8", errors="replace")).get(address, [])
                extra = {p.port for p in fallback if p.protocol == "tcp" and p.state == "open"}
                if extra - set(open_ports):
                    res.limitations.append("ports after `nmap --resume` were read from grepable output")
                open_ports = sorted(set(open_ports) | extra)
        if resumed:
            res.limitations.append("scan was resumed from an interrupted attempt (nmap --resume)")
        _, raw, mode = nmap.privileges(ctx.tool_details)
        p = nmap.params(ctx.profile_params)
        res.ports = [PortRecord(address, "tcp", port, "open") for port in open_ports]
        res.artifacts = {
            "open_ports": open_ports, "scope": nmap.describe_tcp(p["tcp_ports"]),
            "scan_type": "syn" if raw else "connect", "privileges": mode,
            "extraports": [list(e) for e in host.extraports] if host else [], "complete": run.complete,
            "elapsed": run.elapsed,
        }
        if not raw:
            res.limitations.append("TCP connect scan (no raw sockets): slower and more visible than a SYN scan")
        listed = ", ".join(map(str, open_ports[:25])) + (" ..." if len(open_ports) > 25 else "")
        res.summary = (f"{len(open_ports)} open TCP port(s) of {nmap.describe_tcp(p['tcp_ports'])}: {listed}"
                       if open_ports else f"no open TCP ports among {nmap.describe_tcp(p['tcp_ports'])}")
        return res
