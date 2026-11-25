"""dns.dig: DNS server information and records (dig).

Asks the in-scope DNS server only: version.bind, reverse lookup of the target, and for each known
domain SOA, NS, MX/TXT records and a zone transfer (AXFR) attempt. Domains come from the module
options, the target hostname and ``--vhost`` names. Without a known domain only the
server-level queries run.
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
from aiszx.targets.identity import normalise_hostname

QUERY = ["+time=3", "+tries=1"]


def upstream_domains(ctx: PlanContext) -> list[str]:
    """Domains learned earlier in the same run (LDAP RootDSE, SMB banners)."""
    found = []
    for r in ctx.upstream.get("ldap.rootdse", []):
        found.append((r.get("artifacts") or {}).get("domain"))
    for r in ctx.upstream.get("smb.netexec", []):
        found.append(((r.get("artifacts") or {}).get("host") or {}).get("domain"))
    for r in ctx.upstream.get("smb.enum4linux_ng", []):
        found.append((r.get("artifacts") or {}).get("domain"))
    return [d for d in found if isinstance(d, str) and "." in d]


def candidate_domains(ctx: PlanContext) -> list[str]:
    names = list(ctx.options.get("domains", []))
    names += upstream_domains(ctx)
    if not ctx.target.identity.is_ip:
        names.append(ctx.target.canonical)
    names += list(ctx.run_params.get("vhosts", []))
    out: list[str] = []
    for n in names:
        try:
            host = normalise_hostname(n)
        except Exception:
            continue
        labels = host.split(".")
        domain = ".".join(labels[-2:]) if len(labels) >= 2 else host  # box.htb, dev.box.htb → box.htb
        for d in (host, domain) if len(labels) == 2 else (domain, host):
            if d not in out and "." in d:
                out.append(d)
    return out[: int(ctx.options.get("max_domains", 3))]


def parse_axfr(text: str) -> dict:
    records = []
    for line in text.splitlines():
        if not line.strip() or line.startswith(";"):
            continue
        fields = line.split()
        if len(fields) >= 4 and fields[2].upper() == "IN":
            records.append({"name": fields[0], "type": fields[3], "value": " ".join(fields[4:])})
    failed = "Transfer failed" in text or "XFR size" not in text
    return {"allowed": bool(records) and not failed, "records": records}


def short_answers(text: str) -> list[str]:
    return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith(";")]


class Dig(Module):
    meta = ModuleMeta(
        id="dns.dig",
        version="1",
        description="DNS server version, reverse lookup, SOA/NS/MX/TXT and zone-transfer check against the target's DNS",
        stage=Stage.ENUMERATION,
        safety=Safety.ACTIVE_SAFE,
        timeout_seconds=120,
        tools=(ToolRequirement("dig"),),
        categories=("dns",),
        after=("ldap.rootdse", "smb.netexec", "smb.enum4linux_ng"),  # reuse domains they discover
        retry=RetryPolicy(max_attempts=2, backoff_seconds=3),
        config_defaults={"domains": [], "max_domains": 3, "zone_transfer": True},
    )

    def plan(self, ctx: PlanContext) -> list[WorkUnit]:
        svcs = _svc.services_in(ctx, ["dns"])
        if not svcs:
            return []
        port = sorted(svcs, key=lambda s: s.protocol != "tcp")[0].port  # prefer TCP (needed for AXFR)
        return [WorkUnit(self.meta.id, "dns", {"address": ctx.address, "port": port,
                                               "domains": candidate_domains(ctx)})]

    def build_commands(self, unit: WorkUnit, ctx: RunContext) -> list[Command]:
        a, port = unit.inputs["address"], str(unit.inputs["port"])
        server = [f"@{a}", "-p", port]
        cmds = [Command("version", [*server, "version.bind", "CHAOS", "TXT", "+short", *QUERY], tool="dig", targets=[a]),
                Command("reverse", [*server, "-x", a, "+short", *QUERY], tool="dig", targets=[a])]
        for i, domain in enumerate(unit.inputs["domains"]):
            for rtype in ("SOA", "NS", "MX", "TXT"):
                cmds.append(Command(f"d{i}_{rtype.lower()}", [*server, domain, rtype, "+short", *QUERY],
                                    tool="dig", targets=[a]))
            if ctx.options["zone_transfer"]:
                cmds.append(Command(f"d{i}_axfr", [*server, domain, "AXFR", "+time=5", "+tries=1"], tool="dig",
                                    targets=[a]))
        return cmds

    def parse(self, unit: WorkUnit, results, ctx: RunContext) -> ModuleResult:
        a = unit.inputs["address"]
        res = ModuleResult()
        out = {"version": short_answers(_svc.result_text(results, "version")),
               "reverse": short_answers(_svc.result_text(results, "reverse")), "domains": {}}
        url = f"dns://{a}"
        if out["version"]:
            res.observations.append({"key": "dns.version_disclosed", "value": out["version"][0], "url": url})
        for name in out["reverse"]:
            if re.search(r"[a-z]", name, re.IGNORECASE):
                res.observations.append({"key": "dns.reverse_name", "value": name.rstrip("."), "url": url})
        transfers = []
        for i, domain in enumerate(unit.inputs["domains"]):
            d = {rt: short_answers(_svc.result_text(results, f"d{i}_{rt.lower()}")) for rt in ("SOA", "NS", "MX", "TXT")}
            if any(r.label == f"d{i}_axfr" for r in results):
                d["AXFR"] = parse_axfr(_svc.result_text(results, f"d{i}_axfr"))
                if d["AXFR"]["allowed"]:
                    transfers.append(domain)
                    res.observations.append({"key": "dns.zone_transfer_allowed",
                                             "value": {"domain": domain, "records": len(d["AXFR"]["records"])},
                                             "url": url})
            out["domains"][domain] = d
        res.artifacts = out
        if not unit.inputs["domains"]:
            res.limitations.append("no domain known: only server-level queries ran (set modules.dns.dig.options."
                                   "domains, register a hostname target, or pass --vhost)")
        bits = [f"version: {out['version'][0]}" if out["version"] else "version hidden"]
        if out["reverse"]:
            bits.append(f"PTR {', '.join(out['reverse'])}")
        bits.append(f"{len(unit.inputs['domains'])} domain(s) queried")
        if transfers:
            bits.append(f"ZONE TRANSFER ALLOWED for {', '.join(transfers)}")
        res.summary = "; ".join(bits)
        return res
