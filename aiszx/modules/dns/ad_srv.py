"""dns.ad_srv: Active Directory SRV records (domain controllers, Kerberos, global catalog) via dig.

Asks only the target's own DNS server, for the domains already known (module options, LDAP/SMB results
of the same run, the target hostname, accepted virtual hosts). A handful of queries per domain.
"""

from __future__ import annotations

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
from aiszx.modules.dns.dig import QUERY, candidate_domains

SERVICES = {
    "ldap_dc": "_ldap._tcp.dc._msdcs.{d}",
    "ldap_pdc": "_ldap._tcp.pdc._msdcs.{d}",
    "kerberos": "_kerberos._tcp.{d}",
    "kpasswd": "_kpasswd._tcp.{d}",
    "gc": "_gc._tcp.{d}",
}


def parse_srv(text: str) -> list[dict]:
    """`dig +short SRV` answers: '<priority> <weight> <port> <target>.'"""
    out = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) == 4 and all(f.isdigit() for f in fields[:3]):
            out.append({"priority": int(fields[0]), "weight": int(fields[1]), "port": int(fields[2]),
                        "target": fields[3].rstrip(".").lower()})
    return out


class AdSrv(Module):
    meta = ModuleMeta(
        id="dns.ad_srv",
        version="1",
        description="Active Directory SRV records (DCs, Kerberos, global catalog) from the target's DNS server",
        stage=Stage.ENUMERATION,
        safety=Safety.ACTIVE_SAFE,
        timeout_seconds=90,
        tools=(ToolRequirement("dig"),),
        categories=("dns",),
        after=("ldap.rootdse", "smb.netexec", "smb.enum4linux_ng"),
        retry=RetryPolicy(max_attempts=2, backoff_seconds=3),
        config_defaults={"domains": [], "max_domains": 2},
    )

    def plan(self, ctx: PlanContext) -> list[WorkUnit]:
        svcs = _svc.services_in(ctx, ["dns"])
        domains = candidate_domains(ctx)
        if not svcs or not domains:
            return []
        port = sorted(svcs, key=lambda s: s.protocol != "udp")[0].port
        return [WorkUnit(self.meta.id, "dns", {"address": ctx.address, "port": port, "domains": domains})]

    def build_commands(self, unit: WorkUnit, ctx: RunContext) -> list[Command]:
        a = unit.inputs["address"]
        server = [f"@{a}", "-p", str(unit.inputs["port"])]
        return [Command(f"d{i}_{key}", [*server, pattern.format(d=domain), "SRV", "+short", *QUERY], tool="dig",
                        targets=[a])
                for i, domain in enumerate(unit.inputs["domains"]) for key, pattern in SERVICES.items()]

    def parse(self, unit: WorkUnit, results, ctx: RunContext) -> ModuleResult:
        a = unit.inputs["address"]
        res = ModuleResult()
        per_domain: dict[str, dict[str, list[dict]]] = {}
        records: dict[str, list[dict]] = {}
        for i, domain in enumerate(unit.inputs["domains"]):
            for key in SERVICES:
                recs = parse_srv(_svc.result_text(results, f"d{i}_{key}"))
                if recs:
                    per_domain.setdefault(domain, {})[key] = recs
                    records.setdefault(f"{key}@{domain}", []).extend(recs)
        res.artifacts = {"domains": per_domain, "records": records}
        for domain, recs in per_domain.items():
            dcs = sorted({r["target"] for r in recs.get("ldap_dc", []) + recs.get("ldap_pdc", [])})
            res.observations.append({"key": "dns.ad_srv", "url": f"dns://{a}",
                                     "value": {"domain": domain, "domain_controllers": dcs,
                                               "services": sorted(recs)}})
        if per_domain:
            res.summary = "; ".join(f"{d}: {len(r)} SRV service(s), DCs "
                                    f"{', '.join(sorted({x['target'] for x in r.get('ldap_dc', [])})) or '-'}"
                                    for d, r in per_domain.items())
        else:
            res.summary = f"no AD SRV records for {', '.join(unit.inputs['domains'])}"
        return res
