"""dns.dnsrecon: standard DNS records with dnsrecon (``-t std``) from the target's DNS server.

Standard mode only: SOA, NS, A/AAAA, MX, TXT/SPF and the common SRV names. No subdomain brute force,
no zone transfer (``dns.dig`` already makes the single, scoped AXFR attempt). dnsrecon normally also
asks every listed name server for its version and whether it recurses; those servers may be outside
scope, so both checks are switched off (``--disable_check_recursion --disable_check_bindversion``) and
only the target's own server is queried (``-n``).
"""

from __future__ import annotations

import json

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
from aiszx.modules.dns.dig import candidate_domains

RECORD_TYPES = {"A", "AAAA", "CNAME", "MX", "NS", "SOA", "SRV", "TXT", "SPF", "PTR"}


def parse_dnsrecon_json(text: str) -> list[dict]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    out = []
    for rec in data if isinstance(data, list) else []:
        if not isinstance(rec, dict) or str(rec.get("type", "")).upper() not in RECORD_TYPES:
            continue  # skips the "ScanInfo" entry
        keep = {k: (v.rstrip(".").lower() if k in ("name", "target", "exchange", "mname") and isinstance(v, str) else v)
                for k, v in rec.items() if k in ("type", "name", "address", "target", "port", "exchange", "mname",
                                                 "strings", "domain")}
        keep["type"] = str(rec["type"]).upper()
        out.append(keep)
    return out


class DnsRecon(Module):
    meta = ModuleMeta(
        id="dns.dnsrecon",
        version="1",
        description="Standard DNS records (SOA, NS, A/AAAA, MX, TXT, SRV) with dnsrecon -t std; no brute force",
        stage=Stage.ENUMERATION,
        safety=Safety.ACTIVE_SAFE,
        timeout_seconds=300,
        tools=(ToolRequirement("dnsrecon"),),
        categories=("dns",),
        after=("ldap.rootdse", "smb.netexec", "smb.enum4linux_ng"),
        retry=RetryPolicy(max_attempts=2, backoff_seconds=5),
        config_defaults={"domains": [], "max_domains": 2, "lifetime": 3},
    )

    def plan(self, ctx: PlanContext) -> list[WorkUnit]:
        svcs = [s for s in _svc.services_in(ctx, ["dns"]) if s.port == 53]
        domains = candidate_domains(ctx)
        if not svcs or not domains:
            return []
        return [WorkUnit(self.meta.id, "dns", {"address": ctx.address, "domains": domains})]

    def build_commands(self, unit: WorkUnit, ctx: RunContext) -> list[Command]:
        a = unit.inputs["address"]
        return [Command(f"d{i}", ["-d", domain, "-n", a, "-t", "std", "--lifetime", str(int(ctx.options["lifetime"])),
                                  "--disable_check_recursion", "--disable_check_bindversion", "-j", f"d{i}.json"],
                        tool="dnsrecon", targets=[a])
                for i, domain in enumerate(unit.inputs["domains"])]

    def parse(self, unit: WorkUnit, results, ctx: RunContext) -> ModuleResult:
        res = ModuleResult(evidence_descriptions={f"d{i}.json": f"dnsrecon records of {d} (JSON)"
                                                  for i, d in enumerate(unit.inputs["domains"])})
        records, per_domain = [], {}
        for i, domain in enumerate(unit.inputs["domains"]):
            recs = parse_dnsrecon_json(_svc.read(ctx, f"d{i}.json"))
            for r in recs:
                r.setdefault("domain", domain)
            records += recs
            per_domain[domain] = len(recs)
        res.artifacts = {"records": records, "per_domain": per_domain}
        url = f"dns://{unit.inputs['address']}"
        for domain, n in per_domain.items():
            if n:
                types = sorted({r["type"] for r in records if r.get("domain") == domain})
                res.observations.append({"key": "dns.records", "value": {"domain": domain, "count": n, "types": types},
                                         "url": url})
        if not records:
            res.limitations.append("dnsrecon returned no records (domain unknown to this server, or the server refused)")
        res.summary = "; ".join(f"{d}: {n} record(s)" for d, n in per_domain.items())
        return res
