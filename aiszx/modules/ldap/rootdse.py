"""ldap.rootdse: LDAP RootDSE (anonymous base query): naming contexts, domain, DC identification."""

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

TLS_PORTS = {636, 3269}
FIELDS = ("namingContexts", "defaultNamingContext", "rootDomainNamingContext", "configurationNamingContext",
          "dnsHostName", "serverName", "ldapServiceName", "domainFunctionality", "forestFunctionality",
          "domainControllerFunctionality", "supportedLDAPVersion", "supportedSASLMechanisms",
          "isGlobalCatalogReady", "vendorName", "vendorVersion")


def ldap_url(address: str, port: int) -> str:
    host = f"[{address}]" if ":" in address else address
    return f"{'ldaps' if port in TLS_PORTS else 'ldap'}://{host}:{port}"


def ldap_env(port: int) -> dict[str, str]:
    return {"LDAPTLS_REQCERT": "never"} if port in TLS_PORTS else {}


class RootDse(Module):
    meta = ModuleMeta(
        id="ldap.rootdse",
        version="1",
        description="LDAP RootDSE: naming contexts, DNS host name, domain and functional levels (anonymous)",
        stage=Stage.ENUMERATION,
        safety=Safety.ACTIVE_SAFE,
        timeout_seconds=60,
        tools=(ToolRequirement("ldapsearch"),),
        categories=("ldap",),
        retry=RetryPolicy(max_attempts=2, backoff_seconds=5),
    )

    def plan(self, ctx: PlanContext) -> list[WorkUnit]:
        return _svc.per_service_units(self, ctx, ["ldap"])

    def build_commands(self, unit: WorkUnit, ctx: RunContext) -> list[Command]:
        port = int(unit.inputs["port"])
        argv = ["-LLL", "-x", "-H", ldap_url(unit.inputs["address"], port), "-o", "nettimeout=10",
                "-s", "base", "-b", "", "(objectClass=*)", "*", "+"]
        return [Command("rootdse", argv, tool="ldapsearch", targets=[unit.inputs["address"]], env=ldap_env(port))]

    def parse(self, unit: WorkUnit, results, ctx: RunContext) -> ModuleResult:
        entries = _svc.parse_ldif(_svc.result_text(results, "rootdse"))
        attrs = entries[0] if entries else {}
        info = {k: (attrs[k] if len(attrs.get(k, [])) > 1 else attrs.get(k, [None])[0]) for k in FIELDS if k in attrs}
        domain = _svc.dn_to_domain(info.get("defaultNamingContext") if isinstance(info.get("defaultNamingContext"), str)
                                   else None)
        is_dc = "domainControllerFunctionality" in info
        res = ModuleResult(artifacts={**info, "domain": domain, "is_domain_controller": is_dc},
                           evidence_descriptions={"rootdse.stdout.txt": "LDAP RootDSE (LDIF)"})
        url = ldap_url(unit.inputs["address"], int(unit.inputs["port"]))
        if domain:
            res.observations.append({"key": "ldap.domain", "value": domain, "url": url})
        if is_dc:
            res.observations.append({"key": "ldap.domain_controller", "value": info.get("dnsHostName"), "url": url})
        if not attrs:
            res.limitations.append("RootDSE not readable")
        res.summary = (f"{'domain controller ' if is_dc else ''}{info.get('dnsHostName') or ''} domain {domain or '?'}; "
                       f"naming contexts: {len(attrs.get('namingContexts', []))}").strip()
        return res
