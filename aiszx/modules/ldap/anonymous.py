"""ldap.anonymous: does an anonymous bind expose directory contents? (bounded subtree query)

Planned from ``ldap.rootdse`` results in the same run: queries the default naming context
anonymously with a small size limit and records how many entries were readable.
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
from aiszx.modules.ldap.rootdse import ldap_env, ldap_url


class LdapAnonymous(Module):
    meta = ModuleMeta(
        id="ldap.anonymous",
        version="1",
        description="Anonymous read access to the default naming context (bounded query, size limit)",
        stage=Stage.ENUMERATION,
        safety=Safety.ACTIVE_SAFE,
        timeout_seconds=90,
        tools=(ToolRequirement("ldapsearch"),),
        categories=("ldap",),
        depends_on=("ldap.rootdse",),
        retry=RetryPolicy(max_attempts=1),
        config_defaults={"size_limit": 100},
    )

    def plan(self, ctx: PlanContext) -> list[WorkUnit]:
        units = []
        for r in ctx.upstream.get("ldap.rootdse", []):
            nc = (r.get("artifacts") or {}).get("defaultNamingContext")
            key = r.get("unit")
            if isinstance(nc, str) and nc and key:
                port = int(key.split("/", 1)[1])
                units.append(WorkUnit(self.meta.id, key, {"address": ctx.address, "port": port, "base": nc}))
        return units

    def build_commands(self, unit: WorkUnit, ctx: RunContext) -> list[Command]:
        port = int(unit.inputs["port"])
        argv = ["-LLL", "-x", "-H", ldap_url(unit.inputs["address"], port), "-o", "nettimeout=10",
                "-z", str(int(ctx.options["size_limit"])), "-b", unit.inputs["base"], "-s", "sub",
                "(objectClass=*)", "dn", "objectClass"]
        # 4 = size limit exceeded (results returned), 32 = no such object, 50 = insufficient access
        return [Command("search", argv, tool="ldapsearch", targets=[unit.inputs["address"]], env=ldap_env(port),
                        ok_exit_codes=(0, 4, 32, 50))]

    def parse(self, unit: WorkUnit, results, ctx: RunContext) -> ModuleResult:
        r = next((x for x in results if x.label == "search"), None)
        entries = _svc.parse_ldif(r.stdout() if r else "")
        dns = [e["dn"][0] for e in entries if "dn" in e]
        readable = bool(dns)
        res = ModuleResult(artifacts={"base": unit.inputs["base"], "entries": len(dns), "sample": dns[:25],
                                      "exit_code": r.exit_code if r else None})
        res.observations.append({"key": "ldap.anonymous_read", "value": {"readable": readable, "entries": len(dns)},
                                 "url": ldap_url(unit.inputs["address"], int(unit.inputs["port"]))})
        if r is not None and r.exit_code == 4:
            res.limitations.append(f"size limit {ctx.options['size_limit']} reached: more entries are readable")
        res.summary = (f"anonymous read ALLOWED: {len(dns)} entr{'y' if len(dns) == 1 else 'ies'} under "
                       f"{unit.inputs['base']}" if readable else f"anonymous read of {unit.inputs['base']} denied or empty")
        return res
