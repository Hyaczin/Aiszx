"""snmp.walk: system information via SNMP *with community strings you were given*.

Community strings are credentials: Aiszx never guesses them. Configure the authorised ones in
``modules.snmp.walk.options.communities`` (per engagement in overrides.yaml); without them the
module is skipped. Community strings are redacted from stored command lines and results.
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

SYSTEM_MIB = "1.3.6.1.2.1.1"
NAMES = {"1.3.6.1.2.1.1.1.0": "sysDescr", "1.3.6.1.2.1.1.3.0": "sysUpTime", "1.3.6.1.2.1.1.4.0": "sysContact",
         "1.3.6.1.2.1.1.5.0": "sysName", "1.3.6.1.2.1.1.6.0": "sysLocation"}


def parse_walk(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        m = re.match(r"^\.?([\d.]+)\s*=\s*(?:[\w-]+:\s*)?(.*)$", line.strip())
        if m:
            oid = m.group(1)
            out[NAMES.get(oid, oid)] = m.group(2).strip().strip('"')
    return out


class SnmpWalk(Module):
    meta = ModuleMeta(
        id="snmp.walk",
        version="1",
        description="SNMP system information using authorised community strings only (never guessed)",
        stage=Stage.ENUMERATION,
        safety=Safety.ACTIVE_SAFE,
        timeout_seconds=60,
        tools=(ToolRequirement("snmpwalk"),),
        categories=("snmp",),
        retry=RetryPolicy(max_attempts=1),
        config_defaults={"communities": [], "version": "2c"},
        secret_options=("communities",),
    )

    def unavailable_reason(self, ctx: PlanContext) -> str | None:
        if not ctx.options.get("communities"):
            return ("needs authorised community strings in modules.snmp.walk.options.communities "
                    "(Aiszx does not guess them)")
        return None

    def plan(self, ctx: PlanContext) -> list[WorkUnit]:
        svcs = _svc.services_in(ctx, ["snmp"])
        # community strings are deliberately not part of the unit inputs (they would be stored)
        return [WorkUnit(self.meta.id, s.key, {**_svc.service_inputs(ctx, s),
                                               "communities": len(ctx.options.get("communities", []))}) for s in svcs]

    def build_commands(self, unit: WorkUnit, ctx: RunContext) -> list[Command]:
        a = unit.inputs["address"]
        cmds = []
        for i, community in enumerate(ctx.options["communities"]):
            cmds.append(Command(f"c{i}", [f"-v{ctx.options['version']}", "-c", community, "-t", "2", "-r", "1", "-On",
                                          f"{a}:{unit.inputs['port']}", SYSTEM_MIB],
                                tool="snmpwalk", targets=[a], redact=[community], ok_exit_codes=(0, 1, 2)))
        return cmds

    def parse(self, unit: WorkUnit, results, ctx: RunContext) -> ModuleResult:
        res = ModuleResult()
        readable = []
        for r in results:
            values = parse_walk(r.stdout())
            if values:
                readable.append(r.label)
                res.artifacts[f"community_{r.label}"] = values
        url = f"snmp://{unit.inputs['address']}:{unit.inputs['port']}"
        res.observations.append({"key": "snmp.readable", "value": bool(readable), "url": url})
        first = next(iter(v for k, v in res.artifacts.items() if k.startswith("community_")), {})
        res.summary = (f"readable with {len(readable)} of {len(results)} authorised communit"
                       f"{'y' if len(results) == 1 else 'ies'}" + (f"; sysDescr: {first.get('sysDescr', '')[:80]}" if first else ""))
        return res
