"""rservices.exposure: records exposed rexec/rlogin/rsh services for manual review (passive).

These services authenticate with cleartext passwords or host-based trust (.rhosts/hosts.equiv).
Testing them means attempting logins, which Aiszx never does automatically, so this module
only documents the exposure (from reconnaissance data) and what to review manually.
"""

from __future__ import annotations

from aiszx.modules import _svc
from aiszx.modules.base import Module, ModuleMeta, ModuleResult, PlanContext, Safety, Stage, WorkUnit

PORT_NAMES = {512: "rexec", 513: "rlogin", 514: "rsh"}


class RServicesExposure(Module):
    meta = ModuleMeta(
        id="rservices.exposure",
        version="1",
        description="Documents exposed rexec/rlogin/rsh for manual review (passive; no login attempts)",
        stage=Stage.ENUMERATION,
        safety=Safety.PASSIVE,
        timeout_seconds=10,
        categories=("rservices",),
    )

    def plan(self, ctx: PlanContext) -> list[WorkUnit]:
        svcs = _svc.services_in(ctx, ["rservices"], "tcp")
        if not svcs:
            return []
        return [WorkUnit(self.meta.id, "host", {
            "address": ctx.address,
            "services": [{"port": s.port, "service": PORT_NAMES.get(s.port, s.name), "banner": s.banner} for s in svcs],
        })]

    def build_commands(self, unit, ctx):
        return []

    def parse(self, unit, results, ctx) -> ModuleResult:
        svcs = unit.inputs["services"]
        names = ", ".join(f"{s['service']} ({s['port']}/tcp)" for s in svcs)
        res = ModuleResult(artifacts={"services": svcs})
        res.observations.append({"key": "rservices.exposed", "value": svcs, "url": f"tcp://{unit.inputs['address']}"})
        res.limitations.append("exposure recorded only: verifying host-based trust or credentials requires login "
                               "attempts, which need separate authorisation and are done manually")
        res.summary = (f"exposed: {names}. Cleartext/host-trust protocols; review manually "
                       "(trust relationships, which accounts are reachable)")
        return res
