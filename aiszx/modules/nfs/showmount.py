"""nfs.showmount: NFS export list and who may mount each export (showmount -e). Nothing is mounted."""

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


def parse_exports(text: str) -> list[dict]:
    exports = []
    for line in text.splitlines():
        if not line.startswith("/"):
            continue
        path, _, clients = line.partition(" ")
        allowed = [c.strip() for c in clients.replace(",", " ").split() if c.strip()]
        exports.append({"path": path, "clients": allowed,
                        "world": any(c in ("*", "(everyone)", "0.0.0.0/0", "everyone") for c in allowed)})
    return exports


class ShowMount(Module):
    meta = ModuleMeta(
        id="nfs.showmount",
        version="1",
        description="NFS exports and permitted clients (showmount -e); exports are not mounted",
        stage=Stage.ENUMERATION,
        safety=Safety.ACTIVE_SAFE,
        timeout_seconds=60,
        tools=(ToolRequirement("showmount"),),
        categories=("nfs",),
        retry=RetryPolicy(max_attempts=2, backoff_seconds=5),
    )

    def plan(self, ctx: PlanContext) -> list[WorkUnit]:
        return _svc.per_host_unit(self, ctx, ["nfs"])

    def build_commands(self, unit: WorkUnit, ctx: RunContext) -> list[Command]:
        a = unit.inputs["address"]
        return [Command("exports", ["-e", a], tool="showmount", targets=[a], ok_exit_codes=(0, 1))]

    def parse(self, unit: WorkUnit, results, ctx: RunContext) -> ModuleResult:
        text = _svc.result_text(results, "exports")
        exports = parse_exports(text)
        res = ModuleResult(artifacts={"exports": exports})
        url = f"nfs://{unit.inputs['address']}"
        if exports:
            res.observations.append({"key": "nfs.exports", "value": exports, "url": url})
        world = [e["path"] for e in exports if e["world"]]
        if world:
            res.observations.append({"key": "nfs.world_mountable", "value": world, "url": url})
        if not exports and ("RPC" in text or "rpc" in text):
            res.limitations.append("export list not available: " + text.strip().splitlines()[-1][:200])
        res.summary = (f"{len(exports)} export(s)" + (f"; mountable by anyone: {', '.join(world)}" if world else "")
                       if exports else "no exports listed")
        return res
