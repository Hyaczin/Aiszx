"""smb.smbclient: anonymous share list (smbclient -N -L, grepable output)."""

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


def parse_grepable(text: str) -> list[dict]:
    shares = []
    for line in text.splitlines():
        parts = line.strip().split("|")
        if len(parts) >= 2 and parts[0] in ("Disk", "IPC", "Printer"):
            shares.append({"type": parts[0], "name": parts[1], "comment": parts[2] if len(parts) > 2 else ""})
    return shares


class SmbClient(Module):
    meta = ModuleMeta(
        id="smb.smbclient",
        version="1",
        description="Anonymous SMB share listing (smbclient -N -L)",
        stage=Stage.ENUMERATION,
        safety=Safety.ACTIVE_SAFE,
        timeout_seconds=60,
        tools=(ToolRequirement("smbclient"),),
        categories=("smb",),
        retry=RetryPolicy(max_attempts=2, backoff_seconds=5),
    )

    def plan(self, ctx: PlanContext) -> list[WorkUnit]:
        svcs = [s for s in _svc.services_in(ctx, ["smb"], "tcp") if s.port == 445] or _svc.services_in(ctx, ["smb"], "tcp")
        return [WorkUnit(self.meta.id, svcs[0].key, _svc.service_inputs(ctx, svcs[0]))] if svcs else []

    def build_commands(self, unit: WorkUnit, ctx: RunContext) -> list[Command]:
        a = unit.inputs["address"]
        return [Command("list", ["-N", "-g", "-L", f"//{a}", "-p", str(unit.inputs["port"])], tool="smbclient",
                        targets=[a], ok_exit_codes=(0, 1))]

    def parse(self, unit: WorkUnit, results, ctx: RunContext) -> ModuleResult:
        text = _svc.result_text(results, "list")
        shares = parse_grepable(text)
        denied = "NT_STATUS_ACCESS_DENIED" in text or "NT_STATUS_LOGON_FAILURE" in text
        res = ModuleResult(artifacts={"shares": shares, "anonymous_denied": denied})
        res.observations.append({"key": "smb.anonymous_share_list", "value": bool(shares),
                                 "url": f"smb://{unit.inputs['address']}"})
        res.summary = (f"anonymous listing allowed: {', '.join(s['name'] for s in shares)}" if shares
                       else "anonymous share listing denied" if denied else "no shares listed")
        return res
