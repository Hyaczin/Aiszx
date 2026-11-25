"""smb.enum4linux_ng: unauthenticated SMB/RPC enumeration (enum4linux-ng -A, JSON output).

`-A` performs the simple checks (sessions, dialects, domain/OS info, shares, users/groups and
policy *only where a null session allows it*). RID cycling (-R) is not used.
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


def summarise(data: dict) -> dict:
    sessions = data.get("sessions") or {}
    dialects = data.get("smb_dialects") or {}
    shares = data.get("shares") or {}
    users = data.get("users") or {}
    groups = data.get("groups") or {}
    return {
        "null_session": bool(sessions.get("null")),
        "random_user_session": bool(sessions.get("random_user")),
        "signing_required": dialects.get("SMB signing required"),
        "smb1_only": dialects.get("SMB1 only"),
        "dialects": {k: v for k, v in (dialects.get("Supported dialects") or {}).items()},
        "domain": (data.get("smb_domain_info") or {}).get("DNS domain") or (data.get("domain_info") or {}).get("domain"),
        "os": (data.get("os_info") or {}).get("OS") or (data.get("os_info") or {}).get("OS information"),
        "shares": {name: {"type": s.get("type"), "comment": s.get("comment"),
                          "access": (s.get("access") or {})} for name, s in shares.items() if isinstance(s, dict)},
        "users": sorted({u.get("username") for u in users.values() if isinstance(u, dict) and u.get("username")}),
        "groups": sorted({g.get("groupname") for g in groups.values() if isinstance(g, dict) and g.get("groupname")}),
        "policy": data.get("policy") or {},
        "errors": data.get("errors") or {},
    }


class Enum4LinuxNg(Module):
    meta = ModuleMeta(
        id="smb.enum4linux_ng",
        version="1",
        description="Unauthenticated SMB/RPC enumeration: sessions, dialects, domain/OS, shares, users (enum4linux-ng -A)",
        stage=Stage.ENUMERATION,
        safety=Safety.ACTIVE_SAFE,
        timeout_seconds=600,
        tools=(ToolRequirement("enum4linux-ng"),),
        categories=("smb",),
        retry=RetryPolicy(max_attempts=1),
    )

    def plan(self, ctx: PlanContext) -> list[WorkUnit]:
        return _svc.per_host_unit(self, ctx, ["smb"])

    def build_commands(self, unit: WorkUnit, ctx: RunContext) -> list[Command]:
        a = unit.inputs["address"]
        return [Command("e4l", ["-A", "-oJ", "e4l", a], tool="enum4linux-ng", targets=[a], ok_exit_codes=(0, 1))]

    def parse(self, unit: WorkUnit, results, ctx: RunContext) -> ModuleResult:
        res = ModuleResult(evidence_descriptions={"e4l.json": "enum4linux-ng JSON", "e4l.stdout.txt": "enum4linux-ng output"})
        try:
            data = json.loads(_svc.read(ctx, "e4l.json") or "{}")
        except ValueError:
            data = {}
        if not data:
            res.limitations.append("enum4linux-ng produced no JSON output")
            res.summary = "no structured output"
            return res
        s = summarise(data)
        res.artifacts = s
        url = f"smb://{unit.inputs['address']}"
        res.observations.append({"key": "smb.null_session", "value": s["null_session"], "url": url})
        if s["signing_required"] is not None:
            res.observations.append({"key": "smb.signing_required", "value": bool(s["signing_required"]), "url": url})
        listable = [n for n, sh in s["shares"].items() if (sh["access"] or {}).get("listing") == "OK"]
        if listable:
            res.observations.append({"key": "smb.null_listable_shares", "value": listable, "url": url})
        if s["users"]:
            res.observations.append({"key": "smb.users_enumerable", "value": s["users"][:200], "url": url})
        if s["policy"]:
            res.observations.append({"key": "smb.password_policy", "value": s["policy"], "url": url})
        res.summary = (f"null session {'allowed' if s['null_session'] else 'denied'}; domain {s['domain'] or '?'}; "
                       f"{len(s['shares'])} share(s), {len(listable)} listable; {len(s['users'])} user(s)")
        return res
