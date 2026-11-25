"""ssh.audit: SSH banner, algorithms and host keys with ssh-audit (JSON). No authentication attempted."""

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


def weak_algorithms(data: dict) -> dict[str, list[dict]]:
    """Algorithms that ssh-audit flags with 'fail' or 'warn' notes, per class (kex/key/enc/mac)."""
    out: dict[str, list[dict]] = {}
    for cls in ("kex", "key", "enc", "mac"):
        for item in data.get(cls) or []:
            if not isinstance(item, dict):
                continue
            notes = item.get("notes") or {}
            fail = notes.get("fail") or item.get("fail") or []
            warn = notes.get("warn") or item.get("warn") or []
            if fail or warn:
                out.setdefault(cls, []).append({"algorithm": item.get("algorithm"), "fail": fail, "warn": warn})
    return out


class SshAudit(Module):
    meta = ModuleMeta(
        id="ssh.audit",
        version="1",
        description="SSH banner, key exchange/cipher/MAC/host-key algorithms and weaknesses (ssh-audit)",
        stage=Stage.ENUMERATION,
        safety=Safety.ACTIVE_SAFE,
        timeout_seconds=90,
        tools=(ToolRequirement("ssh-audit"),),
        categories=("ssh",),
        retry=RetryPolicy(max_attempts=2, backoff_seconds=5),
    )

    def plan(self, ctx: PlanContext) -> list[WorkUnit]:
        return _svc.per_service_units(self, ctx, ["ssh"])

    def build_commands(self, unit: WorkUnit, ctx: RunContext) -> list[Command]:
        a = unit.inputs["address"]
        # ssh-audit exit codes encode the verdict (0 good, 1 warn, 2 fail, 3 unknown): all are results
        return [Command("audit", ["-j", "-t", "15", "-p", str(unit.inputs["port"]), a], tool="ssh-audit",
                        targets=[a], ok_exit_codes=(0, 1, 2, 3))]

    def parse(self, unit: WorkUnit, results, ctx: RunContext) -> ModuleResult:
        res = ModuleResult(evidence_descriptions={"audit.stdout.txt": "ssh-audit JSON"})
        text = next((r for r in results if r.label == "audit"), None)
        try:
            data = json.loads(text.stdout() if text else "{}")
        except ValueError:
            data = {}
        if not isinstance(data, dict) or not data:
            res.limitations.append("ssh-audit returned no JSON")
            res.summary = "no result"
            return res
        banner = data.get("banner") or {}
        weak = weak_algorithms(data)
        keys = [f.get("hash") for f in data.get("fingerprints") or [] if isinstance(f, dict)]
        res.artifacts = {"banner": banner, "weak": weak, "fingerprints": data.get("fingerprints") or [],
                         "recommendations": data.get("recommendations") or {}}
        url = f"ssh://{unit.inputs['address']}:{unit.inputs['port']}"
        if banner.get("software"):
            res.observations.append({"key": "ssh.software", "value": banner.get("software"), "url": url})
        if weak:
            res.observations.append({"key": "ssh.weak_algorithms",
                                     "value": {c: [w["algorithm"] for w in v] for c, v in weak.items()}, "url": url})
        n_weak = sum(len(v) for v in weak.values())
        res.summary = (f"{banner.get('software') or banner.get('raw') or '?'}; {n_weak} algorithm(s) flagged; "
                       f"{len(keys)} host key fingerprint(s)")
        return res
