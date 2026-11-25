"""smb.netexec: SMB host information, signing/SMBv1, and null/guest share access (NetExec).

Unauthenticated only: one banner query, then one null-session and one guest attempt to list shares
(the standard "guest access" check). No credential guessing.
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

_PREFIX = re.compile(r"^SMB\s+\S+\s+\d+\s+\S+\s+(.*)$")


def message_lines(text: str) -> list[str]:
    out = []
    for line in _svc.strip_ansi(text).splitlines():
        m = _PREFIX.match(line.strip())
        if m:
            out.append(m.group(1).rstrip())
    return out


def parse_banner(text: str) -> dict:
    for msg in message_lines(text):
        if msg.startswith("[*]") and "(name:" in msg:
            info = {"os": msg[3:].split("(", 1)[0].strip()}
            for key, value in re.findall(r"\(([\w ]+):([^)]*)\)", msg):
                info[key.strip().lower().replace(" ", "_")] = value.strip()
            return info
    return {}


def parse_shares(text: str) -> dict:
    """Return {"authenticated": bool|None, "error": str|None, "shares": [{"name","permissions","remark"}]}."""
    out: dict = {"authenticated": None, "error": None, "shares": []}
    in_table = False
    for msg in message_lines(text):
        if msg.startswith("[+]") and "\\" in msg:
            out["authenticated"] = True
        elif msg.startswith("[-]") and out["authenticated"] is None:
            out["authenticated"] = False
            out["error"] = msg[3:].strip()
        elif msg.startswith("[-]"):
            out["error"] = msg[3:].strip()
        elif msg.startswith("Share") and "Permissions" in msg:
            in_table = True
        elif in_table and msg and not msg.startswith("-----") and not msg.startswith("["):
            cols = re.split(r"\s{2,}", msg.strip())
            name = cols[0]
            perms = cols[1] if len(cols) > 1 and re.fullmatch(r"[A-Z,]+", cols[1]) else ""
            remark = cols[-1] if len(cols) > (2 if perms else 1) else ""
            out["shares"].append({"name": name, "permissions": perms, "remark": remark})
    return out


class NetExecSmb(Module):
    meta = ModuleMeta(
        id="smb.netexec",
        version="1",
        description="SMB OS/domain, signing and SMBv1 (NetExec); null-session and guest share listing",
        stage=Stage.ENUMERATION,
        safety=Safety.ACTIVE_SAFE,
        timeout_seconds=180,
        tools=(ToolRequirement("netexec"),),
        categories=("smb",),
        retry=RetryPolicy(max_attempts=2, backoff_seconds=5),
        config_defaults={"guest_check": True, "null_session_check": True},
    )

    def plan(self, ctx: PlanContext) -> list[WorkUnit]:
        svcs = [s for s in _svc.services_in(ctx, ["smb"], "tcp") if s.port == 445] or _svc.services_in(ctx, ["smb"], "tcp")
        return [WorkUnit(self.meta.id, svcs[0].key, _svc.service_inputs(ctx, svcs[0]))] if svcs else []

    def build_commands(self, unit: WorkUnit, ctx: RunContext) -> list[Command]:
        a, port = unit.inputs["address"], str(unit.inputs["port"])
        base = ["smb", a, "--port", port]
        cmds = [Command("info", base, tool="netexec", targets=[a], ok_exit_codes=(0, 1))]
        if ctx.options["null_session_check"]:
            cmds.append(Command("null", [*base, "-u", "", "-p", "", "--shares"], tool="netexec", targets=[a],
                                ok_exit_codes=(0, 1)))
        if ctx.options["guest_check"]:
            cmds.append(Command("guest", [*base, "-u", "guest", "-p", "", "--shares"], tool="netexec", targets=[a],
                                ok_exit_codes=(0, 1)))
        return cmds

    def parse(self, unit: WorkUnit, results, ctx: RunContext) -> ModuleResult:
        res = ModuleResult(evidence_descriptions={"info.stdout.txt": "NetExec SMB banner",
                                                  "null.stdout.txt": "NetExec null-session shares",
                                                  "guest.stdout.txt": "NetExec guest shares"})
        info = parse_banner(_svc.result_text(results, "info"))
        res.artifacts["host"] = info
        url = f"smb://{unit.inputs['address']}:{unit.inputs['port']}"
        if info:
            if "signing" in info:
                res.observations.append({"key": "smb.signing_required", "value": info["signing"].lower() == "true", "url": url})
            if "smbv1" in info:
                res.observations.append({"key": "smb.smbv1_enabled", "value": info["smbv1"].lower() == "true", "url": url})
            if info.get("domain"):
                res.observations.append({"key": "smb.domain", "value": info["domain"], "url": url})
        else:
            res.limitations.append("no NetExec banner parsed")
        parts = []
        for label in ("null", "guest"):
            if not any(r.label == label for r in results):
                continue
            access = parse_shares(_svc.result_text(results, label))
            res.artifacts[label] = access
            readable = [s["name"] for s in access["shares"] if "READ" in s["permissions"]]
            res.observations.append({"key": f"smb.{label}_session", "value": bool(access["authenticated"]), "url": url})
            if readable:
                res.observations.append({"key": f"smb.{label}_readable_shares", "value": readable, "url": url})
            parts.append(f"{label}: " + ("accepted" if access["authenticated"] else "denied")
                         + (f", readable {', '.join(readable)}" if readable else ""))
        head = " ".join(f"{k}={info[k]}" for k in ("name", "domain", "signing", "smbv1") if k in info)
        res.summary = "; ".join(p for p in [f"{info.get('os', '?')} {head}".strip(), *parts] if p)
        return res
