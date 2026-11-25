"""ftp.anonymous: banner and the standard anonymous-login check, with a root listing if permitted (curl).

One login attempt as ``anonymous`` (the conventional public FTP account), no other credentials.
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

ANY = tuple(range(0, 100))


def parse_session(stderr: str) -> dict:
    replies = re.findall(r"^< (\d{3})[ -](.*)$", stderr, re.MULTILINE)
    codes = [c for c, _ in replies]
    banner = next((t.strip() for c, t in replies if c == "220"), None)
    return {"banner": banner, "anonymous": "230" in codes, "denied": "530" in codes, "codes": codes}


class FtpAnonymous(Module):
    meta = ModuleMeta(
        id="ftp.anonymous",
        version="1",
        description="FTP banner, anonymous-login check and root listing when anonymous access is permitted (curl)",
        stage=Stage.ENUMERATION,
        safety=Safety.ACTIVE_SAFE,
        timeout_seconds=60,
        tools=(ToolRequirement("curl"),),
        categories=("ftp",),
        retry=RetryPolicy(max_attempts=2, backoff_seconds=5),
    )

    def plan(self, ctx: PlanContext) -> list[WorkUnit]:
        return _svc.per_service_units(self, ctx, ["ftp"])

    def build_commands(self, unit: WorkUnit, ctx: RunContext) -> list[Command]:
        a = unit.inputs["address"]
        host = f"[{a}]" if ":" in a else a
        return [Command("anon", ["-sS", "-v", "--max-time", "20", "--list-only", "--user",
                                 "anonymous:anonymous@example.com", f"ftp://{host}:{unit.inputs['port']}/"],
                        tool="curl", targets=[a], ok_exit_codes=ANY)]

    def parse(self, unit: WorkUnit, results, ctx: RunContext) -> ModuleResult:
        r = next((x for x in results if x.label == "anon"), None)
        session = parse_session(r.stderr() if r else "")
        listing = [ln for ln in (r.stdout() if r else "").splitlines() if ln.strip()] if session["anonymous"] else []
        res = ModuleResult(artifacts={**session, "listing": listing[:500]})
        url = f"ftp://{unit.inputs['address']}:{unit.inputs['port']}"
        if session["banner"]:
            res.observations.append({"key": "ftp.banner", "value": session["banner"], "url": url})
        res.observations.append({"key": "ftp.anonymous_login", "value": session["anonymous"], "url": url})
        if not session["codes"]:
            res.limitations.append("no FTP dialogue captured (connection failed?)")
        res.summary = (f"banner {session['banner'] or '?'}; anonymous login "
                       + (f"ALLOWED, {len(listing)} entr{'y' if len(listing) == 1 else 'ies'} in /" if session["anonymous"]
                          else "denied" if session["denied"] else "not determined"))
        return res
