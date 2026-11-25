"""http.whatweb: technology fingerprinting with WhatWeb (JSON log)."""

from __future__ import annotations

import json

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
from aiszx.modules.http import _web as web
from aiszx.modules.records import TechnologyRecord

NOISE = {"Country", "IP", "Title", "RedirectLocation", "UncommonHeaders", "HTML5", "Script", "Frame",
         "X-UA-Compatible", "Meta-Author", "Email"}


def load_whatweb(text: str) -> list[dict]:
    """WhatWeb's --log-json output is a JSON array, but older versions write one object per line."""
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
        return [d for d in (data if isinstance(data, list) else [data]) if isinstance(d, dict)]
    except ValueError:
        out = []
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if line.startswith("{"):
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
        return out


class WhatWeb(Module):
    meta = ModuleMeta(
        id="http.whatweb",
        version="1",
        description="Web technology fingerprinting (WhatWeb, aggression level from options)",
        stage=Stage.ENUMERATION,
        safety=Safety.ACTIVE_SAFE,
        timeout_seconds=300,
        tools=(ToolRequirement("whatweb"),),
        categories=("http", "https"),
        retry=RetryPolicy(max_attempts=2, backoff_seconds=5),
        config_defaults={"aggression": 1, "user_agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
                         "vhosts": [], "skip_categories": ["winrm"]},
    )

    def plan(self, ctx: PlanContext) -> list[WorkUnit]:
        return [WorkUnit(self.meta.id, ep.key, ep.inputs()) for ep in web.endpoints(ctx)]

    def build_commands(self, unit: WorkUnit, ctx: RunContext) -> list[Command]:
        ep = web.Endpoint.from_inputs(dict(unit.inputs))
        argv = ["--color=never", "--no-errors", "-a", str(int(ctx.options["aggression"])),
                "-U", str(ctx.options["user_agent"]), "--log-json=whatweb.json",
                *web.host_header(ep, "--header"), ep.address_url]
        return [Command("whatweb", argv, tool="whatweb", targets=web.targets(ep))]

    def parse(self, unit: WorkUnit, results, ctx: RunContext) -> ModuleResult:
        ep = web.Endpoint.from_inputs(dict(unit.inputs))
        try:
            entries = load_whatweb((ctx.attempt_dir / "raw" / "whatweb.json").read_text(encoding="utf-8", errors="replace"))
        except OSError:
            entries = []
        res = ModuleResult(evidence_descriptions={"whatweb.json": "WhatWeb JSON log"})
        seen = set()
        for entry in entries:
            for name, data in (entry.get("plugins") or {}).items():
                if name in NOISE or not isinstance(data, dict):
                    continue
                version = ", ".join(map(str, data.get("version", []))) or None
                detail = ", ".join(map(str, data.get("string", []) + data.get("os", [])))[:300] or None
                key = (name, version, detail)
                if key in seen:
                    continue
                seen.add(key)
                res.technologies.append(TechnologyRecord(ep.url, name, version, detail, "whatweb", "medium"))
        if not entries:
            res.limitations.append("WhatWeb produced no JSON result")
        res.artifacts = {"entries": entries[:20]}
        names = [t.name + (f" {t.version}" if t.version else "") for t in res.technologies]
        res.summary = (f"{len(names)} technolog{'y' if len(names) == 1 else 'ies'}: " + ", ".join(names[:12])
                       + (" ..." if len(names) > 12 else "")) if names else "no technologies identified"
        return res
