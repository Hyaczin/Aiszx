"""http.nikto: Nikto web server checks (noisy). Items are unverified indicators for manual review."""

from __future__ import annotations

import json
import re

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


def load_nikto(text: str) -> list[dict]:
    """Nikto JSON varies by version (object or list of hosts); fall back to scraping "msg" fields."""
    items: list[dict] = []
    try:
        data = json.loads(text)
        hosts = data if isinstance(data, list) else [data]
        for h in hosts:
            for v in (h.get("vulnerabilities") or []) if isinstance(h, dict) else []:
                if isinstance(v, dict):
                    items.append({"id": v.get("id"), "method": v.get("method"), "url": v.get("url"), "msg": v.get("msg")})
        return items
    except ValueError:
        return [{"id": None, "method": None, "url": None, "msg": m}
                for m in re.findall(r'"msg"\s*:\s*"((?:[^"\\]|\\.)*)"', text)]


class Nikto(Module):
    meta = ModuleMeta(
        id="http.nikto",
        version="1",
        description="Nikto web server misconfiguration checks (noisy; results are unverified indicators)",
        stage=Stage.ENUMERATION,
        safety=Safety.ACTIVE_NOISY,
        timeout_seconds=1800,
        tools=(ToolRequirement("nikto"),),
        categories=("http", "https"),
        retry=RetryPolicy(max_attempts=1),
        max_parallel=1,
        config_defaults={"max_time": "15m", "tuning": "", "vhosts": [], "skip_categories": ["winrm"]},
    )

    def plan(self, ctx: PlanContext) -> list[WorkUnit]:
        return [WorkUnit(self.meta.id, ep.key, ep.inputs()) for ep in web.endpoints(ctx)]

    def build_commands(self, unit: WorkUnit, ctx: RunContext) -> list[Command]:
        ep = web.Endpoint.from_inputs(dict(unit.inputs))
        argv = ["-h", ep.address, "-p", str(ep.port), "-Format", "json", "-o", "nikto.json", "-ask", "no",
                "-nointeractive", "-maxtime", str(ctx.options["max_time"])]
        if ep.scheme == "https":
            argv.append("-ssl")
        if ep.is_vhost:
            argv += ["-vhost", ep.host]
        if ctx.options["tuning"]:
            argv += ["-Tuning", str(ctx.options["tuning"])]
        return [Command("nikto", argv, tool="nikto", targets=web.targets(ep), ok_exit_codes=(0, 1))]

    def parse(self, unit: WorkUnit, results, ctx: RunContext) -> ModuleResult:
        ep = web.Endpoint.from_inputs(dict(unit.inputs))
        try:
            items = load_nikto((ctx.attempt_dir / "raw" / "nikto.json").read_text(encoding="utf-8", errors="replace"))
        except OSError:
            items = []
        res = ModuleResult(artifacts={"items": items}, evidence_descriptions={"nikto.json": "Nikto JSON report"})
        for item in items:
            res.observations.append({"key": "nikto.item", "value": item, "url": ep.url})
        res.limitations.append("Nikto items are unverified indicators; validate manually before reporting")
        shown = "; ".join((i["msg"] or "")[:80] for i in items[:3])
        res.summary = f"{len(items)} Nikto item(s)" + (f": {shown}" if shown else "")
        return res
