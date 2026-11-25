"""http.screenshots: EyeWitness screenshots of the identified web endpoints only.

EyeWitness receives exactly the URLs of web services found by reconnaissance (never a port
range). It drives a headless browser and cannot send a custom Host header, so virtual hosts that
only exist via ``--vhost`` are skipped (recorded as a limitation); the IP and a registered target
hostname are captured.
"""

from __future__ import annotations

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


class Screenshots(Module):
    meta = ModuleMeta(
        id="http.screenshots",
        version="1",
        description="EyeWitness screenshots and header report of the identified web endpoints",
        stage=Stage.ENUMERATION,
        safety=Safety.ACTIVE_SAFE,
        timeout_seconds=900,
        tools=(ToolRequirement("eyewitness"),),
        categories=("http", "https"),
        retry=RetryPolicy(max_attempts=1),
        max_parallel=1,
        config_defaults={"timeout": 30, "threads": 2, "vhosts": [], "skip_categories": ["winrm"]},
    )

    def plan(self, ctx: PlanContext) -> list[WorkUnit]:
        eps = web.endpoints(ctx)
        hostname = None if ctx.target.identity.is_ip else ctx.target.canonical
        urls = [ep.url for ep in eps if not ep.is_vhost or ep.host == hostname]
        skipped = [ep.url for ep in eps if ep.url not in urls]
        if not urls:
            return []
        return [WorkUnit(self.meta.id, "all", {"urls": urls, "skipped": skipped, "address": ctx.address,
                                               "hostname": hostname})]

    def build_commands(self, unit: WorkUnit, ctx: RunContext) -> list[Command]:
        raw = ctx.attempt_dir / "raw"
        (raw / "urls.txt").write_text("\n".join(unit.inputs["urls"]) + "\n", encoding="utf-8")
        argv = ["--web", "-f", "urls.txt", "-d", "eyewitness", "--no-prompt",
                "--timeout", str(int(ctx.options["timeout"])), "--threads", str(int(ctx.options["threads"]))]
        hosts = [unit.inputs["address"]] + ([unit.inputs["hostname"]] if unit.inputs["hostname"] else [])
        return [Command("eyewitness", argv, tool="eyewitness", targets=hosts)]

    def parse(self, unit: WorkUnit, results, ctx: RunContext) -> ModuleResult:
        out = ctx.attempt_dir / "raw" / "eyewitness"
        shots = sorted(p.relative_to(ctx.attempt_dir / "raw").as_posix() for p in out.rglob("*.png")) if out.is_dir() else []
        report = out / "report.html"
        res = ModuleResult(
            artifacts={"urls": unit.inputs["urls"], "screenshots": shots,
                       "report": "eyewitness/report.html" if report.is_file() else None},
            evidence_descriptions={"report.html": "EyeWitness report", "urls.txt": "URLs given to EyeWitness"},
        )
        if unit.inputs["skipped"]:
            res.limitations.append("virtual-host URLs skipped (EyeWitness cannot set a Host header): "
                                   + ", ".join(unit.inputs["skipped"]))
        if not shots:
            res.limitations.append("EyeWitness produced no screenshots (check the headless browser/driver; "
                                   "see eyewitness.stderr.txt)")
        res.summary = (f"{len(shots)} screenshot(s) of {len(unit.inputs['urls'])} URL(s)"
                       + ("; report: eyewitness/report.html" if report.is_file() else ""))
        return res
