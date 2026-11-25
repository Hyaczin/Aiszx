"""Planning: which units run, which are skipped and why.

For every selected module (in dependency order):

1. effective configuration (shipped → user → engagement overrides)
2. safety: ``prohibited_auto`` is never planned; classes above the ceiling
   (profile ``max_safety``, lowered by the engagement's rules of engagement) are SKIPPED;
   ``intrusive`` units need approval
3. tools: each required tool must be installed, healthy and meet the module's minimum version;
   otherwise the unit is SKIPPED with the reason and a pointer to `tools missing`
4. ``module.plan()`` produces the units; inputs and configuration are fingerprinted
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from aiszx.modules.base import Module, PlanContext, Safety, WorkUnit
from aiszx.orchestrator.fingerprint import fingerprint
from aiszx.orchestrator.settings import EffectiveModuleConfig, ModuleSettings, Profile
from aiszx.orchestrator.state import PENDING, SKIPPED
from aiszx.tools.versions import satisfies


@dataclass
class ToolResolution:
    status: str                      # ok | missing | broken | incompatible | unknown
    launch: list[str]
    version: str | None = None
    problem: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)   # e.g. nmap privileges


ToolResolver = Callable[[list[str]], dict[str, ToolResolution]]


@dataclass
class PlannedUnit:
    module: Module
    unit: WorkUnit
    config: EffectiveModuleConfig
    input_fp: str
    config_fp: str
    state: str = PENDING
    skip_reason: str | None = None
    needs_approval: bool = False
    tool_launch: dict[str, list[str]] = field(default_factory=dict)
    tool_versions: dict[str, str | None] = field(default_factory=dict)
    tool_details: dict[str, dict[str, Any]] = field(default_factory=dict)
    depends_on: list[str] = field(default_factory=list)
    # filled in by the orchestrator
    row_id: str | None = None
    unit_dir: Path | None = None
    attempts_done: int = 0
    previous_attempt_dir: Path | None = None
    decision: str = "run"            # run | reuse | rerun | recover | skip (resume summary)
    decision_reason: str = ""

    @property
    def key(self) -> tuple[str, str]:
        return self.module.meta.id, self.unit.key

    @property
    def label(self) -> str:
        return f"{self.module.meta.id} [{self.unit.key}]"

    def tools_record(self) -> dict[str, Any]:
        return {name: {"command": launch, "version": self.tool_versions.get(name)}
                for name, launch in self.tool_launch.items()}


def effective_ceiling(profile: Profile, roe_max: Safety | None) -> Safety:
    if roe_max is not None and roe_max.rank < profile.max_safety.rank:
        return roe_max
    return profile.max_safety


class Planner:
    def __init__(self, settings: ModuleSettings, resolve_tools: ToolResolver) -> None:
        self.settings = settings
        self.resolve_tools = resolve_tools

    def plan(self, modules: list[Module], *, engagement, target, address: str, profile: Profile,
             roe_max: Safety | None, upstream: dict[str, list[dict[str, Any]]] | None = None,
             services: list | None = None, blocked: dict[str, str] | None = None,
             run_params: dict[str, Any] | None = None) -> list[PlannedUnit]:
        ceiling = effective_ceiling(profile, roe_max)
        names = sorted({t.name for m in modules for t in m.meta.tools})
        tools = self.resolve_tools(names) if names else {}
        present = {m.meta.id for m in modules}
        planned: list[PlannedUnit] = []

        for module in modules:
            meta = module.meta
            cfg = self.settings.effective(module)
            reason: str | None = None
            needs_approval = False
            if not cfg.enabled:
                reason = "disabled in configuration"
            elif meta.safety is Safety.PROHIBITED_AUTO:
                reason = "prohibited from automatic execution (manual, separately authorised testing only)"
            elif blocked and meta.id in blocked:
                reason = blocked[meta.id]
            elif not meta.safety.allowed_under(ceiling):
                source = "rules of engagement" if roe_max is not None and ceiling == roe_max else f"profile '{profile.name}'"
                reason = f"safety class {meta.safety.value} exceeds the {source} ceiling ({ceiling.value})"
            else:
                needs_approval = meta.safety is Safety.INTRUSIVE

            launch: dict[str, list[str]] = {}
            versions: dict[str, str | None] = {}
            details: dict[str, dict[str, Any]] = {}
            missing: list[str] = []
            for req in meta.tools:
                res = tools.get(req.name, ToolResolution("unknown", [], problem="not in the tool registry"))
                ok_version = satisfies(res.version, req.min_version) is not False
                if res.status == "ok" and res.launch and ok_version:
                    launch[req.name], versions[req.name], details[req.name] = res.launch, res.version, res.detail
                elif not req.optional:
                    why = res.status if ok_version else f"version {res.version} < {req.min_version}"
                    missing.append(f"{req.name} ({why})")
            if reason is None and missing:
                reason = f"required tool unavailable: {', '.join(missing)}; see `tools missing`"

            pctx = PlanContext(engagement, target, address, cfg.options, profile_params=profile.params,
                               tool_details=details, upstream=upstream or {}, services=list(services or []),
                               run_params=run_params or {})
            if reason is None:
                reason = module.unavailable_reason(pctx)
            units = module.plan(pctx)
            config_fp = fingerprint({
                "module": meta.id, "version": meta.version, "options": dict(cfg.options),
                "profile": {sec: profile.params.get(sec) for sec in meta.profile_sections},
            })
            for unit in units:
                planned.append(PlannedUnit(
                    module=module, unit=unit, config=cfg,
                    input_fp=fingerprint(dict(unit.inputs)), config_fp=config_fp,
                    state=SKIPPED if reason else PENDING, skip_reason=reason, needs_approval=needs_approval,
                    tool_launch=launch, tool_versions=versions, tool_details=details,
                    depends_on=[d for d in meta.depends_on if d in present],
                    decision="skip" if reason else "run", decision_reason=reason or "",
                ))
        return planned
