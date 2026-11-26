"""Run lifecycle: preflight → layered plan/execute → checkpoint → finalise; and resume.

Preflight (every start and resume)
    * reconcile crashed runs and stale locks
    * engagement must be within its validity window
    * the target is re-resolved and re-checked against scope (hostname drift); the address
      used for this run is pinned and recorded in ``<run>/scope/scope.json``

Layers
    Modules are grouped by (stage, dependency depth): preflight → recon → enumeration → assessment,
    and within a stage by ``depends_on``. Each layer is planned only after the previous layers
    finished, so a module's units can depend on results of the same run (service identification
    plans from the ports just found; enumeration plans from the services just identified).

Checkpointing
    * unit rows are written before their layer runs; state changes are committed as they happen
    * each attempt writes to its own ``attempt-NN`` directory; every file is hashed and registered
      as evidence (failed attempts included); hosts/ports/services are stored per unit
    * ``<run>/manifest.json`` is rewritten atomically after each unit finishes
"""

from __future__ import annotations

import json
import re
import signal
import threading
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from aiszx import __version__
from aiszx.classify.classifier import Classifier
from aiszx.core.diskspace import require_free_space
from aiszx.core.errors import AiszxError, NotFoundError, ScopeError, ValidationError
from aiszx.core.fsutil import atomic_write_text
from aiszx.core.timeutil import iso
from aiszx.modules.base import Module, ModuleResult, RunContext, Safety, Stage
from aiszx.modules.registry import STAGE_ORDER, ModuleRegistry, discover
from aiszx.orchestrator.executor import AttemptFinished, AttemptStarted, Executor, UnitFinished, UnitSkipped
from aiszx.orchestrator.fingerprint import file_sha256, fingerprint
from aiszx.orchestrator.locks import LockManager
from aiszx.orchestrator.planner import PlannedUnit, Planner, ToolResolution, ToolResolver
from aiszx.orchestrator.procutil import Owner
from aiszx.orchestrator.recovery import decide, reconcile
from aiszx.orchestrator.runlog import RunLog, unit_slug
from aiszx.orchestrator.settings import ModuleSettings, Profile, load_settings
from aiszx.orchestrator.state import (
    COMPLETED,
    EXEC_COMPLETED,
    EXEC_FAILED,
    EXEC_INTERRUPTED,
    EXEC_PARTIAL,
    EXEC_RUNNING,
    FAILED,
    INTERRUPTED,
    PENDING,
    RECOVERY_REQUIRED,
    RUNNING,
    SKIPPED,
    ExecutionStore,
)
from aiszx.orchestrator.toolrunner import ScopeGuard, ToolRunner
from aiszx.recon.store import ReconStore
from aiszx.targets.engagements import ACTIVE, Engagement
from aiszx.targets.manager import Target


RESUMABLE_COMMANDS = ("run", "recon", "enumerate", "full")


@dataclass
class RunReport:
    execution_id: str
    run_id: str
    run_dir: Path
    status: str
    units: list[PlannedUnit]
    states: dict[tuple[str, str], str] = field(default_factory=dict)
    messages: list[str] = field(default_factory=list)
    executed: bool = True

    @property
    def counts(self) -> Counter:
        return Counter(self.states.values())


@dataclass
class _Run:
    eid: str
    run_id: str
    run_dir: Path
    eng: Engagement
    target: Target
    address: str
    profile: Profile
    settings: ModuleSettings
    rows: dict[tuple[str, str], Any] | None      # previous unit rows when resuming
    run_params: dict[str, Any] = field(default_factory=dict)
    previous_status: str | None = None
    confirmed: bool = False
    declined: bool = False
    forced: bool = False


def inventory_tool_resolver(app) -> ToolResolver:
    def resolve(names: list[str]) -> dict[str, ToolResolution]:
        registry = app.tool_registry()
        known = [n for n in names if n in registry.tools]
        inventory = app.tool_inventory(registry).detect(known) if known else None
        out: dict[str, ToolResolution] = {}
        for name in names:
            if inventory is None or name not in inventory.tools:
                out[name] = ToolResolution("unknown", [], problem="not in the tool registry")
                continue
            t = inventory.tools[name]
            out[name] = ToolResolution(t.status, t.launch, t.version, "; ".join(t.problems) or None, dict(t.detail))
        return out
    return resolve


def layers(modules: list[Module]) -> list[list[Module]]:
    present = {m.meta.id: m for m in modules}
    depth: dict[str, int] = {}

    def d(mid: str) -> int:
        if mid not in depth:
            deps = [x for x in (*present[mid].meta.depends_on, *present[mid].meta.after) if x in present]
            depth[mid] = 0 if not deps else 1 + max(d(x) for x in deps)
        return depth[mid]

    keys = {mid: (STAGE_ORDER.index(m.meta.stage), d(mid)) for mid, m in present.items()}
    return [[present[mid] for mid in sorted(present) if keys[mid] == k] for k in sorted(set(keys.values()))]


class Orchestrator:
    def __init__(
        self,
        app,
        *,
        registry: ModuleRegistry | None = None,
        settings: ModuleSettings | None = None,
        resolve_tools: ToolResolver | None = None,
        approve: Callable[[PlannedUnit], bool] | None = None,
        confirm: Callable[[list[PlannedUnit]], bool] | None = None,
        progress: Callable[[str], None] | None = None,
        announce: Callable[[list[PlannedUnit], dict[str, Any]], None] | None = None,
        cancel_event: threading.Event | None = None,
        handle_signals: bool = True,
        classifier: Classifier | None = None,
    ) -> None:
        self.app = app
        self.db = app.db
        self.store = ExecutionStore(self.db)
        self.recon = ReconStore(self.db)
        self.registry = registry or discover()
        self._settings = settings
        self.resolve_tools = resolve_tools or inventory_tool_resolver(app)
        self.approve_cb = approve or (lambda pu: False)
        self.confirm_cb = confirm or (lambda units: True)
        self.progress = progress or (lambda line: None)
        self.announce = announce or (lambda units, info: None)
        self.cancel = cancel_event or threading.Event()
        self.handle_signals = handle_signals
        self.classifier = classifier or Classifier.load(user_config_dir=app.config.user_config_dir)
        self.cfg = app.config.orchestrator
        self.owner = Owner.current()
        self.locks = LockManager(self.db, self.owner, self.cfg.stale_after_seconds)

    # -- public ------------------------------------------------------------
    def reconcile(self) -> list[str]:
        return reconcile(self.db, self.owner, self.cfg.stale_after_seconds)

    def start(self, engagement_slug: str, target_raw: str, tokens: list[str], *, profile: str | None = None,
              command: str = "run", run_params: dict[str, Any] | None = None) -> RunReport:
        if not tokens:
            raise ValidationError("select at least one module (-m MODULE); see `modules list`")
        messages = self.reconcile()
        eng, target = self._load(engagement_slug, target_raw)
        address, decision, target = self._preflight(eng, target)
        settings = self.settings_for(eng)
        prof = settings.profile(profile or self.cfg.default_profile)
        modules = self.registry.select(tokens)

        self.store.sync_modules(self.registry)
        run = self.app.layout.create_target_run(eng.slug, target.slug)
        snapshot = {
            "command": command, "modules": list(tokens), "profile": prof.name, "address": address,
            "ceiling": _ceiling_text(prof, eng), "profile_params": dict(prof.params),
            "run_params": dict(run_params or {}),
            "effective": {m.meta.id: _effective_dict(settings, m) for m in modules},
            "settings_sources": [str(s) for s in settings.sources],
        }
        now = iso()
        eid = self.store.create_execution(
            run_id=run.run_id, engagement_id=eng.id, target_id=target.id, command=command, profile=prof.name,
            status=EXEC_RUNNING, pinned_address=address, config_fingerprint=fingerprint(snapshot),
            config_snapshot=snapshot, framework_version=__version__, owner_pid=self.owner.pid,
            owner_host=self.owner.host, boot_id=self.owner.boot, heartbeat_at=now, started_at=now,
            workspace_path=run.path.relative_to(self.app.config.data_dir).as_posix(),
        )
        self._write_scope_record(run.path, eng, target, address, decision)
        state = _Run(eid, run.run_id, run.path, eng, target, address, prof, settings, rows=None,
                     run_params=dict(run_params or {}))
        report = self._run(state, modules)
        report.messages = messages + report.messages
        return report

    def resume(self, engagement_slug: str, target_raw: str, *, run_id: str | None = None) -> RunReport:
        messages = self.reconcile()
        eng, target = self._load(engagement_slug, target_raw)
        ex = self.store.find_run(target.id, run_id, commands=RESUMABLE_COMMANDS)
        if ex is None:
            raise NotFoundError(f"no run {'`' + run_id + '` ' if run_id else ''}found for {target.canonical}")
        if ex["command"] not in RESUMABLE_COMMANDS:
            raise AiszxError(f"run {ex['run_id']} is a `{ex['command']}` run, which is not resumable; re-run the command")
        if ex["status"] == EXEC_RUNNING:
            raise AiszxError(f"run {ex['run_id']} is still running (pid {ex['owner_pid']} on {ex['owner_host']})")
        snapshot = json.loads(ex["config_snapshot"])
        address, decision, target = self._preflight(eng, target)
        settings = self.settings_for(eng)
        prof = settings.profile(snapshot["profile"])
        modules = self.registry.select(snapshot["modules"])
        run_dir = self.app.config.data_dir / ex["workspace_path"]
        self.app.layout.verify_target(eng.slug, target.slug, repair=True)  # recreate missing directories only
        rows = {(r["module_id"], r["unit_key"]): r for r in self.store.units(ex["id"])}
        self.store.sync_modules(self.registry)
        state = _Run(ex["id"], ex["run_id"], run_dir, eng, target, address, prof, settings, rows=rows,
                     previous_status=ex["status"], run_params=dict(snapshot.get("run_params", {})))
        self._write_scope_record(run_dir, eng, target, address, decision)
        report = self._run(state, modules)
        if state.declined:
            report.messages.append("resume cancelled; nothing was executed")
        elif not report.executed:
            report.messages.append("nothing to resume: every unit is complete and verified, or cannot run")
        report.messages = messages + report.messages
        return report

    def settings_for(self, eng: Engagement) -> ModuleSettings:
        if self._settings is not None:
            return self._settings
        return load_settings(user_config_dir=self.app.config.user_config_dir,
                             engagement_dir=self.app.layout.engagement_dir(eng.slug))

    # -- layered run ---------------------------------------------------------
    def _run(self, run: _Run, modules: list[Module]) -> RunReport:
        runlog = RunLog(run.run_dir, run.run_id, run.target.canonical)
        planner = Planner(run.settings, self.resolve_tools)
        upstream: dict[str, list[dict[str, Any]]] = {}
        all_planned: list[PlannedUnit] = []
        states: dict[tuple[str, str], str] = {}
        executing = False
        restore = None
        new_run = run.rows is None
        try:
            for index, layer in enumerate(layers(modules)):
                if self.cancel.is_set() or run.forced:
                    break
                services = self.recon.latest_services(run.target.id, prefer_execution=run.eid).services
                # re-apply the current service_map, so classification changes reach older scan results
                services = self.classifier.apply(services)
                planned = planner.plan(layer, engagement=run.eng, target=run.target, address=run.address,
                                       profile=run.profile, roe_max=_roe(run.eng), upstream=upstream,
                                       services=services, blocked=self._blocked(layer, all_planned, states),
                                       run_params=run.run_params)
                for pu in planned:
                    pu.unit_dir = self._unit_dir(run.run_dir, pu)
                if new_run:
                    with self.db.transaction():
                        for pu in planned:
                            pu.row_id = self.store.insert_unit(**self._unit_fields(run.eid, run.target, pu))
                elif not self._apply_resume_decisions(run, planned, upstream):
                    break  # declined
                runnable = any(pu.state == PENDING for pu in planned)
                if (runnable or new_run) and not executing:
                    executing = True
                    ok, why = self.locks.acquire(f"execution:{run.eid}", run.eid)
                    if not ok:
                        raise AiszxError(f"run {run.run_id} is locked: {why}")
                    if not new_run:
                        self.store.update_execution(run.eid, status=EXEC_RUNNING, owner_pid=self.owner.pid,
                                                    owner_host=self.owner.host, boot_id=self.owner.boot,
                                                    heartbeat_at=iso(), ended_at=None, pinned_address=run.address)
                    runlog.event("INFO", "run.start" if new_run else "run.resume", f"address {run.address}")
                    if self.handle_signals:
                        restore = self._install_sigint()
                self.announce(planned, {"run_id": run.run_id, "run_dir": run.run_dir, "address": run.address,
                                        "engagement": run.eng.slug, "target": run.target.canonical,
                                        "profile": run.profile.name, "layer": index, "new_run": new_run})
                for pu in planned:
                    if pu.state == SKIPPED:
                        runlog.event("INFO", "unit.skipped", pu.skip_reason or pu.decision_reason,
                                     module=pu.module.meta.id, unit=pu.unit.key)
                if runnable:
                    states.update(self._execute_layer(run, planned, upstream, services, runlog))
                else:
                    states.update({pu.key: pu.state for pu in planned})
                all_planned.extend(planned)
        finally:
            if restore:
                restore()
            if executing:
                status = _final_status(states, self.cancel.is_set() or run.forced)
                counts = Counter(r["state"] for r in self.store.units(run.eid))
                self.store.update_execution(run.eid, status=status, ended_at=iso(), heartbeat_at=iso(),
                                            summary_json={k: counts[k] for k in sorted(counts)})
                self.locks.release_execution(run.eid)
                self._write_manifest(run)
                runlog.event("INFO", "run.end", f"{status}: " + ", ".join(
                    f"{n} {s.lower()}" for s, n in sorted(states_counter(states).items())))
                self.store.log(run.eid, "INFO", "run.end", status, counts=dict(counts))
        status = _final_status(states, self.cancel.is_set() or run.forced) if executing else (run.previous_status or "")
        return RunReport(run.eid, run.run_id, run.run_dir, status, all_planned, states, executed=executing)

    def _blocked(self, layer: list[Module], done: list[PlannedUnit], states: dict) -> dict[str, str]:
        blocked = {}
        for m in layer:
            for dep in m.meta.depends_on:
                units = [pu for pu in done if pu.module.meta.id == dep]
                if units and not any(states.get(pu.key) == COMPLETED for pu in units):
                    worst = next((states.get(pu.key) for pu in units if states.get(pu.key) != COMPLETED), "?")
                    blocked[m.meta.id] = f"upstream {dep} did not complete ({worst})"
        return blocked

    def _apply_resume_decisions(self, run: _Run, planned: list[PlannedUnit], upstream: dict) -> bool:
        for pu in planned:
            decide(pu, run.rows.get(pu.key), run.run_dir)
        actionable = [pu for pu in planned if pu.decision in ("run", "rerun", "recover")]
        if actionable and not run.confirmed:
            if not self.confirm_cb(planned):
                with self.db.transaction():
                    for pu in planned:
                        if pu.decision == "recover" and pu.row_id:
                            self.store.update_unit(pu.row_id, state=RECOVERY_REQUIRED, error_message=pu.decision_reason)
                run.declined = True
                return False
            run.confirmed = True
        with self.db.transaction():
            for pu in planned:
                if pu.decision in ("run", "rerun", "recover"):
                    pu.state = PENDING
                    fields = self._unit_fields(run.eid, run.target, pu)
                    if pu.row_id:
                        for k in ("execution_id", "module_id", "unit_key", "target_id"):
                            fields.pop(k)
                        fields.update(error_class=None, error_message=None, exit_code=None, ended_at=None, summary=None)
                        self.store.update_unit(pu.row_id, **fields)
                        self.recon.delete_for_unit(pu.row_id)  # its old hosts/ports/services are superseded
                    else:
                        pu.row_id = self.store.insert_unit(**fields)
                elif pu.decision == "skip":
                    if pu.row_id:
                        self.store.update_unit(pu.row_id, skip_reason=pu.decision_reason)
                    else:
                        pu.row_id = self.store.insert_unit(**self._unit_fields(run.eid, run.target, pu))
                elif pu.decision == "reuse":
                    _load_upstream(upstream, pu, run.run_dir / run.rows[pu.key]["output_dir"])
        return True

    def _execute_layer(self, run: _Run, planned: list[PlannedUnit], upstream: dict, services: list,
                       runlog: RunLog) -> dict[tuple[str, str], str]:
        eid, target, run_dir = run.eid, run.target, run.run_dir
        # Connections always go to the pinned address; host names (target hostname, --vhost names) are only
        # sent as Host header/SNI, so they are evaluated against scope with that address.
        pinned = {} if target.identity.is_ip else {target.canonical: [run.address]}
        for vhost in run.run_params.get("vhosts", []):
            pinned.setdefault(vhost, [run.address])
        guard = ScopeGuard(self.app.scope().policy(run.eng), run.eng, self._resolver(), pinned)
        launch_all: dict[str, list[str]] = {}
        for pu in planned:
            launch_all.update(pu.tool_launch)
        runner = ToolRunner(guard, launch_all, self.cancel, kill_grace=self.cfg.kill_grace_seconds)
        attempt_ids: dict[tuple[tuple[str, str], int], str] = {}

        def on_event(ev) -> None:
            pu = ev.pu
            mid, ukey = pu.key
            if isinstance(ev, AttemptStarted):
                rel = ev.attempt_dir.relative_to(run_dir).as_posix()
                with self.db.transaction():
                    self.store.update_unit(pu.row_id, state=RUNNING, attempt=ev.attempt, output_dir=rel,
                                           started_at=iso(), heartbeat_at=iso())
                    attempt_ids[(pu.key, ev.attempt)] = self.store.start_attempt(pu.row_id, ev.attempt, rel)
                runlog.event("INFO", "attempt.start", f"attempt {ev.attempt}", module=mid, unit=ukey)
            elif isinstance(ev, AttemptFinished):
                with self.db.transaction():
                    self.store.finish_attempt(attempt_ids[(pu.key, ev.attempt)], status=ev.status,
                                              commands_json=ev.commands, exit_code=ev.exit_code,
                                              error_class=ev.error_class, error_message=ev.error_message,
                                              duration_s=round(ev.duration_s, 3))
                    self._register_evidence(eid, target, pu, ev.attempt, ev.attempt_dir, run_dir, ev.result)
                for c in ev.commands:
                    runlog.event("INFO", "command", " ".join(c["argv"]), module=mid, unit=ukey,
                                 exit_code=c["exit_code"], duration_s=c["duration_s"], timed_out=c["timed_out"])
                runlog.event("INFO" if ev.status == "ok" else "WARNING", "attempt.end",
                             f"attempt {ev.attempt}: {ev.status}"
                             + (f" ({ev.error_class}: {ev.error_message})" if ev.error_class else ""),
                             module=mid, unit=ukey)
            elif isinstance(ev, UnitSkipped):
                self.store.update_unit(pu.row_id, state=SKIPPED, skip_reason=ev.reason, ended_at=iso())
                runlog.event("INFO", "unit.skipped", ev.reason, module=mid, unit=ukey)
                self.progress(f"[skip] {pu.label}: {ev.reason}")
            elif isinstance(ev, UnitFinished):
                fields: dict[str, Any] = {"state": ev.state, "ended_at": iso(), "exit_code": ev.exit_code,
                                          "error_class": ev.error_class, "error_message": ev.error_message}
                if ev.state == COMPLETED and ev.attempt_dir is not None:
                    fields["outputs_json"] = _outputs(ev.attempt_dir, run_dir)
                    fields["summary"] = ev.result.summary if ev.result else None
                    _load_upstream(upstream, pu, ev.attempt_dir)
                with self.db.transaction():
                    self.store.update_unit(pu.row_id, **fields)
                    if ev.state == COMPLETED and ev.result is not None:
                        self.recon.replace_for_unit(unit_id=pu.row_id, execution_id=eid, engagement_id=run.eng.id,
                                                    target_id=target.id, result=ev.result)
                    if ev.state != COMPLETED:
                        self.store.log(eid, "WARNING", "unit.end", f"{pu.label}: {ev.state}", unit_id=pu.row_id,
                                       error=ev.error_message)
                self.locks.release(_unit_lock(target, pu))
                self._write_manifest(run)
                tag = {COMPLETED: " ok ", FAILED: "FAIL", INTERRUPTED: "STOP"}.get(ev.state, ev.state)
                detail = (ev.result.summary if ev.result else "") or ev.error_message or ""
                runlog.event("INFO" if ev.state == COMPLETED else "WARNING", "unit.end", f"{ev.state}: {detail}",
                             module=mid, unit=ukey)
                self.progress(f"[{tag}] {pu.label} ({ev.duration_s:.1f}s): {detail}")
                if ev.result is not None:
                    for lim in ev.result.limitations:
                        self.progress(f"       note: {lim}")

        def approve(pu: PlannedUnit) -> bool:
            granted = bool(self.approve_cb(pu))
            self.store.record_approval(execution_id=eid, target_id=target.id, action=f"module:{pu.module.meta.id}",
                                       safety=pu.module.meta.safety.value, approved=granted, actor=self.app.actor,
                                       note=pu.unit.key)
            return granted

        def heartbeat() -> None:
            now = iso()
            self.store.update_execution(eid, heartbeat_at=now)
            self.db.execute("UPDATE module_executions SET heartbeat_at = ? WHERE execution_id = ? AND state = ?",
                            (now, eid, RUNNING))
            self.locks.heartbeat(eid)

        def postprocess(pu: PlannedUnit, result: ModuleResult) -> None:
            self.classifier.apply(result.services)

        contexts = {pu.key: RunContext(
            execution_id=eid, run_id=run.run_id, run_dir=run_dir, engagement=run.eng, target=target,
            address=run.address, profile=run.profile.name, options=dict(pu.config.options),
            tool_launch=pu.tool_launch, tool_versions=pu.tool_versions, upstream=upstream, cancel_event=self.cancel,
            previous_attempt_dir=pu.previous_attempt_dir, profile_params=run.profile.params,
            tool_details=pu.tool_details, services=list(services), run_params=run.run_params,
        ) for pu in planned}

        executor = Executor(
            max_workers=self.cfg.max_workers, runner=runner, cancel_event=self.cancel, on_event=on_event,
            approve=approve, acquire=lambda pu: self.locks.acquire(_unit_lock(target, pu), eid),
            heartbeat=heartbeat, heartbeat_seconds=self.cfg.heartbeat_seconds, postprocess=postprocess,
        )
        try:
            return executor.run(planned, contexts)
        except KeyboardInterrupt:
            run.forced = True
            self.cancel.set()
            self.db.execute("UPDATE module_executions SET state = ?, ended_at = ? WHERE execution_id = ? AND state = ?",
                            (INTERRUPTED, iso(), eid, RUNNING))
            current = {(r["module_id"], r["unit_key"]): r["state"] for r in self.store.units(eid)}
            return {pu.key: current.get(pu.key, pu.state) for pu in planned}

    # -- helpers -------------------------------------------------------------
    def _load(self, engagement_slug: str, target_raw: str) -> tuple[Engagement, Target]:
        eng = self.app.engagements().get(engagement_slug)
        return eng, self.app.targets().get(eng, target_raw)

    def _preflight(self, eng: Engagement, target: Target):
        require_free_space(self.app.config.data_dir, self.cfg.min_free_mb)
        validity = eng.validity()
        if validity != ACTIVE:
            raise ScopeError(f"engagement '{eng.slug}' is {validity}; testing is only allowed inside its validity window "
                             "(see `engagement update`)")
        if target.status != "active":
            raise ValidationError(f"target {target.canonical} is archived; re-activate it with `target add`")
        refreshed = self.app.targets().add(eng.slug, target.canonical)  # re-resolves and re-checks scope
        candidates = [a.address for a in refreshed.decision.addresses if a.in_scope]
        if not candidates:
            raise ScopeError(f"{target.canonical} has no in-scope address to test (does it resolve? "
                             "for HTB hostnames add an /etc/hosts entry or register the IP)")
        address = sorted(candidates, key=lambda a: ":" in a)[0]  # prefer IPv4
        return address, refreshed.decision, refreshed.target

    def _unit_dir(self, run_dir: Path, pu: PlannedUnit) -> Path:
        meta = pu.module.meta
        if meta.stage in (Stage.PREFLIGHT, Stage.RECON):
            base = run_dir / "reconnaissance"
        elif meta.stage is Stage.ENUMERATION:
            cats = self.app.config.workspace.enumeration_categories
            cat = meta.categories[0] if meta.categories and meta.categories[0] in cats else "other"
            # enumeration/<category>/<module name without family>: e.g. enumeration/http/content_discovery
            return (run_dir / "enumeration" / cat / meta.id.split(".", 1)[1]
                    / re.sub(r"[^A-Za-z0-9._-]", "_", pu.unit.key))
        else:
            base = run_dir / "assessment"
        return base / meta.id / re.sub(r"[^A-Za-z0-9._-]", "_", pu.unit.key)

    def _unit_fields(self, eid: str, target: Target, pu: PlannedUnit) -> dict[str, Any]:
        return {
            "execution_id": eid, "module_id": pu.module.meta.id, "target_id": target.id, "unit_key": pu.unit.key,
            "state": pu.state, "skip_reason": pu.skip_reason if pu.state == SKIPPED else None,
            "needs_approval": int(pu.needs_approval), "module_version": pu.module.meta.version,
            "inputs_json": dict(pu.unit.inputs), "input_fingerprint": pu.input_fp,
            "config_fingerprint": pu.config_fp, "depends_on_json": pu.depends_on, "tools_json": pu.tools_record(),
        }

    def _write_scope_record(self, run_dir: Path, eng: Engagement, target: Target, address: str, decision) -> None:
        record = {
            "recorded_at": iso(), "engagement": eng.slug, "authorisation_ref": eng.authorisation_ref,
            "validity": eng.validity(), "valid_from": eng.valid_from, "valid_until": eng.valid_until,
            "target": target.canonical, "pinned_address": address, "decision": decision.to_dict(),
            "rules": [r.to_dict() for r in self.app.scope().rules(eng)],
            "rules_of_engagement": eng.roe,
        }
        name = f"scope-{iso().replace(':', '').replace('-', '')}.json"
        text = json.dumps(record, indent=2, sort_keys=True)
        atomic_write_text(run_dir / "scope" / name, text)
        atomic_write_text(run_dir / "scope" / "scope.json", text)

    def _register_evidence(self, eid: str, target: Target, pu: PlannedUnit, attempt: int, adir: Path,
                           run_dir: Path, result) -> None:
        register_evidence(self.store, eid=eid, target_id=target.id, unit_id=pu.row_id, attempt=attempt, adir=adir,
                          run_dir=run_dir, result=result, tools=",".join(sorted(pu.tool_launch)) or None)

    def _write_manifest(self, run: _Run) -> None:
        units = []
        for r in self.store.units(run.eid):
            units.append({"module": r["module_id"], "unit": r["unit_key"], "state": r["state"], "attempt": r["attempt"],
                          "output_dir": r["output_dir"], "outputs": json.loads(r["outputs_json"] or "[]")})
        manifest = {"run_id": run.run_id, "execution_id": run.eid, "engagement": run.eng.slug,
                    "target": run.target.canonical, "updated_at": iso(), "units": units}
        atomic_write_text(run.run_dir / "manifest.json", json.dumps(manifest, indent=2, sort_keys=True))

    def _resolver(self):
        from aiszx.targets import resolver
        return resolver.resolve_host

    def _install_sigint(self):
        return install_sigint(self.cancel, self.progress)


def install_sigint(cancel: threading.Event, progress: Callable[[str], None]):
    """First Ctrl+C sets ``cancel`` (tools are stopped, state saved); a second one raises KeyboardInterrupt."""
    if threading.current_thread() is not threading.main_thread():
        return None

    def handler(signum, frame):
        if cancel.is_set():
            raise KeyboardInterrupt
        cancel.set()
        progress("Interrupt received: stopping running tools and saving state (press Ctrl+C again to force)")

    previous = signal.signal(signal.SIGINT, handler)
    return lambda: signal.signal(signal.SIGINT, previous)


# --- helpers ------------------------------------------------------------------------

def register_evidence(store: ExecutionStore, *, eid: str, target_id: str | None, unit_id: str | None,
                      attempt: int | None, adir: Path, run_dir: Path, result=None, tools: str | None = None) -> None:
    descriptions = result.evidence_descriptions if result else {}
    sensitive = set(result.sensitive_files) if result else set()
    for path in sorted(p for p in adir.rglob("*") if p.is_file()):
        rel = path.relative_to(run_dir).as_posix()
        if rel.startswith("reports/"):
            kind = "report"
        elif "/parsed/" in f"/{rel}":
            kind = "parsed"
        elif path.suffix.lower() in (".png", ".jpg", ".jpeg"):
            kind = "screenshot"
        elif path.name.endswith(".cmd.txt"):
            kind = "log"
        else:
            kind = "raw"
        store.add_evidence(
            execution_id=eid, target_id=target_id, module_execution_id=unit_id, attempt=attempt, tool=tools,
            kind=kind, rel_path=rel, sha256=file_sha256(path), size_bytes=path.stat().st_size,
            sensitive=path.name in sensitive, description=descriptions.get(path.name),
        )


def states_counter(states: dict) -> Counter:
    return Counter(states.values())


def _effective_dict(settings: ModuleSettings, module: Module) -> dict[str, Any]:
    eff = settings.effective(module)
    options = {k: ("***" if k in module.meta.secret_options and v else v) for k, v in eff.options.items()}
    return {"enabled": eff.enabled, "options": options, "timeout": eff.timeout,
            "max_attempts": eff.retry.max_attempts}


def _roe(eng: Engagement) -> Safety | None:
    value = (eng.roe or {}).get("max_safety")
    return Safety(value) if value else None


def _ceiling_text(profile, eng: Engagement) -> str:
    roe = _roe(eng)
    return f"profile {profile.name}={profile.max_safety.value}" + (f", RoE={roe.value}" if roe else "")


def _unit_lock(target: Target, pu: PlannedUnit) -> str:
    return f"target:{target.id}:unit:{unit_slug(*pu.key)}"


def _outputs(adir: Path, run_dir: Path) -> list[dict[str, Any]]:
    return [{"path": p.relative_to(run_dir).as_posix(), "sha256": file_sha256(p), "size": p.stat().st_size}
            for p in sorted(adir.rglob("*")) if p.is_file()]


def _load_upstream(upstream: dict, pu: PlannedUnit, adir: Path) -> None:
    try:
        data = json.loads((adir / "parsed" / "result.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    upstream.setdefault(pu.module.meta.id, []).append(data)


def _final_status(states: dict, cancelled: bool) -> str:
    counts = Counter(states.values())
    if cancelled or counts[INTERRUPTED] or counts[RUNNING]:
        return EXEC_INTERRUPTED
    if counts[FAILED] or counts[RECOVERY_REQUIRED]:
        return EXEC_PARTIAL if counts[COMPLETED] else EXEC_FAILED
    return EXEC_COMPLETED
