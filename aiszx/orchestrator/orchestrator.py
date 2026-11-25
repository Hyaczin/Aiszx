"""Run lifecycle: preflight → plan → persist → execute → checkpoint → finalise; and resume.

Preflight (every start and resume)
    * reconcile crashed runs and stale locks
    * engagement must be within its validity window
    * the target is re-resolved and re-checked against scope (hostname drift); the address
      used for this run is pinned and recorded in ``<run>/scope/scope.json``

Checkpointing
    * unit rows are created before anything runs; state changes are committed as they happen
    * each attempt writes to its own ``attempt-NN`` directory; every file is hashed and
      registered as evidence (failed attempts included)
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
from aiszx.core.errors import AiszxError, NotFoundError, ScopeError, ValidationError
from aiszx.core.fsutil import atomic_write_text
from aiszx.core.timeutil import iso
from aiszx.modules.base import RunContext, Safety, Stage
from aiszx.modules.registry import ModuleRegistry, discover
from aiszx.orchestrator.executor import AttemptFinished, AttemptStarted, Executor, UnitFinished, UnitSkipped
from aiszx.orchestrator.fingerprint import file_sha256, fingerprint
from aiszx.orchestrator.locks import LockManager
from aiszx.orchestrator.planner import PlannedUnit, Planner, ToolResolution, ToolResolver
from aiszx.orchestrator.procutil import Owner
from aiszx.orchestrator.recovery import decide, reconcile
from aiszx.orchestrator.runlog import RunLog, unit_slug
from aiszx.orchestrator.settings import ModuleSettings, load_settings
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
from aiszx.targets.engagements import ACTIVE, Engagement
from aiszx.targets.manager import Target


@dataclass
class RunReport:
    execution_id: str
    run_id: str
    run_dir: Path
    status: str
    units: list[PlannedUnit]
    states: dict[tuple[str, str], str] = field(default_factory=dict)
    messages: list[str] = field(default_factory=list)

    @property
    def counts(self) -> Counter:
        return Counter(self.states.values())


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
            out[name] = ToolResolution(t.status, t.launch, t.version, "; ".join(t.problems) or None)
        return out
    return resolve


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
    ) -> None:
        self.app = app
        self.db = app.db
        self.store = ExecutionStore(self.db)
        self.registry = registry or discover()
        self._settings = settings
        self.resolve_tools = resolve_tools or inventory_tool_resolver(app)
        self.approve_cb = approve or (lambda pu: False)
        self.confirm_cb = confirm or (lambda units: True)
        self.progress = progress or (lambda line: None)
        self.announce = announce or (lambda units, info: None)
        self.cancel = cancel_event or threading.Event()
        self.handle_signals = handle_signals
        self.cfg = app.config.orchestrator
        self.owner = Owner.current()
        self.locks = LockManager(self.db, self.owner, self.cfg.stale_after_seconds)

    # -- public ------------------------------------------------------------
    def reconcile(self) -> list[str]:
        return reconcile(self.db, self.owner, self.cfg.stale_after_seconds)

    def start(self, engagement_slug: str, target_raw: str, tokens: list[str], *, profile: str | None = None,
              command: str = "run") -> RunReport:
        if not tokens:
            raise ValidationError("select at least one module (-m MODULE); see `modules list`")
        messages = self.reconcile()
        eng, target = self._load(engagement_slug, target_raw)
        address, decision, target = self._preflight(eng, target)
        settings = self.settings_for(eng)
        prof = settings.profile(profile or self.cfg.default_profile)
        modules = self.registry.select(tokens)
        planned = self._planner(settings).plan(modules, engagement=eng, target=target, address=address,
                                               profile=prof, roe_max=_roe(eng))
        if not planned:
            raise ValidationError("the selected modules produced no work for this target")

        self.store.sync_modules(self.registry)
        run = self.app.layout.create_target_run(eng.slug, target.slug)
        snapshot = {
            "command": command, "modules": list(tokens), "profile": prof.name, "address": address,
            "ceiling": _ceiling_text(prof, eng),
            "effective": {pu.module.meta.id: {"options": dict(pu.config.options), "timeout": pu.config.timeout,
                                              "max_attempts": pu.config.retry.max_attempts} for pu in planned},
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
        with self.db.transaction():
            for pu in planned:
                pu.unit_dir = self._unit_dir(run.path, pu)
                pu.row_id = self.store.insert_unit(**self._unit_fields(eid, target, pu))
        report = self._execute(eid, run.run_id, run.path, eng, target, address, planned, upstream={},
                               profile_name=prof.name)
        report.messages = messages + report.messages
        return report

    def resume(self, engagement_slug: str, target_raw: str, *, run_id: str | None = None) -> RunReport:
        messages = self.reconcile()
        eng, target = self._load(engagement_slug, target_raw)
        ex = self.store.find_run(target.id, run_id)
        if ex is None:
            raise NotFoundError(f"no run {'`' + run_id + '` ' if run_id else ''}found for {target.canonical}")
        if ex["status"] == EXEC_RUNNING:
            raise AiszxError(f"run {ex['run_id']} is still running (pid {ex['owner_pid']} on {ex['owner_host']})")
        snapshot = json.loads(ex["config_snapshot"])
        address, decision, target = self._preflight(eng, target)
        settings = self.settings_for(eng)
        prof = settings.profile(snapshot["profile"])
        modules = self.registry.select(snapshot["modules"])
        planned = self._planner(settings).plan(modules, engagement=eng, target=target, address=address,
                                               profile=prof, roe_max=_roe(eng))
        run_dir = self.app.config.data_dir / ex["workspace_path"]
        self.app.layout.verify_target(eng.slug, target.slug, repair=True)  # recreate missing directories only
        rows = {(r["module_id"], r["unit_key"]): r for r in self.store.units(ex["id"])}
        for pu in planned:
            pu.unit_dir = self._unit_dir(run_dir, pu)
            decide(pu, rows.get(pu.key), run_dir)

        actionable = [pu for pu in planned if pu.decision in ("run", "rerun", "recover")]
        report = RunReport(ex["id"], ex["run_id"], run_dir, ex["status"], planned,
                           {pu.key: pu.state for pu in planned}, messages)
        if not actionable:
            report.messages.append("nothing to resume: every unit is complete and verified, or cannot run")
            return report
        if not self.confirm_cb(planned):
            with self.db.transaction():
                for pu in planned:
                    if pu.decision == "recover" and pu.row_id:
                        self.store.update_unit(pu.row_id, state=RECOVERY_REQUIRED, error_message=pu.decision_reason)
            report.messages.append("resume cancelled; nothing was executed")
            return report

        self.store.sync_modules(self.registry)
        upstream: dict[str, list[dict[str, Any]]] = {}
        with self.db.transaction():
            for pu in planned:
                if pu.decision in ("run", "rerun", "recover"):
                    pu.state = PENDING
                    fields = self._unit_fields(ex["id"], target, pu)
                    if pu.row_id:
                        fields.update(error_class=None, error_message=None, exit_code=None, ended_at=None)
                        fields.pop("execution_id"), fields.pop("module_id"), fields.pop("unit_key"), fields.pop("target_id")
                        self.store.update_unit(pu.row_id, **fields)
                    else:
                        pu.row_id = self.store.insert_unit(**fields)
                elif pu.decision == "skip":
                    if pu.row_id:
                        self.store.update_unit(pu.row_id, skip_reason=pu.decision_reason)
                    else:
                        pu.row_id = self.store.insert_unit(**self._unit_fields(ex["id"], target, pu))
                elif pu.decision == "reuse":
                    row = rows[pu.key]
                    _load_upstream(upstream, pu, run_dir / row["output_dir"])
            self.store.update_execution(ex["id"], status=EXEC_RUNNING, owner_pid=self.owner.pid,
                                        owner_host=self.owner.host, boot_id=self.owner.boot, heartbeat_at=iso(),
                                        ended_at=None, pinned_address=address)
        self._write_scope_record(run_dir, eng, target, address, decision)
        out = self._execute(ex["id"], ex["run_id"], run_dir, eng, target, address, planned, upstream,
                            profile_name=prof.name)
        out.messages = messages + out.messages
        return out

    def settings_for(self, eng: Engagement) -> ModuleSettings:
        if self._settings is not None:
            return self._settings
        return load_settings(user_config_dir=self.app.config.user_config_dir,
                             engagement_dir=self.app.layout.engagement_dir(eng.slug))

    # -- internals ---------------------------------------------------------
    def _planner(self, settings: ModuleSettings) -> Planner:
        return Planner(settings, self.resolve_tools)

    def _load(self, engagement_slug: str, target_raw: str) -> tuple[Engagement, Target]:
        eng = self.app.engagements().get(engagement_slug)
        return eng, self.app.targets().get(eng, target_raw)

    def _preflight(self, eng: Engagement, target: Target):
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
            base = run_dir / "enumeration" / cat
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

    def _execute(self, eid: str, run_id: str, run_dir: Path, eng: Engagement, target: Target, address: str,
                 planned: list[PlannedUnit], upstream: dict[str, list[dict[str, Any]]], *,
                 profile_name: str) -> RunReport:
        runlog = RunLog(run_dir, run_id, target.canonical)
        ok, why = self.locks.acquire(f"execution:{eid}", eid)
        if not ok:
            raise AiszxError(f"run {run_id} is locked: {why}")
        self.announce(planned, {"run_id": run_id, "run_dir": run_dir, "address": address, "engagement": eng.slug,
                                "target": target.canonical, "profile": profile_name})
        runlog.event("INFO", "run.start", f"{len(planned)} unit(s), address {address}")
        self.store.log(eid, "INFO", "run.start", f"{len(planned)} unit(s)", address=address)
        for pu in planned:
            if pu.state == SKIPPED:
                runlog.event("INFO", "unit.skipped", pu.skip_reason or pu.decision_reason,
                             module=pu.module.meta.id, unit=pu.unit.key)

        pinned = {} if target.identity.is_ip else {target.canonical: [address]}
        guard = ScopeGuard(self.app.scope().policy(eng), eng, self._resolver(), pinned)
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
                level = "INFO" if ev.status == "ok" else "WARNING"
                runlog.event(level, "attempt.end", f"attempt {ev.attempt}: {ev.status}"
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
                    if ev.state != COMPLETED:
                        self.store.log(eid, "WARNING", "unit.end", f"{pu.label}: {ev.state}", unit_id=pu.row_id,
                                       error=ev.error_message)
                self.locks.release(_unit_lock(target, pu))
                self._write_manifest(eid, run_id, run_dir, eng, target)
                tag = {COMPLETED: " ok ", FAILED: "FAIL", INTERRUPTED: "STOP"}.get(ev.state, ev.state)
                detail = (ev.result.summary if ev.result else "") or ev.error_message or ""
                runlog.event("INFO" if ev.state == COMPLETED else "WARNING", "unit.end", f"{ev.state}: {detail}",
                             module=mid, unit=ukey)
                self.progress(f"[{tag}] {pu.label} ({ev.duration_s:.1f}s): {detail}")

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

        contexts = {pu.key: RunContext(
            execution_id=eid, run_id=run_id, run_dir=run_dir, engagement=eng, target=target, address=address,
            profile=profile_name, options=dict(pu.config.options), tool_launch=pu.tool_launch, tool_versions=pu.tool_versions,
            upstream=upstream, cancel_event=self.cancel, previous_attempt_dir=pu.previous_attempt_dir,
        ) for pu in planned}

        executor = Executor(
            max_workers=self.cfg.max_workers, runner=runner, cancel_event=self.cancel, on_event=on_event,
            approve=approve, acquire=lambda pu: self.locks.acquire(_unit_lock(target, pu), eid),
            heartbeat=heartbeat, heartbeat_seconds=self.cfg.heartbeat_seconds,
        )
        restore = self._install_sigint() if self.handle_signals else None
        states: dict[tuple[str, str], str] = {pu.key: pu.state for pu in planned}
        forced = False
        try:
            states = executor.run(planned, contexts)
        except KeyboardInterrupt:
            forced = True
        finally:
            if restore:
                restore()
            if forced:
                self.db.execute("UPDATE module_executions SET state = ?, ended_at = ? WHERE execution_id = ? AND state = ?",
                                (INTERRUPTED, iso(), eid, RUNNING))
                states = {(r["module_id"], r["unit_key"]): r["state"] for r in self.store.units(eid)}
            status = _final_status(states, self.cancel.is_set() or forced)
            counts = Counter(states.values())
            self.store.update_execution(eid, status=status, ended_at=iso(), heartbeat_at=iso(),
                                        summary_json={k: counts[k] for k in sorted(counts)})
            self.locks.release_execution(eid)
            self._write_manifest(eid, run_id, run_dir, eng, target)
            runlog.event("INFO", "run.end", f"{status}: " + ", ".join(f"{n} {s.lower()}" for s, n in sorted(counts.items())))
            self.store.log(eid, "INFO", "run.end", status, counts=dict(counts))
        return RunReport(eid, run_id, run_dir, status, planned, states)

    def _register_evidence(self, eid: str, target: Target, pu: PlannedUnit, attempt: int, adir: Path,
                           run_dir: Path, result) -> None:
        descriptions = result.evidence_descriptions if result else {}
        sensitive = set(result.sensitive_files) if result else set()
        tools = ",".join(sorted(pu.tool_launch)) or None
        for path in sorted(p for p in adir.rglob("*") if p.is_file()):
            rel = path.relative_to(run_dir).as_posix()
            kind = "parsed" if "/parsed/" in f"/{rel}" else ("log" if path.name.endswith(".cmd.txt") else "raw")
            self.store.add_evidence(
                execution_id=eid, target_id=target.id, module_execution_id=pu.row_id, attempt=attempt, tool=tools,
                kind=kind, rel_path=rel, sha256=file_sha256(path), size_bytes=path.stat().st_size,
                sensitive=path.name in sensitive, description=descriptions.get(path.name),
            )

    def _write_manifest(self, eid: str, run_id: str, run_dir: Path, eng: Engagement, target: Target) -> None:
        units = []
        for r in self.store.units(eid):
            units.append({"module": r["module_id"], "unit": r["unit_key"], "state": r["state"], "attempt": r["attempt"],
                          "output_dir": r["output_dir"], "outputs": json.loads(r["outputs_json"] or "[]")})
        manifest = {"run_id": run_id, "execution_id": eid, "engagement": eng.slug, "target": target.canonical,
                    "updated_at": iso(), "units": units}
        atomic_write_text(run_dir / "manifest.json", json.dumps(manifest, indent=2, sort_keys=True))

    def _resolver(self):
        from aiszx.targets import resolver
        return resolver.resolve_host

    def _install_sigint(self):
        if threading.current_thread() is not threading.main_thread():
            return None

        def handler(signum, frame):
            if self.cancel.is_set():
                raise KeyboardInterrupt
            self.cancel.set()
            self.progress("Interrupt received: stopping running tools and saving state "
                          "(press Ctrl+C again to force)")

        previous = signal.signal(signal.SIGINT, handler)
        return lambda: signal.signal(signal.SIGINT, previous)


# --- helpers ------------------------------------------------------------------------

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
