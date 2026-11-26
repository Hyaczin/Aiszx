"""Concurrent execution of planned units.

* Worker threads run units (commands are subprocess-bound, so threads suffice).
* Workers never touch the database: they post events to a queue that the main thread
  drains and persists (single SQLite writer), in order.
* Retries follow each module's RetryPolicy (transient/timeout by default) with exponential
  backoff; the wait is interrupted immediately by cancellation.
* A unit whose dependency did not complete is SKIPPED; unrelated units continue (failure isolation).
"""

from __future__ import annotations

import dataclasses
import queue
import threading
import time
import traceback
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from aiszx.core.fsutil import atomic_write_text
from aiszx.modules.base import DEPENDENCY, PERMANENT, SCOPE, ModuleResult, RunContext
from aiszx.orchestrator.planner import PlannedUnit
from aiszx.orchestrator.state import COMPLETED, FAILED, INTERRUPTED, PENDING, RUNNING, SKIPPED
from aiszx.orchestrator.toolrunner import ScopeViolation, ToolRunner, ToolUnavailable


# --- events (worker → main thread) ------------------------------------------------

@dataclass
class AttemptStarted:
    pu: PlannedUnit
    attempt: int
    attempt_dir: Path


@dataclass
class AttemptFinished:
    pu: PlannedUnit
    attempt: int
    attempt_dir: Path
    status: str                      # ok | failed | interrupted
    error_class: str | None
    error_message: str | None
    exit_code: int | None
    duration_s: float
    commands: list[dict[str, Any]]
    result: ModuleResult | None = None


@dataclass
class UnitSkipped:
    pu: PlannedUnit
    reason: str


@dataclass
class UnitFinished:
    pu: PlannedUnit
    state: str
    attempt: int
    attempt_dir: Path | None
    result: ModuleResult | None = None
    error_class: str | None = None
    error_message: str | None = None
    exit_code: int | None = None
    duration_s: float = 0.0


@dataclass
class _AttemptOutcome:
    status: str
    error_class: str | None = None
    error_message: str | None = None
    exit_code: int | None = None
    commands: list[dict[str, Any]] = field(default_factory=list)
    result: ModuleResult | None = None


class Executor:
    def __init__(
        self,
        *,
        max_workers: int,
        runner: ToolRunner,
        cancel_event: threading.Event,
        on_event: Callable[[Any], None],
        approve: Callable[[PlannedUnit], bool],
        acquire: Callable[[PlannedUnit], tuple[bool, str | None]],
        heartbeat: Callable[[], None],
        heartbeat_seconds: float,
        postprocess: Callable[[PlannedUnit, ModuleResult], None] | None = None,
    ) -> None:
        self.max_workers = max(1, max_workers)
        self.runner = runner
        self.cancel = cancel_event
        self.on_event = on_event
        self.approve = approve
        self.acquire = acquire
        self.heartbeat = heartbeat
        self.heartbeat_seconds = heartbeat_seconds
        self.postprocess = postprocess
        self.events: queue.Queue = queue.Queue()

    # -- main loop (main thread) ---------------------------------------------
    def run(self, units: list[PlannedUnit], contexts: dict[tuple[str, str], RunContext]) -> dict[tuple[str, str], str]:
        states = {pu.key: pu.state for pu in units}
        by_module: dict[str, list[PlannedUnit]] = {}
        for pu in units:
            by_module.setdefault(pu.module.meta.id, []).append(pu)
        todo = [pu for pu in units if pu.state == PENDING]
        running: dict[Future, PlannedUnit] = {}
        per_module: Counter = Counter()
        last_beat = time.monotonic()
        pool = ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="aiszx-unit")
        try:
            while todo or running:
                if self.cancel.is_set():
                    todo.clear()  # never-started units stay PENDING; resume runs them
                for pu in list(todo):
                    if len(running) >= self.max_workers:
                        break
                    deps = [d for mid in pu.depends_on for d in by_module.get(mid, [])]
                    if any(states[d.key] in (PENDING, RUNNING) for d in deps):
                        continue
                    limit = pu.module.meta.max_parallel
                    if limit and per_module[pu.module.meta.id] >= limit:
                        continue
                    todo.remove(pu)
                    bad = [d for d in deps if states[d.key] != COMPLETED]
                    if bad:
                        self._skip(pu, states, f"upstream {bad[0].label} is {states[bad[0].key]}")
                        continue
                    if pu.needs_approval and not self.approve(pu):
                        self._skip(pu, states, "intrusive module not approved")
                        continue
                    ok, why = self.acquire(pu)
                    if not ok:
                        self._skip(pu, states, f"already running elsewhere ({why})")
                        continue
                    states[pu.key] = RUNNING
                    per_module[pu.module.meta.id] += 1
                    running[pool.submit(self._work, pu, contexts[pu.key])] = pu

                if running:
                    done, _ = wait(list(running), timeout=0.5, return_when=FIRST_COMPLETED)
                else:
                    done = set()
                    if todo:
                        time.sleep(0.05)
                self._drain()
                for fut in done:
                    pu = running.pop(fut)
                    per_module[pu.module.meta.id] -= 1
                    try:
                        finished: UnitFinished = fut.result()
                    except Exception as exc:  # a bug in the executor or module: isolate it
                        finished = UnitFinished(pu, FAILED, pu.attempts_done, None, error_class=PERMANENT,
                                                error_message=f"internal error: {exc!r}")
                    self._drain()
                    states[pu.key] = finished.state
                    self.on_event(finished)
                if time.monotonic() - last_beat >= self.heartbeat_seconds:
                    self.heartbeat()
                    last_beat = time.monotonic()
        finally:
            if running:  # forced exit (second Ctrl+C): stop tools, then record what we know
                self.cancel.set()
            pool.shutdown(wait=True)
            self._drain()
            for fut, pu in running.items():
                if fut.done() and not fut.exception():
                    finished = fut.result()
                else:
                    finished = UnitFinished(pu, INTERRUPTED, pu.attempts_done, None, error_message="interrupted")
                states[pu.key] = finished.state
                self.on_event(finished)
        return states

    def _skip(self, pu: PlannedUnit, states: dict, reason: str) -> None:
        states[pu.key] = SKIPPED
        self.on_event(UnitSkipped(pu, reason))

    def _drain(self) -> None:
        while True:
            try:
                event = self.events.get_nowait()
            except queue.Empty:
                return
            self.on_event(event)

    # -- worker --------------------------------------------------------------
    def _work(self, pu: PlannedUnit, ctx: RunContext) -> UnitFinished:
        policy = pu.config.retry
        attempt = pu.attempts_done
        previous = pu.previous_attempt_dir
        started = time.monotonic()
        for n in range(1, policy.max_attempts + 1):
            attempt += 1
            adir = pu.unit_dir / f"attempt-{attempt:02d}"
            # Never write into an existing attempt directory: after a hard crash the database can lag behind
            # the filesystem (the attempt started but was not yet recorded). Keep that output untouched,
            # use the next number, and offer the leftover as the previous attempt (e.g. for nmap --resume).
            while adir.exists():
                previous = adir  # the newest leftover is the most useful one to resume from
                attempt += 1
                adir = pu.unit_dir / f"attempt-{attempt:02d}"
            (adir / "raw").mkdir(parents=True)
            (adir / "parsed").mkdir(parents=True)
            self.events.put(AttemptStarted(pu, attempt, adir))
            t0 = time.monotonic()
            uctx = dataclasses.replace(ctx, previous_attempt_dir=previous, attempt_dir=adir)
            out = self._attempt(pu, uctx, adir)
            self.events.put(AttemptFinished(pu, attempt, adir, out.status, out.error_class, out.error_message,
                                            out.exit_code, time.monotonic() - t0, out.commands, out.result))
            if out.status == "ok":
                return UnitFinished(pu, COMPLETED, attempt, adir, out.result, exit_code=out.exit_code,
                                    duration_s=time.monotonic() - started)
            if out.status == "interrupted":
                return UnitFinished(pu, INTERRUPTED, attempt, adir, error_message="interrupted",
                                    duration_s=time.monotonic() - started)
            retryable = out.error_class in policy.retry_on and n < policy.max_attempts
            if not retryable:
                break
            if self.cancel.wait(policy.delay(n)):
                return UnitFinished(pu, INTERRUPTED, attempt, adir, error_message="interrupted during retry backoff",
                                    duration_s=time.monotonic() - started)
            previous = adir
        return UnitFinished(pu, FAILED, attempt, adir, error_class=out.error_class, error_message=out.error_message,
                            exit_code=out.exit_code, duration_s=time.monotonic() - started)

    def _attempt(self, pu: PlannedUnit, ctx: RunContext, adir: Path) -> _AttemptOutcome:
        module, unit = pu.module, pu.unit
        out = _AttemptOutcome("failed")
        try:
            commands = module.build_commands(unit, ctx)
        except Exception as exc:
            out.error_class, out.error_message = PERMANENT, f"build_commands failed: {exc!r}"
            _write_traceback(adir)
            return out
        results = []
        for cmd in commands:
            if self.cancel.is_set():
                out.status = "interrupted"
                return out
            try:
                res = self.runner.run(cmd, adir / "raw", pu.config.timeout)
            except ScopeViolation as exc:
                out.error_class, out.error_message = SCOPE, str(exc)
                return out
            except ToolUnavailable as exc:
                out.error_class, out.error_message = DEPENDENCY, str(exc)
                return out
            results.append(res)
            out.commands.append(res.to_dict())
            out.exit_code = res.exit_code
            if res.cancelled:
                out.status = "interrupted"
                return out
            failure = module.classify_failure(cmd, res)
            if failure:
                out.error_class, out.error_message = failure
                return out
        try:
            result = module.parse(unit, results, ctx)
        except Exception as exc:
            out.error_class, out.error_message = PERMANENT, f"parse failed: {exc!r} (raw output kept)"
            _write_traceback(adir)
            return out
        if self.postprocess is not None:
            try:
                self.postprocess(pu, result)
            except Exception as exc:
                out.error_class, out.error_message = PERMANENT, f"post-processing failed: {exc!r}"
                return out
        atomic_write_text(adir / "parsed" / "result.json", result.to_json(module.meta.id, unit.key))
        problems = module.validate_outputs(unit, adir)
        if problems:
            out.error_class, out.error_message = PERMANENT, "output validation failed: " + "; ".join(problems)
            return out
        out.status, out.result = "ok", result
        return out


def _write_traceback(adir: Path) -> None:
    (adir / "parsed").mkdir(parents=True, exist_ok=True)
    (adir / "parsed" / "error.txt").write_text(traceback.format_exc(), encoding="utf-8")
