"""Module interface.

A module is a class with a :class:`ModuleMeta` description and four steps::

    plan()  →  build_commands()  →  [ToolRunner executes]  →  parse()  →  validate_outputs()
    pure       pure                  side effects               pure        file reads

Only the ToolRunner touches the network or spawns processes, and it enforces scope,
timeouts and cancellation. Everything a module decides is therefore testable with
saved tool output. Modules never write to the database: they return a
:class:`ModuleResult`, which the orchestrator persists.

Modules that need no external tool return no commands and do their work in ``parse``.
"""

from __future__ import annotations

import abc
import json
import re
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Mapping, Sequence

if TYPE_CHECKING:
    from aiszx.targets.engagements import Engagement
    from aiszx.targets.manager import Target


class Stage(str, Enum):
    PREFLIGHT = "preflight"
    RECON = "recon"
    ENUMERATION = "enumeration"
    ASSESSMENT = "assessment"


class Safety(str, Enum):
    PASSIVE = "passive"                  # sends nothing to the target
    ACTIVE_SAFE = "active_safe"          # standard, low-volume enumeration
    ACTIVE_NOISY = "active_noisy"        # content discovery, vulnerability scanners
    INTRUSIVE = "intrusive"              # needs explicit per-run human approval
    PROHIBITED_AUTO = "prohibited_auto"  # never scheduled automatically

    @property
    def rank(self) -> int:
        return SAFETY_ORDER.index(self)

    def allowed_under(self, ceiling: "Safety") -> bool:
        return self.rank <= ceiling.rank


SAFETY_ORDER = [Safety.PASSIVE, Safety.ACTIVE_SAFE, Safety.ACTIVE_NOISY, Safety.INTRUSIVE, Safety.PROHIBITED_AUTO]

# Error classes used for retry decisions.
TRANSIENT = "transient"
TIMEOUT = "timeout"
PERMANENT = "permanent"
SCOPE = "scope"
DEPENDENCY = "dependency"

_TRANSIENT_RE = re.compile(
    r"network is unreachable|no route to host|connection reset|temporary failure in name resolution"
    r"|connection timed out|resource temporarily unavailable",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 2
    backoff_seconds: float = 5.0
    backoff_factor: float = 2.0
    retry_on: tuple[str, ...] = (TRANSIENT, TIMEOUT)

    def delay(self, attempt_index: int) -> float:
        """Delay before retry number ``attempt_index`` (1 = first retry)."""
        return self.backoff_seconds * (self.backoff_factor ** max(0, attempt_index - 1))


@dataclass(frozen=True)
class ToolRequirement:
    name: str                       # logical name from config/tools.yaml
    min_version: str | None = None
    optional: bool = False


@dataclass(frozen=True)
class ModuleMeta:
    id: str                          # "<family>.<name>", e.g. "smb.enum4linux_ng"
    version: str                     # bump when output format/semantics change (invalidates checkpoints)
    description: str
    stage: Stage
    safety: Safety
    timeout_seconds: int
    tools: tuple[ToolRequirement, ...] = ()
    categories: tuple[str, ...] = ()     # service categories handled (used from Milestone 4)
    depends_on: tuple[str, ...] = ()     # module ids that must finish first *within the same run*
    retry: RetryPolicy = RetryPolicy()
    resumable: bool = False              # can continue from a previous attempt's partial output
    ok_exit_codes: tuple[int, ...] = (0,)
    max_parallel: int | None = None      # limit concurrent units of this module
    config_defaults: Mapping[str, Any] = field(default_factory=dict)

    @property
    def family(self) -> str:
        return self.id.split(".", 1)[0]


@dataclass(frozen=True)
class WorkUnit:
    module_id: str
    key: str                         # unique per module within a run: "host", "tcp/445", ...
    inputs: Mapping[str, Any]        # JSON-serialisable; hashed into the input fingerprint


@dataclass
class Command:
    label: str                       # file name stem for raw output: <label>.stdout.txt
    argv: list[str]                  # arguments (appended to the tool's launch command when ``tool`` is set)
    tool: str | None = None          # logical tool name; resolved to an absolute path by the runner
    targets: Sequence[str] = ()      # every host this command contacts: checked against scope before execution
    timeout: int | None = None       # defaults to the module timeout
    env: Mapping[str, str] = field(default_factory=dict)
    redact: Sequence[str] = ()       # secrets to mask in logs and stored command lines
    ok_exit_codes: tuple[int, ...] | None = None  # defaults to the module's


@dataclass
class CommandResult:
    label: str
    argv_redacted: list[str]
    exit_code: int | None
    duration_s: float
    stdout_path: Path
    stderr_path: Path
    timed_out: bool = False
    cancelled: bool = False
    error: str | None = None          # could not start

    def stdout(self, limit: int = 5_000_000) -> str:
        return _read(self.stdout_path, limit)

    def stderr(self, limit: int = 1_000_000) -> str:
        return _read(self.stderr_path, limit)

    def to_dict(self) -> dict[str, Any]:
        return {"label": self.label, "argv": self.argv_redacted, "exit_code": self.exit_code,
                "duration_s": round(self.duration_s, 3), "timed_out": self.timed_out,
                "cancelled": self.cancelled, "error": self.error}


@dataclass
class ModuleResult:
    summary: str = ""
    artifacts: dict[str, Any] = field(default_factory=dict)         # structured, module-specific output
    observations: list[dict[str, Any]] = field(default_factory=list)  # typed facts for assessment (M7)
    limitations: list[str] = field(default_factory=list)
    evidence_descriptions: dict[str, str] = field(default_factory=dict)  # file name → description
    sensitive_files: list[str] = field(default_factory=list)            # file names to mark sensitive

    def to_json(self, module_id: str, unit_key: str) -> str:
        return json.dumps({
            "module": module_id, "unit": unit_key, "summary": self.summary, "artifacts": self.artifacts,
            "observations": self.observations, "limitations": self.limitations,
        }, indent=2, sort_keys=True, default=str)


@dataclass
class PlanContext:
    engagement: "Engagement"
    target: "Target"
    address: str
    options: Mapping[str, Any]


@dataclass
class RunContext:
    execution_id: str
    run_id: str
    run_dir: Path
    engagement: "Engagement"
    target: "Target"
    address: str
    profile: str
    options: Mapping[str, Any]
    tool_launch: Mapping[str, list[str]]
    tool_versions: Mapping[str, str | None]
    upstream: Mapping[str, list[dict[str, Any]]]   # module id → parsed results of completed units in this run
    cancel_event: threading.Event
    previous_attempt_dir: Path | None = None


class Module(abc.ABC):
    meta: ClassVar[ModuleMeta]

    def plan(self, ctx: PlanContext) -> list[WorkUnit]:
        """Default: one unit for the target host."""
        return [WorkUnit(self.meta.id, "host", {"target": ctx.target.canonical, "address": ctx.address})]

    @abc.abstractmethod
    def build_commands(self, unit: WorkUnit, ctx: RunContext) -> list[Command]:
        """Pure: describe the commands to run. Return [] for in-process modules."""

    @abc.abstractmethod
    def parse(self, unit: WorkUnit, results: list[CommandResult], ctx: RunContext) -> ModuleResult:
        """Pure: turn raw output into a ModuleResult. Must tolerate partial or garbled output."""

    def classify_failure(self, command: Command, result: CommandResult) -> tuple[str, str] | None:
        """Return (error_class, message) if this command result is a failure, else None."""
        if result.error:
            return DEPENDENCY, f"could not start: {result.error}"
        if result.cancelled:
            return None
        if result.timed_out:
            return TIMEOUT, f"`{command.label}` exceeded its timeout"
        ok_codes = command.ok_exit_codes or self.meta.ok_exit_codes
        if result.exit_code in ok_codes:
            return None
        stderr = result.stderr(64_000)
        cls = TRANSIENT if _TRANSIENT_RE.search(stderr) else PERMANENT
        tail = stderr.strip().splitlines()[-1:] or [""]
        return cls, f"`{command.label}` exited with {result.exit_code}: {tail[0][:300]}"

    def validate_outputs(self, unit: WorkUnit, attempt_dir: Path) -> list[str]:
        """Problems with a completed attempt's outputs (used by resume). Default: parsed result readable."""
        result_file = attempt_dir / "parsed" / "result.json"
        try:
            json.loads(result_file.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return [f"{result_file.name} unreadable: {exc}"]
        return []


def _read(path: Path, limit: int) -> str:
    try:
        with path.open("rb") as fh:
            return fh.read(limit).decode("utf-8", errors="replace")
    except OSError:
        return ""
