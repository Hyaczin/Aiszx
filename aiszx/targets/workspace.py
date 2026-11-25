"""Filesystem workspace layout.

::

    <data>/engagements/<engagement>/
        engagement.yaml  scope.yaml          (generated mirrors of the database)
        runs/                                (range-level discovery runs)
        targets/<target-slug>/
            target.yaml
            history/  runs/  consolidated/  logs/
            runs/<run-id>/ ...                (layout from workspace.run_subdirs)

Run directories are created with an exclusive ``mkdir`` so an existing run can never
be overwritten; a collision within the same second gets a ``_2``, ``_3`` … suffix.
Repair only ever recreates *missing directories*; it never touches file content.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from aiszx.core.config import WorkspaceConfig
from aiszx.core.errors import WorkspaceError
from aiszx.core.fsutil import ensure_dir, set_mode
from aiszx.core.timeutil import utcnow

RUN_ID_FORMAT = "%Y-%m-%d_%H%M%S"
RUN_ID_RE = re.compile(r"^\d{4}-\d{2}-\d{2}_\d{6}(?:_\d+)?$")
MAX_RUN_SUFFIX = 999


@dataclass(frozen=True)
class RunWorkspace:
    run_id: str
    path: Path


@dataclass
class WorkspaceReport:
    root: Path
    missing: list[Path] = field(default_factory=list)
    repaired: list[Path] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems and all(p in self.repaired for p in self.missing)


def _check_component(value: str) -> str:
    if not value or value in (".", "..") or "/" in value or "\\" in value:
        raise WorkspaceError(f"unsafe path component {value!r}")
    return value


class WorkspaceLayout:
    def __init__(self, data_dir: Path, cfg: WorkspaceConfig) -> None:
        self.data_dir = data_dir
        self.cfg = cfg

    # -- paths ---------------------------------------------------------------
    @property
    def engagements_root(self) -> Path:
        return self.data_dir / "engagements"

    def engagement_dir(self, engagement_slug: str) -> Path:
        return self.engagements_root / _check_component(engagement_slug)

    def target_dir(self, engagement_slug: str, target_slug: str) -> Path:
        return self.engagement_dir(engagement_slug) / "targets" / _check_component(target_slug)

    def target_runs_dir(self, engagement_slug: str, target_slug: str) -> Path:
        return self.target_dir(engagement_slug, target_slug) / "runs"

    def trash_dir(self, engagement_slug: str) -> Path:
        return self.engagement_dir(engagement_slug) / ".trash"

    # -- creation ------------------------------------------------------------
    def ensure_data_dir(self) -> list[Path]:
        created = []
        for d in (self.data_dir, self.data_dir / "logs", self.engagements_root):
            if ensure_dir(d, self.cfg.dir_mode):
                created.append(d)
        return created

    def _engagement_dirs(self, slug: str) -> list[Path]:
        base = self.engagement_dir(slug)
        return [base, base / "runs", base / "targets"]

    def _target_dirs(self, engagement_slug: str, target_slug: str) -> list[Path]:
        base = self.target_dir(engagement_slug, target_slug)
        return [base] + [base / sub for sub in self.cfg.target_subdirs]

    def _run_dirs(self, run_path: Path) -> list[tuple[Path, int]]:
        protected = set(self.cfg.protected_subdirs)
        dirs: list[tuple[Path, int]] = [(run_path, self.cfg.dir_mode)]
        for sub in self.cfg.run_subdirs:
            mode = self.cfg.protected_dir_mode if sub in protected else self.cfg.dir_mode
            dirs.append((run_path / sub, mode))
        if "enumeration" in self.cfg.run_subdirs:
            for cat in self.cfg.enumeration_categories:
                dirs.append((run_path / "enumeration" / cat, self.cfg.dir_mode))
        return dirs

    def ensure_engagement(self, slug: str) -> list[Path]:
        return [d for d in self._engagement_dirs(slug) if ensure_dir(d, self.cfg.dir_mode)]

    def ensure_target(self, engagement_slug: str, target_slug: str) -> list[Path]:
        self.ensure_engagement(engagement_slug)
        return [d for d in self._target_dirs(engagement_slug, target_slug) if ensure_dir(d, self.cfg.dir_mode)]

    def _create_run_in(self, runs_dir: Path, now: datetime | None) -> RunWorkspace:
        ensure_dir(runs_dir, self.cfg.dir_mode)
        base = (now or utcnow()).astimezone(timezone.utc).strftime(RUN_ID_FORMAT)
        for n in range(1, MAX_RUN_SUFFIX + 1):
            run_id = base if n == 1 else f"{base}_{n}"
            path = runs_dir / run_id
            try:
                path.mkdir()  # exclusive: fails if it exists → never reuse a run directory
            except FileExistsError:
                continue
            for d, mode in self._run_dirs(path):
                ensure_dir(d, mode)
                if d == path:
                    set_mode(d, mode)
            return RunWorkspace(run_id, path)
        raise WorkspaceError(f"could not allocate a unique run id under {runs_dir}")

    def create_target_run(self, engagement_slug: str, target_slug: str, now: datetime | None = None) -> RunWorkspace:
        self.ensure_target(engagement_slug, target_slug)
        return self._create_run_in(self.target_runs_dir(engagement_slug, target_slug), now)

    def create_engagement_run(self, engagement_slug: str, now: datetime | None = None) -> RunWorkspace:
        self.ensure_engagement(engagement_slug)
        return self._create_run_in(self.engagement_dir(engagement_slug) / "runs", now)

    # -- verification / repair ----------------------------------------------
    def _verify_dirs(self, report: WorkspaceReport, dirs: list[tuple[Path, int]], repair: bool) -> None:
        for d, mode in dirs:
            if d.exists() and not d.is_dir():
                report.problems.append(f"{d} exists but is not a directory")
                continue
            if not d.is_dir():
                report.missing.append(d)
                if repair:
                    ensure_dir(d, mode)
                    report.repaired.append(d)
                continue
            if os.name == "posix" and mode == self.cfg.protected_dir_mode:
                actual = stat.S_IMODE(d.stat().st_mode)
                if actual & ~mode:
                    if repair:
                        set_mode(d, mode)
                    else:
                        report.problems.append(f"{d} has permissions {actual:04o}; expected {mode:04o} or stricter")

    def verify_engagement(self, slug: str, *, repair: bool = False) -> WorkspaceReport:
        report = WorkspaceReport(self.engagement_dir(slug))
        self._verify_dirs(report, [(d, self.cfg.dir_mode) for d in self._engagement_dirs(slug)], repair)
        return report

    def verify_target(self, engagement_slug: str, target_slug: str, *, repair: bool = False) -> WorkspaceReport:
        report = WorkspaceReport(self.target_dir(engagement_slug, target_slug))
        self._verify_dirs(report, [(d, self.cfg.dir_mode) for d in self._target_dirs(engagement_slug, target_slug)], repair)
        runs_dir = self.target_runs_dir(engagement_slug, target_slug)
        if runs_dir.is_dir():
            for entry in sorted(runs_dir.iterdir()):
                if entry.is_dir() and RUN_ID_RE.fullmatch(entry.name):
                    self._verify_dirs(report, self._run_dirs(entry), repair)
                else:
                    report.problems.append(f"unexpected entry in runs directory: {entry.name}")
        return report

    def list_target_dirs(self, engagement_slug: str) -> list[str]:
        targets_dir = self.engagement_dir(engagement_slug) / "targets"
        if not targets_dir.is_dir():
            return []
        return sorted(p.name for p in targets_dir.iterdir() if p.is_dir())
