"""``report``: build the model, render the formats, store them as a run of their own.

* Each report is a run (``command='report'``, no module units) under the target's ``runs/``;
  previous reports are never overwritten. Files go to ``<run>/reports/report.{md,html,json}`` and
  are registered as evidence (kind ``report``) with their SHA-256.
* When ``reporting.write_consolidated`` is on, the same report is also rendered into
  ``<target>/consolidated/`` as the always-current view of the target (links adjusted).
* ``compare`` results are written to ``<target>/history/``.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aiszx import __version__
from aiszx.core.errors import ConfigError
from aiszx.core.fsutil import atomic_write_text
from aiszx.core.timeutil import iso
from aiszx.orchestrator.fingerprint import fingerprint
from aiszx.orchestrator.orchestrator import register_evidence
from aiszx.orchestrator.procutil import Owner
from aiszx.orchestrator.state import EXEC_COMPLETED, EXEC_FAILED, EXEC_RUNNING, ExecutionStore
from aiszx.reporting.builder import ReportBuilder
from aiszx.reporting.compare import Comparator
from aiszx.reporting.render import render
from aiszx.reporting.settings import EXTENSIONS, FORMATS, ReportSettings, load_report_settings


@dataclass
class ReportResult:
    run_id: str
    run_dir: Path
    files: dict[str, Path]
    consolidated: dict[str, Path] = field(default_factory=dict)
    model: dict[str, Any] = field(default_factory=dict)


def _link_base(out_dir: Path, target_dir: Path) -> str:
    return Path(os.path.relpath(target_dir, out_dir)).as_posix()


class Reporter:
    def __init__(self, app, settings: ReportSettings | None = None) -> None:
        self.app = app
        self.store = ExecutionStore(app.db)
        self._settings = settings

    def settings(self, eng_slug: str) -> ReportSettings:
        return self._settings or load_report_settings(user_config_dir=self.app.config.user_config_dir,
                                                      engagement_dir=self.app.layout.engagement_dir(eng_slug))

    def _write(self, model: dict[str, Any], formats: tuple[str, ...], out_dir: Path, target_dir: Path,
               settings: ReportSettings) -> dict[str, Path]:
        base = _link_base(out_dir, target_dir)
        written = {}
        for fmt in formats:
            text = render(model, fmt, link_base=base, max_rows=settings.max_table_rows,
                          max_value=settings.max_value_chars)
            path = out_dir / f"report.{EXTENSIONS[fmt]}"
            atomic_write_text(path, text)
            written[fmt] = path
        return written

    def run(self, engagement_slug: str, target_raw: str, formats: tuple[str, ...] | None = None) -> ReportResult:
        eng = self.app.engagements().get(engagement_slug)
        target = self.app.targets().get(eng, target_raw)
        settings = self.settings(eng.slug)
        formats = tuple(dict.fromkeys(formats or settings.formats))
        bad = [f for f in formats if f not in FORMATS]
        if bad:
            raise ConfigError(f"unknown report format(s): {', '.join(bad)} (choose from {', '.join(FORMATS)})")
        model = ReportBuilder(self.app, settings).build(eng.slug, target.canonical)

        target_dir = self.app.layout.target_dir(eng.slug, target.slug)
        run = self.app.layout.create_target_run(eng.slug, target.slug)
        owner = Owner.current()
        now = iso()
        snapshot = {"command": "report", "formats": list(formats), "sources": [str(p) for p in settings.sources]}
        eid = self.store.create_execution(
            run_id=run.run_id, engagement_id=eng.id, target_id=target.id, command="report", profile="-",
            status=EXEC_RUNNING, pinned_address=None, config_fingerprint=fingerprint(snapshot), config_snapshot=snapshot,
            framework_version=__version__, owner_pid=owner.pid, owner_host=owner.host, boot_id=owner.boot,
            heartbeat_at=now, started_at=now, workspace_path=run.path.relative_to(self.app.config.data_dir).as_posix())
        try:
            model["meta"]["report_run"] = run.run_id
            files = self._write(model, formats, run.path / "reports", target_dir, settings)
            consolidated = {}
            if settings.write_consolidated:
                consolidated = self._write(model, formats, target_dir / "consolidated", target_dir, settings)
            with self.app.db.transaction():
                register_evidence(self.store, eid=eid, target_id=target.id, unit_id=None, attempt=None,
                                  adir=run.path / "reports", run_dir=run.path, tools=None)
                self.store.update_execution(eid, status=EXEC_COMPLETED, ended_at=iso(), summary_json={
                    "findings": model["findings"]["open_count"], "files": len(files)})
        except BaseException:
            self.store.update_execution(eid, status=EXEC_FAILED, ended_at=iso())
            raise
        return ReportResult(run.run_id, run.path, files, consolidated, model)


def compare_and_store(app, engagement_slug: str, target_raw: str, from_run: str | None = None,
                      to_run: str | None = None) -> tuple[dict[str, Any], Path]:
    eng = app.engagements().get(engagement_slug)
    target = app.targets().get(eng, target_raw)
    result = Comparator(app.db, target.id).compare(from_run, to_run)
    result = {"target": target.canonical, "engagement": eng.slug, "compared_at": iso(), **result}
    stamp = result["compared_at"].replace(":", "").replace("-", "")[:15]
    path = app.layout.target_dir(eng.slug, target.slug) / "history" / f"compare_{stamp}.json"
    atomic_write_text(path, json.dumps(result, indent=2, default=str))
    return result, path
