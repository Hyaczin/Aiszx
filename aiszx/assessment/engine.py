"""Assessment engine: gather knowledge, apply rules, reconcile findings, write the assessment run.

* Each assessment is a run of its own (``command='assess'``) with files under ``<run>/findings`` and
  ``<run>/assessment``; every finding seen is snapshotted in ``assessment_results``.
* Findings are identified by a stable fingerprint (rule, target, service, location, discriminator):
  the same issue keeps its ID across assessments; analyst decisions (false positive, confirmed, …)
  are kept. Findings no longer produced become ``not_reproduced`` and are never deleted.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable

from aiszx import __version__
from aiszx.assessment import exploitdb
from aiszx.assessment.knowledge import Knowledge, gather
from aiszx.assessment.model import FALSE_POSITIVE, FindingDraft, finding_id, priority
from aiszx.assessment.rules import RULES
from aiszx.core.fsutil import atomic_write_text
from aiszx.core.process import ProcessRunner
from aiszx.core.timeutil import iso
from aiszx.orchestrator.fingerprint import fingerprint
from aiszx.orchestrator.orchestrator import register_evidence
from aiszx.orchestrator.procutil import Owner
from aiszx.orchestrator.state import EXEC_COMPLETED, EXEC_RUNNING, ExecutionStore


@dataclass
class Finding:
    id: str
    draft: FindingDraft
    fingerprint: str
    status: str
    analyst_classification: str | None
    analyst_notes: str | None
    first_seen_at: str
    new: bool

    @property
    def classification(self) -> str:
        return self.analyst_classification or self.draft.classification

    @property
    def priority(self) -> int:
        return priority(self.draft.severity, self.draft.confidence, self.classification)


@dataclass
class AssessmentReport:
    execution_id: str
    run_id: str
    run_dir: Any
    findings: list[Finding]
    not_reproduced: list[str]
    paths: list[dict[str, Any]]
    limitations: list[str] = field(default_factory=list)
    knowledge_runs: list[str] = field(default_factory=list)


def investigation_paths(findings: list[Finding]) -> list[dict[str, Any]]:
    """Prioritised manual next steps (false positives excluded), one entry per distinct step."""
    seen, out = set(), []
    for f in sorted(findings, key=lambda f: -f.priority):
        if f.classification == FALSE_POSITIVE:
            continue
        for step in f.draft.next_steps:
            if step in seen:
                continue
            seen.add(step)
            out.append({"priority": f.priority, "finding": f.id, "severity": f.draft.severity, "step": step,
                        "why": f.draft.title})
    return out


class Assessor:
    def __init__(self, app, *, runner: ProcessRunner | None = None,
                 searchsploit: Callable[[], list[str] | None] | None = None) -> None:
        self.app = app
        self.db = app.db
        self.store = ExecutionStore(app.db)
        self.runner = runner or app.runner()
        self._searchsploit = searchsploit

    def _searchsploit_launch(self) -> list[str] | None:
        if self._searchsploit is not None:
            return self._searchsploit()
        registry = self.app.tool_registry()
        if "searchsploit" not in registry.tools:
            return None
        t = self.app.tool_inventory(registry).detect(["searchsploit"]).tools["searchsploit"]
        return t.launch if t.status == "ok" else None

    def drafts(self, k: Knowledge, *, exploitdb_lookup: bool = True) -> tuple[list[FindingDraft], list[str]]:
        drafts: list[FindingDraft] = []
        notes: list[str] = []
        for rule_id, fn in RULES.items():
            try:
                drafts.extend(fn(k))
            except Exception as exc:  # one broken rule must not stop the assessment
                notes.append(f"rule {rule_id} failed: {exc!r}")
        if exploitdb_lookup:
            launch = self._searchsploit_launch()
            if launch:
                more, extra = exploitdb.lookup(self.runner, launch, k)
                drafts += more
                notes += extra
            else:
                notes.append("searchsploit not available: no version-based hypotheses (see `tools missing`)")
        return drafts, notes

    def run(self, engagement_slug: str, target_raw: str, *, exploitdb_lookup: bool = True) -> AssessmentReport:
        eng = self.app.engagements().get(engagement_slug)
        target = self.app.targets().get(eng, target_raw)
        k = gather(self.db, self.app.config.data_dir, target.id, target.canonical)
        drafts, notes = self.drafts(k, exploitdb_lookup=exploitdb_lookup)
        if not k.results:
            notes.append("no completed module results yet: run `recon`/`enumerate` first")

        run = self.app.layout.create_target_run(eng.slug, target.slug)
        owner = Owner.current()
        now = iso()
        snapshot = {"command": "assess", "rules": sorted(RULES), "exploitdb": exploitdb_lookup, "runs_used": k.runs_used}
        eid = self.store.create_execution(
            run_id=run.run_id, engagement_id=eng.id, target_id=target.id, command="assess", profile="-",
            status=EXEC_RUNNING, pinned_address=None, config_fingerprint=fingerprint(snapshot), config_snapshot=snapshot,
            framework_version=__version__, owner_pid=owner.pid, owner_host=owner.host, boot_id=owner.boot,
            heartbeat_at=now, started_at=now, workspace_path=run.path.relative_to(self.app.config.data_dir).as_posix())

        findings: list[Finding] = []
        seen_ids: set[str] = set()
        with self.db.transaction():
            for d in drafts:
                fp = d.fingerprint(target.canonical)
                fid = finding_id(fp)
                if fid in seen_ids:  # two drafts for the same thing: keep the first
                    continue
                seen_ids.add(fid)
                row = self.db.query_one("SELECT * FROM findings WHERE id = ?", (fid,))
                fields = (d.rule_id, d.title, d.service_key, d.location, d.description, d.impact, d.recommendation,
                          json.dumps(d.next_steps), d.severity, d.confidence, d.classification,
                          json.dumps(d.evidence_refs()), json.dumps(d.details, default=str), now, eid)
                if row is None:
                    self.db.execute(
                        "INSERT INTO findings (rule_id, title, service_key, location, description, impact, recommendation,"
                        " next_steps_json, severity, confidence, classification, evidence_json, details_json,"
                        " last_seen_at, last_assessment_id, id, target_id, fingerprint, first_seen_at, status)"
                        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')",
                        (*fields, fid, target.id, fp, now))
                    findings.append(Finding(fid, d, fp, "open", None, None, now, True))
                else:
                    self.db.execute(
                        "UPDATE findings SET rule_id = ?, title = ?, service_key = ?, location = ?, description = ?,"
                        " impact = ?, recommendation = ?, next_steps_json = ?, severity = ?, confidence = ?,"
                        " classification = ?, evidence_json = ?, details_json = ?, last_seen_at = ?,"
                        " last_assessment_id = ?, status = 'open' WHERE id = ?", (*fields, fid))
                    findings.append(Finding(fid, d, fp, "open", row["analyst_classification"], row["analyst_notes"],
                                            row["first_seen_at"], False))
                self.db.execute(
                    "INSERT INTO assessment_results (assessment_id, finding_id, severity, confidence, classification)"
                    " VALUES (?, ?, ?, ?, ?)", (eid, fid, d.severity, d.confidence, findings[-1].classification))
            gone = [r["id"] for r in self.db.query("SELECT id FROM findings WHERE target_id = ? AND status = 'open'",
                                                   (target.id,)) if r["id"] not in seen_ids]
            for fid in gone:
                self.db.execute("UPDATE findings SET status = 'not_reproduced' WHERE id = ?", (fid,))

        paths = investigation_paths(findings)
        findings.sort(key=lambda f: -f.priority)
        out = {
            "assessed_at": now, "target": target.canonical, "engagement": eng.slug, "runs_used": k.runs_used,
            "findings": [{"id": f.id, "new": f.new, "classification": f.classification, **f.draft.to_dict()}
                         for f in findings],
            "not_reproduced": gone, "limitations": notes,
        }
        atomic_write_text(run.path / "findings" / "findings.json", json.dumps(out, indent=2, default=str))
        atomic_write_text(run.path / "assessment" / "investigation.json", json.dumps(paths, indent=2))
        with self.db.transaction():
            for sub in ("findings", "assessment"):
                register_evidence(self.store, eid=eid, target_id=target.id, unit_id=None, attempt=None,
                                  adir=run.path / sub, run_dir=run.path, tools=None)
            self.store.update_execution(eid, status=EXEC_COMPLETED, ended_at=iso(), summary_json={
                "findings": len(findings), "new": sum(f.new for f in findings), "not_reproduced": len(gone)})
        return AssessmentReport(eid, run.run_id, run.path, findings, gone, paths, notes, k.runs_used)
