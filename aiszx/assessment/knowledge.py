"""Consolidated knowledge about a target: the latest completed result of every module unit across
all runs, plus the latest services, web endpoints and technologies. This is what assessment rules read.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aiszx.db.connection import Database
from aiszx.modules.records import ServiceRecord
from aiszx.recon.store import ReconStore


@dataclass
class Observation:
    module: str
    unit: str
    key: str
    value: Any
    url: str | None
    run_id: str
    files: list[str]                 # evidence files of the unit (relative to the run directory)

    def ref(self) -> dict[str, Any]:
        return {"run_id": self.run_id, "module": self.module, "unit": self.unit, "observation": self.key,
                "files": self.files[:12]}


@dataclass
class Knowledge:
    target: str
    observations: list[Observation] = field(default_factory=list)
    services: list[ServiceRecord] = field(default_factory=list)
    services_run: str | None = None
    endpoints: list[dict] = field(default_factory=list)
    resources: list[dict] = field(default_factory=list)
    technologies: list[dict] = field(default_factory=list)
    results: dict[tuple[str, str], dict] = field(default_factory=dict)   # (module, unit) → parsed result
    runs_used: list[str] = field(default_factory=list)

    def find(self, key: str) -> list[Observation]:
        return [o for o in self.observations if o.key == key]

    def find_prefix(self, prefix: str) -> list[Observation]:
        return [o for o in self.observations if o.key.startswith(prefix)]


def _evidence_files(row) -> list[str]:
    """Files worth citing as evidence: not command-line logs, not empty (e.g. a silent stderr)."""
    return [o["path"] for o in json.loads(row["outputs_json"] or "[]")
            if not o["path"].endswith(".cmd.txt") and o.get("size") != 0]


def gather(db: Database, data_dir: Path, target_id: str, target_name: str, run_id: str | None = None) -> Knowledge:
    """Latest completed result per (module, unit) across the target's runs (or only ``run_id``)."""
    sql = ("SELECT u.*, e.run_id, e.workspace_path, e.started_at AS run_started FROM module_executions u "
           "JOIN executions e ON e.id = u.execution_id WHERE e.target_id = ? AND u.state = 'COMPLETED' "
           "AND u.output_dir IS NOT NULL")
    params: list[Any] = [target_id]
    if run_id:
        sql += " AND e.run_id = ?"
        params.append(run_id)
    rows = db.query(sql + " ORDER BY e.started_at DESC, e.run_id DESC, u.ended_at DESC", params)
    k = Knowledge(target_name)
    seen: set[tuple[str, str]] = set()
    for row in rows:
        key = (row["module_id"], row["unit_key"])
        if key in seen:
            continue
        seen.add(key)
        try:
            data = json.loads((data_dir / row["workspace_path"] / row["output_dir"] / "parsed" / "result.json")
                              .read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        k.results[key] = data
        if row["run_id"] not in k.runs_used:
            k.runs_used.append(row["run_id"])
        files = _evidence_files(row)
        for o in data.get("observations", []):
            k.observations.append(Observation(row["module_id"], row["unit_key"], o.get("key", "?"), o.get("value"),
                                              o.get("url"), row["run_id"], files))

    store = ReconStore(db)
    snap = store.latest_services(target_id)
    k.services, k.services_run = snap.services, snap.run_id
    web = store.latest_web_execution(target_id)
    if web:
        w = store.web_for_execution(web[0])
        k.endpoints = [dict(r) for r in w["endpoints"]]
        k.resources = [dict(r) for r in w["resources"]]
        k.technologies = [dict(r) for r in w["technologies"]]
    return k
