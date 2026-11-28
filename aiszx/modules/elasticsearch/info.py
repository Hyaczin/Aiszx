"""elasticsearch.info: does Elasticsearch answer without credentials? (two read-only GET requests)

``GET /`` returns the cluster name and version; ``GET /_cat/indices`` lists index names, document counts
and sizes. No document is read and nothing is written. An HTTP 401 means authentication is enforced.
"""

from __future__ import annotations

import json

from aiszx.modules import _svc
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


def parse_cat_indices(text: str) -> list[dict]:
    """`_cat/indices?v` table: header line, then one index per line."""
    lines = [ln.split() for ln in text.splitlines() if ln.strip()]
    if not lines or "index" not in lines[0]:
        return []
    header = lines[0]
    return [dict(zip(header, row)) for row in lines[1:] if len(row) == len(header)]


class ElasticsearchInfo(Module):
    meta = ModuleMeta(
        id="elasticsearch.info",
        version="1",
        description="Elasticsearch cluster info and index list without credentials (GET / and /_cat/indices)",
        stage=Stage.ENUMERATION,
        safety=Safety.ACTIVE_SAFE,
        timeout_seconds=60,
        tools=(ToolRequirement("curl"),),
        categories=("elasticsearch",),
        retry=RetryPolicy(max_attempts=2, backoff_seconds=5),
        config_defaults={"timeout": 10},
    )

    def plan(self, ctx: PlanContext) -> list[WorkUnit]:
        units = []
        for s in _svc.services_in(ctx, ["elasticsearch"], "tcp"):
            scheme = "https" if "https" in s.categories or (s.tunnel or "") == "ssl" else "http"
            units.append(WorkUnit(self.meta.id, s.key, {**_svc.service_inputs(ctx, s), "scheme": scheme}))
        return units

    def build_commands(self, unit: WorkUnit, ctx: RunContext) -> list[Command]:
        i = unit.inputs
        t = str(int(ctx.options["timeout"]))
        cmds = []
        for label, path in (("root", "/"), ("indices", "/_cat/indices?v&s=index")):
            url = web.build_url(i["scheme"], i["address"], int(i["port"]), path)
            cmds.append(Command(label, ["-sS", "-k", "--max-time", t, "--max-filesize", "2000000",
                                        "-o", f"{label}.body", "-w", "%{http_code}", url],
                                tool="curl", targets=[i["address"]], ok_exit_codes=tuple(range(0, 100))))
        return cmds

    def parse(self, unit: WorkUnit, results, ctx: RunContext) -> ModuleResult:
        i = unit.inputs
        res = ModuleResult(evidence_descriptions={"root.body": "Elasticsearch GET / response",
                                                  "indices.body": "Elasticsearch _cat/indices response"})

        def status(label: str) -> int | None:
            code = _svc.result_text(results, label).strip().split("\n")[0].strip()
            return int(code) if code.isdigit() and code != "000" else None

        root_status, idx_status = status("root"), status("indices")
        try:
            root = json.loads(_svc.read(ctx, "root.body"))
        except ValueError:
            root = {}
        root = root if isinstance(root, dict) else {}
        version = (root.get("version") or {}).get("number") if isinstance(root.get("version"), dict) else None
        indices = parse_cat_indices(_svc.read(ctx, "indices.body")) if idx_status == 200 else []
        open_access = root_status == 200 and ("cluster_name" in root or version is not None)
        res.artifacts = {"root_status": root_status, "indices_status": idx_status, "cluster_name": root.get("cluster_name"),
                         "version": version, "indices": [{k: x.get(k) for k in ("index", "health", "docs.count",
                                                                               "store.size")} for x in indices[:200]],
                         "index_count": len(indices)}
        url = web.build_url(i["scheme"], i["address"], int(i["port"]))
        if open_access:
            res.observations.append({"key": "elasticsearch.unauthenticated", "url": url,
                                     "value": {"cluster_name": root.get("cluster_name"), "version": version,
                                               "indices": len(indices)}})
        if root_status == 401:
            res.summary = "authentication required (401)"
        elif open_access:
            res.summary = (f"no authentication: cluster {root.get('cluster_name')!r}, version {version or '?'}, "
                           f"{len(indices)} index(es)")
        else:
            res.summary = f"no Elasticsearch answer recognised (HTTP {root_status or 'none'})"
            res.limitations.append("GET / did not return Elasticsearch cluster information")
        return res
