"""Report data model: everything known about one target, assembled from the database and the run
directories, in the 15 sections of the specification. Renderers only format this model.

* **Consolidated view.** Like ``assess``, the model uses the latest completed result of every module
  unit across all of the target's runs, the latest port scan per protocol, the latest service
  identification and the latest web enumeration. Each section names the run(s) its data came from.
* **Evidence references.** Paths are relative to the target directory (``runs/<run>/...``) so the
  same model can be rendered into any directory below the target; renderers turn them into links.
* **Redaction.** The finished model passes through :class:`~aiszx.reporting.redact.Redactor`;
  protected (sensitive) evidence is listed without its path.
* **Verified vs hypothesis.** Findings are grouped by classification; unverified hypotheses are
  always labelled as such and never mixed with confirmed observations.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from aiszx import __version__
from aiszx.assessment.knowledge import gather
from aiszx.assessment.model import (CLASSIFICATIONS, CONFIDENCES, CONFIRMED, FALSE_POSITIVE, HYPOTHESIS, MANUAL,
                                    POTENTIAL, SCALE_HELP, SEVERITIES, priority)
from aiszx.classify.classifier import Classifier
from aiszx.core.timeutil import iso
from aiszx.recon.store import ReconStore
from aiszx.reporting.compare import PORT_MODULES, Comparator
from aiszx.reporting.redact import Redactor
from aiszx.reporting.settings import ReportSettings

SCHEMA_VERSION = 1
SECTIONS = [
    ("engagement", "Engagement information"),
    ("scope", "Scope and exclusions"),
    ("summary", "Executive summary"),
    ("target", "Target inventory"),
    ("hosts", "Host discovery"),
    ("ports", "Open-port inventory"),
    ("services", "Service identification"),
    ("enumeration", "Service-specific enumeration"),
    ("web", "Web application inventory"),
    ("evidence", "Evidence index"),
    ("findings", "Potential findings"),
    ("scales", "Confidence and severity"),
    ("attack_surface", "Attack surface assessment"),
    ("investigation", "Recommended manual investigation"),
    ("limitations", "Limitations and incomplete checks"),
]
CLASSIFICATION_GROUPS = [
    (CONFIRMED, "Confirmed observations", "Directly observed facts. Verified by the tool output referenced."),
    (POTENTIAL, "Potential vulnerabilities", "Configurations known to enable attacks; impact depends on context."),
    (MANUAL, "Requires manual validation", "Plausible issues that a person must validate before relying on them."),
    (HYPOTHESIS, "Unverified hypotheses", "Inferred (for example from a version number). NOT verified; "
                                          "treat as leads, not as findings."),
]
STANDARD_LIMITATIONS = [
    "Testing was automated, unauthenticated and non-exploitative: no credential attacks, exploitation, "
    "destructive actions or post-exploitation were performed. Absence of a finding is not evidence of absence.",
    "Service and version identification relies on banners and fingerprints, which can be wrong, hidden or "
    "deliberately misleading. Distribution packages often backport fixes without changing version numbers.",
    "Results reflect the target at the time of each run listed in the target inventory.",
]
ENUM_EXCLUDED_PREFIXES = ("recon.", "core.")


def _rel(path: Path, base: Path) -> str:
    try:
        return path.relative_to(base).as_posix()
    except ValueError:
        return path.as_posix()


class ReportBuilder:
    def __init__(self, app, settings: ReportSettings) -> None:
        self.app = app
        self.db = app.db
        self.settings = settings
        self.data_dir: Path = app.config.data_dir

    # -- helpers ---------------------------------------------------------------
    def _secret_literals(self, eng_slug: str) -> list[str]:
        """Values of module options declared secret (e.g. SNMP communities) so they are masked everywhere."""
        try:
            from aiszx.orchestrator.settings import load_settings

            settings = load_settings(user_config_dir=self.app.config.user_config_dir,
                                     engagement_dir=self.app.layout.engagement_dir(eng_slug))
            out: list[str] = []
            for mid, module in self.app.module_registry().modules.items():
                opts = (settings.modules.get(mid) or {}).get("options") or {}
                for name in module.meta.secret_options:
                    value = opts.get(name)
                    out += value if isinstance(value, list) else [value] if value else []
            return [str(v) for v in out]
        except Exception:  # never let configuration problems block a report; patterns still apply
            return []

    def _target_rel(self, workspace_path: str, rel: str) -> str:
        return _rel(self.data_dir / workspace_path / rel, self.target_dir)

    def _useful(self, workspace_path: str, files: list[str]) -> list[str]:
        """Evidence files worth citing: existing, non-empty, not command-line logs (the index lists all)."""
        out = []
        for f in files:
            if f.endswith(".cmd.txt"):
                continue
            try:
                if (self.data_dir / workspace_path / f).stat().st_size == 0:
                    continue
            except OSError:
                continue
            out.append(self._target_rel(workspace_path, f))
        return out

    # -- build -----------------------------------------------------------------
    def build(self, engagement_slug: str, target_raw: str) -> dict[str, Any]:
        eng = self.app.engagements().get(engagement_slug)
        target = self.app.targets().get(eng, target_raw)
        self.eng, self.target = eng, target
        self.target_dir = self.app.layout.target_dir(eng.slug, target.slug)
        self.k = gather(self.db, self.data_dir, target.id, target.canonical)
        # re-apply the current service_map (as planning does), so older scans get today's categories
        self.k.services = Classifier.load(user_config_dir=self.app.config.user_config_dir).apply(self.k.services)
        self.runs = {r["run_id"]: r for r in self.db.query(
            "SELECT * FROM executions WHERE target_id = ? ORDER BY started_at, run_id", (target.id,))}
        self.modules_meta = {r["id"]: r for r in self.db.query("SELECT * FROM modules")}
        self._load_units()
        self.limitations: list[str] = []

        model: dict[str, Any] = {"schema_version": SCHEMA_VERSION}
        model["engagement"] = self.s_engagement()
        model["scope"] = self.s_scope()
        model["target"] = self.s_target()
        model["hosts"] = self.s_hosts()
        model["ports"] = self.s_ports()
        model["services"] = self.s_services()
        model["enumeration"] = self.s_enumeration()
        model["web"] = self.s_web()
        model["evidence"] = self.s_evidence()
        model["findings"] = self.s_findings()
        model["scales"] = self.s_scales(model["findings"])
        model["attack_surface"] = self.s_attack_surface(model["findings"])
        model["investigation"] = self.s_investigation(model["findings"])
        model["summary"] = self.s_summary(model)
        model["limitations"] = self.s_limitations(model)

        redactor = Redactor(extra_patterns=self.settings.extra_patterns,
                            extra_secret_keys=self.settings.extra_secret_keys,
                            literals=self._secret_literals(eng.slug))
        ordered = {"schema_version": SCHEMA_VERSION}
        ordered.update({key: redactor.value(model[key]) for key, _ in SECTIONS})
        if redactor.count:
            ordered["limitations"]["entries"].append(
                f"{redactor.count} value(s) that looked like credentials, tokens, keys or hashes were redacted from this "
                "report. The referenced evidence files are unchanged; handle them as sensitive.")
        ordered["meta"] = {
            "generated_at": iso(), "framework_version": __version__, "target": target.canonical,
            "engagement": eng.slug, "operator": self.app.actor, "redactions": redactor.count,
            "sections": [{"key": k, "number": n, "title": t} for n, (k, t) in enumerate(SECTIONS, 1)],
            "paths_relative_to": "target directory", "target_directory": _rel(self.target_dir, self.data_dir),
        }
        return ordered

    def _load_units(self) -> None:
        rows = self.db.query(
            "SELECT u.*, e.run_id, e.workspace_path FROM module_executions u JOIN executions e ON e.id = u.execution_id"
            " WHERE e.target_id = ? ORDER BY e.started_at DESC, e.run_id DESC, u.ended_at DESC", (self.target.id,))
        self.latest_any: dict[tuple[str, str], Any] = {}
        self.latest_done: dict[tuple[str, str], Any] = {}
        for r in rows:
            key = (r["module_id"], r["unit_key"])
            self.latest_any.setdefault(key, r)
            if r["state"] == "COMPLETED" and r["output_dir"]:
                self.latest_done.setdefault(key, r)

    # -- 1-2 -------------------------------------------------------------------
    def s_engagement(self) -> dict[str, Any]:
        e = self.eng.to_dict()
        e.pop("id", None)
        return e

    def s_scope(self) -> dict[str, Any]:
        rules = [r.to_dict() for r in self.app.scope().rules(self.eng)]
        decision = self.app.targets().decide(self.target).to_dict()
        return {"includes": [r for r in rules if r["action"] == "include"],
                "excludes": [r for r in rules if r["action"] == "exclude"],
                "decision": decision,
                "note": "Exclusions always win over inclusions. Every command was checked against these rules at the "
                        "point of execution (scope guard)."}

    # -- 4-7 -------------------------------------------------------------------
    def s_target(self) -> dict[str, Any]:
        t = self.target
        hostnames: list[str] = []
        os_guesses: list[str] = []
        for r in self.db.query("SELECT hostnames_json, os_json FROM discovered_hosts WHERE target_id = ?"
                               " ORDER BY discovered_at DESC", (t.id,)):
            for h in json.loads(r["hostnames_json"] or "[]"):
                name = h.get("name") if isinstance(h, dict) else h
                if name and name not in hostnames:
                    hostnames.append(name)
            for o in json.loads(r["os_json"] or "[]"):
                label = o.get("name") if isinstance(o, dict) else o
                if label and label not in os_guesses:
                    os_guesses.append(str(label) + (f" ({o['accuracy']}%)" if isinstance(o, dict) and o.get("accuracy") else ""))
        runs = [{"run_id": r["run_id"], "command": r["command"], "profile": r["profile"], "status": r["status"],
                 "started_at": r["started_at"], "ended_at": r["ended_at"],
                 "summary": json.loads(r["summary_json"] or "{}")} for r in reversed(list(self.runs.values()))]
        return {"canonical": t.canonical, "kind": t.kind, "status": t.status, "source": t.source, "notes": t.notes,
                "created_at": t.created_at, "addresses": [a.to_dict() for a in t.addresses],
                "hostnames": hostnames, "os_guesses": os_guesses[:5], "runs": runs,
                "runs_used": self.k.runs_used}

    def s_hosts(self) -> dict[str, Any]:
        row = self.db.query_one("SELECT h.execution_id, e.run_id FROM discovered_hosts h JOIN executions e"
                                " ON e.id = h.execution_id WHERE h.target_id = ? ORDER BY e.started_at DESC,"
                                " e.run_id DESC LIMIT 1", (self.target.id,))
        if row is None:
            return {"run_id": None, "entries": []}
        items = []
        for h in ReconStore(self.db).hosts_for_execution(row["execution_id"]):
            names = [x.get("name") if isinstance(x, dict) else x for x in json.loads(h["hostnames_json"] or "[]")]
            os_ = [o.get("name") if isinstance(o, dict) else o for o in json.loads(h["os_json"] or "[]")]
            items.append({"address": h["address"], "status": h["status"], "method": h["method"], "reason": h["reason"],
                          "hostnames": [n for n in names if n], "os": [o for o in os_ if o][:3]})
        return {"run_id": row["run_id"], "entries": items}

    def s_ports(self) -> dict[str, Any]:
        services = {s.key: s for s in self.k.services}
        items, coverage = [], []
        for proto, module in PORT_MODULES.items():
            row = self.db.query_one(
                "SELECT e.id, e.run_id, e.profile FROM executions e JOIN module_executions u ON u.execution_id = e.id"
                " WHERE e.target_id = ? AND u.module_id = ? AND u.state = 'COMPLETED'"
                " ORDER BY e.started_at DESC, e.run_id DESC LIMIT 1", (self.target.id, module))
            if row is None:
                coverage.append({"protocol": proto, "scanned": False, "run_id": None, "profile": None})
                continue
            coverage.append({"protocol": proto, "scanned": True, "run_id": row["run_id"], "profile": row["profile"]})
            seen: dict[int, Any] = {}
            for p in self.db.query("SELECT port, state, reason FROM discovered_ports WHERE execution_id = ?"
                                   " AND protocol = ? ORDER BY port", (row["id"], proto)):
                if seen.get(p["port"]) is None or p["state"] == "open":
                    seen[p["port"]] = p
            for port, p in sorted(seen.items()):
                s = services.get(f"{proto}/{port}")
                items.append({"protocol": proto, "port": port, "state": p["state"], "reason": p["reason"],
                              "uncertain": p["state"] != "open", "service": s.name if s else None,
                              "run_id": row["run_id"]})
        return {"entries": items, "coverage": coverage,
                "open": sum(1 for i in items if i["state"] == "open"),
                "uncertain": sum(1 for i in items if i["uncertain"])}

    def s_services(self) -> dict[str, Any]:
        items = []
        for s in self.k.services:
            items.append({"service": s.key, "address": s.address, "state": s.state, "name": s.name,
                          "product": s.product, "version": s.version, "extrainfo": s.extrainfo, "tunnel": s.tunnel,
                          "confidence": s.confidence, "method": s.method, "categories": s.categories,
                          "category_confidence": s.category_confidence, "cpes": s.cpes,
                          "scripts": [{"id": k, "output": v} for k, v in sorted(s.scripts.items())]})
        return {"run_id": self.k.services_run, "entries": items}

    # -- 8-10 ------------------------------------------------------------------
    def _unit_entry(self, key: tuple[str, str], row) -> dict[str, Any]:
        data = self.k.results.get(key, {})
        files = [o["path"] for o in json.loads(row["outputs_json"] or "[]")]
        latest = self.latest_any.get(key)
        newer = None
        if latest is not None and latest["id"] != row["id"]:
            newer = {"run_id": latest["run_id"], "state": latest["state"],
                     "reason": latest["error_message"] or latest["skip_reason"]}
        return {"module": key[0], "unit": key[1], "run_id": row["run_id"],
                "description": (self.modules_meta.get(key[0]) or {"description": None})["description"],
                "summary": data.get("summary") or row["summary"],
                "observations": [{"key": o.get("key"), "value": o.get("value"), "url": o.get("url")}
                                 for o in data.get("observations", [])],
                "limitations": data.get("limitations", []),
                "evidence": self._useful(row["workspace_path"], files),
                "newer_attempt": newer}

    def s_enumeration(self) -> dict[str, Any]:
        families: dict[str, list] = defaultdict(list)
        for key, row in sorted(self.latest_done.items()):
            if key[0].startswith(ENUM_EXCLUDED_PREFIXES):
                continue
            families[key[0].split(".")[0]].append(self._unit_entry(key, row))
        return {"families": [{"family": f, "units": u} for f, u in sorted(families.items())]}

    def s_web(self) -> dict[str, Any]:
        web = ReconStore(self.db).latest_web_execution(self.target.id)
        tech_by_ep: dict[str, list[str]] = defaultdict(list)
        for t in self.k.technologies:
            tech_by_ep[t["endpoint_url"]].append(t["name"] + (f" {t['version']}" if t.get("version") else ""))
        endpoints = [{"url": e["url"], "service": e["service_key"], "host": e["host"], "address": e["address"],
                      "status_code": e["status_code"], "title": e["title"], "server": e["server"],
                      "location": e["location"], "content_type": e["content_type"],
                      "content_length": e["content_length"], "headers": json.loads(e["headers_json"] or "{}"),
                      "tls": json.loads(e["tls_json"] or "{}"), "technologies": tech_by_ep.get(e["url"], [])}
                     for e in self.k.endpoints]
        resources = [{"endpoint": r["endpoint_url"], "url": r["url"], "path": r["path"], "status_code": r["status_code"],
                      "content_length": r["content_length"], "redirect": r["redirect"], "source": r["source_tool"]}
                     for r in self.k.resources]
        technologies = [{"endpoint": t["endpoint_url"], "name": t["name"], "version": t["version"],
                         "detail": t["detail"], "source": t["source_tool"], "confidence": t["confidence"]}
                        for t in self.k.technologies]
        shots = []
        for key, row in self.latest_done.items():
            if key[0] != "http.screenshots":
                continue
            for ev in self.db.query("SELECT rel_path, description, sensitive FROM evidence WHERE module_execution_id = ?"
                                    " AND kind = 'screenshot' ORDER BY rel_path", (row["id"],)):
                if not ev["sensitive"]:
                    shots.append({"path": self._target_rel(row["workspace_path"], ev["rel_path"]),
                                  "description": ev["description"]})
        return {"run_id": web[1] if web else None, "endpoints": endpoints, "technologies": technologies,
                "resources": resources, "screenshots": shots}

    def s_evidence(self) -> dict[str, Any]:
        unit_ids = {row["id"]: key for key, row in self.latest_done.items()}
        items, withheld = [], 0
        rows = []
        if unit_ids:
            marks = ",".join("?" * len(unit_ids))
            rows = self.db.query(f"SELECT v.*, e.run_id, e.workspace_path FROM evidence v JOIN executions e"
                                 f" ON e.id = v.execution_id WHERE v.module_execution_id IN ({marks})"
                                 " ORDER BY e.started_at, v.rel_path", list(unit_ids))
        assess = self.db.query_one("SELECT id FROM executions WHERE target_id = ? AND command = 'assess' AND status ="
                                   " 'COMPLETED' ORDER BY started_at DESC, run_id DESC LIMIT 1", (self.target.id,))
        if assess:
            rows += self.db.query("SELECT v.*, e.run_id, e.workspace_path FROM evidence v JOIN executions e"
                                  " ON e.id = v.execution_id WHERE v.execution_id = ? ORDER BY v.rel_path", (assess["id"],))
        for v in rows:
            key = unit_ids.get(v["module_execution_id"])
            entry = {"id": v["id"], "run_id": v["run_id"], "module": key[0] if key else "assessment",
                     "unit": key[1] if key else None, "kind": v["kind"], "sha256": v["sha256"],
                     "size": v["size_bytes"], "description": v["description"], "protected": bool(v["sensitive"])}
            if v["sensitive"]:
                withheld += 1
                entry["path"] = None
            else:
                entry["path"] = self._target_rel(v["workspace_path"], v["rel_path"])
            items.append(entry)
        return {"entries": items, "withheld": withheld,
                "note": "SHA-256 hashes were recorded when each file was written. Protected evidence is listed "
                        "without its location; access it from the workspace directly."}

    # -- 11-14 -----------------------------------------------------------------
    def _finding(self, r) -> dict[str, Any]:
        cls = r["analyst_classification"] or r["classification"]
        refs = []
        for ref in json.loads(r["evidence_json"] or "[]"):
            run = self.runs.get(ref.get("run_id"))
            refs.append({**ref, "files": self._useful(run["workspace_path"], ref.get("files", [])) if run else []})
        return {"id": r["id"], "rule_id": r["rule_id"], "title": r["title"], "severity": r["severity"],
                "confidence": r["confidence"], "classification": cls, "tool_classification": r["classification"],
                "analyst_classification": r["analyst_classification"], "analyst_notes": r["analyst_notes"],
                "status": r["status"], "service": r["service_key"], "location": r["location"],
                "where": r["service_key"] or r["location"], "description": r["description"], "impact": r["impact"],
                "recommendation": r["recommendation"], "next_steps": json.loads(r["next_steps_json"] or "[]"),
                "evidence": refs, "details": json.loads(r["details_json"] or "{}"),
                "first_seen_at": r["first_seen_at"], "last_seen_at": r["last_seen_at"],
                "priority": priority(r["severity"], r["confidence"], cls)}

    def s_findings(self) -> dict[str, Any]:
        rows = self.db.query("SELECT * FROM findings WHERE target_id = ?", (self.target.id,))
        all_f = sorted((self._finding(r) for r in rows), key=lambda f: (-f["priority"], f["id"]))
        open_f = [f for f in all_f if f["status"] == "open" and f["classification"] != FALSE_POSITIVE]
        hidden = 0
        groups = []
        for cls, label, explanation in CLASSIFICATION_GROUPS:
            items = [f for f in open_f if f["classification"] == cls]
            if cls == HYPOTHESIS and not self.settings.include_hypotheses:
                hidden, items = len(items), []
            groups.append({"classification": cls, "label": label, "explanation": explanation, "entries": items})
        last = self.db.query_one("SELECT run_id, started_at FROM executions WHERE target_id = ? AND command = 'assess'"
                                 " AND status = 'COMPLETED' ORDER BY started_at DESC, run_id DESC LIMIT 1",
                                 (self.target.id,))
        return {"groups": groups, "open_count": len(open_f) - hidden, "hypotheses_hidden": hidden,
                "false_positives": [f for f in all_f if f["classification"] == FALSE_POSITIVE],
                "not_reproduced": [f for f in all_f if f["status"] == "not_reproduced"
                                   and f["classification"] != FALSE_POSITIVE],
                "last_assessment": {"run_id": last["run_id"], "at": last["started_at"]} if last else None}

    @staticmethod
    def _reported(findings: dict[str, Any]) -> list[dict[str, Any]]:
        return [f for g in findings["groups"] for f in g["entries"]]

    def s_scales(self, findings: dict[str, Any]) -> dict[str, Any]:
        reported = self._reported(findings)
        matrix = {s: {c: 0 for c in CONFIDENCES} for s in SEVERITIES}
        for f in reported:
            matrix[f["severity"]][f["confidence"]] += 1
        by_cls = Counter(f["classification"] for f in reported)
        return {"severity": SCALE_HELP["severity"], "confidence": SCALE_HELP["confidence"],
                "classifications": [{"classification": c, "meaning": SCALE_HELP[c], "count": by_cls.get(c, 0)}
                                    for c in CLASSIFICATIONS],
                "matrix": [{"severity": s, **matrix[s], "total": sum(matrix[s].values())} for s in reversed(SEVERITIES)],
                "priority": "Findings are ordered by priority = severity, then confidence, then classification "
                            "(confirmed facts rise, hypotheses sink). Severity is the rule's default for the "
                            "finding type and does not model business context."}

    def s_attack_surface(self, findings: dict[str, Any]) -> dict[str, Any]:
        reported = self._reported(findings)
        ep_service = {e["url"]: e["service_key"] for e in self.k.endpoints}
        cats: dict[str, list] = defaultdict(list)
        for s in self.k.services:
            for c in (s.categories or ["other"]):
                cats[c].append(s)
        areas = []
        for cat, services in sorted(cats.items(), key=lambda kv: (kv[0] == "other", kv[0])):
            keys = {s.key for s in services}
            related = [f for f in reported if f["service"] in keys
                       or (f["location"] and ep_service.get(_endpoint_of(f["location"], ep_service)) in keys)]
            mods = sorted({mid for (mid, _u) in self.latest_any
                           if cat in json.loads((self.modules_meta.get(mid) or {"categories_json": "[]"})["categories_json"])})
            enumerated = [{"module": m, "completed": any(k[0] == m for k in self.latest_done)} for m in mods]
            worst = max((SEVERITIES.index(f["severity"]) for f in related), default=None)
            areas.append({"category": cat,
                          "services": [{"service": s.key, "banner": s.banner or s.name or ""} for s in services],
                          "enumerated_by": enumerated, "findings": [f["id"] for f in related],
                          "highest_severity": SEVERITIES[worst] if worst is not None else None,
                          "confirmed": sum(1 for f in related if f["classification"] == CONFIRMED),
                          "hypotheses": sum(1 for f in related if f["classification"] == HYPOTHESIS)})
        areas.sort(key=lambda a: (-(SEVERITIES.index(a["highest_severity"]) if a["highest_severity"] else -1),
                                  a["category"]))
        return {"areas": areas,
                "note": "Exposure per service category: what is reachable, which modules looked at it, and the "
                        "findings attached to it. Categories without enumeration modules were only fingerprinted."}

    def s_investigation(self, findings: dict[str, Any]) -> dict[str, Any]:
        seen, steps = set(), []
        for f in self._reported(findings):
            for step in f["next_steps"]:
                if step not in seen:
                    seen.add(step)
                    steps.append({"priority": f["priority"], "finding": f["id"], "severity": f["severity"],
                                  "classification": f["classification"], "step": step, "why": f["title"]})
        return {"steps": steps,
                "note": "Manual follow-up only, within the authorised scope and rules of engagement. Aiszx does not "
                        "perform these actions automatically."}

    # -- 3 + 15 ----------------------------------------------------------------
    def _staleness(self, findings: dict[str, Any]) -> str | None:
        last = findings["last_assessment"]
        if last is None:
            return "No assessment has been run yet, so no findings are reported. Run `assess` and report again."
        # newer = a unit that finished after the assessment started, or belongs to a run created after it
        # (insertion order breaks ties within the same second)
        newer = self.db.query_one(
            "SELECT 1 FROM module_executions u JOIN executions e ON e.id = u.execution_id WHERE e.target_id = ?"
            " AND u.state = 'COMPLETED' AND (u.ended_at > ? OR e.rowid > (SELECT rowid FROM executions"
            " WHERE target_id = ? AND run_id = ?)) LIMIT 1", (self.target.id, last["at"], self.target.id, last["run_id"]))
        if newer:
            return (f"Module results newer than the last assessment ({last['run_id']}) exist; findings may be out of "
                    "date. Run `assess` and report again.")
        return None

    def s_summary(self, m: dict[str, Any]) -> dict[str, Any]:
        reported = self._reported(m["findings"])
        sev = Counter(f["severity"] for f in reported)
        cls = Counter(f["classification"] for f in reported)
        ports = m["ports"]
        counts = {
            "open_tcp": sum(1 for p in ports["entries"] if p["protocol"] == "tcp" and p["state"] == "open"),
            "open_udp": sum(1 for p in ports["entries"] if p["protocol"] == "udp" and p["state"] == "open"),
            "uncertain_udp": sum(1 for p in ports["entries"] if p["protocol"] == "udp" and p["uncertain"]),
            "services": len(m["services"]["entries"]), "web_endpoints": len(m["web"]["endpoints"]),
            "web_resources": len(m["web"]["resources"]), "findings": len(reported),
            "by_severity": {s: sev.get(s, 0) for s in reversed(SEVERITIES)},
            "by_classification": {c: cls.get(c, 0) for c, _l, _e in CLASSIFICATION_GROUPS},
        }
        lines = [f"{self.target.canonical} exposes {counts['open_tcp']} open TCP port(s)"
                 + (f" and {counts['open_udp']} open UDP port(s)" if counts["open_udp"] else "")
                 + (f" ({counts['uncertain_udp']} more UDP port(s) open|filtered, unconfirmed)"
                    if counts["uncertain_udp"] else "")
                 + f"; {counts['services']} service(s) identified"
                 + (f", {counts['web_endpoints']} web endpoint(s)" if counts["web_endpoints"] else "") + "."]
        if reported:
            sev_text = ", ".join(f"{n} {s}" for s, n in counts["by_severity"].items() if n)
            lines.append(f"{len(reported)} open finding(s): {sev_text}. Of these, {cls.get(CONFIRMED, 0)} are confirmed "
                         f"observations, {cls.get(POTENTIAL, 0)} potential vulnerabilities, {cls.get(MANUAL, 0)} require "
                         f"manual validation and {cls.get(HYPOTHESIS, 0)} are unverified hypotheses.")
        elif m["findings"]["last_assessment"]:
            lines.append("The last assessment produced no open findings.")
        try:
            changes = Comparator(self.db, self.target.id).compare()
        except Exception as exc:  # comparison is informative only
            changes = {"summary": {"lines": [], "compared": [], "no_changes": False}, "error": str(exc)}
        stale = self._staleness(m["findings"])
        top = [{"id": f["id"], "title": f["title"], "severity": f["severity"], "confidence": f["confidence"],
                "classification": f["classification"], "where": f["where"]} for f in reported[:5]]
        return {"lines": lines, "counts": counts, "top_findings": top, "stale_warning": stale,
                "changes": changes["summary"]}

    def s_limitations(self, m: dict[str, Any]) -> dict[str, Any]:
        items = list(STANDARD_LIMITATIONS)
        stale = m["summary"]["stale_warning"]
        if stale:
            items.append(stale)
        for cov in m["ports"]["coverage"]:
            if not cov["scanned"]:
                items.append(f"{cov['protocol'].upper()} ports were not scanned (no completed {PORT_MODULES[cov['protocol']]} "
                             "unit); the port inventory covers the other protocol only.")
        if m["ports"]["uncertain"]:
            items.append(f"{m['ports']['uncertain']} port(s) are open|filtered: no response was received, so they may be "
                         "open or filtered. They are not counted as open.")
        if any("http" in s["categories"] or "https" in s["categories"] for s in m["services"]["entries"]) \
                and not m["web"]["endpoints"]:
            items.append("Web services were identified but not enumerated (run `enumerate TARGET -m http`).")
        if m["findings"]["hypotheses_hidden"]:
            items.append(f"{m['findings']['hypotheses_hidden']} unverified hypothesis/hypotheses hidden by configuration "
                         "(reporting.include_hypotheses: false).")
        if m["evidence"]["withheld"]:
            items.append(f"{m['evidence']['withheld']} protected evidence file(s) are listed without their location.")
        incomplete = []
        for key, row in sorted(self.latest_any.items()):
            if row["state"] == "COMPLETED":
                continue
            reason = row["error_message"] or row["skip_reason"] or row["state"].lower()
            older = self.latest_done.get(key)
            incomplete.append({"module": key[0], "unit": key[1], "state": row["state"], "run_id": row["run_id"],
                               "reason": reason, "older_result_used": older["run_id"] if older else None})
        unit_limits = []
        for key, data in sorted(self.k.results.items()):
            for text in data.get("limitations", []) or []:
                unit_limits.append({"module": key[0], "unit": key[1], "text": text})
        last = m["findings"]["last_assessment"]
        if last and last["run_id"] in self.runs:
            path = self.data_dir / self.runs[last["run_id"]]["workspace_path"] / "findings" / "findings.json"
            try:
                for note in json.loads(path.read_text(encoding="utf-8")).get("limitations", []):
                    items.append(f"Assessment: {note}")
            except (OSError, ValueError):
                items.append(f"Assessment output of {last['run_id']} could not be read ({path.name}).")
        return {"entries": items, "incomplete_units": incomplete, "module_limitations": unit_limits}


def _endpoint_of(location: str, endpoints: dict[str, Any]) -> str | None:
    """Endpoint URL that a finding location (endpoint or resource URL) belongs to."""
    best = None
    for url in endpoints:
        if location.startswith(url) and (best is None or len(url) > len(best)):
            best = url
    return best
