"""Run-to-run comparison of one target.

Different kinds of data come from different runs (a ``recon`` run has ports and services, an
``enumerate`` run has web data, an ``assess`` run has findings), so the comparison is made per
category, each between the two runs that hold that kind of data:

* **ports**      newly open, no longer open, state changes. A protocol is only compared when both
                 runs actually scanned it (completed ``recon.tcp_ports`` / ``recon.udp`` unit), so an
                 unscanned protocol is never reported as "closed".
* **services**   new, removed, and changed name/product/version/extra info/tunnel per service key.
* **web**        endpoints (new/removed/status, title or server changes), technologies (new/removed/
                 version changes) and discovered resources (new/no longer found). Technologies and
                 resources are only compared when both runs ran the module that produces them.
* **findings**   between two assessments: new, no longer reproduced, and severity/confidence/
                 classification changes. Nothing is deleted when a finding stops reproducing.

``--latest`` picks the two most recent runs per category; ``--from/--to`` pins the runs, and a
category is "not comparable" when either pinned run has no data of that kind.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from aiszx.db.connection import Database

PORT_MODULES = {"tcp": "recon.tcp_ports", "udp": "recon.udp"}
TECH_MODULES = ("http.whatweb",)
RESOURCE_MODULE = "http.content_discovery"
SERVICE_FIELDS = ("name", "product", "version", "extrainfo", "tunnel")
ENDPOINT_FIELDS = ("status_code", "title", "server", "location")
OPEN_STATES = ("open", "open|filtered")


@dataclass(frozen=True)
class RunRef:
    id: str
    run_id: str
    command: str
    profile: str
    started_at: str

    def to_dict(self) -> dict[str, Any]:
        return {"run_id": self.run_id, "command": self.command, "profile": self.profile, "started_at": self.started_at}


class Comparator:
    def __init__(self, db: Database, target_id: str) -> None:
        self.db = db
        self.target_id = target_id

    # -- run selection -------------------------------------------------------
    def _runs_with(self, table: str, extra: str = "") -> list[RunRef]:
        rows = self.db.query(
            f"SELECT e.id, e.run_id, e.command, e.profile, e.started_at FROM executions e WHERE e.target_id = ? "
            f"AND EXISTS (SELECT 1 FROM {table} t WHERE t.execution_id = e.id) {extra} "
            "ORDER BY e.started_at DESC, e.run_id DESC", (self.target_id,))
        return [RunRef(r["id"], r["run_id"], r["command"], r["profile"], r["started_at"]) for r in rows]

    def _assessments(self) -> list[RunRef]:
        rows = self.db.query(
            "SELECT id, run_id, command, profile, started_at FROM executions WHERE target_id = ? AND command = 'assess'"
            " AND status = 'COMPLETED' ORDER BY started_at DESC, run_id DESC", (self.target_id,))
        return [RunRef(r["id"], r["run_id"], r["command"], r["profile"], r["started_at"]) for r in rows]

    def _ref(self, run_id: str) -> RunRef | None:
        r = self.db.query_one("SELECT id, run_id, command, profile, started_at FROM executions WHERE target_id = ?"
                              " AND run_id = ?", (self.target_id, run_id))
        return RunRef(r["id"], r["run_id"], r["command"], r["profile"], r["started_at"]) if r else None

    def _pick(self, candidates: list[RunRef], what: str, a: RunRef | None, b: RunRef | None
              ) -> tuple[RunRef | None, RunRef | None, str | None]:
        if a is None and b is None:
            if len(candidates) < 2:
                return None, None, (f"only {len(candidates)} run(s) with {what}; nothing to compare yet")
            return candidates[1], candidates[0], None
        ids = {c.id for c in candidates}
        missing = [r.run_id for r in (a, b) if r is not None and r.id not in ids]
        if missing:
            return None, None, f"run(s) {', '.join(missing)} have no {what}"
        return a, b, None

    def _completed_modules(self, execution_id: str) -> set[str]:
        return {r["module_id"] for r in self.db.query(
            "SELECT DISTINCT module_id FROM module_executions WHERE execution_id = ? AND state = 'COMPLETED'",
            (execution_id,))}

    # -- categories ----------------------------------------------------------
    def _ports(self, eid: str) -> dict[tuple[str, int], str]:
        out: dict[tuple[str, int], str] = {}
        for r in self.db.query("SELECT protocol, port, state FROM discovered_ports WHERE execution_id = ?", (eid,)):
            key = (r["protocol"], r["port"])
            if out.get(key) != "open":  # 'open' wins over 'open|filtered' when units disagree
                out[key] = r["state"]
        return out

    def compare_ports(self, a: RunRef, b: RunRef) -> dict[str, Any]:
        pa, pb = self._ports(a.id), self._ports(b.id)
        ma, mb = self._completed_modules(a.id), self._completed_modules(b.id)
        compared = [p for p, mod in PORT_MODULES.items() if mod in ma and mod in mb]
        skipped = [p for p, mod in PORT_MODULES.items() if (mod in ma) != (mod in mb)]
        opened, closed, changed = [], [], []
        for proto in compared:
            oa = {k: v for k, v in pa.items() if k[0] == proto and v in OPEN_STATES}
            ob = {k: v for k, v in pb.items() if k[0] == proto and v in OPEN_STATES}
            opened += [{"protocol": k[0], "port": k[1], "state": ob[k]} for k in sorted(ob.keys() - oa.keys())]
            closed += [{"protocol": k[0], "port": k[1], "state": oa[k]} for k in sorted(oa.keys() - ob.keys())]
            changed += [{"protocol": k[0], "port": k[1], "before": oa[k], "after": ob[k]}
                        for k in sorted(oa.keys() & ob.keys()) if oa[k] != ob[k]]
        notes = [f"{p.upper()} was scanned in only one of the two runs; not compared" for p in skipped]
        if a.profile != b.profile:
            notes.append(f"the runs used different profiles ({a.profile} → {b.profile}); differences in port coverage "
                         "can look like ports opening or closing")
        return {"opened": opened, "closed": closed, "state_changed": changed, "protocols": compared, "notes": notes}

    def _services(self, eid: str) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for r in self.db.query("SELECT * FROM services WHERE execution_id = ? ORDER BY protocol, port", (eid,)):
            cur = out.get(r["service_key"])
            if cur is None or (bool(r["product"]), bool(r["name"])) > (bool(cur["product"]), bool(cur["name"])):
                out[r["service_key"]] = {f: r[f] for f in SERVICE_FIELDS}
        return out

    def compare_services(self, a: RunRef, b: RunRef) -> dict[str, Any]:
        sa, sb = self._services(a.id), self._services(b.id)
        changed = []
        for key in sorted(sa.keys() & sb.keys(), key=_svc_sort):
            diffs = {f: {"before": sa[key][f], "after": sb[key][f]} for f in SERVICE_FIELDS if sa[key][f] != sb[key][f]}
            if diffs:
                changed.append({"service": key, "changes": diffs,
                                "version_changed": "version" in diffs or "product" in diffs})
        return {"new": [{"service": k, **sb[k]} for k in sorted(sb.keys() - sa.keys(), key=_svc_sort)],
                "removed": [{"service": k, **sa[k]} for k in sorted(sa.keys() - sb.keys(), key=_svc_sort)],
                "changed": changed}

    def compare_web(self, a: RunRef, b: RunRef) -> dict[str, Any]:
        q = self.db.query
        ea = {r["url"]: r for r in q("SELECT * FROM web_endpoints WHERE execution_id = ?", (a.id,))}
        eb = {r["url"]: r for r in q("SELECT * FROM web_endpoints WHERE execution_id = ?", (b.id,))}
        out: dict[str, Any] = {
            "endpoints_new": sorted(eb.keys() - ea.keys()),
            "endpoints_removed": sorted(ea.keys() - eb.keys()),
            "endpoints_changed": [
                {"url": u, "changes": {f: {"before": ea[u][f], "after": eb[u][f]} for f in ENDPOINT_FIELDS
                                       if ea[u][f] != eb[u][f]}}
                for u in sorted(ea.keys() & eb.keys()) if any(ea[u][f] != eb[u][f] for f in ENDPOINT_FIELDS)],
            "notes": [],
        }
        ma, mb = self._completed_modules(a.id), self._completed_modules(b.id)
        if any(m in ma for m in TECH_MODULES) and any(m in mb for m in TECH_MODULES):
            ta = _tech(q("SELECT endpoint_url, name, version FROM technologies WHERE execution_id = ?", (a.id,)))
            tb = _tech(q("SELECT endpoint_url, name, version FROM technologies WHERE execution_id = ?", (b.id,)))
            out["technologies_new"] = [{"endpoint": k[0], "name": k[1], "version": tb[k]} for k in sorted(tb.keys() - ta.keys())]
            out["technologies_removed"] = [{"endpoint": k[0], "name": k[1], "version": ta[k]}
                                           for k in sorted(ta.keys() - tb.keys())]
            out["technologies_changed"] = [{"endpoint": k[0], "name": k[1], "before": ta[k], "after": tb[k]}
                                           for k in sorted(ta.keys() & tb.keys()) if ta[k] != tb[k]]
        else:
            out["notes"].append("technology fingerprinting (whatweb) did not run in both runs; technologies not compared")
        if RESOURCE_MODULE in ma and RESOURCE_MODULE in mb:
            ra = {r["url"] for r in q("SELECT url FROM web_resources WHERE execution_id = ?", (a.id,))}
            rb = {r["url"] for r in q("SELECT url FROM web_resources WHERE execution_id = ?", (b.id,))}
            out["resources_new"] = sorted(rb - ra)
            out["resources_removed"] = sorted(ra - rb)
        else:
            out["notes"].append("content discovery did not run in both runs; discovered resources not compared")
        return out

    def compare_findings(self, a: RunRef, b: RunRef) -> dict[str, Any]:
        def snap(eid: str) -> dict[str, Any]:
            return {r["finding_id"]: r for r in self.db.query(
                "SELECT r.finding_id, r.severity, r.confidence, r.classification, f.title, f.service_key, f.location"
                " FROM assessment_results r JOIN findings f ON f.id = r.finding_id WHERE r.assessment_id = ?", (eid,))}

        fa, fb = snap(a.id), snap(b.id)

        def brief(r) -> dict[str, Any]:
            return {"id": r["finding_id"], "title": r["title"], "severity": r["severity"], "confidence": r["confidence"],
                    "classification": r["classification"], "where": r["service_key"] or r["location"]}

        changed = []
        for fid in sorted(fa.keys() & fb.keys()):
            diffs = {f: {"before": fa[fid][f], "after": fb[fid][f]} for f in ("severity", "confidence", "classification")
                     if fa[fid][f] != fb[fid][f]}
            if diffs:
                changed.append({"id": fid, "title": fb[fid]["title"], "changes": diffs})
        return {"new": [brief(fb[i]) for i in sorted(fb.keys() - fa.keys())],
                "not_reproduced": [brief(fa[i]) for i in sorted(fa.keys() - fb.keys())],
                "changed": changed}

    # -- entry point ---------------------------------------------------------
    def compare(self, from_run: str | None = None, to_run: str | None = None) -> dict[str, Any]:
        a = b = None
        if from_run or to_run:
            if not (from_run and to_run):
                raise ValueError("give both --from and --to, or neither (--latest)")
            a, b = self._ref(from_run), self._ref(to_run)
            unknown = [r for r, ref in ((from_run, a), (to_run, b)) if ref is None]
            if unknown:
                raise LookupError(f"unknown run(s): {', '.join(unknown)}")
            if a.started_at > b.started_at:
                a, b = b, a
        plan = [
            ("ports", self._runs_with("discovered_ports"), "port scan results", self.compare_ports),
            ("services", self._runs_with("services"), "service identification", self.compare_services),
            ("web", self._runs_with("web_endpoints"), "web enumeration", self.compare_web),
            ("findings", self._assessments(), "assessment", self.compare_findings),
        ]
        out: dict[str, Any] = {"mode": "explicit" if a else "latest", "categories": {}}
        for name, candidates, what, fn in plan:
            ra, rb, why = self._pick(candidates, what, a, b)
            if why:
                out["categories"][name] = {"compared": False, "reason": why}
            else:
                out["categories"][name] = {"compared": True, "from": ra.to_dict(), "to": rb.to_dict(), **fn(ra, rb)}
        out["summary"] = summarise(out)
        return out


def _svc_sort(key: str) -> tuple[str, int]:
    proto, _, port = key.partition("/")
    return proto, int(port) if port.isdigit() else 0


def _tech(rows) -> dict[tuple[str, str], str | None]:
    out: dict[tuple[str, str], str | None] = {}
    for r in rows:
        out[(r["endpoint_url"], r["name"])] = r["version"] or out.get((r["endpoint_url"], r["name"]))
    return out


SUMMARY_KEYS = [
    ("ports", "opened", "newly open port(s)"), ("ports", "closed", "port(s) no longer open"),
    ("services", "new", "new service(s)"), ("services", "removed", "removed service(s)"),
    ("services", "changed", "changed service(s)"), ("web", "endpoints_new", "new web endpoint(s)"),
    ("web", "technologies_changed", "changed web technolog(y/ies)"), ("web", "technologies_new", "new web technolog(y/ies)"),
    ("web", "resources_new", "newly discovered resource(s)"), ("findings", "new", "new finding(s)"),
    ("findings", "not_reproduced", "finding(s) no longer reproduced"),
    ("findings", "changed", "finding(s) with changed severity/confidence/classification"),
]


def summarise(result: dict[str, Any]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    lines: list[str] = []
    for cat, key, label in SUMMARY_KEYS:
        c = result["categories"].get(cat, {})
        if not c.get("compared"):
            continue
        n = len(c.get(key) or [])
        counts[f"{cat}.{key}"] = n
        if n:
            lines.append(f"{n} {label}")
    compared = [k for k, v in result["categories"].items() if v.get("compared")]
    return {"counts": counts, "lines": lines, "compared": compared,
            "no_changes": bool(compared) and not lines}


def to_json(result: dict[str, Any]) -> str:
    return json.dumps(result, indent=2, default=str)
