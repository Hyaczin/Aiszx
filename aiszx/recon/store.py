"""Persistence and queries for hosts, ports and services."""

from __future__ import annotations

import json
from dataclasses import dataclass

from aiszx.core.ids import new_id
from aiszx.core.timeutil import iso
from aiszx.db.connection import Database
from aiszx.modules.base import ModuleResult
from aiszx.modules.records import HostRecord, ServiceRecord


@dataclass
class ServiceSnapshot:
    execution_id: str | None
    run_id: str | None
    services: list[ServiceRecord]


class ReconStore:
    def __init__(self, db: Database) -> None:
        self.db = db

    def delete_for_unit(self, unit_id: str) -> None:
        for table in ("services", "discovered_ports", "discovered_hosts", "web_endpoints", "web_resources",
                      "technologies"):
            self.db.execute(f"DELETE FROM {table} WHERE module_execution_id = ?", (unit_id,))

    def replace_for_unit(self, *, unit_id: str, execution_id: str, engagement_id: str, target_id: str | None,
                         result: ModuleResult) -> None:
        self.delete_for_unit(unit_id)
        now = iso()
        for h in result.hosts:
            self.insert_host(execution_id=execution_id, engagement_id=engagement_id, target_id=target_id,
                             unit_id=unit_id, host=h, now=now)
        for p in result.ports:
            self.db.execute(
                "INSERT INTO discovered_ports (id, execution_id, target_id, module_execution_id, address, protocol, port,"
                " state, reason, discovered_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT (module_execution_id, address, protocol, port) DO UPDATE SET state = excluded.state",
                (new_id(), execution_id, target_id, unit_id, p.address, p.protocol, p.port, p.state, p.reason, now))
        for s in result.services:
            self.db.execute(
                "INSERT INTO services (id, execution_id, target_id, module_execution_id, address, protocol, port,"
                " service_key, state, name, product, version, extrainfo, tunnel, cpe_json, confidence,"
                " detection_method, categories_json, category_confidence, scripts_json, discovered_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT (module_execution_id, address, service_key) DO NOTHING",
                (new_id(), execution_id, target_id, unit_id, s.address, s.protocol, s.port, s.key, s.state, s.name,
                 s.product, s.version, s.extrainfo, s.tunnel, json.dumps(s.cpes), s.confidence, s.method,
                 json.dumps(s.categories), s.category_confidence, json.dumps(s.scripts, sort_keys=True), now))
        for e in result.endpoints:
            self.db.execute(
                "INSERT INTO web_endpoints (id, execution_id, target_id, module_execution_id, service_key, url, scheme,"
                " host, port, address, status_code, title, server, location, content_type, content_length,"
                " headers_json, tls_json, discovered_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT (module_execution_id, url) DO NOTHING",
                (new_id(), execution_id, target_id, unit_id, e.service_key, e.url, e.scheme, e.host, e.port, e.address,
                 e.status, e.title, e.server, e.location, e.content_type, e.content_length,
                 json.dumps(e.headers, sort_keys=True), json.dumps(e.tls, sort_keys=True), now))
        for r in result.resources:
            self.db.execute(
                "INSERT INTO web_resources (id, execution_id, target_id, module_execution_id, endpoint_url, url, path,"
                " status_code, content_length, redirect, source_tool, discovered_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (module_execution_id, url) DO NOTHING",
                (new_id(), execution_id, target_id, unit_id, r.endpoint_url, r.url, r.path, r.status, r.length,
                 r.redirect, r.source, now))
        for t in result.technologies:
            self.db.execute(
                "INSERT INTO technologies (id, execution_id, target_id, module_execution_id, endpoint_url, name, version,"
                " detail, source_tool, confidence, discovered_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (new_id(), execution_id, target_id, unit_id, t.endpoint_url, t.name, t.version, t.detail, t.source,
                 t.confidence, now))

    def insert_host(self, *, execution_id: str, engagement_id: str, target_id: str | None, unit_id: str | None,
                    host: HostRecord, now: str | None = None, in_scope: bool = True) -> str:
        hid = new_id()
        self.db.execute(
            "INSERT INTO discovered_hosts (id, execution_id, engagement_id, target_id, module_execution_id, address,"
            " hostnames_json, status, method, reason, os_json, in_scope, discovered_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (hid, execution_id, engagement_id, target_id, unit_id, host.address, json.dumps(host.hostnames),
             host.status, host.method, host.reason, json.dumps(host.os), int(in_scope), now or iso()))
        return hid

    # -- queries ---------------------------------------------------------------
    def services_for_execution(self, execution_id: str) -> list[ServiceRecord]:
        rows = self.db.query("SELECT * FROM services WHERE execution_id = ? ORDER BY protocol, port", (execution_id,))
        return _dedupe([ServiceRecord.from_row(r) for r in rows])

    def latest_services(self, target_id: str, prefer_execution: str | None = None) -> ServiceSnapshot:
        """Services of ``prefer_execution`` if it has any, else of the most recent run that identified services."""
        if prefer_execution:
            current = self.services_for_execution(prefer_execution)
            if current:
                row = self.db.query_one("SELECT run_id FROM executions WHERE id = ?", (prefer_execution,))
                return ServiceSnapshot(prefer_execution, row["run_id"] if row else None, current)
        row = self.db.query_one(
            "SELECT e.id, e.run_id FROM executions e WHERE e.target_id = ? AND EXISTS"
            " (SELECT 1 FROM services s WHERE s.execution_id = e.id) ORDER BY e.started_at DESC, e.run_id DESC LIMIT 1",
            (target_id,))
        if row is None:
            return ServiceSnapshot(None, None, [])
        return ServiceSnapshot(row["id"], row["run_id"], self.services_for_execution(row["id"]))

    def ports_for_execution(self, execution_id: str) -> list:
        return self.db.query("SELECT * FROM discovered_ports WHERE execution_id = ? ORDER BY protocol, port",
                             (execution_id,))

    def latest_web_execution(self, target_id: str) -> tuple[str, str] | None:
        row = self.db.query_one(
            "SELECT e.id, e.run_id FROM executions e WHERE e.target_id = ? AND EXISTS"
            " (SELECT 1 FROM web_endpoints w WHERE w.execution_id = e.id) ORDER BY e.started_at DESC, e.run_id DESC LIMIT 1",
            (target_id,))
        return (row["id"], row["run_id"]) if row else None

    def web_for_execution(self, execution_id: str) -> dict[str, list]:
        q = self.db.query
        return {
            "endpoints": q("SELECT * FROM web_endpoints WHERE execution_id = ? ORDER BY port, host", (execution_id,)),
            "resources": q("SELECT * FROM web_resources WHERE execution_id = ? ORDER BY endpoint_url, path",
                           (execution_id,)),
            "technologies": q("SELECT * FROM technologies WHERE execution_id = ? ORDER BY endpoint_url, name",
                              (execution_id,)),
        }

    def hosts_for_execution(self, execution_id: str) -> list:
        return self.db.query("SELECT * FROM discovered_hosts WHERE execution_id = ? ORDER BY address", (execution_id,))


def _dedupe(services: list[ServiceRecord]) -> list[ServiceRecord]:
    """One record per address+key; prefer the most informative (named, with product) one."""
    best: dict[tuple[str, str], ServiceRecord] = {}
    for s in services:
        k = (s.address, s.key)
        cur = best.get(k)
        if cur is None or (bool(s.product), bool(s.name), s.confidence or 0) > (bool(cur.product), bool(cur.name), cur.confidence or 0):
            best[k] = s
    return sorted(best.values(), key=lambda s: (s.protocol, s.port))
