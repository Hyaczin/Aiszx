"""Structured records that modules return and the orchestrator persists (hosts, ports, services)."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class HostRecord:
    address: str
    status: str                       # up | down | unknown
    method: str                       # how it was determined, e.g. "nmap -sn"
    reason: str | None = None         # nmap reason, e.g. "echo-reply"
    hostnames: list[str] = field(default_factory=list)
    os: list[dict[str, Any]] = field(default_factory=list)   # [{"name", "accuracy"}]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PortRecord:
    address: str
    protocol: str                     # tcp | udp
    port: int
    state: str                        # open | open|filtered | filtered | closed
    reason: str | None = None

    @property
    def key(self) -> str:
        return f"{self.protocol}/{self.port}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ServiceRecord:
    address: str
    protocol: str
    port: int
    state: str = "open"
    name: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    tunnel: str | None = None
    cpes: list[str] = field(default_factory=list)
    confidence: int | None = None
    method: str | None = None
    categories: list[str] = field(default_factory=list)
    category_confidence: str | None = None
    scripts: dict[str, str] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.protocol}/{self.port}"

    @property
    def banner(self) -> str:
        return " ".join(p for p in (self.product, self.version, f"({self.extrainfo})" if self.extrainfo else None) if p)

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "key": self.key}

    @classmethod
    def from_row(cls, row) -> "ServiceRecord":
        return cls(
            address=row["address"], protocol=row["protocol"], port=row["port"], state=row["state"],
            name=row["name"], product=row["product"], version=row["version"], extrainfo=row["extrainfo"],
            tunnel=row["tunnel"], cpes=json.loads(row["cpe_json"] or "[]"), confidence=row["confidence"],
            method=row["detection_method"], categories=json.loads(row["categories_json"] or "[]"),
            category_confidence=row["category_confidence"], scripts=json.loads(row["scripts_json"] or "{}"),
        )
