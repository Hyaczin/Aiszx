"""Map nmap service observations to Aiszx categories (driven by config/service_map.yaml)."""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path

from aiszx.core import paths
from aiszx.core.config import ListOf, MapOf, deep_merge, load_yaml_file, validate
from aiszx.core.errors import ConfigError
from aiszx.modules.records import ServiceRecord

RULE_SCHEMA = {
    "names?": ListOf(str), "ssl_names?": ListOf(str), "plain_only?": bool, "products?": ListOf(str),
    "ports?": ListOf(int), "ports_required?": bool,
}
SCHEMA = {"version": int, "categories": MapOf(RULE_SCHEMA, r"^[a-z0-9][a-z0-9_-]{0,31}$")}
UNNAMED = {None, "", "unknown", "tcpwrapped"}


@dataclass(frozen=True)
class Rule:
    category: str
    names: tuple[str, ...] = ()
    ssl_names: tuple[str, ...] = ()
    plain_only: bool = False
    products: tuple[str, ...] = ()
    ports: tuple[int, ...] = ()
    ports_required: bool = False


@dataclass
class Classification:
    categories: list[str] = field(default_factory=list)
    confidence: str = "low"           # high | medium | low


def _match(value: str | None, patterns: tuple[str, ...]) -> bool:
    return bool(value) and any(fnmatchcase(value.lower(), p.lower()) for p in patterns)


class Classifier:
    def __init__(self, rules: list[Rule]) -> None:
        self.rules = rules

    @classmethod
    def load(cls, *, user_config_dir: Path | None = None, shipped_dir: Path | None = None) -> "Classifier":
        shipped = (shipped_dir or paths.SHIPPED_CONFIG_DIR) / "service_map.yaml"
        data = load_yaml_file(shipped)
        if user_config_dir is not None and (user_config_dir / "service_map.yaml").is_file():
            data = deep_merge(data, load_yaml_file(user_config_dir / "service_map.yaml"))
        validate(data, SCHEMA)
        rules = []
        for name, r in data["categories"].items():
            rule = Rule(name, tuple(r.get("names", ())), tuple(r.get("ssl_names", ())), r.get("plain_only", False),
                        tuple(r.get("products", ())), tuple(r.get("ports", ())), r.get("ports_required", False))
            if rule.ports_required and not rule.ports:
                raise ConfigError(f"service_map.categories.{name}: ports_required needs ports")
            rules.append(rule)
        return cls(rules)

    def classify(self, svc: ServiceRecord) -> Classification:
        name = (svc.name or "").lower() or None
        ssl = (svc.tunnel or "").lower() == "ssl"
        strong: list[str] = []
        for r in self.rules:
            hit = False
            if _match(name, r.names) and not (r.plain_only and ssl):
                hit = True
            elif ssl and _match(name, r.ssl_names):
                hit = True
            elif _match(svc.product, r.products):
                hit = True
            if hit and r.ports_required and svc.port not in r.ports:
                hit = False
            if hit:
                strong.append(r.category)
        if strong:
            probed = svc.method == "probed" and (svc.confidence or 0) >= 8
            return Classification(strong, "high" if probed else "medium")
        if name in UNNAMED or svc.method == "table":
            hinted = [r.category for r in self.rules if svc.port in r.ports and not r.ports_required]
            if hinted:
                return Classification(hinted[:1], "low")
        return Classification(["other"], "low")

    def apply(self, services: list[ServiceRecord]) -> list[ServiceRecord]:
        for svc in services:
            c = self.classify(svc)
            svc.categories, svc.category_confidence = c.categories, c.confidence
        return services
