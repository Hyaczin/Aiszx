"""Module and profile configuration, layered:

    config/modules.yaml, config/profiles.yaml          (shipped defaults)
    ~/.config/aiszx/modules.yaml, profiles.yaml         (user overrides)
    <engagement dir>/overrides.yaml                     (per-engagement: keys `modules:` / `profiles:`)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from aiszx.core import paths
from aiszx.core.config import Choice, ListOf, MapOf, deep_merge, load_yaml_file, validate
from aiszx.core.errors import ConfigError, NotFoundError
from aiszx.modules.base import Module, RetryPolicy, Safety

SAFETY_NAMES = tuple(s.value for s in Safety if s is not Safety.PROHIBITED_AUTO)
_MODULE_KEY = r"^[a-z0-9]+(?:\.[a-z0-9_]+)+$"

MODULE_ENTRY = {
    "enabled?": bool,
    "timeout?": int,
    "retry?": {"max_attempts?": int, "backoff_seconds?": int},
    "options?": dict,
}
MODULES_SCHEMA = {"version": int, "modules": MapOf(MODULE_ENTRY, _MODULE_KEY)}
NMAP_PROFILE = {
    "timing?": int,                 # -T0..5
    "discovery_probes?": ListOf(str),  # host discovery probe flags, e.g. -PE, -PS22,80
    "tcp_ports?": str,              # "all" | "top:<n>" | explicit list "22,80,443"
    "min_rate?": int,               # 0 = nmap default
    "max_retries?": int,
    "scripts?": bool,               # -sC during service identification
    "version_all?": bool,           # --version-all
    "os_detection?": bool,          # -O (needs raw sockets)
    "udp_top_ports?": int,          # 0 = no UDP scan
}
PROFILE_ENTRY = {"description": str, "max_safety": Choice(*SAFETY_NAMES), "nmap?": NMAP_PROFILE}
_PROBE_RE = re.compile(r"^-P(?:E|P|M|[SAUY][0-9,\-]*|O[0-9,]*)$")
_TCP_PORTS_RE = re.compile(r"^(all|top:\d{1,5}|\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*)$")
PROFILES_SCHEMA = {"version": int, "profiles": MapOf(PROFILE_ENTRY, r"^[a-z0-9][a-z0-9_-]*$")}
OVERRIDES_SCHEMA = {"modules?": MapOf(MODULE_ENTRY, _MODULE_KEY), "profiles?": MapOf(PROFILE_ENTRY, r"^[a-z0-9][a-z0-9_-]*$"),
                    "reporting?": dict}  # validated by aiszx.reporting.settings


@dataclass(frozen=True)
class Profile:
    name: str
    description: str
    max_safety: Safety
    params: Mapping[str, Any] = field(default_factory=dict)   # tool sections, e.g. {"nmap": {...}}


def _check_profile(name: str, p: Mapping[str, Any]) -> None:
    nmap = p.get("nmap", {})
    where = f"profiles.{name}.nmap"
    for probe in nmap.get("discovery_probes", []):
        if not _PROBE_RE.fullmatch(probe):
            raise ConfigError(f"{where}.discovery_probes: {probe!r} is not a host discovery probe (-PE, -PP, -PM, -PS<ports>, ...)")
    if "tcp_ports" in nmap and not _TCP_PORTS_RE.fullmatch(nmap["tcp_ports"]):
        raise ConfigError(f"{where}.tcp_ports: use 'all', 'top:<n>' or a port list like '22,80,8000-8100'")
    if not 0 <= nmap.get("timing", 3) <= 5:
        raise ConfigError(f"{where}.timing must be 0-5")
    for key in ("min_rate", "max_retries", "udp_top_ports"):
        if nmap.get(key, 0) < 0:
            raise ConfigError(f"{where}.{key} must be >= 0")


@dataclass(frozen=True)
class EffectiveModuleConfig:
    enabled: bool
    timeout: int
    retry: RetryPolicy
    options: Mapping[str, Any] = field(default_factory=dict)


@dataclass
class ModuleSettings:
    modules: dict[str, dict[str, Any]]
    profiles: dict[str, Profile]
    sources: list[Path]

    def profile(self, name: str) -> Profile:
        if name not in self.profiles:
            raise NotFoundError(f"unknown profile '{name}'; available: {', '.join(sorted(self.profiles))}")
        return self.profiles[name]

    def effective(self, module: Module) -> EffectiveModuleConfig:
        meta = module.meta
        raw = self.modules.get(meta.id, {})
        options = dict(meta.config_defaults)
        unknown = set(raw.get("options", {})) - set(options)
        if unknown:
            raise ConfigError(f"modules.{meta.id}.options: unknown option(s) {', '.join(sorted(unknown))}; "
                              f"valid: {', '.join(sorted(options)) or '(none)'}")
        options.update(raw.get("options", {}))
        retry = meta.retry
        if "retry" in raw:
            retry = RetryPolicy(
                max_attempts=raw["retry"].get("max_attempts", retry.max_attempts),
                backoff_seconds=raw["retry"].get("backoff_seconds", retry.backoff_seconds),
                backoff_factor=retry.backoff_factor,
                retry_on=retry.retry_on,
            )
        timeout = raw.get("timeout", meta.timeout_seconds)
        if timeout <= 0 or retry.max_attempts < 1:
            raise ConfigError(f"modules.{meta.id}: timeout must be > 0 and retry.max_attempts >= 1")
        return EffectiveModuleConfig(raw.get("enabled", True), timeout, retry, options)


def load_settings(*, user_config_dir: Path | None, engagement_dir: Path | None,
                  shipped_dir: Path | None = None) -> ModuleSettings:
    shipped = shipped_dir or paths.SHIPPED_CONFIG_DIR
    sources: list[Path] = []

    def layered(name: str, schema: dict) -> dict:
        data = load_yaml_file(shipped / name)
        sources.append(shipped / name)
        if user_config_dir is not None and (user_config_dir / name).is_file():
            data = deep_merge(data, load_yaml_file(user_config_dir / name))
            sources.append(user_config_dir / name)
        validate(data, schema)
        return data

    modules = layered("modules.yaml", MODULES_SCHEMA)["modules"]
    profiles = layered("profiles.yaml", PROFILES_SCHEMA)["profiles"]
    if engagement_dir is not None and (engagement_dir / "overrides.yaml").is_file():
        ov = load_yaml_file(engagement_dir / "overrides.yaml")
        validate(ov, OVERRIDES_SCHEMA, "overrides")
        modules = deep_merge(modules, ov.get("modules", {}))
        profiles = deep_merge(profiles, ov.get("profiles", {}))
        sources.append(engagement_dir / "overrides.yaml")
    for name, prof in profiles.items():
        _check_profile(name, prof)
    return ModuleSettings(
        modules=modules,
        profiles={n: Profile(n, p["description"], Safety(p["max_safety"]),
                             {k: v for k, v in p.items() if k not in ("description", "max_safety")})
                  for n, p in profiles.items()},
        sources=sources,
    )
