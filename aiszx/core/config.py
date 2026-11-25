"""Layered YAML configuration.

Layers, lowest to highest precedence:

1. Shipped defaults: ``<project>/config/framework.yaml`` (complete; every key present)
2. User overrides:   ``<user config dir>/framework.yaml`` (only the keys you change)
3. Environment / CLI: data directory only (``$AISZX_DATA_DIR`` / ``--data-dir``)

Mappings merge recursively; lists and scalars replace. The merged result is
validated strictly: unknown keys are errors (catches typos), types are checked.
Per-engagement overrides are added with the orchestrator in Milestone 3.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

import yaml

from aiszx.core import paths
from aiszx.core.errors import ConfigError

SUPPORTED_CONFIG_VERSION = 1
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
_CATEGORY_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")


# --- schema primitives -------------------------------------------------------

class Choice:
    def __init__(self, *choices: Any) -> None:
        self.choices = choices


class ListOf:
    def __init__(self, item: Any) -> None:
        self.item = item


class Optional:
    """Value may be null."""

    def __init__(self, inner: Any) -> None:
        self.inner = inner


class MapOf:
    """Mapping with arbitrary keys (matching ``key_re``) whose values share one schema."""

    def __init__(self, value: Any, key_re: str = r"^[A-Za-z0-9][A-Za-z0-9_.-]*$") -> None:
        self.value = value
        self.key_re = re.compile(key_re)


# In dict schemas, a key ending in "?" is optional (e.g. "notes?": str).


FRAMEWORK_SCHEMA: dict[str, Any] = {
    "version": int,
    "paths": {"data_dir": Optional(str)},
    "logging": {
        "level": Choice(*LOG_LEVELS),
        "console_level": Choice(*LOG_LEVELS),
        "max_bytes": int,
        "backup_count": int,
    },
    "engagements": {"default_slug": str},
    "scope": {"resolve_hostnames": bool, "strict_hostname_resolution": bool},
    "workspace": {
        "dir_mode": str,
        "protected_dir_mode": str,
        "target_subdirs": ListOf(str),
        "run_subdirs": ListOf(str),
        "protected_subdirs": ListOf(str),
        "enumeration_categories": ListOf(str),
    },
}


def validate(data: Any, schema: Any, path: str = "") -> None:
    """Validate ``data`` against a nested schema of dicts, types and the primitives above."""
    where = path or "<root>"
    if isinstance(schema, dict):
        if not isinstance(data, dict):
            raise ConfigError(f"{where}: expected a mapping, got {type(data).__name__}")
        names = {raw.rstrip("?"): raw for raw in schema}
        unknown = set(data) - set(names)
        if unknown:
            raise ConfigError(f"{where}: unknown key(s): {', '.join(sorted(map(str, unknown)))}")
        missing = {name for name, raw in names.items() if not raw.endswith("?")} - set(data)
        if missing:
            raise ConfigError(f"{where}: missing key(s): {', '.join(sorted(missing))}")
        for name, raw in names.items():
            if name in data:
                validate(data[name], schema[raw], f"{path}.{name}" if path else name)
        return
    if isinstance(schema, MapOf):
        if not isinstance(data, dict):
            raise ConfigError(f"{where}: expected a mapping, got {type(data).__name__}")
        for key, value in data.items():
            if not isinstance(key, str) or not schema.key_re.fullmatch(key):
                raise ConfigError(f"{where}: invalid key {key!r}")
            validate(value, schema.value, f"{path}.{key}" if path else key)
        return
    if isinstance(schema, Optional):
        if data is not None:
            validate(data, schema.inner, path)
        return
    if isinstance(schema, Choice):
        if data not in schema.choices:
            raise ConfigError(f"{where}: must be one of {', '.join(map(str, schema.choices))}; got {data!r}")
        return
    if isinstance(schema, ListOf):
        if not isinstance(data, list):
            raise ConfigError(f"{where}: expected a list, got {type(data).__name__}")
        for i, item in enumerate(data):
            validate(item, schema.item, f"{where}[{i}]")
        return
    # bool is a subclass of int; do not accept true/false where a number is expected.
    if (schema is int and isinstance(data, bool)) or not isinstance(data, schema):
        raise ConfigError(f"{where}: expected {schema.__name__}, got {type(data).__name__} ({data!r})")


def deep_merge(base: Mapping[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), Mapping):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_yaml_file(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror or exc}") from None
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from None
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top level must be a mapping")
    return data


# --- typed configuration -----------------------------------------------------

@dataclass(frozen=True)
class LoggingConfig:
    level: str
    console_level: str
    max_bytes: int
    backup_count: int


@dataclass(frozen=True)
class ScopeConfig:
    resolve_hostnames: bool
    strict_hostname_resolution: bool


@dataclass(frozen=True)
class WorkspaceConfig:
    dir_mode: int
    protected_dir_mode: int
    target_subdirs: tuple[str, ...]
    run_subdirs: tuple[str, ...]
    protected_subdirs: tuple[str, ...]
    enumeration_categories: tuple[str, ...]


@dataclass(frozen=True)
class FrameworkConfig:
    data_dir: Path
    user_config_dir: Path
    sources: tuple[Path, ...]
    default_engagement: str
    logging: LoggingConfig
    scope: ScopeConfig
    workspace: WorkspaceConfig
    raw: Mapping[str, Any]

    @property
    def db_path(self) -> Path:
        return self.data_dir / "aiszx.db"

    @property
    def log_dir(self) -> Path:
        return self.data_dir / "logs"


def _parse_mode(value: str, where: str) -> int:
    try:
        mode = int(value, 8)
    except ValueError:
        raise ConfigError(f"{where}: {value!r} is not an octal permission string such as \"0750\"") from None
    if not 0 <= mode <= 0o777:
        raise ConfigError(f"{where}: {value!r} is outside 0000-0777")
    return mode


def _check_relpaths(values: list[str], where: str) -> tuple[str, ...]:
    out = []
    for value in values:
        p = PurePosixPath(value)
        if not value.strip() or "\\" in value or p.is_absolute() or ".." in p.parts:
            raise ConfigError(f"{where}: {value!r} must be a relative path without '..' or backslashes")
        out.append(str(p))
    return tuple(out)


def _build(merged: dict[str, Any], *, data_dir: Path, user_config_dir: Path, sources: list[Path]) -> FrameworkConfig:
    from aiszx.targets.identity import normalise_slug  # local import: avoid a module cycle at import time

    ws = merged["workspace"]
    run_subdirs = _check_relpaths(ws["run_subdirs"], "workspace.run_subdirs")
    protected = _check_relpaths(ws["protected_subdirs"], "workspace.protected_subdirs")
    not_listed = [p for p in protected if p not in run_subdirs]
    if not_listed:
        raise ConfigError(f"workspace.protected_subdirs: {', '.join(not_listed)} must also appear in run_subdirs")
    for cat in ws["enumeration_categories"]:
        if not _CATEGORY_RE.fullmatch(cat):
            raise ConfigError(f"workspace.enumeration_categories: invalid name {cat!r}")
    try:
        default_slug = normalise_slug(merged["engagements"]["default_slug"])
    except Exception as exc:  # ValidationError → ConfigError with location
        raise ConfigError(f"engagements.default_slug: {exc}") from None

    lg = merged["logging"]
    if lg["max_bytes"] < 0 or lg["backup_count"] < 0:
        raise ConfigError("logging.max_bytes and logging.backup_count must be >= 0")

    return FrameworkConfig(
        data_dir=data_dir,
        user_config_dir=user_config_dir,
        sources=tuple(sources),
        default_engagement=default_slug,
        logging=LoggingConfig(lg["level"], lg["console_level"], lg["max_bytes"], lg["backup_count"]),
        scope=ScopeConfig(**merged["scope"]),
        workspace=WorkspaceConfig(
            dir_mode=_parse_mode(ws["dir_mode"], "workspace.dir_mode"),
            protected_dir_mode=_parse_mode(ws["protected_dir_mode"], "workspace.protected_dir_mode"),
            target_subdirs=_check_relpaths(ws["target_subdirs"], "workspace.target_subdirs"),
            run_subdirs=run_subdirs,
            protected_subdirs=protected,
            enumeration_categories=tuple(ws["enumeration_categories"]),
        ),
        raw=merged,
    )


def load_config(
    *,
    shipped_dir: Path | None = None,
    user_config_dir: str | Path | None = None,
    data_dir: str | Path | None = None,
    env: Mapping[str, str] | None = None,
) -> FrameworkConfig:
    env = os.environ if env is None else env
    shipped_dir = shipped_dir or paths.SHIPPED_CONFIG_DIR
    shipped_file = shipped_dir / "framework.yaml"
    if not shipped_file.is_file():
        raise ConfigError(f"shipped configuration not found: {shipped_file}")

    merged = load_yaml_file(shipped_file)
    sources = [shipped_file]

    ucd = paths.resolve_user_config_dir(user_config_dir, env)
    user_file = ucd / "framework.yaml"
    if user_file.is_file():
        merged = deep_merge(merged, load_yaml_file(user_file))
        sources.append(user_file)

    validate(merged, FRAMEWORK_SCHEMA)
    if merged["version"] != SUPPORTED_CONFIG_VERSION:
        raise ConfigError(f"configuration version {merged['version']} is not supported (expected {SUPPORTED_CONFIG_VERSION})")

    configured = merged["paths"]["data_dir"]
    if configured is not None and not Path(configured).expanduser().is_absolute():
        raise ConfigError(f"paths.data_dir must be absolute or start with '~' (got {configured!r})")

    resolved_data = paths.resolve_data_dir(data_dir, env, configured)
    return _build(merged, data_dir=resolved_data, user_config_dir=ucd, sources=sources)
