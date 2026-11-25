"""Tool registry: ``config/tools.yaml`` merged with ``<user config dir>/tools.yaml``."""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aiszx.core import paths
from aiszx.core.config import Choice, ListOf, MapOf, deep_merge, load_yaml_file, validate
from aiszx.core.errors import ConfigError, NotFoundError
from aiszx.tools.versions import parse_version

METHODS = ("apt", "pipx", "go", "git")
SUPPORTED_REGISTRY_VERSION = 1
_TOOL_KEY = r"^[a-z0-9][a-z0-9_.-]{0,40}$"
_INTERPRETER_RE = re.compile(r"^(pyenv:\d+(\.\d+)*|[A-Za-z0-9_.+-]+|/.+)$")

TOOL_SCHEMA: dict[str, Any] = {
    "description": str,
    "binaries?": ListOf(str),
    "known_paths?": ListOf(str),
    "interpreter?": str,
    "apt?": str,
    "pipx?": str,
    "pipx_python?": str,
    "go?": str,
    "git?": str,
    "install_preference?": ListOf(Choice(*METHODS)),
    "version_cmd?": ListOf(str),
    "version_regex?": str,
    "min_version?": str,
    "health_requires?": ListOf(str),
    "notes?": str,
}

REGISTRY_SCHEMA: dict[str, Any] = {
    "version": int,
    "settings": {
        "command_timeout": int,
        "max_workers": int,
        "search_dirs": ListOf(str),
        "git_roots": ListOf(str),
        "git_install_dir": str,
        "pipx_homes": ListOf(str),
        "pyenv_roots": ListOf(str),
    },
    "tools": MapOf(TOOL_SCHEMA, _TOOL_KEY),
    "capabilities": MapOf(
        {"description": str, "requires?": ListOf(str), "requires_any?": ListOf(str), "optional?": ListOf(str)},
        r"^[a-z0-9][a-z0-9_.-]{0,60}$",
    ),
}


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    binaries: tuple[str, ...] = ()
    known_paths: tuple[str, ...] = ()
    interpreter: str | None = None
    apt: str | None = None
    pipx: str | None = None
    pipx_python: str | None = None
    go: str | None = None
    git: str | None = None
    install_preference: tuple[str, ...] = METHODS
    version_cmd: tuple[str, ...] | None = None
    version_regex: str | None = None
    min_version: str | None = None
    health_requires: tuple[str, ...] = ()
    notes: str | None = None

    def source_for(self, method: str) -> str | None:
        return getattr(self, method)


@dataclass(frozen=True)
class CapabilitySpec:
    name: str
    description: str
    requires: tuple[str, ...] = ()
    requires_any: tuple[str, ...] = ()
    optional: tuple[str, ...] = ()

    @property
    def tools(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(self.requires + self.requires_any + self.optional))


@dataclass(frozen=True)
class RegistrySettings:
    command_timeout: int
    max_workers: int
    search_dirs: tuple[str, ...]
    git_roots: tuple[str, ...]
    git_install_dir: str
    pipx_homes: tuple[str, ...]
    pyenv_roots: tuple[str, ...]


@dataclass(frozen=True)
class ToolRegistry:
    settings: RegistrySettings
    tools: dict[str, ToolSpec]
    capabilities: dict[str, CapabilitySpec]
    sources: tuple[Path, ...]

    def get(self, name: str) -> ToolSpec:
        key = name.strip().lower()
        if key in self.tools:
            return self.tools[key]
        close = difflib.get_close_matches(key, list(self.tools), n=3)
        hint = f"; did you mean {', '.join(close)}?" if close else "; see `tools inventory` for known tools"
        raise NotFoundError(f"unknown tool '{name}'{hint}")

    def capabilities_for(self, tool: str) -> list[str]:
        return [c.name for c in self.capabilities.values() if tool in c.tools]


def _build_tool(name: str, raw: dict[str, Any]) -> ToolSpec:
    where = f"tools.{name}"
    if not raw.get("binaries") and not raw.get("known_paths"):
        raise ConfigError(f"{where}: needs 'binaries' and/or 'known_paths'")
    if raw.get("version_regex"):
        try:
            re.compile(raw["version_regex"])
        except re.error as exc:
            raise ConfigError(f"{where}.version_regex: invalid regular expression: {exc}") from None
    if raw.get("min_version") and parse_version(raw["min_version"]) is None:
        raise ConfigError(f"{where}.min_version: {raw['min_version']!r} is not a version number")
    for key in ("interpreter", "pipx_python"):
        if raw.get(key) and not _INTERPRETER_RE.fullmatch(raw[key]):
            raise ConfigError(f"{where}.{key}: use a command name, an absolute path or 'pyenv:<version>'")
    preference = tuple(raw.get("install_preference") or [m for m in METHODS if raw.get(m)])
    for method in preference:
        if not raw.get(method):
            raise ConfigError(f"{where}.install_preference: '{method}' is listed but '{method}' is not set")
    return ToolSpec(
        name=name,
        description=raw["description"],
        binaries=tuple(raw.get("binaries") or ()),
        known_paths=tuple(raw.get("known_paths") or ()),
        interpreter=raw.get("interpreter"),
        apt=raw.get("apt"),
        pipx=raw.get("pipx"),
        pipx_python=raw.get("pipx_python"),
        go=raw.get("go"),
        git=raw.get("git"),
        install_preference=preference,
        version_cmd=tuple(raw["version_cmd"]) if raw.get("version_cmd") else None,
        version_regex=raw.get("version_regex"),
        min_version=raw.get("min_version"),
        health_requires=tuple(raw.get("health_requires") or ()),
        notes=raw.get("notes"),
    )


def load_registry(*, shipped_dir: Path | None = None, user_config_dir: Path | None = None) -> ToolRegistry:
    shipped_file = (shipped_dir or paths.SHIPPED_CONFIG_DIR) / "tools.yaml"
    if not shipped_file.is_file():
        raise ConfigError(f"shipped tool registry not found: {shipped_file}")
    merged = load_yaml_file(shipped_file)
    sources = [shipped_file]
    if user_config_dir is not None:
        user_file = user_config_dir / "tools.yaml"
        if user_file.is_file():
            merged = deep_merge(merged, load_yaml_file(user_file))
            sources.append(user_file)

    validate(merged, REGISTRY_SCHEMA)
    if merged["version"] != SUPPORTED_REGISTRY_VERSION:
        raise ConfigError(f"tool registry version {merged['version']} is not supported")
    s = merged["settings"]
    if s["command_timeout"] < 1 or s["max_workers"] < 1:
        raise ConfigError("settings.command_timeout and settings.max_workers must be >= 1")

    tools = {name: _build_tool(name, raw) for name, raw in sorted(merged["tools"].items())}
    capabilities: dict[str, CapabilitySpec] = {}
    for name, raw in sorted(merged["capabilities"].items()):
        cap = CapabilitySpec(
            name=name,
            description=raw["description"],
            requires=tuple(raw.get("requires") or ()),
            requires_any=tuple(raw.get("requires_any") or ()),
            optional=tuple(raw.get("optional") or ()),
        )
        unknown = [t for t in cap.tools if t not in tools]
        if unknown:
            raise ConfigError(f"capabilities.{name}: unknown tool(s) {', '.join(unknown)}")
        if not cap.requires and not cap.requires_any:
            raise ConfigError(f"capabilities.{name}: needs 'requires' or 'requires_any'")
        capabilities[name] = cap

    return ToolRegistry(
        settings=RegistrySettings(
            command_timeout=s["command_timeout"],
            max_workers=s["max_workers"],
            search_dirs=tuple(s["search_dirs"]),
            git_roots=tuple(s["git_roots"]),
            git_install_dir=s["git_install_dir"],
            pipx_homes=tuple(s["pipx_homes"]),
            pyenv_roots=tuple(s["pyenv_roots"]),
        ),
        tools=tools,
        capabilities=capabilities,
        sources=tuple(sources),
    )
