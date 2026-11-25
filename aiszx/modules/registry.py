"""Module discovery, validation and selection."""

from __future__ import annotations

import difflib
import importlib
import inspect
import pkgutil
import re
from dataclasses import dataclass
from typing import Iterable

from aiszx.core.errors import ConfigError, NotFoundError
from aiszx.modules.base import Module, Safety, Stage

STAGE_ORDER = [Stage.PREFLIGHT, Stage.RECON, Stage.ENUMERATION, Stage.ASSESSMENT]

MODULE_ID_RE = re.compile(r"^[a-z0-9]+(?:\.[a-z0-9_]+)+$")
_SKIP = {"base", "registry"}


@dataclass
class ModuleRegistry:
    modules: dict[str, Module]

    def get(self, module_id: str) -> Module:
        if module_id in self.modules:
            return self.modules[module_id]
        close = difflib.get_close_matches(module_id, list(self.modules), n=3)
        hint = f"; did you mean {', '.join(close)}?" if close else "; see `modules list`"
        raise NotFoundError(f"unknown module '{module_id}'{hint}")

    def select(self, tokens: Iterable[str]) -> list[Module]:
        """Resolve exact ids, families ('smb' → 'smb.*') or service categories; dependency order."""
        chosen: dict[str, Module] = {}
        for token in tokens:
            t = token.strip().lower()
            if t in self.modules:
                matches = [self.modules[t]]
            else:
                matches = [m for mid, m in self.modules.items() if mid.startswith(t + ".")]
                matches = matches or [m for m in self.modules.values() if t in m.meta.categories]
            if not matches:
                self.get(t)  # raises with suggestions
            for m in matches:
                chosen[m.meta.id] = m
        return self.ordered(chosen.values())

    def ordered(self, modules: Iterable[Module]) -> list[Module]:
        """Topological order by ``depends_on`` (only among the given modules), stable by id."""
        pending = {m.meta.id: m for m in modules}
        out: list[Module] = []
        while pending:
            ready = sorted(mid for mid, m in pending.items()
                           if not any(d in pending for d in m.meta.depends_on))
            if not ready:  # validated at discovery, so this cannot happen
                raise ConfigError(f"module dependency cycle among {sorted(pending)}")
            for mid in ready:
                out.append(pending.pop(mid))
        return out


def _validate(modules: dict[str, Module]) -> None:
    for mid, mod in modules.items():
        meta = mod.meta
        if not MODULE_ID_RE.fullmatch(mid):
            raise ConfigError(f"module id {mid!r} must look like '<family>.<name>' (lowercase)")
        if meta.timeout_seconds <= 0 or meta.retry.max_attempts < 1:
            raise ConfigError(f"module {mid}: timeout must be > 0 and retry.max_attempts >= 1")
        if not isinstance(meta.safety, Safety):
            raise ConfigError(f"module {mid}: invalid safety class")
        for dep in meta.depends_on:
            if dep not in modules:
                raise ConfigError(f"module {mid} depends on unknown module {dep}")
            if STAGE_ORDER.index(modules[dep].meta.stage) > STAGE_ORDER.index(meta.stage):
                raise ConfigError(f"module {mid} ({meta.stage.value}) cannot depend on a later-stage module {dep}")
    # cycle detection
    state: dict[str, int] = {}

    def visit(mid: str, chain: list[str]) -> None:
        if state.get(mid) == 2:
            return
        if state.get(mid) == 1:
            raise ConfigError(f"module dependency cycle: {' -> '.join(chain + [mid])}")
        state[mid] = 1
        for dep in modules[mid].meta.depends_on:
            visit(dep, chain + [mid])
        state[mid] = 2

    for mid in modules:
        visit(mid, [])


def discover(packages: Iterable[str] = ("aiszx.modules",)) -> ModuleRegistry:
    found: dict[str, Module] = {}
    for pkg_name in packages:
        pkg = importlib.import_module(pkg_name)
        names = [pkg_name]
        if hasattr(pkg, "__path__"):
            names += [info.name for info in pkgutil.walk_packages(pkg.__path__, prefix=pkg_name + ".")
                      if info.name.rsplit(".", 1)[-1] not in _SKIP]
        for name in names:
            mod = importlib.import_module(name)
            for obj in vars(mod).values():
                if (inspect.isclass(obj) and issubclass(obj, Module) and obj.__module__ == mod.__name__
                        and not inspect.isabstract(obj) and hasattr(obj, "meta")):
                    mid = obj.meta.id
                    if mid in found and type(found[mid]) is not obj:
                        raise ConfigError(f"duplicate module id {mid}")
                    found[mid] = obj()
    _validate(found)
    return ModuleRegistry(dict(sorted(found.items())))
