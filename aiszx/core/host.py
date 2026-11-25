"""Read-only view of the local host: PATH, home directory, environment-relative paths."""

from __future__ import annotations

import glob
import os
from pathlib import Path
from typing import Iterable, Mapping


class HostEnv:
    def __init__(self, env: Mapping[str, str] | None = None) -> None:
        self.env = dict(os.environ if env is None else env)
        self.home = Path(self.env["HOME"]) if self.env.get("HOME") else Path.home()

    @property
    def path_dirs(self) -> list[Path]:
        return [Path(p) for p in self.env.get("PATH", "").split(os.pathsep) if p]

    def expand(self, value: str) -> Path | None:
        """Expand ``~`` and a leading ``$VAR``. Returns None when the variable is unset."""
        if value.startswith("$"):
            name, _, rest = value[1:].partition("/")
            base = self.env.get(name)
            if not base:
                return None
            return Path(base) / rest if rest else Path(base)
        if value == "~":
            return self.home
        if value.startswith("~/"):
            return self.home / value[2:]
        return Path(value)

    def expand_all(self, values: Iterable[str]) -> list[Path]:
        out: list[Path] = []
        for v in values:
            p = self.expand(v)
            if p is not None and p not in out:
                out.append(p)
        return out

    @staticmethod
    def is_executable(path: Path) -> bool:
        return path.is_file() and os.access(path, os.X_OK)

    def which(self, name: str, extra_dirs: Iterable[Path] = ()) -> Path | None:
        if os.sep in name or (os.altsep and os.altsep in name):
            p = Path(name)
            return p if self.is_executable(p) else None
        for d in [*self.path_dirs, *extra_dirs]:
            candidate = d / name
            if self.is_executable(candidate):
                return candidate
        return None

    def glob(self, pattern: str) -> list[Path]:
        expanded = self.expand(pattern)
        if expanded is None:
            return []
        return [Path(p) for p in sorted(glob.glob(str(expanded)))]

    @staticmethod
    def is_root() -> bool:
        return os.name == "posix" and os.geteuid() == 0
