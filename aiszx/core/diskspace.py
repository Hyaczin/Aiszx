"""Free-space checks: refuse to start work that would likely fail half-way on a full disk.

A full disk mid-run is survivable (units fail, output already written is kept, ``resume`` continues
once space is freed), but it produces confusing partial results; checking up front is cheaper.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from aiszx.core.errors import WorkspaceError

MIB = 1024 * 1024


def free_mb(path: Path) -> float:
    """Free space (MiB) on the filesystem holding ``path`` (or its nearest existing parent)."""
    p = Path(path)
    while not p.exists() and p != p.parent:
        p = p.parent
    return shutil.disk_usage(p).free / MIB


def require_free_space(path: Path, min_mb: int, what: str = "start a run") -> None:
    if min_mb <= 0:
        return
    free = free_mb(path)
    if free < min_mb:
        raise WorkspaceError(
            f"only {free:.0f} MiB free on the filesystem of {path}; refusing to {what} (needs {min_mb} MiB, "
            "orchestrator.min_free_mb). Free space (see `workspace stats` for the largest runs) or lower the setting.")
