"""Small filesystem helpers: safe directory creation, atomic writes, containment checks."""

from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path
from typing import Any

import yaml

from aiszx.core.errors import WorkspaceError


def set_mode(path: Path, mode: int) -> None:
    """Apply POSIX permissions. Windows (development only) ignores most mode bits, so skip it there."""
    if os.name == "posix":
        os.chmod(path, mode)


def ensure_dir(path: Path, mode: int | None = None) -> bool:
    """Create ``path`` if missing. Returns True when it was created."""
    if path.is_dir():
        return False
    if path.exists():
        raise WorkspaceError(f"{path} exists but is not a directory")
    path.mkdir(parents=True, exist_ok=True)
    if mode is not None:
        set_mode(path, mode)
    return True


def atomic_write_text(path: Path, text: str, mode: int | None = None) -> None:
    """Write via a temporary file + rename so readers never see a partial file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        if mode is not None:
            set_mode(Path(tmp), mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def write_yaml(path: Path, data: Any, header: str | None = None) -> None:
    body = yaml.safe_dump(data, sort_keys=False, allow_unicode=True, default_flow_style=False)
    atomic_write_text(path, (header or "") + body)


def is_within(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True
