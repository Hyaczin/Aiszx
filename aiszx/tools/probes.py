"""Low-level probes of how software is installed: dpkg/APT, pipx, pyenv, git checkouts, Python venvs.

Everything here is read-only. Package-manager queries go through :class:`ProcessRunner`
(mockable in tests); pipx and git metadata are read straight from disk.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from aiszx.core.host import HostEnv
from aiszx.core.process import ProcessRunner

_DPKG_CHUNK = 200


# --- dpkg / APT ------------------------------------------------------------------

@dataclass(frozen=True)
class PackageState:
    name: str
    installed: bool
    version: str | None
    status: str


def dpkg_states(runner: ProcessRunner, host: HostEnv, packages: Iterable[str]) -> dict[str, PackageState]:
    pkgs = sorted({p for p in packages if p})
    dpkg = host.which("dpkg-query")
    if not pkgs or dpkg is None:
        return {}
    states: dict[str, PackageState] = {}
    fmt = "${Package}\t${db:Status-Abbrev}\t${Version}\n"
    for i in range(0, len(pkgs), _DPKG_CHUNK):
        res = runner.run([str(dpkg), "-W", f"--showformat={fmt}", *pkgs[i:i + _DPKG_CHUNK]], timeout=30)
        for line in res.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            name, status, version = parts[0].split(":")[0], parts[1].strip(), parts[2].strip()
            states[name] = PackageState(name, status.startswith("ii"), version or None, status)
    return states


def dpkg_owners(runner: ProcessRunner, host: HostEnv, paths: Iterable[str]) -> dict[str, str]:
    """Map file path → owning Debian package (first one if several)."""
    items = sorted({p for p in paths if p})
    dpkg = host.which("dpkg-query")
    if not items or dpkg is None:
        return {}
    owners: dict[str, str] = {}
    for i in range(0, len(items), _DPKG_CHUNK):
        res = runner.run([str(dpkg), "-S", *items[i:i + _DPKG_CHUNK]], timeout=30)
        for line in res.stdout.splitlines():
            # "pkg[:arch][, pkg2]: /path"; package names never contain ": " (arch suffixes have no space)
            if line.startswith("diversion by"):
                continue
            pkgs, sep, path = line.partition(": ")
            if not sep or not path.strip():
                continue
            owners[path.strip()] = pkgs.split(",")[0].strip().split(":")[0]
    return owners


def apt_candidates(runner: ProcessRunner, host: HostEnv, packages: Iterable[str]) -> dict[str, str | None]:
    """Candidate version APT would install for each package (None when unavailable)."""
    pkgs = sorted({p for p in packages if p})
    apt_cache = host.which("apt-cache")
    if not pkgs or apt_cache is None:
        return {}
    res = runner.run([str(apt_cache), "policy", *pkgs], timeout=60)
    out: dict[str, str | None] = {}
    current: str | None = None
    for line in res.stdout.splitlines():
        header = re.match(r"^(\S+?)(?::\S+)?:$", line)
        if header:
            current = header.group(1)
            out[current] = None
            continue
        m = re.match(r"^\s+Candidate:\s*(\S+)", line)
        if m and current:
            out[current] = None if m.group(1) == "(none)" else m.group(1)
    return out


# --- pipx ------------------------------------------------------------------------

@dataclass(frozen=True)
class PipxVenv:
    name: str
    root: Path
    package: str | None
    version: str | None
    python: str | None


def pipx_venvs(host: HostEnv, homes: Iterable[str]) -> list[PipxVenv]:
    """Read pipx metadata from disk (works even when the pipx command itself is not installed)."""
    venvs: list[PipxVenv] = []
    for home in host.expand_all(homes):
        vroot = home / "venvs"
        if not vroot.is_dir():
            continue
        for d in sorted(p for p in vroot.iterdir() if p.is_dir()):
            package = version = python = None
            meta_file = d / "pipx_metadata.json"
            if meta_file.is_file():
                try:
                    meta = json.loads(meta_file.read_text(encoding="utf-8"))
                    main = meta.get("main_package") or {}
                    package, version = main.get("package"), main.get("package_version")
                    python = meta.get("python_version")
                except (OSError, ValueError, AttributeError):
                    pass
            venvs.append(PipxVenv(d.name, d.resolve(), package, version, python))
    return venvs


def pipx_venv_for(real_path: Path, venvs: list[PipxVenv]) -> PipxVenv | None:
    for venv in venvs:
        if _is_relative_to(real_path, venv.root):
            return venv
    return None


# --- pyenv / interpreters --------------------------------------------------------

@dataclass(frozen=True)
class Interpreter:
    kind: str  # "pyenv" | "system"
    version: str
    path: str


def pyenv_root(host: HostEnv, roots: Iterable[str]) -> Path | None:
    for root in host.expand_all(roots):
        if (root / "versions").is_dir():
            return root
    return None


def pyenv_interpreters(host: HostEnv, roots: Iterable[str]) -> list[Interpreter]:
    root = pyenv_root(host, roots)
    if root is None:
        return []
    found = []
    for d in (root / "versions").iterdir():
        py = d / "bin" / "python"
        if host.is_executable(py):
            found.append(Interpreter("pyenv", d.name, str(py)))
    return sorted(found, key=lambda i: _version_key(i.version), reverse=True)


def resolve_interpreter(spec: str, host: HostEnv, interpreters: list[Interpreter]) -> str | None:
    """'python3' → PATH lookup; '/abs/path' → itself; 'pyenv:2.7' → newest pyenv 2.7.x."""
    if spec.startswith("pyenv:"):
        prefix = spec.split(":", 1)[1]
        for interp in interpreters:  # newest first
            if interp.kind == "pyenv" and (interp.version == prefix or interp.version.startswith(prefix + ".")):
                return interp.path
        return None
    found = host.which(spec)
    return str(found) if found else None


def _version_key(v: str) -> tuple:
    return tuple(int(p) if p.isdigit() else -1 for p in re.split(r"[.\-]", v))


# --- git checkouts / venvs -------------------------------------------------------

def git_checkout(path: Path, max_depth: int = 6) -> tuple[Path, str | None] | None:
    """If ``path`` lives in a git working tree, return (repo root, short commit)."""
    current = path if path.is_dir() else path.parent
    for _ in range(max_depth):
        git_dir = current / ".git"
        if git_dir.is_dir():
            return current, _read_head(git_dir)
        if current.parent == current:
            break
        current = current.parent
    return None


def _read_head(git_dir: Path) -> str | None:
    try:
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
        if not head.startswith("ref:"):
            return head[:12] or None
        ref = head.split(":", 1)[1].strip()
        ref_file = git_dir / ref
        if ref_file.is_file():
            return ref_file.read_text(encoding="utf-8").strip()[:12]
        packed = git_dir / "packed-refs"
        if packed.is_file():
            for line in packed.read_text(encoding="utf-8").splitlines():
                if line.endswith(" " + ref):
                    return line.split(" ", 1)[0][:12]
    except OSError:
        return None
    return None


def in_python_venv(real_path: Path) -> Path | None:
    venv = real_path.parent.parent
    return venv if (venv / "pyvenv.cfg").is_file() else None


def _is_relative_to(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
    except ValueError:
        return False
    return True
