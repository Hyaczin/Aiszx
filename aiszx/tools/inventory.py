"""Discover which registered tools exist on this host, how they were installed, and their versions.

Detection order (everything found is recorded; the first one on PATH is used):

1. ``PATH`` (equivalent to ``command -v``) and ``settings.search_dirs``
   (``~/.local/bin``, ``~/go/bin``, ``~/.cargo/bin``, ``/usr/sbin``, ...)
2. ``known_paths`` from the registry (git checkouts under /opt, ~/tools, ~/htb-tools, ...)

Each installation is then classified by origin: pipx venv, dpkg/APT ownership
(``dpkg-query -S``), Go or Cargo bin directory, git working tree, Python venv,
or plain PATH. Nothing is installed or modified.
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from aiszx.core.host import HostEnv
from aiszx.core.process import ProcessRunner
from aiszx.core.timeutil import iso
from aiszx.tools import probes
from aiszx.tools.health_check import check_health
from aiszx.tools.registry import ToolRegistry, ToolSpec

OK = "ok"
MISSING = "missing"
BROKEN = "broken"
INCOMPATIBLE = "incompatible"
STATUSES = (OK, MISSING, BROKEN, INCOMPATIBLE)


@dataclass
class Installation:
    path: str
    real_path: str
    on_path: bool = False
    source: str = "path"  # apt | pipx | go | cargo | git | venv | path
    package: str | None = None
    package_version: str | None = None
    commit: str | None = None
    launch: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolStatus:
    name: str
    description: str
    status: str = MISSING
    version: str | None = None
    installations: list[Installation] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def primary(self) -> Installation | None:
        return self.installations[0] if self.installations else None

    @property
    def path(self) -> str | None:
        return self.primary.path if self.primary else None

    @property
    def source(self) -> str | None:
        return self.primary.source if self.primary else None

    @property
    def package(self) -> str | None:
        return self.primary.package if self.primary else None

    @property
    def launch(self) -> list[str]:
        return self.primary.launch if self.primary else []

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "description": self.description, "status": self.status, "version": self.version,
            "path": self.path, "source": self.source, "package": self.package, "launch": self.launch,
            "installations": [i.to_dict() for i in self.installations], "problems": self.problems,
            "notes": self.notes, "capabilities": self.capabilities, "detail": self.detail,
        }


@dataclass
class Inventory:
    checked_at: str
    tools: dict[str, ToolStatus]
    interpreters: list[probes.Interpreter]
    complete: bool
    dpkg_available: bool

    def by_status(self, *statuses: str) -> list[ToolStatus]:
        return [t for t in self.tools.values() if t.status in statuses]

    def to_dict(self) -> dict[str, Any]:
        return {
            "checked_at": self.checked_at,
            "complete": self.complete,
            "dpkg_available": self.dpkg_available,
            "tools": {name: t.to_dict() for name, t in self.tools.items()},
            "interpreters": [asdict(i) for i in self.interpreters],
        }


class ToolInventory:
    def __init__(self, registry: ToolRegistry, runner: ProcessRunner, host: HostEnv) -> None:
        self.registry = registry
        self.runner = runner
        self.host = host
        s = registry.settings
        self.search_dirs = host.expand_all(s.search_dirs)
        self.go_dirs = host.expand_all(["$GOPATH/bin", "~/go/bin"])
        self.cargo_dirs = host.expand_all(["$CARGO_HOME/bin", "~/.cargo/bin"])

    # -- public --------------------------------------------------------------
    def detect(self, names: Iterable[str] | None = None) -> Inventory:
        selected = list(names) if names else []
        specs = [self.registry.get(n) for n in selected] if selected else list(self.registry.tools.values())
        s = self.registry.settings

        interpreters = self._interpreters()
        pipx = probes.pipx_venvs(self.host, s.pipx_homes)
        found = {spec.name: self._candidates(spec, interpreters) for spec in specs}
        all_paths = {p for insts in found.values() for i in insts for p in (i.path, i.real_path)}
        owners = probes.dpkg_owners(self.runner, self.host, all_paths)
        # Query the registry's package names *and* the packages that actually own the files found
        # (e.g. a binary shipped by a differently named package).
        pkg_states = probes.dpkg_states(
            self.runner, self.host, [spec.apt for spec in specs if spec.apt] + list(owners.values()))

        statuses: dict[str, ToolStatus] = {}
        for spec in specs:
            for inst in found[spec.name]:
                self._classify(inst, owners, pkg_states, pipx)
            statuses[spec.name] = self._status(spec, found[spec.name], pkg_states)

        checkable = [spec for spec in specs if statuses[spec.name].primary and statuses[spec.name].launch]
        with ThreadPoolExecutor(max_workers=s.max_workers) as pool:
            futures = [
                pool.submit(check_health, spec, statuses[spec.name], self.runner, self.host, s.command_timeout)
                for spec in checkable
            ]
            for f in futures:
                f.result()

        return Inventory(
            checked_at=iso(),
            tools=statuses,
            interpreters=interpreters,
            complete=not selected,
            dpkg_available=self.host.which("dpkg-query") is not None,
        )

    # -- internals -----------------------------------------------------------
    def _interpreters(self) -> list[probes.Interpreter]:
        found = probes.pyenv_interpreters(self.host, self.registry.settings.pyenv_roots)
        system = Path("/usr/bin/python3")
        if self.host.is_executable(system):
            res = self.runner.run([str(system), "--version"], timeout=5)
            version = res.output.strip().replace("Python ", "") or "unknown"
            found.append(probes.Interpreter("system", version, str(system)))
        return found

    def _candidates(self, spec: ToolSpec, interpreters: list[probes.Interpreter]) -> list[Installation]:
        results: dict[str, Installation] = {}
        path_dirs = {str(d) for d in self.host.path_dirs}

        def add(p: Path, on_path: bool) -> None:
            real = os.path.realpath(p)
            if real in results:
                results[real].on_path = results[real].on_path or on_path
                return
            results[real] = Installation(str(p), real, on_path=on_path, launch=self._launch(spec, p, interpreters))

        for binary in spec.binaries:
            for d in [*self.host.path_dirs, *self.search_dirs]:
                candidate = d / binary
                if self.host.is_executable(candidate):
                    add(candidate, str(d) in path_dirs)
        for pattern in spec.known_paths:
            expanded = (
                [pattern.replace("{git_root}", root) for root in self.registry.settings.git_roots]
                if "{git_root}" in pattern else [pattern]
            )
            for pat in expanded:
                for p in self.host.glob(pat):
                    if p.is_file():
                        add(p, False)
        # Prefer what the user would run from a shell (on PATH), keep discovery order otherwise.
        return sorted(results.values(), key=lambda i: not i.on_path)

    def _launch(self, spec: ToolSpec, path: Path, interpreters: list[probes.Interpreter]) -> list[str]:
        interp_spec = spec.interpreter
        if interp_spec is None and path.suffix == ".py" and not (os.name == "posix" and os.access(path, os.X_OK)):
            interp_spec = "python3"
        if interp_spec is None:
            return [str(path)]
        interp = probes.resolve_interpreter(interp_spec, self.host, interpreters)
        return [interp, str(path)] if interp else []

    def _classify(self, inst: Installation, owners: dict[str, str], pkg_states: dict[str, probes.PackageState],
                  pipx: list[probes.PipxVenv]) -> None:
        real = Path(inst.real_path)
        venv = probes.pipx_venv_for(real, pipx)
        if venv is not None:
            inst.source, inst.package, inst.package_version = "pipx", venv.package or venv.name, venv.version
            return
        owner = owners.get(inst.path) or owners.get(inst.real_path)
        if owner:
            inst.source, inst.package = "apt", owner
            state = pkg_states.get(owner)
            inst.package_version = state.version if state else None
            return
        if any(_under(real, d) for d in self.go_dirs):
            inst.source = "go"
            return
        if any(_under(real, d) for d in self.cargo_dirs):
            inst.source = "cargo"
            return
        checkout = probes.git_checkout(real)
        if checkout is not None:
            inst.source, inst.commit = "git", checkout[1]
            inst.package = str(checkout[0])
            return
        if probes.in_python_venv(real) is not None:
            inst.source = "venv"

    def _status(self, spec: ToolSpec, insts: list[Installation], pkg_states: dict[str, probes.PackageState]) -> ToolStatus:
        st = ToolStatus(spec.name, spec.description, installations=insts,
                        capabilities=self.registry.capabilities_for(spec.name))
        apt_state = pkg_states.get(spec.apt) if spec.apt else None
        if not insts:
            if apt_state and apt_state.installed:
                st.status = BROKEN
                st.problems.append(
                    f"APT package {spec.apt} ({apt_state.version}) is installed but none of "
                    f"{', '.join(spec.binaries) or 'its files'} was found"
                )
                return st
            st.status = MISSING
            looked = ", ".join(spec.binaries) if spec.binaries else "-"
            st.problems.append(f"not found: looked for [{looked}] on PATH and in {len(self.search_dirs)} search directories"
                               + (f" and {len(spec.known_paths)} known location pattern(s)" if spec.known_paths else ""))
            if spec.apt:
                st.problems.append(f"APT package {spec.apt} is not installed")
            return st

        st.status = OK
        primary = insts[0]
        if not primary.launch:
            st.status = BROKEN
            st.problems.append(f"{primary.path} needs interpreter '{spec.interpreter or 'python3'}', which was not found")
        if not primary.on_path:
            st.notes.append(f"not on PATH; found at {primary.path}")
        if len(insts) > 1:
            others = ", ".join(f"{i.path} ({i.source})" for i in insts[1:])
            st.notes.append(f"{len(insts)} installations found; using {primary.path} ({primary.source}); others: {others}")
        return st


def _under(path: Path, base: Path) -> bool:
    try:
        path.relative_to(Path(os.path.realpath(base)))
    except ValueError:
        return False
    return True
