"""Shared fixtures. Every test uses its own temporary data and config directories; nothing touches the network."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

import pytest

from aiszx.core.config import FrameworkConfig, load_config
from aiszx.core.logging import shutdown_logging
from aiszx.db.connection import Database
from aiszx.db.migrate import migrate
from aiszx.targets.engagements import EngagementStore
from aiszx.targets.manager import TargetManager
from aiszx.targets.scope_store import ScopeStore
from aiszx.targets.workspace import WorkspaceLayout


class FakeRunner:
    """Mock for ProcessRunner: responses keyed by program basename + leading arguments.

    runner.on("nmap", "--version", stdout="Nmap version 7.94")
    Later registrations override earlier ones. Unmocked commands fail as "not found".
    """

    def __init__(self) -> None:
        self.handlers: list[tuple[str, tuple[str, ...], dict]] = []
        self.calls: list[tuple[str, ...]] = []
        self.interactive_calls: list[tuple[str, ...]] = []
        self.interactive_rc = 0
        self.interactive_hook = None

    def on(self, program: str, *args: str, stdout: str = "", stderr: str = "", returncode: int = 0,
           error: str | None = None, timed_out: bool = False) -> "FakeRunner":
        self.handlers.append((program, tuple(args), {"stdout": stdout, "stderr": stderr, "returncode": returncode,
                                                     "error": error, "timed_out": timed_out}))
        return self

    def run(self, argv, *, timeout=10.0, env=None, cwd=None):
        from aiszx.core.process import ProcessResult

        args = tuple(str(a) for a in argv)
        self.calls.append(args)
        name = Path(args[0]).name
        for program, prefix, res in reversed(self.handlers):
            if program == name and args[1:1 + len(prefix)] == prefix:
                return ProcessResult(args, None if res["error"] else res["returncode"], res["stdout"], res["stderr"],
                                     res["timed_out"], res["error"])
        return ProcessResult(args, None, error="FileNotFoundError: not mocked")

    def run_interactive(self, argv) -> int:
        self.interactive_calls.append(tuple(str(a) for a in argv))
        if self.interactive_hook:
            self.interactive_hook(argv)
        return self.interactive_rc


class FakeHost:
    """A fake filesystem layout under tmp_path with its own HOME and PATH."""

    def __init__(self, root: Path) -> None:
        import os

        self.root = root
        self.home = root / "home"
        self.bin = root / "usr-bin"
        self.home.mkdir(parents=True)
        self.bin.mkdir(parents=True)
        self.extra_path: list[Path] = []
        self._os = os

    def exe(self, path: Path, content: str = "#!/bin/sh\n") -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        self._os.chmod(path, 0o755)
        return path

    def add_path(self, d: Path) -> None:
        d.mkdir(parents=True, exist_ok=True)
        self.extra_path.append(d)

    @property
    def env(self) -> dict[str, str]:
        dirs = [str(self.bin), *(str(d) for d in self.extra_path)]
        return {"HOME": str(self.home), "PATH": self._os.pathsep.join(dirs)}

    def host(self):
        from aiszx.core.host import HostEnv

        return HostEnv(self.env)


TEST_REGISTRY = r"""
version: 1
settings:
  command_timeout: 5
  max_workers: 2
  search_dirs: ["~/.local/bin", "~/go/bin"]
  git_roots: ["~/tools"]
  git_install_dir: "~/tools"
  pipx_homes: ["~/.local/share/pipx"]
  pyenv_roots: ["~/.pyenv"]
tools:
  nmap: {description: scanner, binaries: [nmap], apt: nmap, version_cmd: [--version],
         version_regex: 'Nmap version (\d+\.\d+(?:\.\d+)?)', min_version: "7.80"}
  whatweb: {description: fingerprint, binaries: [whatweb], apt: whatweb}
  netexec: {description: smb, binaries: [nxc], apt: netexec, pipx: netexec}
  gobuster: {description: dirs, binaries: [gobuster], apt: gobuster, go: "github.com/OJ/gobuster/v3@latest"}
  legacy: {description: py2 tool, known_paths: ["{git_root}/legacy/legacy.py"], interpreter: "pyenv:2.7",
           git: "https://example.invalid/legacy.git"}
  eyewitness: {description: screenshots, binaries: [eyewitness], apt: eyewitness, health_requires: [geckodriver]}
capabilities:
  recon.nmap: {description: nmap scans, requires: [nmap]}
  http.content: {description: content, requires_any: [gobuster, whatweb], optional: [eyewitness]}
  legacy.cap: {description: legacy, requires: [legacy]}
"""


@pytest.fixture
def fakehost(tmp_path: Path) -> FakeHost:
    return FakeHost(tmp_path / "host")


@pytest.fixture
def fakerunner() -> FakeRunner:
    return FakeRunner()


@pytest.fixture
def test_registry_dir(tmp_path: Path) -> Path:
    d = tmp_path / "shipped"
    d.mkdir()
    (d / "tools.yaml").write_text(TEST_REGISTRY, encoding="utf-8")
    return d


class FakeResolver:
    """Deterministic stand-in for DNS resolution."""

    def __init__(self, table: dict[str, list[str]] | None = None) -> None:
        self.table = table or {}
        self.calls: list[str] = []

    def __call__(self, hostname: str) -> list[str]:
        self.calls.append(hostname)
        return list(self.table.get(hostname, []))


@pytest.fixture
def isolated_env(tmp_path: Path) -> dict[str, str]:
    """Environment mapping that points every XDG location into tmp_path."""
    return {"XDG_DATA_HOME": str(tmp_path / "xdg-data"), "XDG_CONFIG_HOME": str(tmp_path / "xdg-config")}


@pytest.fixture
def config(tmp_path: Path, isolated_env: dict[str, str]) -> FrameworkConfig:
    return load_config(data_dir=tmp_path / "data", user_config_dir=tmp_path / "cfg", env=isolated_env)


@pytest.fixture
def layout(config: FrameworkConfig) -> WorkspaceLayout:
    lay = WorkspaceLayout(config.data_dir, config.workspace)
    lay.ensure_data_dir()
    return lay


@pytest.fixture
def db(config: FrameworkConfig, layout: WorkspaceLayout):
    database = Database(config.db_path).connect()
    migrate(database)
    yield database
    database.close()


@pytest.fixture
def resolver() -> FakeResolver:
    return FakeResolver()


@pytest.fixture
def services(db, layout, config, resolver):
    engagements = EngagementStore(db, layout, "tester")
    scope = ScopeStore(db, layout, config.scope, "tester")
    manager = TargetManager(db, layout, engagements, scope, config.scope, resolver, "tester")
    default, _ = engagements.ensure("default")
    return {"engagements": engagements, "scope": scope, "targets": manager, "default": default}


@pytest.fixture
def cli(tmp_path: Path, monkeypatch) -> Callable[..., int]:
    """Run the CLI with isolated directories: cli("target", "add", "10.10.10.5")."""
    from aiszx.cli.main import main

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))
    monkeypatch.delenv("AISZX_DATA_DIR", raising=False)
    monkeypatch.delenv("AISZX_CONFIG_DIR", raising=False)
    monkeypatch.setattr("aiszx.targets.resolver.resolve_host", FakeResolver({"app.lab.local": ["10.10.10.20"]}))

    def run(*argv: str) -> int:
        return main(["--data-dir", str(tmp_path / "data"), "--config-dir", str(tmp_path / "cfg"), *argv])

    yield run
    shutdown_logging()
