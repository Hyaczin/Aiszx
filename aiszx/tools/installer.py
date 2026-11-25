"""Installation recommendations and confirmed execution.

Policy
    * Preference order per tool (default: APT, pipx, Go, git); the first *available* method wins.
    * APT: only if ``apt-cache policy`` shows a candidate. Runs ``sudo apt-get install <pkg>``
      (apt asks its own confirmation as well).
    * pipx: user-level, isolated venv; optional ``--python`` from pyenv.
    * Go: ``go install <module>`` into ~/go/bin.
    * git: ``git clone --depth 1`` only. Aiszx never runs a project's install scripts;
      the follow-up setup is listed as a manual step for you to review.
    * Never ``sudo pip``; prerequisites (pipx, go, git) are recommended, not installed implicitly.
    * Nothing runs without an explicit confirmation per tool.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from typing import Callable

from aiszx.core.host import HostEnv
from aiszx.core.process import ProcessRunner
from aiszx.tools import probes
from aiszx.tools.inventory import BROKEN, INCOMPATIBLE, MISSING, Inventory, ToolStatus
from aiszx.tools.registry import ToolRegistry, ToolSpec

INSTALL = "install"
UPGRADE = "upgrade"
REPAIR = "repair"


@dataclass
class InstallOption:
    method: str
    available: bool
    steps: list[list[str]] = field(default_factory=list)
    reason: str = ""
    manual: list[str] = field(default_factory=list)

    @property
    def privileged(self) -> bool:
        return any(step and step[0] == "sudo" for step in self.steps)

    def commands(self) -> list[str]:
        return [shlex.join(step) for step in self.steps]


@dataclass
class InstallPlan:
    tool: str
    action: str
    current_status: str
    reasons: list[str]
    chosen: InstallOption | None
    alternatives: list[InstallOption] = field(default_factory=list)

    def to_dict(self) -> dict:
        def opt(o: InstallOption | None) -> dict | None:
            if o is None:
                return None
            return {"method": o.method, "available": o.available, "commands": o.commands(),
                    "reason": o.reason, "manual": o.manual, "privileged": o.privileged}
        return {"tool": self.tool, "action": self.action, "status": self.current_status, "reasons": self.reasons,
                "recommended": opt(self.chosen), "alternatives": [opt(a) for a in self.alternatives]}


@dataclass
class InstallOutcome:
    tool: str
    result: str  # installed | declined | failed | skipped
    detail: str = ""


class Installer:
    def __init__(self, registry: ToolRegistry, runner: ProcessRunner, host: HostEnv, inventory: Inventory) -> None:
        self.registry = registry
        self.runner = runner
        self.host = host
        self.inventory = inventory
        self._candidates: dict[str, str | None] | None = None

    # -- planning ------------------------------------------------------------
    def plan(self, names: list[str] | None = None) -> list[InstallPlan]:
        if names:
            statuses = [self.inventory.tools[self.registry.get(n).name] for n in names]
        else:
            statuses = self.inventory.by_status(MISSING, BROKEN, INCOMPATIBLE)
        apt_pkgs = [self.registry.tools[s.name].apt for s in statuses if self.registry.tools[s.name].apt]
        self._candidates = probes.apt_candidates(self.runner, self.host, apt_pkgs)
        return [self._plan_one(self.registry.tools[s.name], s) for s in statuses]

    def _plan_one(self, spec: ToolSpec, st: ToolStatus) -> InstallPlan:
        if st.status == INCOMPATIBLE:
            action = UPGRADE
        elif st.status == BROKEN:
            action = REPAIR
        elif st.status == MISSING:
            action = INSTALL
        else:
            return InstallPlan(spec.name, "none", st.status, ["already installed and working"], None)

        if action == UPGRADE:
            options = [self._upgrade_option(spec, st)]
        elif action == REPAIR and st.source in (None, "apt") and spec.apt:
            options = [self._apt_option(spec, reinstall=True)]
        else:
            options = [self._option(spec, method) for method in spec.install_preference]
        chosen = next((o for o in options if o.available), None)
        alternatives = [o for o in options if o is not chosen]
        return InstallPlan(spec.name, action, st.status, list(st.problems), chosen, alternatives)

    def _option(self, spec: ToolSpec, method: str) -> InstallOption:
        return {"apt": self._apt_option, "pipx": self._pipx_option, "go": self._go_option, "git": self._git_option}[method](spec)

    def _apt_option(self, spec: ToolSpec, reinstall: bool = False) -> InstallOption:
        pkg = spec.apt or ""
        if self.host.which("apt-get") is None:
            return InstallOption("apt", False, reason="apt-get not found (not a Debian-based system?)")
        candidate = (self._candidates or {}).get(pkg)
        if candidate is None:
            return InstallOption("apt", False, reason=f"no APT candidate for {pkg}; try `sudo apt update` first")
        argv = ["sudo", "apt-get", "install", *(["--reinstall"] if reinstall else []), pkg]
        return InstallOption("apt", True, [argv], reason=f"Parrot repository version {candidate}")

    def _pipx_option(self, spec: ToolSpec) -> InstallOption:
        if self.host.which("pipx", self.host.expand_all(["~/.local/bin"])) is None:
            return InstallOption("pipx", False, reason="pipx is not installed (`sudo apt install pipx`, then `pipx ensurepath`)")
        argv = ["pipx", "install"]
        if spec.pipx_python:
            interp = probes.resolve_interpreter(
                spec.pipx_python, self.host, probes.pyenv_interpreters(self.host, self.registry.settings.pyenv_roots))
            if interp is None:
                return InstallOption("pipx", False, reason=f"interpreter {spec.pipx_python} not found (pyenv install it first)")
            argv += ["--python", interp]
        argv.append(spec.pipx or "")
        return InstallOption("pipx", True, [argv], reason="isolated user-level install (pipx)")

    def _go_option(self, spec: ToolSpec) -> InstallOption:
        if self.host.which("go") is None:
            return InstallOption("go", False, reason="Go toolchain not installed (`sudo apt install golang-go`)")
        return InstallOption("go", True, [["go", "install", spec.go or ""]],
                             reason="builds into ~/go/bin (ensure it is on PATH)")

    def _git_option(self, spec: ToolSpec) -> InstallOption:
        if self.host.which("git") is None:
            return InstallOption("git", False, reason="git not installed (`sudo apt install git`)")
        dest_root = self.host.expand(self.registry.settings.git_install_dir)
        repo_name = (spec.git or "").rstrip("/").rsplit("/", 1)[-1].removesuffix(".git") or spec.name
        dest = dest_root / repo_name if dest_root else None
        if dest is not None and dest.exists():
            return InstallOption("git", False, reason=f"{dest} already exists; inspect it instead of cloning again")
        return InstallOption(
            "git", True, [["git", "clone", "--depth", "1", spec.git or "", str(dest)]],
            reason="source checkout",
            manual=[f"review {dest}/README* and install its dependencies in a dedicated venv "
                    f"(e.g. python3 -m venv {dest}/.venv); Aiszx does not run project install scripts"],
        )

    def _upgrade_option(self, spec: ToolSpec, st: ToolStatus) -> InstallOption:
        src = st.source
        if src == "apt" and spec.apt:
            return InstallOption("apt", True, [["sudo", "apt-get", "install", "--only-upgrade", st.package or spec.apt]],
                                 reason=f"installed {st.version}, need >= {spec.min_version}")
        if src == "pipx" and st.package:
            return InstallOption("pipx", True, [["pipx", "upgrade", st.package]],
                                 reason=f"installed {st.version}, need >= {spec.min_version}")
        return InstallOption(src or "manual", False,
                             reason=f"installed from {src}; upgrade it manually to >= {spec.min_version}")

    # -- execution -----------------------------------------------------------
    def execute(
        self,
        plans: list[InstallPlan],
        confirm: Callable[[InstallPlan], bool],
        on_event: Callable[[InstallPlan, InstallOutcome], None] | None = None,
    ) -> list[InstallOutcome]:
        outcomes = []
        for plan in plans:
            if plan.chosen is None:
                outcome = InstallOutcome(plan.tool, "skipped", "no available installation method")
            elif not confirm(plan):
                outcome = InstallOutcome(plan.tool, "declined")
            else:
                outcome = InstallOutcome(plan.tool, "installed")
                for step in plan.chosen.steps:
                    rc = self.runner.run_interactive(step)
                    if rc != 0:
                        outcome = InstallOutcome(plan.tool, "failed", f"`{shlex.join(step)}` exited with {rc}")
                        break
            if on_event:
                on_event(plan, outcome)
            outcomes.append(outcome)
        return outcomes
