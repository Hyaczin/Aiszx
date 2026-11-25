"""Executes module commands: scope guard, tool resolution, streaming capture, timeouts, cancellation.

* **Scope guard**: every host a command declares in ``targets`` is checked against the engagement
  scope (and its validity window) immediately before the process starts. A violation refuses
  the command; nothing is executed.
* stdout/stderr stream straight to files in the attempt's ``raw/`` directory, so partial output
  survives crashes, timeouts and Ctrl+C.
* Each process gets its own process group; timeout or cancellation terminates the whole tree
  (SIGTERM, then SIGKILL after a grace period).
* Secrets listed in ``Command.redact`` never appear in stored command lines or logs.
"""

from __future__ import annotations

import contextlib
import ipaddress
import os
import shlex
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable

from aiszx.core.errors import ScopeError
from aiszx.modules.base import Command, CommandResult
from aiszx.targets.engagements import ACTIVE, Engagement
from aiszx.targets.identity import normalise_target
from aiszx.targets.scope import ScopePolicy

REDACTED = "***"


class ScopeViolation(ScopeError):
    pass


class ToolUnavailable(Exception):
    """A command referenced a tool that was not resolved for its module (a module bug)."""


class ScopeGuard:
    def __init__(self, policy: ScopePolicy, engagement: Engagement, resolver: Callable[[str], list[str]],
                 pinned: dict[str, list[str]] | None = None) -> None:
        self.policy = policy
        self.engagement = engagement
        self.resolver = resolver
        self._resolved: dict[str, list[str]] = dict(pinned or {})
        self._lock = threading.Lock()

    MAX_RANGE = 65536

    def check(self, targets, exclude=()) -> None:
        validity = self.engagement.validity()
        if validity != ACTIVE:
            raise ScopeViolation(f"engagement '{self.engagement.slug}' is {validity}; refusing to contact targets")
        for raw in targets:
            if "/" in str(raw):
                self.check_network(str(raw), exclude)
                continue
            identity = normalise_target(raw)
            if identity.is_ip:
                if not self.policy.address_allowed(identity.canonical):
                    raise ScopeViolation(f"{identity.canonical} is not in scope; command refused")
                continue
            with self._lock:
                if identity.canonical not in self._resolved:
                    self._resolved[identity.canonical] = self.resolver(identity.canonical)
                addresses = self._resolved[identity.canonical]
            decision = self.policy.evaluate(identity, addresses)
            if not decision.in_scope:
                raise ScopeViolation(f"{identity.canonical} is not in scope ({'; '.join(decision.reasons)}); command refused")


    def check_network(self, cidr: str, exclude=()) -> None:
        """Every address of the range must be in scope, or be skipped via the command's exclusions."""
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            raise ScopeViolation(f"{cidr!r} is not a valid network") from None
        if net.num_addresses > self.MAX_RANGE:
            raise ScopeViolation(f"{net} has {net.num_addresses} addresses; split ranges larger than /16 (IPv4)")
        def nets(rules):
            return [ipaddress.ip_network(r.value) for r in rules if r.is_address_rule]
        inc, exc = nets(self.policy.includes), nets(self.policy.excludes)
        skipped = []
        for item in exclude:
            try:
                skipped.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                raise ScopeViolation(f"invalid exclusion {item!r}") from None
        uncovered = 0
        first = None
        for addr in net:
            if any(addr in n for n in skipped if n.version == addr.version):
                continue
            allowed = any(addr in n for n in inc if n.version == addr.version) and                 not any(addr in n for n in exc if n.version == addr.version)
            if not allowed:
                uncovered += 1
                first = first or addr
        if uncovered:
            raise ScopeViolation(f"{uncovered} address(es) of {net} are out of scope (first: {first}); "
                                 "the whole range must be covered by include rules, with exclusions passed to the tool")


def redact(argv: list[str], secrets) -> list[str]:
    out = []
    for arg in argv:
        for secret in secrets:
            if secret:
                arg = arg.replace(secret, REDACTED)
        out.append(arg)
    return out


class ToolRunner:
    def __init__(self, guard: ScopeGuard, tool_launch: dict[str, list[str]], cancel_event: threading.Event,
                 kill_grace: float = 5.0, poll_interval: float = 0.2) -> None:
        self.guard = guard
        self.tool_launch = tool_launch
        self.cancel_event = cancel_event
        self.kill_grace = kill_grace
        self.poll_interval = poll_interval

    def run(self, cmd: Command, out_dir: Path, default_timeout: int) -> CommandResult:
        self.guard.check(cmd.targets, cmd.exclude)  # raises ScopeViolation: nothing is started
        if cmd.tool is not None:
            launch = self.tool_launch.get(cmd.tool)
            if not launch:
                raise ToolUnavailable(f"tool '{cmd.tool}' is not available to this module")
            argv = [*launch, *cmd.argv]
        else:
            argv = list(cmd.argv)
        shown = redact(argv, cmd.redact)
        out_dir.mkdir(parents=True, exist_ok=True)
        stdout_path, stderr_path = out_dir / f"{cmd.label}.stdout.txt", out_dir / f"{cmd.label}.stderr.txt"
        (out_dir / f"{cmd.label}.cmd.txt").write_text(shlex.join(shown) + "\n", encoding="utf-8")
        timeout = cmd.timeout or default_timeout
        env = {**os.environ, "LC_ALL": "C", **cmd.env}

        start = time.monotonic()
        with stdout_path.open("wb") as out, stderr_path.open("wb") as err:
            try:
                # cwd = the attempt's raw directory: tools that drop files in their working directory
                # (state files, logs, geckodriver.log, ...) keep them with the evidence.
                proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err, env=env,
                                        cwd=str(out_dir), start_new_session=os.name == "posix")
            except OSError as exc:
                return CommandResult(cmd.label, shown, None, time.monotonic() - start, stdout_path, stderr_path,
                                     error=f"{type(exc).__name__}: {exc.strerror or exc}")
            timed_out = cancelled = False
            while True:
                try:
                    proc.wait(timeout=self.poll_interval)
                    break
                except subprocess.TimeoutExpired:
                    pass
                if self.cancel_event.is_set():
                    cancelled = True
                    self._terminate(proc)
                    break
                if time.monotonic() - start > timeout:
                    timed_out = True
                    self._terminate(proc)
                    break
        return CommandResult(cmd.label, shown, proc.returncode, time.monotonic() - start, stdout_path, stderr_path,
                             timed_out=timed_out, cancelled=cancelled)

    def _terminate(self, proc: subprocess.Popen) -> None:
        def send(sig: int) -> None:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                if os.name == "posix":
                    os.killpg(proc.pid, sig)
                elif sig == signal.SIGTERM:
                    proc.terminate()
                else:
                    proc.kill()

        send(signal.SIGTERM)
        try:
            proc.wait(timeout=self.kill_grace)
        except subprocess.TimeoutExpired:
            send(getattr(signal, "SIGKILL", signal.SIGTERM))
            proc.wait()
