"""Controlled subprocess execution.

* argv lists only (never a shell), stdin closed, output captured, ``LC_ALL=C`` for parseable output.
* Each process runs in its own session/process group so a timeout kills the whole tree.
* A missing or non-executable program is reported as a result, not an exception.

Interactive execution (installers, ``sudo`` prompts) inherits the terminal.
The execution-time scope guard for target-facing tools is layered on top in Milestone 3.
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
from dataclasses import dataclass, field
from typing import Mapping, Sequence


@dataclass(frozen=True)
class ProcessResult:
    argv: tuple[str, ...]
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    error: str | None = None  # could not start (not found, permission denied, ...)

    @property
    def ok(self) -> bool:
        return self.error is None and not self.timed_out and self.returncode == 0

    @property
    def output(self) -> str:
        return f"{self.stdout}\n{self.stderr}" if self.stderr else self.stdout


@dataclass
class ProcessRunner:
    base_env: Mapping[str, str] | None = None
    extra_env: dict[str, str] = field(default_factory=lambda: {"LC_ALL": "C"})

    def _env(self, env: Mapping[str, str] | None) -> dict[str, str]:
        merged = dict(os.environ if self.base_env is None else self.base_env)
        merged.update(self.extra_env)
        if env:
            merged.update(env)
        return merged

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float = 10.0,
        env: Mapping[str, str] | None = None,
        cwd: str | None = None,
    ) -> ProcessResult:
        args = tuple(str(a) for a in argv)
        try:
            proc = subprocess.Popen(
                args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self._env(env),
                cwd=cwd,
                start_new_session=os.name == "posix",
            )
        except OSError as exc:
            return ProcessResult(args, None, error=f"{type(exc).__name__}: {exc.strerror or exc}")
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            self._kill(proc)
            out, err = proc.communicate()
            return ProcessResult(args, proc.returncode, _decode(out), _decode(err), timed_out=True)
        return ProcessResult(args, proc.returncode, _decode(out), _decode(err))

    def run_interactive(self, argv: Sequence[str]) -> int:
        """Run with the terminal attached (for installers and sudo prompts). Returns the exit code."""
        try:
            return subprocess.call([str(a) for a in argv])
        except FileNotFoundError:
            return 127
        except OSError:
            return 126

    @staticmethod
    def _kill(proc: subprocess.Popen) -> None:
        if os.name == "posix":
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()


def _decode(data: bytes | None) -> str:
    return (data or b"").decode("utf-8", errors="replace")
