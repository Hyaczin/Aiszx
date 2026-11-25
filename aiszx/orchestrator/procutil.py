"""Process identity helpers used to tell live owners from crashed ones."""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from pathlib import Path


def hostname() -> str:
    return socket.gethostname()


def boot_id() -> str | None:
    """Linux boot id: changes on every reboot, so locks from before a reboot are recognised as stale."""
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip() or None
    except OSError:
        return None


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "posix":
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True  # exists, owned by someone else
        return True
    # Windows (development only). Never use os.kill(pid, 0) here: it terminates the process.
    import ctypes

    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return False
    code = ctypes.c_ulong()
    try:
        kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        return code.value == 259  # STILL_ACTIVE
    finally:
        kernel32.CloseHandle(handle)


@dataclass(frozen=True)
class Owner:
    pid: int
    host: str
    boot: str | None

    @classmethod
    def current(cls) -> "Owner":
        return cls(os.getpid(), hostname(), boot_id())

    def is_alive(self, pid: int | None, host: str | None, boot: str | None) -> bool | None:
        """True/False when determinable on this host; None for another host."""
        if host != self.host:
            return None
        if boot and self.boot and boot != self.boot:
            return False
        return pid is not None and pid_alive(pid)
