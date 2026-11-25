"""Nmap raw-socket privileges via Linux file capabilities.

Without root or capabilities nmap can only do TCP connect scans (``-sT``): no SYN
scans, no UDP scans, no OS detection. The one-time setup grants the nmap binary::

    sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip <real nmap path>

Consequences, shown to the user before applying:

* Any local user can then send raw packets through nmap. That is acceptable on a
  single-user testing VM, but not on shared systems.
* Nmap must be told to use them: ``--privileged`` (or ``NMAP_PRIVILEGED=1``).
  The reconnaissance modules (M4) do this automatically when the mode is ``capabilities``.
* Upgrading the nmap package replaces the binary and drops the capabilities.
  `tools check` detects this and reports ``unprivileged`` until they are re-applied.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from aiszx.core.host import HostEnv
from aiszx.core.process import ProcessRunner

CAPABILITY_SET = "cap_net_raw,cap_net_admin,cap_net_bind_service+eip"
REQUIRED_CAPS = frozenset({"cap_net_raw", "cap_net_admin"})
SBIN_DIRS = (Path("/usr/sbin"), Path("/sbin"))

MODE_ROOT = "root"
MODE_CAPS = "capabilities"
MODE_UNPRIVILEGED = "unprivileged"
MODE_UNKNOWN = "unknown"

SECURITY_NOTE = (
    "After this change ANY local user can send raw packets through nmap. That is fine on a "
    "single-user testing VM but not on shared systems. Remove it with `tools nmap-caps --remove`."
)


@dataclass
class NmapPrivileges:
    nmap_path: str
    mode: str
    capabilities: list[str] = field(default_factory=list)
    flags: str = ""
    getcap: str | None = None
    message: str = ""

    @property
    def raw_sockets(self) -> bool:
        return self.mode in (MODE_ROOT, MODE_CAPS)

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "raw_sockets": self.raw_sockets}


def parse_getcap(output: str) -> tuple[set[str], str]:
    """Handle both ``path cap_a,cap_b=eip`` (libcap ≥2.4x) and ``path = cap_a,cap_b+eip`` (older)."""
    caps = set(re.findall(r"cap_[a-z_]+", output))
    m = re.search(r"[=+]([eip]+)\s*$", output.strip())
    return caps, (m.group(1) if m else "")


def find_getcap(host: HostEnv) -> Path | None:
    return host.which("getcap", SBIN_DIRS)


def check(runner: ProcessRunner, host: HostEnv, nmap_real_path: str) -> NmapPrivileges:
    if host.is_root():
        return NmapPrivileges(nmap_real_path, MODE_ROOT, message="running as root: privileged scans available")
    getcap = find_getcap(host)
    if getcap is None:
        return NmapPrivileges(
            nmap_real_path, MODE_UNKNOWN,
            message="getcap not found (APT package libcap2-bin); cannot tell whether nmap has capabilities",
        )
    res = runner.run([str(getcap), nmap_real_path], timeout=5)
    caps, flags = parse_getcap(res.stdout)
    priv = NmapPrivileges(nmap_real_path, MODE_UNPRIVILEGED, sorted(caps), flags, str(getcap))
    if REQUIRED_CAPS <= caps and "e" in flags and "p" in flags:
        priv.mode = MODE_CAPS
        priv.message = "nmap has raw-socket capabilities; Aiszx will run it with --privileged"
    else:
        priv.message = (
            "nmap will run unprivileged: TCP connect scans only (no SYN, UDP or OS detection). "
            "Grant capabilities once with `python3 pentest.py tools nmap-caps --apply`"
        )
    return priv


def apply_command(nmap_real_path: str) -> list[str]:
    return ["sudo", "setcap", CAPABILITY_SET, nmap_real_path]


def remove_command(nmap_real_path: str) -> list[str]:
    return ["sudo", "setcap", "-r", nmap_real_path]
