"""Nmap command construction shared by the reconnaissance modules.

* Scan parameters come from the profile's ``nmap`` section (defaults below), never hardcoded in modules.
* Privileges come from the tool inventory: ``capabilities`` → ``--privileged`` (raw sockets via
  setcap), ``root`` → nothing extra, otherwise ``--unprivileged`` with TCP connect scans only.
* Every scan writes ``-oA`` (XML for parsing, normal and grepable for humans) into the attempt's raw directory.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

DEFAULTS: dict[str, Any] = {
    "timing": 4,
    "discovery_probes": ["-PE", "-PS22,80,443,445,3389", "-PA80,443"],
    "tcp_ports": "all",
    "min_rate": 0,
    "max_retries": 2,
    "scripts": True,
    "version_all": False,
    "os_detection": False,
    "udp_top_ports": 0,
}


def params(profile_params: Mapping[str, Any]) -> dict[str, Any]:
    return {**DEFAULTS, **dict(profile_params.get("nmap", {}))}


def privileges(tool_details: Mapping[str, Mapping[str, Any]]) -> tuple[list[str], bool, str]:
    """(flags, raw_sockets_available, mode) for the current nmap installation."""
    mode = (tool_details.get("nmap", {}).get("privileges") or {}).get("mode", "unknown")
    if mode == "capabilities":
        return ["--privileged"], True, mode
    if mode == "root":
        return [], True, mode
    return ["--unprivileged"], False, mode


def common(p: Mapping[str, Any], priv_flags: list[str], address: str) -> list[str]:
    args = ["-n", "--reason", f"-T{int(p['timing'])}", "--stats-every", "60s", *priv_flags]
    if ":" in address:
        args.append("-6")
    return args


def outputs(attempt_dir: Path, name: str) -> list[str]:
    return ["-oA", str(attempt_dir / "raw" / name)]


def tcp_port_args(spec: str) -> list[str]:
    if spec == "all":
        return ["-p-"]
    if spec.startswith("top:"):
        return ["--top-ports", spec.split(":", 1)[1]]
    return ["-p", spec]


def rate_args(p: Mapping[str, Any]) -> list[str]:
    args = ["--max-retries", str(int(p["max_retries"]))]
    if int(p["min_rate"]) > 0:
        args += ["--min-rate", str(int(p["min_rate"]))]
    return args


def describe_tcp(spec: str) -> str:
    return {"all": "all 65535 TCP ports"}.get(spec, f"top {spec[4:]} TCP ports" if spec.startswith("top:") else f"TCP ports {spec}")
