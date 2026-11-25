"""core.connectivity: is the target routable from here, and does it answer ICMP?

* ``ip route get <address>`` (no packets sent): which interface/gateway is used. On HTB this
  shows whether traffic goes through the VPN (``tun0``) or nowhere ("Network is unreachable").
* ``ping -c <count>``: ICMP echo. Many hosts drop ICMP, so no reply is recorded as an
  observation, not as "host down".
"""

from __future__ import annotations

import re

from aiszx.modules.base import (
    Command,
    CommandResult,
    Module,
    ModuleMeta,
    ModuleResult,
    RetryPolicy,
    RunContext,
    Safety,
    Stage,
    ToolRequirement,
    WorkUnit,
)

_PKTS_RE = re.compile(r"(\d+)\s+packets transmitted,\s+(\d+)\s+(?:packets )?received")
_RTT_RE = re.compile(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)")


def parse_route(text: str) -> dict:
    line = next((ln for ln in text.splitlines() if " dev " in ln), "")
    if not line:
        reason = text.strip().splitlines()[-1] if text.strip() else "no output"
        return {"routable": False, "reason": reason}
    def field(name: str) -> str | None:
        m = re.search(rf"\b{name}\s+(\S+)", line)
        return m.group(1) if m else None

    return {"routable": True, "dev": field("dev"), "via": field("via"), "src": field("src"), "raw": line.strip()}


def parse_ping(text: str) -> dict:
    m = _PKTS_RE.search(text)
    if not m:
        return {"sent": None, "received": None}
    out: dict = {"sent": int(m.group(1)), "received": int(m.group(2))}
    rtt = _RTT_RE.search(text)
    if rtt:
        out.update(rtt_min_ms=float(rtt.group(1)), rtt_avg_ms=float(rtt.group(2)), rtt_max_ms=float(rtt.group(3)))
    return out


class Connectivity(Module):
    meta = ModuleMeta(
        id="core.connectivity",
        version="1",
        description="Route lookup (no packets) and ICMP echo to the target; detects VPN/routing problems early",
        stage=Stage.PREFLIGHT,
        safety=Safety.ACTIVE_SAFE,
        timeout_seconds=30,
        tools=(ToolRequirement("ping"), ToolRequirement("ip", optional=True)),
        retry=RetryPolicy(max_attempts=2, backoff_seconds=3),
        ok_exit_codes=(0, 1),  # ping exits 1 when no reply arrives; that is a result, not an error
        config_defaults={"count": 2, "wait_seconds": 2},
    )

    def build_commands(self, unit: WorkUnit, ctx: RunContext) -> list[Command]:
        address = unit.inputs["address"]
        cmds = []
        if "ip" in ctx.tool_launch:
            cmds.append(Command("route", ["route", "get", address], tool="ip", ok_exit_codes=(0, 1, 2)))
        count, wait = int(ctx.options["count"]), int(ctx.options["wait_seconds"])
        cmds.append(Command("ping", ["-n", "-c", str(count), "-W", str(wait), address], tool="ping",
                            targets=[address], timeout=count * (wait + 1) + 5))
        return cmds

    def parse(self, unit: WorkUnit, results: list[CommandResult], ctx: RunContext) -> ModuleResult:
        by_label = {r.label: r for r in results}
        res = ModuleResult(evidence_descriptions={
            "route.stdout.txt": "ip route get output", "ping.stdout.txt": "ping output"})
        parts = []
        if "route" in by_label:
            r = by_label["route"]
            route = parse_route(r.stdout() + "\n" + r.stderr())
            res.artifacts["route"] = route
            res.observations.append({"key": "host.routable", "value": route["routable"]})
            if route["routable"]:
                parts.append(f"route via {route.get('dev', '?')}" + (f" (src {route['src']})" if route.get("src") else ""))
            else:
                parts.append(f"NO ROUTE: {route['reason']}")
        else:
            res.limitations.append("`ip` not available: route lookup skipped")

        ping = parse_ping(by_label["ping"].stdout()) if "ping" in by_label else {"sent": None, "received": None}
        res.artifacts["icmp"] = ping
        replied = bool(ping.get("received"))
        res.observations.append({"key": "host.icmp_reply", "value": replied})
        if ping["sent"] is None:
            parts.append("ping output not understood")
            res.limitations.append("could not parse ping output")
        elif replied:
            avg = f", avg {ping['rtt_avg_ms']} ms" if "rtt_avg_ms" in ping else ""
            parts.append(f"ICMP {ping['received']}/{ping['sent']} replies{avg}")
        else:
            parts.append(f"no ICMP reply (0/{ping['sent']}); many hosts block ICMP, so this is not proof the host is down")
        res.summary = "; ".join(parts)
        return res
