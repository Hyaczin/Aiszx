"""http.content_discovery: wordlist-based path discovery with feroxbuster (preferred) or gobuster.

Noisy by nature (``active_noisy``): skipped by the conservative profile. Bounded by a time limit,
thread count and recursion depth from the module options.
"""

from __future__ import annotations

import json
import os
import re

from aiszx.modules.base import (
    Command,
    Module,
    ModuleMeta,
    ModuleResult,
    PlanContext,
    RetryPolicy,
    RunContext,
    Safety,
    Stage,
    ToolRequirement,
    WorkUnit,
)
from aiszx.modules.http import _web as web
from aiszx.modules.records import WebResourceRecord

DEFAULT_WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
    "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
]
_GOBUSTER_RE = re.compile(r"^(/\S*)\s+\(Status:\s*(\d{3})\)(?:\s+\[Size:\s*(\d+)\])?(?:\s+\[-->\s*(\S+)\])?")


def parse_ferox(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if item.get("type") == "response":
            out.append(item)
    return out


def parse_gobuster(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        m = _GOBUSTER_RE.match(line.strip())
        if m:
            out.append({"path": m.group(1), "status": int(m.group(2)),
                        "content_length": int(m.group(3)) if m.group(3) else None, "location": m.group(4)})
    return out


class ContentDiscovery(Module):
    meta = ModuleMeta(
        id="http.content_discovery",
        version="1",
        description="Path discovery with feroxbuster (or gobuster) using a wordlist; bounded by time and depth",
        stage=Stage.ENUMERATION,
        safety=Safety.ACTIVE_NOISY,
        timeout_seconds=1800,
        tools=(ToolRequirement("feroxbuster", optional=True), ToolRequirement("gobuster", optional=True)),
        categories=("http", "https"),
        retry=RetryPolicy(max_attempts=1),
        max_parallel=2,
        config_defaults={"wordlists": DEFAULT_WORDLISTS, "threads": 20, "depth": 2, "extensions": [],
                         "time_limit": "10m", "tool": "auto", "vhosts": [], "skip_categories": ["winrm"]},
    )

    def _tool(self, ctx) -> str | None:
        available = [t for t in ("feroxbuster", "gobuster") if t in ctx.tool_details]
        wanted = ctx.options.get("tool", "auto")
        if wanted != "auto":
            return wanted if wanted in available else None
        return available[0] if available else None

    @staticmethod
    def _wordlist(ctx) -> str | None:
        return next((w for w in ctx.options["wordlists"] if os.path.isfile(w)), None)

    def unavailable_reason(self, ctx: PlanContext) -> str | None:
        if self._tool(ctx) is None:
            return "needs feroxbuster or gobuster (see `tools missing`)"
        if self._wordlist(ctx) is None:
            return ("no wordlist found; install one (e.g. `sudo apt install seclists`) or set "
                    "modules.http.content_discovery.options.wordlists")
        return None

    def plan(self, ctx: PlanContext) -> list[WorkUnit]:
        tool, wordlist = self._tool(ctx), self._wordlist(ctx)
        return [WorkUnit(self.meta.id, ep.key, {**ep.inputs(), "tool": tool, "wordlist": wordlist})
                for ep in web.endpoints(ctx)]

    def build_commands(self, unit: WorkUnit, ctx: RunContext) -> list[Command]:
        ep = web.Endpoint.from_inputs(dict(unit.inputs))
        o = ctx.options
        exts = ",".join(e.lstrip(".") for e in o["extensions"])
        if unit.inputs["tool"] == "feroxbuster":
            argv = ["-u", ep.address_url, "-w", unit.inputs["wordlist"], "-t", str(int(o["threads"])),
                    "-d", str(int(o["depth"])), "-k", "--no-state", "--json", "-o", "ferox.json",
                    "--time-limit", str(o["time_limit"]), "--silent", *web.host_header(ep)]
            if exts:
                argv += ["-x", exts]
            return [Command("ferox", argv, tool="feroxbuster", targets=web.targets(ep), ok_exit_codes=(0, 1))]
        argv = ["dir", "-u", ep.address_url, "-w", unit.inputs["wordlist"], "-t", str(int(o["threads"])), "-k", "-q",
                "--no-error", "-o", "gobuster.txt", "--timeout", "10s", *web.host_header(ep)]
        if exts:
            argv += ["-x", exts]
        return [Command("gobuster", argv, tool="gobuster", targets=web.targets(ep), ok_exit_codes=(0, 1))]

    def parse(self, unit: WorkUnit, results, ctx: RunContext) -> ModuleResult:
        ep = web.Endpoint.from_inputs(dict(unit.inputs))
        raw = ctx.attempt_dir / "raw"
        tool = unit.inputs["tool"]
        res = ModuleResult(evidence_descriptions={"ferox.json": "feroxbuster JSON results",
                                                  "gobuster.txt": "gobuster results"})

        def read(name: str) -> str:
            try:
                return (raw / name).read_text(encoding="utf-8", errors="replace")
            except OSError:
                return ""

        if tool == "feroxbuster":
            for item in parse_ferox(read("ferox.json")):
                url = item.get("url", "")
                path = item.get("path") or re.sub(r"^[a-z]+://[^/]+", "", url) or "/"
                location = (item.get("headers") or {}).get("location")
                res.resources.append(WebResourceRecord(ep.url, web.build_url(ep.scheme, ep.host, ep.port, path), path,
                                                       item.get("status"), item.get("content_length"), location,
                                                       "feroxbuster"))
        else:
            for item in parse_gobuster(read("gobuster.txt")):
                res.resources.append(WebResourceRecord(ep.url, web.build_url(ep.scheme, ep.host, ep.port, item["path"]),
                                                       item["path"], item["status"], item["content_length"],
                                                       item["location"], "gobuster"))
            if int(ctx.options["depth"]) > 1:
                res.limitations.append("gobuster does not recurse; only the top level was tested")
        uniq = {r.url: r for r in res.resources}
        res.resources = sorted(uniq.values(), key=lambda r: r.path)
        res.artifacts = {"tool": tool, "wordlist": unit.inputs["wordlist"], "count": len(res.resources)}
        res.limitations.append(f"coverage limited to wordlist {os.path.basename(unit.inputs['wordlist'])} "
                               f"and time limit {ctx.options['time_limit']}")
        shown = ", ".join(f"{r.path} ({r.status})" for r in res.resources[:10])
        res.summary = (f"{len(res.resources)} path(s) via {tool}: {shown}" + (" ..." if len(res.resources) > 10 else "")
                       if res.resources else f"no paths found via {tool}")
        return res
