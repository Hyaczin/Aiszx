"""http.vhost_discovery: name-based virtual-host discovery with ffuf (preferred) or gobuster ``vhost``.

Requests go to the target's pinned in-scope address; only the Host header varies (``<word>.<base>``).
Base domains are names that already passed the scope check: the target's own hostname, accepted
virtual hosts (``hints accept``) and ``--vhost`` names. Nothing is discovered without one.

Catch-all servers answer every name the same way. ffuf's auto-calibration (``-ac``) drops those
responses; in addition, any (status, size) combination returned for many names is discarded for both
tools. What is left is reported as host-name *hints*: they are not tested until you accept them.

Noisy by nature (``active_noisy``): skipped by the conservative profile.
"""

from __future__ import annotations

import json
import math
import os
import re
from collections import Counter

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
from aiszx.targets.identity import normalise_hostname

DEFAULT_WORDLISTS = [
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/seclists/Discovery/DNS/namelist.txt",
    "/usr/share/wordlists/amass/subdomains-top1mil-5000.txt",
]
_GOBUSTER_RE = re.compile(r"^Found:\s+(\S+)\s+\(?Status:\s*(\d{3})\)?\s*\[Size:\s*(\d+)\]", re.IGNORECASE)


def base_domains(ctx: PlanContext) -> list[str]:
    names = [] if ctx.target.identity.is_ip else [ctx.target.canonical]
    names += list(ctx.run_params.get("vhosts", []))
    out: list[str] = []
    for n in names:
        try:
            host = normalise_hostname(n)
        except Exception:
            continue
        if "." in host and host not in out:
            out.append(host)
    return out[: int(ctx.options.get("max_domains", 3))]


def parse_ffuf(text: str, base: str) -> list[dict]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    out = []
    for r in data.get("results", []) if isinstance(data, dict) else []:
        word = (r.get("input") or {}).get("FUZZ")
        if not word:
            continue
        out.append({"name": f"{word}.{base}".lower(), "status": r.get("status"), "length": r.get("length"),
                    "words": r.get("words"), "redirect": r.get("redirectlocation") or None})
    return out


def parse_gobuster_vhost(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        m = _GOBUSTER_RE.match(line.strip())
        if m:
            out.append({"name": m.group(1).lower(), "status": int(m.group(2)), "length": int(m.group(3)),
                        "words": None, "redirect": None})
    return out


def drop_catch_all(found: list[dict]) -> tuple[list[dict], list[tuple]]:
    """Remove (status, length) combinations returned for many names: those are a default/catch-all page."""
    counts = Counter((f["status"], f["length"]) for f in found)
    threshold = max(3, math.ceil(0.1 * len(found)))
    noisy = {k for k, n in counts.items() if n >= threshold}
    return [f for f in found if (f["status"], f["length"]) not in noisy], sorted(noisy, key=str)


class VhostDiscovery(Module):
    meta = ModuleMeta(
        id="http.vhost_discovery",
        version="1",
        description="Name-based virtual-host discovery (ffuf or gobuster vhost) under accepted base domains",
        stage=Stage.ENUMERATION,
        safety=Safety.ACTIVE_NOISY,
        timeout_seconds=1200,
        tools=(ToolRequirement("ffuf", optional=True), ToolRequirement("gobuster", optional=True)),
        categories=("http", "https"),
        retry=RetryPolicy(max_attempts=1),
        max_parallel=1,
        config_defaults={"wordlists": DEFAULT_WORDLISTS, "threads": 20, "max_time": 300, "rate": 0,
                         "max_domains": 3, "tool": "auto", "skip_categories": ["winrm"]},
    )

    def _tool(self, ctx) -> str | None:
        available = [t for t in ("ffuf", "gobuster") if t in ctx.tool_details]
        wanted = ctx.options.get("tool", "auto")
        if wanted != "auto":
            return wanted if wanted in available else None
        return available[0] if available else None

    @staticmethod
    def _wordlist(ctx) -> str | None:
        return next((w for w in ctx.options["wordlists"] if os.path.isfile(w)), None)

    def unavailable_reason(self, ctx: PlanContext) -> str | None:
        if self._tool(ctx) is None:
            return "needs ffuf or gobuster (see `tools missing`)"
        if self._wordlist(ctx) is None:
            return ("no subdomain wordlist found; install one (e.g. `sudo apt install seclists`) or set "
                    "modules.http.vhost_discovery.options.wordlists")
        return None

    def plan(self, ctx: PlanContext) -> list[WorkUnit]:
        bases = base_domains(ctx)
        tool, wordlist = self._tool(ctx), self._wordlist(ctx)
        units = []
        for svc in web.web_services(ctx.services, ctx.options.get("skip_categories", ("winrm",))):
            scheme = "https" if "https" in svc.categories or (svc.tunnel or "") == "ssl" else "http"
            for base in bases:
                units.append(WorkUnit(self.meta.id, f"{svc.key}@{base}",
                                      {"address": ctx.address, "port": svc.port, "scheme": scheme, "base": base,
                                       "service_key": svc.key, "tool": tool, "wordlist": wordlist}))
        return units

    def build_commands(self, unit: WorkUnit, ctx: RunContext) -> list[Command]:
        i, o = unit.inputs, ctx.options
        url = web.build_url(i["scheme"], i["address"], int(i["port"]))
        targets = [i["address"], i["base"]]  # the base name is pinned to the address and scope-checked like --vhost
        if i["tool"] == "ffuf":
            argv = ["-u", url, "-H", f"Host: FUZZ.{i['base']}", "-w", i["wordlist"], "-t", str(int(o["threads"])),
                    "-mc", "all", "-ac", "-of", "json", "-o", "ffuf.json", "-s", "-timeout", "10",
                    "-maxtime", str(int(o["max_time"]))]
            if int(o.get("rate") or 0) > 0:
                argv += ["-rate", str(int(o["rate"]))]
            return [Command("ffuf", argv, tool="ffuf", targets=targets, timeout=int(o["max_time"]) + 60)]
        argv = ["vhost", "-u", url, "--domain", i["base"], "--append-domain", "-w", i["wordlist"],
                "-t", str(int(o["threads"])), "-k", "-q", "--no-error", "-o", "gobuster.txt", "--timeout", "10s"]
        return [Command("gobuster", argv, tool="gobuster", targets=targets, ok_exit_codes=(0, 1),
                        timeout=int(o["max_time"]) + 60)]

    def parse(self, unit: WorkUnit, results, ctx: RunContext) -> ModuleResult:
        i = unit.inputs
        raw = ctx.attempt_dir / "raw"
        res = ModuleResult(evidence_descriptions={"ffuf.json": "ffuf virtual-host results (JSON)",
                                                  "gobuster.txt": "gobuster vhost results"})

        def read(name: str) -> str:
            try:
                return (raw / name).read_text(encoding="utf-8", errors="replace")
            except OSError:
                return ""

        found = parse_ffuf(read("ffuf.json"), i["base"]) if i["tool"] == "ffuf" else parse_gobuster_vhost(read("gobuster.txt"))
        found = [f for f in found if f["name"].endswith("." + i["base"]) and f["name"] != i["base"]]
        kept, dropped = drop_catch_all(found)
        n_dropped = len(found) - len(kept)
        kept = sorted({f["name"]: f for f in kept}.values(), key=lambda f: f["name"])
        res.artifacts = {"tool": i["tool"], "base": i["base"], "wordlist": i["wordlist"], "found": kept,
                         "discarded_as_catch_all": [list(d) for d in dropped], "raw_matches": len(found)}
        url = web.build_url(i["scheme"], i["address"], int(i["port"]))
        if kept:
            res.observations.append({"key": "http.vhost_found", "value": [f["name"] for f in kept], "url": url})
            res.limitations.append(f"discovered name(s) are not tested yet: review with `hints list` and accept the "
                                   f"ones you want (`hints accept {ctx.target.canonical} NAME`)")
        if dropped:
            res.limitations.append(f"{n_dropped} response(s) discarded as a catch-all page (same status and size for "
                                   "many names)")
        res.limitations.append(f"coverage limited to wordlist {os.path.basename(i['wordlist'])} under {i['base']}")
        shown = ", ".join(f"{f['name']} ({f['status']})" for f in kept[:8])
        res.summary = (f"{len(kept)} virtual host(s) under {i['base']} via {i['tool']}: {shown}"
                       + (" ..." if len(kept) > 8 else "") if kept else f"no virtual hosts found under {i['base']}")
        return res
