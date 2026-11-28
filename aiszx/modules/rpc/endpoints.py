"""rpc.endpoints: anonymous MSRPC endpoint-mapper listing with impacket ``rpcdump`` (port 135/593).

The endpoint mapper answers without credentials on most Windows hosts; this is the same information
``rpcinfo``-style tools show. No credentials are sent and no RPC interface is called. Interfaces that are
known to be abusable for authentication coercion (print spooler, EFSRPC, DFS namespace management,
file server VSS agent) are flagged for manual review.
"""

from __future__ import annotations

import re

from aiszx.modules import _svc
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

# interface UUID (upper case) → short protocol name
NOTABLE = {
    "12345678-1234-ABCD-EF00-0123456789AB": "MS-RPRN (print spooler)",
    "76F03F96-CDFD-44FC-A22C-64950A001209": "MS-PAR (print spooler, async)",
    "C681D488-D850-11D0-8C52-00C04FD90F7E": "MS-EFSR (EFSRPC)",
    "DF1941C5-FE89-4E79-BF10-463657ACF44D": "MS-EFSR (EFSRPC)",
    "4FC742E0-4A10-11CF-8273-00AA004AE673": "MS-DFSNM (DFS namespace management)",
    "A8E0653C-2744-4389-A61D-7373DF8B2292": "MS-FSRVP (file server VSS agent)",
}
_FIELD_RE = re.compile(r"^(Protocol|Provider|UUID)\s*:\s*(.*)$")
_UUID_RE = re.compile(r"([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})(?:\s+v(\S+))?")


def parse_rpcdump(text: str) -> dict:
    """Blocks of 'Protocol: / Provider: / UUID: / Bindings:' lines; endpoints de-duplicated by UUID."""
    endpoints: dict[str, dict] = {}
    current: dict = {}
    in_bindings = False

    def flush() -> None:
        uuid = current.get("uuid")
        if uuid:
            entry = endpoints.setdefault(uuid, {"uuid": uuid, "version": current.get("version"),
                                                "protocol": current.get("protocol"), "provider": current.get("provider"),
                                                "bindings": []})
            for b in current.get("bindings", []):
                if b not in entry["bindings"]:
                    entry["bindings"].append(b)

    for raw in text.splitlines():
        line = raw.strip()
        m = _FIELD_RE.match(line)
        if m:
            key, value = m.group(1).lower(), m.group(2).strip()
            if key == "protocol" and current.get("uuid"):
                flush()
                current = {}
            in_bindings = False
            if key == "uuid":
                um = _UUID_RE.search(value)
                if um:
                    current["uuid"], current["version"] = um.group(1).upper(), um.group(2)
            else:
                current[key] = None if value in ("N/A", "") else value
        elif line.startswith("Bindings:"):
            in_bindings = True
        elif in_bindings and line and not line.startswith("["):
            current.setdefault("bindings", []).append(line)
        elif not line:
            in_bindings = False
    flush()
    m = re.search(r"Received (\d+) endpoints", text)
    return {"endpoints": sorted(endpoints.values(), key=lambda e: (e["protocol"] or "~", e["uuid"])),
            "received": int(m.group(1)) if m else None, "error": next((ln[3:].strip() for ln in text.splitlines()
                                                                     if ln.startswith("[-]")), None)}


def notable(endpoints: list[dict]) -> list[dict]:
    return [{"uuid": e["uuid"], "name": NOTABLE[e["uuid"]], "provider": e["provider"]}
            for e in endpoints if e["uuid"] in NOTABLE]


class RpcEndpoints(Module):
    meta = ModuleMeta(
        id="rpc.endpoints",
        version="1",
        description="Anonymous MSRPC endpoint-mapper listing (impacket rpcdump); flags coercion-prone interfaces",
        stage=Stage.ENUMERATION,
        safety=Safety.ACTIVE_SAFE,
        timeout_seconds=120,
        tools=(ToolRequirement("impacket-rpcdump"),),
        categories=("rpc",),
        retry=RetryPolicy(max_attempts=2, backoff_seconds=5),
    )

    def plan(self, ctx: PlanContext) -> list[WorkUnit]:
        return [u for u in _svc.per_service_units(self, ctx, ["rpc"]) if int(u.inputs["port"]) in (135, 593)]

    def build_commands(self, unit: WorkUnit, ctx: RunContext) -> list[Command]:
        a = unit.inputs["address"]
        return [Command("rpcdump", ["-port", str(unit.inputs["port"]), a], tool="impacket-rpcdump", targets=[a])]

    def parse(self, unit: WorkUnit, results, ctx: RunContext) -> ModuleResult:
        data = parse_rpcdump(_svc.result_text(results, "rpcdump"))
        res = ModuleResult(evidence_descriptions={"rpcdump.stdout.txt": "rpcdump endpoint-mapper listing"})
        flagged = notable(data["endpoints"])
        res.artifacts = {**data, "notable": flagged}
        url = f"tcp://{unit.inputs['address']}:{unit.inputs['port']}"
        if data["endpoints"]:
            res.observations.append({"key": "rpc.endpoint_mapper_anonymous", "url": url,
                                     "value": {"interfaces": len(data["endpoints"]), "received": data["received"]}})
        if flagged:
            res.observations.append({"key": "rpc.notable_interfaces", "value": flagged, "url": url})
        if not data["endpoints"]:
            res.limitations.append("no endpoints listed" + (f": {data['error']}" if data["error"] else ""))
        res.summary = (f"{len(data['endpoints'])} RPC interface(s)"
                       + (f"; notable: {', '.join(sorted({f['name'] for f in flagged}))}" if flagged else ""))
        return res
