"""Capability readiness: which future module groups can run with the tools present.

States
    ready        every required tool and at least one ``requires_any`` tool is OK, no optional tool missing
    degraded     runnable, but some optional/alternative tools are missing or unusable
    unavailable  a required tool is not OK, or none of the ``requires_any`` tools is OK

Module-level dependency checks (exact tools per module, version constraints) are added with
the module interface in Milestone 3 and reuse this inventory.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from aiszx.tools.inventory import BROKEN, INCOMPATIBLE, MISSING, OK, Inventory
from aiszx.tools.registry import ToolRegistry

READY = "ready"
DEGRADED = "degraded"
UNAVAILABLE = "unavailable"

_DEP_STATUS = {OK: "satisfied", MISSING: "missing", BROKEN: "broken", INCOMPATIBLE: "incompatible"}


@dataclass
class Requirement:
    tool: str
    requirement: str  # required | any_of | optional
    status: str       # satisfied | missing | broken | incompatible


@dataclass
class CapabilityStatus:
    name: str
    description: str
    state: str
    requirements: list[Requirement] = field(default_factory=list)
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self)}


def evaluate(registry: ToolRegistry, inventory: Inventory) -> list[CapabilityStatus]:
    results = []
    for cap in registry.capabilities.values():
        def status(tool: str) -> str:
            t = inventory.tools.get(tool)
            return _DEP_STATUS[t.status] if t else "missing"

        reqs = [Requirement(t, "required", status(t)) for t in cap.requires]
        reqs += [Requirement(t, "any_of", status(t)) for t in cap.requires_any if t not in cap.requires]
        reqs += [Requirement(t, "optional", status(t)) for t in cap.optional
                 if t not in cap.requires and t not in cap.requires_any]

        failed_required = [r.tool for r in reqs if r.requirement == "required" and r.status != "satisfied"]
        any_of = [r for r in reqs if r.requirement == "any_of"]
        any_ok = [r.tool for r in any_of if r.status == "satisfied"]
        soft_missing = [r.tool for r in reqs if r.requirement in ("any_of", "optional") and r.status != "satisfied"]

        if failed_required:
            state, message = UNAVAILABLE, f"needs {', '.join(failed_required)}"
        elif any_of and not any_ok:
            state, message = UNAVAILABLE, f"needs one of {', '.join(r.tool for r in any_of)}"
        elif soft_missing:
            state, message = DEGRADED, f"works; missing optional/alternative: {', '.join(soft_missing)}"
        else:
            state, message = READY, ""
        results.append(CapabilityStatus(cap.name, cap.description, state, reqs, message))
    return results
