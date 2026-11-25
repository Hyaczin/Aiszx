"""Helpers shared by the service enumeration modules (Milestone 6)."""

from __future__ import annotations

import base64
import re
from typing import Any, Iterable

from aiszx.modules.base import Module, PlanContext, RunContext, WorkUnit
from aiszx.modules.records import ServiceRecord

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)


def services_in(ctx: PlanContext, categories: Iterable[str], protocol: str | None = None) -> list[ServiceRecord]:
    cats = set(categories)
    return [s for s in ctx.services
            if s.state == "open" and cats & set(s.categories) and (protocol is None or s.protocol == protocol)]


def service_inputs(ctx: PlanContext, svc: ServiceRecord) -> dict[str, Any]:
    return {"address": ctx.address, "port": svc.port, "protocol": svc.protocol, "name": svc.name,
            "product": svc.product, "version": svc.version}


def per_service_units(module: Module, ctx: PlanContext, categories: Iterable[str],
                      protocol: str | None = "tcp") -> list[WorkUnit]:
    return [WorkUnit(module.meta.id, s.key, service_inputs(ctx, s)) for s in services_in(ctx, categories, protocol)]


def per_host_unit(module: Module, ctx: PlanContext, categories: Iterable[str], **extra: Any) -> list[WorkUnit]:
    svcs = services_in(ctx, categories)
    if not svcs:
        return []
    return [WorkUnit(module.meta.id, "host", {"address": ctx.address, "services": sorted(s.key for s in svcs),
                                               "ports": sorted({s.port for s in svcs}), **extra})]


def read(ctx: RunContext, name: str, limit: int = 5_000_000) -> str:
    try:
        return (ctx.attempt_dir / "raw" / name).read_bytes()[:limit].decode("utf-8", errors="replace")
    except OSError:
        return ""


def result_text(results, label: str) -> str:
    r = next((r for r in results if r.label == label), None)
    return "" if r is None else strip_ansi(r.stdout() + "\n" + r.stderr())


def parse_ldif(text: str) -> list[dict[str, list[str]]]:
    """Minimal LDIF reader: entries separated by blank lines, folded lines, base64 ('attr:: ') values."""
    entries: list[dict[str, list[str]]] = []
    current: dict[str, list[str]] = {}
    lines: list[str] = []
    for raw in text.splitlines():
        if raw.startswith(" ") and lines:
            lines[-1] += raw[1:]
        else:
            lines.append(raw)
    for line in lines + [""]:
        if not line.strip():
            if current:
                entries.append(current)
                current = {}
            continue
        if line.startswith("#") or ":" not in line:
            continue
        attr, _, value = line.partition(":")
        if value.startswith(":"):
            try:
                value = base64.b64decode(value[1:].strip()).decode("utf-8", errors="replace")
            except ValueError:
                value = value[1:].strip()
        else:
            value = value.strip()
        current.setdefault(attr.strip(), []).append(value)
    return entries


def dn_to_domain(dn: str | None) -> str | None:
    if not dn:
        return None
    parts = [p.split("=", 1)[1] for p in dn.split(",") if p.strip().upper().startswith("DC=")]
    return ".".join(parts).lower() or None
