"""Plain-text output helpers (no third-party dependencies)."""

from __future__ import annotations

import json
import sys
from typing import Any, Sequence

from aiszx.targets.scope import ScopeDecision


def emit_json(obj: Any) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False, default=str))


def table(rows: Sequence[Sequence[Any]], headers: Sequence[str], indent: str = "") -> str:
    cells = [[str(h) for h in headers]] + [["" if c is None else str(c) for c in row] for row in rows]
    widths = [max(len(r[i]) for r in cells) for i in range(len(headers))]
    lines = []
    for n, row in enumerate(cells):
        lines.append(indent + "  ".join(c.ljust(widths[i]) for i, c in enumerate(row)).rstrip())
        if n == 0:
            lines.append(indent + "  ".join("-" * w for w in widths))
    return "\n".join(lines)


def kv(pairs: Sequence[tuple[str, Any]], indent: str = "  ") -> str:
    width = max((len(k) for k, _ in pairs), default=0)
    return "\n".join(f"{indent}{k.ljust(width)} : {'-' if v in (None, '') else v}" for k, v in pairs)


def format_decision(decision: ScopeDecision, indent: str = "  ") -> str:
    verdict = "IN SCOPE" if decision.in_scope else "OUT OF SCOPE"
    lines = [f"{indent}{decision.value}: {verdict}"]
    lines += [f"{indent}  reason : {r}" for r in decision.reasons]
    lines += [f"{indent}  warning: {w}" for w in decision.warnings]
    for ad in decision.addresses:
        if ad.address != decision.value:
            lines.append(f"{indent}  address {ad.address}: {'in' if ad.in_scope else 'OUT'} ({ad.reason})")
    return "\n".join(lines)


def confirm(prompt: str, *, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        print(f"{prompt} [y/N] refusing: no interactive terminal (use --yes to confirm)", file=sys.stderr)
        return False
    try:
        answer = input(f"{prompt} [y/N] ").strip().lower()
    except EOFError:
        return False
    return answer in ("y", "yes")
