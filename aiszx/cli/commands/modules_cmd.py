"""``modules list|show``: the module catalogue."""

from __future__ import annotations

import argparse

from aiszx.app import AppContext
from aiszx.cli.commands import help_handler
from aiszx.cli.output import emit_json, kv, table


def register(sub: argparse._SubParsersAction, common: argparse.ArgumentParser) -> None:
    p = sub.add_parser("modules", help="list available modules and their requirements")
    p.set_defaults(handler=help_handler(p))
    msub = p.add_subparsers(dest="modules_action", metavar="ACTION")
    ls = msub.add_parser("list", parents=[common], help="list modules")
    ls.add_argument("--json", action="store_true")
    ls.set_defaults(handler=cmd_list)
    sh = msub.add_parser("show", parents=[common], help="details of one module")
    sh.add_argument("module_id", metavar="MODULE")
    sh.set_defaults(handler=cmd_show)


def _tools(meta) -> str:
    return ", ".join(t.name + ("?" if t.optional else "") + (f">={t.min_version}" if t.min_version else "")
                     for t in meta.tools) or "-"


def cmd_list(ctx: AppContext, args: argparse.Namespace) -> int:
    registry = ctx.module_registry()
    metas = [m.meta for m in registry.modules.values()]
    if args.json:
        emit_json([{"id": m.id, "version": m.version, "stage": m.stage.value, "safety": m.safety.value,
                    "tools": [t.name for t in m.tools], "description": m.description} for m in metas])
        return 0
    print(table([(m.id, m.stage.value, m.safety.value, _tools(m), m.description) for m in metas],
                ("MODULE", "STAGE", "SAFETY", "TOOLS (?=optional)", "DESCRIPTION")))
    return 0


def cmd_show(ctx: AppContext, args: argparse.Namespace) -> int:
    meta = ctx.module_registry().get(args.module_id).meta
    print(f"Module {meta.id} (version {meta.version})")
    print(kv([
        ("description", meta.description), ("stage", meta.stage.value), ("safety", meta.safety.value),
        ("tools", _tools(meta)), ("categories", ", ".join(meta.categories)), ("depends on", ", ".join(meta.depends_on)),
        ("timeout", f"{meta.timeout_seconds}s"),
        ("retry", f"{meta.retry.max_attempts} attempt(s) on {', '.join(meta.retry.retry_on)}, "
                  f"backoff {meta.retry.backoff_seconds}s x{meta.retry.backoff_factor}"),
        ("resumable", "yes" if meta.resumable else "no"),
        ("options", ", ".join(f"{k}={v}" for k, v in meta.config_defaults.items())),
    ]))
    return 0
