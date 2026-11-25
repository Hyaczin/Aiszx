"""``config show``: print the effective (merged, validated) configuration and where it came from."""

from __future__ import annotations

import argparse

import yaml

from aiszx.app import AppContext
from aiszx.cli.commands import help_handler
from aiszx.cli.output import emit_json


def register(sub: argparse._SubParsersAction, common: argparse.ArgumentParser) -> None:
    p = sub.add_parser("config", help="inspect the effective configuration")
    p.set_defaults(handler=help_handler(p))
    csub = p.add_subparsers(dest="config_action", metavar="ACTION")
    s = csub.add_parser("show", parents=[common], help="show merged configuration and its sources (validates it)")
    s.add_argument("--json", action="store_true")
    s.set_defaults(handler=cmd_show)


def cmd_show(ctx: AppContext, args: argparse.Namespace) -> int:
    cfg = ctx.config
    effective = {
        "sources": [str(s) for s in cfg.sources],
        "user_config_dir": str(cfg.user_config_dir),
        "data_dir": str(cfg.data_dir),
        "database": str(cfg.db_path),
        "settings": cfg.raw,
    }
    if args.json:
        emit_json(effective)
    else:
        print("# configuration is valid")
        print(yaml.safe_dump(effective, sort_keys=False, default_flow_style=False).rstrip())
    return 0
