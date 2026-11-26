"""Command-line entry point: ``python3 pentest.py <command> ...``.

Global options (``--data-dir``, ``--config-dir``, ``-e/--engagement``, ``-v``, ``-q``, ``-y``)
are accepted both before and after the command name.
"""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from aiszx import __version__
from aiszx.app import AppContext
from aiszx.cli.commands import (
    assess_cmd,
    config_cmd,
    engagement_cmd,
    enum_cmd,
    history_cmd,
    init_cmd,
    maintenance_cmd,
    modules_cmd,
    recon_cmd,
    report_cmd,
    run_cmd,
    scope_cmd,
    target_cmd,
    tools_cmd,
    workspace_cmd,
)
from aiszx.core.errors import AiszxError
from aiszx.core.logging import get_logger, setup_logging, shutdown_logging

COMMAND_MODULES = (init_cmd, engagement_cmd, target_cmd, scope_cmd, workspace_cmd, tools_cmd, modules_cmd,
                   recon_cmd, enum_cmd, assess_cmd, report_cmd, run_cmd, history_cmd, config_cmd, maintenance_cmd)
GLOBAL_DEFAULTS = {"data_dir": None, "config_dir": None, "engagement": None, "verbose": 0, "quiet": False, "yes": False}


def _common_options() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    g = common.add_argument_group("global options")
    s = argparse.SUPPRESS  # so a value given before the command is not reset by the subcommand's defaults
    g.add_argument("--data-dir", default=s, help="runtime data directory (default: $AISZX_DATA_DIR or ~/.local/share/aiszx)")
    g.add_argument("--config-dir", default=s, help="user configuration directory (default: ~/.config/aiszx)")
    g.add_argument("-e", "--engagement", default=s, help="engagement name (default: engagements.default_slug)")
    g.add_argument("-v", "--verbose", action="count", default=s, help="more console output (-vv for debug)")
    g.add_argument("-q", "--quiet", action="store_true", default=s, help="errors only on the console")
    g.add_argument("-y", "--yes", action="store_true", default=s, help="answer yes to confirmations")
    return common


def build_parser() -> argparse.ArgumentParser:
    common = _common_options()
    parser = argparse.ArgumentParser(
        prog="pentest.py",
        parents=[common],
        description="Aiszx: reconnaissance, enumeration and assessment framework for AUTHORISED testing.",
        epilog="Run `pentest.py COMMAND --help` for command details.",
    )
    parser.add_argument("--version", action="version", version=f"Aiszx {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    for module in COMMAND_MODULES:
        module.register(sub, common)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    for key, value in GLOBAL_DEFAULTS.items():
        if not hasattr(args, key):
            setattr(args, key, value)
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return 2

    ctx: AppContext | None = None
    try:
        ctx = AppContext.create(data_dir=args.data_dir, config_dir=args.config_dir, assume_yes=args.yes)
        if getattr(args, "creates_data_dir", False):
            ctx.layout.ensure_data_dir()
        log_dir = ctx.config.log_dir if ctx.config.data_dir.is_dir() else None
        setup_logging(ctx.config.logging, log_dir, verbosity=args.verbose, quiet=args.quiet)
        get_logger("cli").debug("command %s", args.command)
        return int(handler(ctx, args) or 0)
    except AiszxError as exc:
        print(f"error: {exc}", file=sys.stderr)
        get_logger("cli").debug("command %s failed: %s", args.command, exc)
        return exc.exit_code
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    finally:
        if ctx is not None:
            ctx.close()
        shutdown_logging()


if __name__ == "__main__":
    sys.exit(main())
