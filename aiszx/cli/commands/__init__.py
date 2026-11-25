"""CLI command groups. Each module exposes ``register(subparsers, common_parent)``."""

from __future__ import annotations

import argparse
from typing import Callable

from aiszx.app import AppContext


def help_handler(parser: argparse.ArgumentParser) -> Callable[[AppContext, argparse.Namespace], int]:
    """Handler for a command group invoked without an action: print its help."""

    def _show(_ctx: AppContext, _args: argparse.Namespace) -> int:
        parser.print_help()
        return 2

    return _show


def engagement_slug(ctx: AppContext, args: argparse.Namespace) -> str:
    return args.engagement or ctx.config.default_engagement
