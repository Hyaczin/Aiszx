"""``init``: create the data directory, database (or migrate it), default engagement; repair workspaces."""

from __future__ import annotations

import argparse

from aiszx import __version__
from aiszx.app import AppContext
from aiszx.cli.output import kv


def register(sub: argparse._SubParsersAction, common: argparse.ArgumentParser) -> None:
    p = sub.add_parser(
        "init", parents=[common], help="initialise or upgrade the data directory and database (idempotent)",
        description="Create the data directory, initialise or migrate the database, ensure the default "
                    "engagement exists and repair missing workspace directories. Safe to run repeatedly.",
    )
    p.set_defaults(handler=handle, creates_data_dir=True)


def handle(ctx: AppContext, args: argparse.Namespace) -> int:
    cfg = ctx.config
    ctx.layout.ensure_data_dir()
    db = ctx.open_db(migrate_schema=True)
    mig = ctx.migration
    engagement, created = ctx.engagements().ensure(cfg.default_engagement)

    store = ctx.engagements()
    manager = ctx.targets()
    checked = repaired = 0
    problems: list[str] = []
    for eng in store.list(include_archived=True):
        problems += ctx.layout.verify_engagement(eng.slug, repair=True).problems
        for target in manager.list(eng, include_archived=True):
            report = ctx.layout.verify_target(eng.slug, target.slug, repair=True)
            checked += 1
            repaired += len(report.repaired)
            problems += report.problems
        ctx.scope().write_mirror(eng)

    if mig and mig.applied:
        schema = f"v{mig.to_version} (applied {', '.join(mig.applied)})"
        if mig.backup:
            schema += f"; backup: {mig.backup}"
    else:
        schema = f"v{db.user_version()} (up to date)"
    user_file = cfg.user_config_dir / "framework.yaml"
    print(f"Aiszx {__version__} initialised")
    print(kv([
        ("data directory", cfg.data_dir),
        ("database", f"{cfg.db_path} — schema {schema}"),
        ("journal mode", db.journal_mode),
        ("configuration", ", ".join(str(s) for s in cfg.sources)),
        ("user overrides", user_file if user_file.is_file() else f"{user_file} (not present)"),
        ("engagement", f"{engagement.slug} ({'created' if created else 'exists'})"),
        ("workspaces", f"{checked} target(s) checked, {repaired} director(y/ies) repaired"),
    ]))
    if db.journal_mode != "wal":
        print("warning: SQLite WAL mode is unavailable on this filesystem (shared/network folder?). "
              "Keep the data directory on the VM's local disk.")
    for problem in problems:
        print(f"warning: {problem}")
    if not ctx.scope().rules(engagement):
        print("\nNext: define scope, e.g. `python3 pentest.py scope add 10.10.10.0/24`, then `target add <ip>`.")
    return 0
