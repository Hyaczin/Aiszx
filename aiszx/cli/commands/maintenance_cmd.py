"""``doctor`` (read-only health check) and ``backup`` (consistent archive of the data directory)."""

from __future__ import annotations

import argparse

from aiszx.app import AppContext
from aiszx.cli.output import emit_json
from aiszx.maintenance.doctor import FAIL, WARN, Doctor, summary, version_line

TAGS = {"ok": "[ OK ]", "info": "[INFO]", "warn": "[WARN]", "fail": "[FAIL]"}


def register(sub: argparse._SubParsersAction, common: argparse.ArgumentParser) -> None:
    d = sub.add_parser("doctor", parents=[common], help="check the installation (read-only)",
                       description="Checks Python and dependencies, configuration files, the data directory, free "
                                   "space, database integrity, interrupted runs, workspaces, logs and tools. Nothing "
                                   "is changed; each problem comes with the command that fixes it.")
    d.add_argument("--no-tools", action="store_true", help="skip the tool and nmap privilege checks")
    d.add_argument("--json", action="store_true")
    d.set_defaults(handler=cmd_doctor)

    b = sub.add_parser("backup", parents=[common], help="archive the database and workspaces",
                       description="Writes aiszx-backup-<time>.tar.gz (mode 0600) with a consistent database snapshot, "
                                   "the engagement workspaces and a manifest, plus a .sha256 file. Default location: "
                                   "aiszx-backups/ next to the data directory. Copy it off the VM to protect against "
                                   "disk loss. Restoring is manual: see docs/DEPLOYMENT.md.")
    b.add_argument("--out", metavar="DIR", help="directory for the archive (must be outside the data directory)")
    b.add_argument("--include-logs", action="store_true", help="also archive the central logs")
    b.add_argument("--verify", metavar="ARCHIVE", help="check an existing archive instead of creating one")
    b.add_argument("--json", action="store_true")
    b.set_defaults(handler=cmd_backup)


def cmd_doctor(ctx: AppContext, args: argparse.Namespace) -> int:
    checks = Doctor(ctx, tools=not args.no_tools).run()
    counts = summary(checks)
    if args.json:
        emit_json({"version": version_line(), "summary": counts, "checks": [c.to_dict() for c in checks]})
        return 1 if counts[FAIL] else 0
    print(version_line())
    area = None
    for c in checks:
        if c.area != area:
            area = c.area
            print(f"\n{area}")
        print(f"  {TAGS[c.status]} {c.message}")
        if c.fix and c.status != "ok":
            print(f"         -> {c.fix}")  # ASCII: doctor must work on any console encoding
    print(f"\n{counts['ok']} ok, {counts['info']} info, {counts[WARN]} warning(s), {counts[FAIL]} failure(s)")
    return 1 if counts[FAIL] else 0


def cmd_backup(ctx: AppContext, args: argparse.Namespace) -> int:
    from pathlib import Path

    from aiszx.maintenance.backup import create_backup, verify_backup
    from aiszx.maintenance.stats import human

    if args.verify:
        report = verify_backup(Path(args.verify))
        if args.json:
            emit_json(report)
        else:
            man = report.get("manifest", {})
            print(f"{report['archive']}: {'OK' if report['ok'] else 'PROBLEMS'}")
            print(f"  archive hash      : {report.get('archive_hash')}")
            print(f"  database integrity: {report.get('database_integrity', '-')}")
            if man:
                print(f"  created {man.get('created_at')} by Aiszx {man.get('framework_version')}, schema "
                      f"v{man.get('schema_version')}, counts {man.get('counts')}")
            for p in report["problems"]:
                print(f"  problem: {p}")
        return 0 if report["ok"] else 1
    res = create_backup(ctx, Path(args.out) if args.out else None, include_logs=args.include_logs)
    if args.json:
        emit_json({"archive": str(res.path), "sha256": res.sha256, "bytes": res.size, "files": res.files,
                   "warnings": res.warnings})
        return 0
    for w in res.warnings:
        print(f"warning: {w}")
    print(f"Backup written: {res.path} ({human(res.size)}, {res.files} files)")
    print(f"  sha256: {res.sha256}  (also in {res.path.name}.sha256)")
    print("  The archive contains evidence: keep it private and copy it off the VM.")
    print(f"  Check it with: python3 pentest.py backup --verify {res.path}")
    return 0
