"""Schema migrations.

Each ``aiszx/db/migrations/NNNN_name.sql`` runs inside one transaction together
with ``PRAGMA user_version = NNNN``; a failure rolls back that migration
completely. Before upgrading an existing database a backup copy is written next
to it using SQLite's online backup API.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from aiszx.core.errors import DatabaseError
from aiszx.core.timeutil import utcnow
from aiszx.db.connection import Database

_MIGRATION_RE = re.compile(r"^(\d{4})_([a-z0-9_]+)\.sql$")


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    sql: str

    @property
    def label(self) -> str:
        return f"{self.version:04d}_{self.name}"


@dataclass
class MigrationResult:
    from_version: int
    to_version: int
    applied: list[str] = field(default_factory=list)
    backup: Path | None = None


def discover_migrations() -> list[Migration]:
    found: list[Migration] = []
    for entry in resources.files("aiszx.db.migrations").iterdir():
        m = _MIGRATION_RE.fullmatch(entry.name)
        if m:
            found.append(Migration(int(m.group(1)), m.group(2), entry.read_text(encoding="utf-8")))
    found.sort(key=lambda mig: mig.version)
    expected = list(range(1, len(found) + 1))
    if [mig.version for mig in found] != expected:
        raise DatabaseError(f"migrations must be numbered contiguously from 0001; found {[mig.label for mig in found]}")
    return found


def latest_version() -> int:
    migrations = discover_migrations()
    return migrations[-1].version if migrations else 0


def _backup(db: Database, version: int) -> Path:
    stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
    target = db.path.with_name(f"{db.path.name}.bak-v{version}-{stamp}")
    dst = sqlite3.connect(str(target))
    try:
        db.conn.backup(dst)
    finally:
        dst.close()
    return target


def migrate(db: Database, *, backup: bool = True) -> MigrationResult:
    migrations = discover_migrations()
    current = db.user_version()
    latest = migrations[-1].version if migrations else 0
    if current > latest:
        raise DatabaseError(
            f"database schema v{current} is newer than this version of Aiszx supports (v{latest}); upgrade Aiszx"
        )
    result = MigrationResult(from_version=current, to_version=current)
    pending = [mig for mig in migrations if mig.version > current]
    if not pending:
        return result
    if backup and current > 0:
        result.backup = _backup(db, current)

    conn = db.conn
    for mig in pending:
        script = f"BEGIN IMMEDIATE;\n{mig.sql}\n;PRAGMA user_version = {mig.version};\nCOMMIT;"
        try:
            conn.executescript(script)
        except sqlite3.Error as exc:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise DatabaseError(f"migration {mig.label} failed and was rolled back: {exc}") from None
        result.applied.append(mig.label)
        result.to_version = mig.version

    problems = conn.execute("PRAGMA foreign_key_check").fetchall()
    if problems:
        raise DatabaseError(f"foreign key check failed after migration: {len(problems)} violation(s)")
    return result


def require_current(db: Database) -> None:
    """Refuse to operate on a database whose schema does not match the code."""
    current = db.user_version()
    latest = latest_version()
    if current < latest:
        raise DatabaseError(
            f"database schema is v{current} but this version of Aiszx expects v{latest}; "
            "run `python3 pentest.py init` to migrate (a backup is taken first)"
        )
    if current > latest:
        raise DatabaseError(f"database schema v{current} is newer than supported (v{latest}); upgrade Aiszx")
