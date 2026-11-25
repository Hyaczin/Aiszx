import sqlite3

import pytest

from aiszx.core.errors import DatabaseError
from aiszx.db import migrate as migrate_mod
from aiszx.db.connection import Database
from aiszx.db.migrate import Migration, latest_version, migrate, require_current


def test_fresh_migration_sets_version(tmp_path):
    db = Database(tmp_path / "a.db").connect()
    result = migrate(db)
    assert result.from_version == 0 and result.to_version == latest_version() >= 1
    assert "0001_foundation" in result.applied
    assert result.backup is None  # nothing to back up for a new database
    tables = {r[0] for r in db.query("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"engagements", "scope_rules", "targets", "target_addresses", "audit_events"} <= tables
    db.close()


def test_migration_is_idempotent(tmp_path):
    db = Database(tmp_path / "a.db").connect()
    migrate(db)
    again = migrate(db)
    assert again.applied == [] and again.from_version == again.to_version
    require_current(db)
    db.close()


def test_wal_and_foreign_keys_enabled(tmp_path):
    db = Database(tmp_path / "a.db").connect()
    migrate(db)
    assert db.journal_mode == "wal"
    with pytest.raises(sqlite3.IntegrityError):
        db.execute(
            "INSERT INTO targets (id, engagement_id, canonical_id, kind, slug, source, created_at, updated_at)"
            " VALUES ('t', 'missing-engagement', 'x', 'ipv4', 'x', 'manual', 'now', 'now')"
        )
    db.close()


def test_newer_schema_is_refused(tmp_path):
    db = Database(tmp_path / "a.db").connect()
    migrate(db)
    db.execute(f"PRAGMA user_version = {latest_version() + 5}")
    with pytest.raises(DatabaseError, match="newer"):
        migrate(db)
    with pytest.raises(DatabaseError, match="newer"):
        require_current(db)
    db.close()


def test_outdated_schema_requires_init(tmp_path):
    db = Database(tmp_path / "a.db").connect()
    with pytest.raises(DatabaseError, match="run `python3 pentest.py init`"):
        require_current(db)
    db.close()


def test_failed_migration_rolls_back_and_backs_up(tmp_path, monkeypatch):
    db = Database(tmp_path / "a.db").connect()
    migrate(db)
    good = migrate_mod.discover_migrations()
    broken = Migration(len(good) + 1, "broken", "CREATE TABLE half_done (x INTEGER);\nTHIS IS NOT SQL;")
    monkeypatch.setattr(migrate_mod, "discover_migrations", lambda: good + [broken])
    with pytest.raises(DatabaseError, match="rolled back"):
        migrate(db)
    assert db.user_version() == len(good)
    assert db.query_one("SELECT name FROM sqlite_master WHERE name = 'half_done'") is None
    assert list(tmp_path.glob("a.db.bak-v*")), "a backup should be taken before upgrading an existing database"
    db.close()


def test_nested_transaction_rolls_back_inner_only(tmp_path):
    db = Database(tmp_path / "a.db").connect()
    migrate(db)
    with db.transaction():
        db.execute("INSERT INTO engagements (id, slug, name, created_at, updated_at) VALUES ('1', 'a', 'a', 'n', 'n')")
        with pytest.raises(RuntimeError):
            with db.transaction():
                db.execute("INSERT INTO engagements (id, slug, name, created_at, updated_at) VALUES ('2', 'b', 'b', 'n', 'n')")
                raise RuntimeError("inner failure")
    slugs = [r["slug"] for r in db.query("SELECT slug FROM engagements")]
    assert slugs == ["a"]
    db.close()


def test_outer_transaction_failure_rolls_back_everything(tmp_path):
    db = Database(tmp_path / "a.db").connect()
    migrate(db)
    with pytest.raises(RuntimeError):
        with db.transaction():
            db.execute("INSERT INTO engagements (id, slug, name, created_at, updated_at) VALUES ('1', 'a', 'a', 'n', 'n')")
            raise RuntimeError("boom")
    assert db.query("SELECT * FROM engagements") == []
    db.close()
