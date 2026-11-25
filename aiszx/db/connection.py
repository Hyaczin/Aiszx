"""SQLite connection wrapper.

* ``foreign_keys=ON``, WAL journal, ``busy_timeout`` so short concurrent writes wait instead of failing.
* Explicit transactions via :meth:`Database.transaction`; nested calls become SAVEPOINTs,
  so a store method can be transactional on its own *and* compose inside a larger operation.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Sequence

from aiszx.core.errors import DatabaseError

BUSY_TIMEOUT_MS = 5000


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._conn: sqlite3.Connection | None = None
        self._depth = 0
        self.journal_mode: str | None = None

    # -- lifecycle -----------------------------------------------------------
    def connect(self) -> "Database":
        if self._conn is not None:
            return self
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            conn = sqlite3.connect(str(self.path), isolation_level=None, timeout=BUSY_TIMEOUT_MS / 1000)
        except sqlite3.Error as exc:
            raise DatabaseError(f"cannot open database {self.path}: {exc}") from None
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
        # WAL fails on some network/shared filesystems (e.g. VMware shared folders); fall back gracefully.
        self.journal_mode = str(conn.execute("PRAGMA journal_mode = WAL").fetchone()[0]).lower()
        conn.execute("PRAGMA synchronous = NORMAL")
        self._conn = conn
        return self

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise DatabaseError("database is not connected")
        return self._conn

    # -- transactions --------------------------------------------------------
    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        conn = self.conn
        if self._depth == 0:
            conn.execute("BEGIN IMMEDIATE")
            begin, commit, rollback = None, "COMMIT", "ROLLBACK"
        else:
            name = f"sp_{self._depth}"
            conn.execute(f"SAVEPOINT {name}")
            begin, commit, rollback = name, f"RELEASE SAVEPOINT {name}", f"ROLLBACK TO SAVEPOINT {name}"
        self._depth += 1
        try:
            yield conn
        except BaseException:
            self._depth -= 1
            # SQLite may already have rolled back on some errors; only undo what is still open.
            if conn.in_transaction:
                conn.execute(rollback)
                if begin is not None:
                    conn.execute(f"RELEASE SAVEPOINT {begin}")
            raise
        else:
            self._depth -= 1
            conn.execute(commit)

    # -- helpers -------------------------------------------------------------
    def execute(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Cursor:
        return self.conn.execute(sql, params)

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        return self.conn.execute(sql, params).fetchall()

    def query_one(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
        return self.conn.execute(sql, params).fetchone()

    def user_version(self) -> int:
        return int(self.conn.execute("PRAGMA user_version").fetchone()[0])
