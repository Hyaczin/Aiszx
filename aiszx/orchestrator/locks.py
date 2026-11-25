"""Database-backed locks that prevent the same work from running twice concurrently.

A lock is live when its owner process is still running on this host (same boot).
Locks owned by another host are trusted until their heartbeat is older than
``stale_after`` seconds.
"""

from __future__ import annotations

from datetime import timedelta

from aiszx.core.timeutil import iso, parse_iso, utcnow
from aiszx.db.connection import Database
from aiszx.orchestrator.procutil import Owner


class LockManager:
    def __init__(self, db: Database, owner: Owner, stale_after: int) -> None:
        self.db = db
        self.owner = owner
        self.stale_after = stale_after

    def _live(self, row) -> bool:
        if row["owner_pid"] == self.owner.pid and row["owner_host"] == self.owner.host:
            return True
        alive = self.owner.is_alive(row["owner_pid"], row["owner_host"], row["boot_id"])
        if alive is None:
            return utcnow() - parse_iso(row["heartbeat_at"]) < timedelta(seconds=self.stale_after)
        return alive

    def acquire(self, key: str, execution_id: str | None) -> tuple[bool, str | None]:
        with self.db.transaction():
            row = self.db.query_one("SELECT * FROM locks WHERE resource_key = ?", (key,))
            if row is not None:
                if self._live(row):
                    if row["owner_pid"] == self.owner.pid and row["execution_id"] == execution_id:
                        return True, None
                    return False, f"held by pid {row['owner_pid']} on {row['owner_host']} since {row['acquired_at']}"
                self.db.execute("DELETE FROM locks WHERE resource_key = ?", (key,))
            now = iso()
            self.db.execute(
                "INSERT INTO locks (resource_key, execution_id, owner_pid, owner_host, boot_id, acquired_at, heartbeat_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (key, execution_id, self.owner.pid, self.owner.host, self.owner.boot, now, now),
            )
        return True, None

    def release(self, key: str) -> None:
        self.db.execute("DELETE FROM locks WHERE resource_key = ? AND owner_pid = ? AND owner_host = ?",
                        (key, self.owner.pid, self.owner.host))

    def release_execution(self, execution_id: str) -> None:
        self.db.execute("DELETE FROM locks WHERE execution_id = ? AND owner_pid = ? AND owner_host = ?",
                        (execution_id, self.owner.pid, self.owner.host))

    def heartbeat(self, execution_id: str) -> None:
        self.db.execute("UPDATE locks SET heartbeat_at = ? WHERE execution_id = ? AND owner_pid = ?",
                        (iso(), execution_id, self.owner.pid))

    def reap_stale(self) -> list[str]:
        stale = [r["resource_key"] for r in self.db.query("SELECT * FROM locks") if not self._live(r)]
        for key in stale:
            self.db.execute("DELETE FROM locks WHERE resource_key = ?", (key,))
        return stale
