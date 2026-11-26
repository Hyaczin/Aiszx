"""``backup``: a consistent, self-describing archive of the Aiszx data directory.

* The database is copied with SQLite's online backup API (consistent even while open), never by
  copying the live file and its WAL.
* Workspaces (``engagements/``) are archived as files; symlinks are stored as links, not followed.
  Logs are optional. Older ``aiszx.db.bak-*`` files and the backups directory itself are excluded.
* ``manifest.json`` inside the archive records versions, counts and the database SHA-256; a
  ``<archive>.sha256`` file is written next to it. Archives are created with mode 0600 because
  they contain evidence.
* ``verify`` re-checks the archive hash, the manifest and the integrity of the contained database.

Restoring is deliberately manual (see docs/DEPLOYMENT.md): it replaces the whole data directory.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path

from aiszx import __version__
from aiszx.core.diskspace import free_mb
from aiszx.core.errors import AiszxError, WorkspaceError
from aiszx.core.timeutil import iso, utcnow
from aiszx.maintenance.stats import tree_size


@dataclass
class BackupResult:
    path: Path
    sha256: str
    size: int
    files: int
    warnings: list[str]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def default_backup_dir(app) -> Path:
    return app.config.data_dir.parent / "aiszx-backups"


def create_backup(app, out_dir: Path | None = None, *, include_logs: bool = False) -> BackupResult:
    data_dir = app.config.data_dir
    out_dir = Path(out_dir or default_backup_dir(app)).expanduser().resolve()
    if out_dir == data_dir.resolve() or data_dir.resolve() in out_dir.parents:
        raise WorkspaceError(f"write backups outside the data directory ({data_dir}), not into {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    warnings = []
    running = app.db.query("SELECT run_id FROM executions WHERE status = 'RUNNING'")
    if running:
        warnings.append(f"{len(running)} run(s) in progress ({', '.join(r['run_id'] for r in running)}): their files may "
                        "be incomplete in this backup (the database snapshot itself is consistent)")
    sources = [data_dir / "engagements"] + ([app.config.log_dir] if include_logs else [])
    estimate = sum(tree_size(p)[0] for p in sources if p.is_dir()) + app.config.db_path.stat().st_size
    if free_mb(out_dir) * 1024 * 1024 < estimate * 1.1:
        raise WorkspaceError(f"not enough free space in {out_dir} for a backup of about {estimate / 1024 / 1024:.0f} MiB")

    stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
    archive = out_dir / f"aiszx-backup-{stamp}.tar.gz"
    if archive.exists():
        raise WorkspaceError(f"{archive} already exists")
    with tempfile.TemporaryDirectory(prefix="aiszx-backup-") as tmp:
        snap = Path(tmp) / "aiszx.db"
        dst = sqlite3.connect(str(snap))
        try:
            app.db.conn.backup(dst)
        finally:
            dst.close()
        counts = {t: app.db.query_one(f"SELECT COUNT(*) FROM {t}")[0]
                  for t in ("engagements", "targets", "executions", "findings", "evidence")}
        manifest = {"format": 1, "created_at": iso(), "framework_version": __version__,
                    "schema_version": app.db.user_version(), "database_sha256": _sha256(snap), "counts": counts,
                    "includes_logs": include_logs, "source_data_dir": str(data_dir)}
        (Path(tmp) / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        files = 0

        def count(info: tarfile.TarInfo) -> tarfile.TarInfo:
            nonlocal files
            if info.isfile():
                files += 1
            return info

        fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as raw, tarfile.open(fileobj=raw, mode="w:gz") as tar:
                tar.add(Path(tmp) / "manifest.json", arcname="manifest.json")
                tar.add(snap, arcname="aiszx.db")
                for src in sources:
                    if src.is_dir():
                        tar.add(src, arcname=src.relative_to(data_dir).as_posix(), filter=count)
        except BaseException:
            archive.unlink(missing_ok=True)
            raise
    digest = _sha256(archive)
    (archive.parent / (archive.name + ".sha256")).write_text(f"{digest}  {archive.name}\n", encoding="utf-8")
    return BackupResult(archive, digest, archive.stat().st_size, files + 2, warnings)


def verify_backup(path: Path) -> dict:
    """Check the archive hash (if the .sha256 file exists), the manifest and the contained database."""
    path = Path(path).expanduser()
    if not path.is_file():
        raise AiszxError(f"{path} not found")
    report: dict = {"archive": str(path), "problems": []}
    side = path.with_name(path.name + ".sha256")
    digest = _sha256(path)
    if side.is_file():
        expected = side.read_text(encoding="utf-8").split()[0]
        report["archive_hash"] = "ok" if expected == digest else "MISMATCH"
        if expected != digest:
            report["problems"].append("archive SHA-256 does not match the .sha256 file (corrupted or modified)")
    else:
        report["archive_hash"] = "no .sha256 file"
    with tempfile.TemporaryDirectory(prefix="aiszx-verify-") as tmp:
        try:
            with tarfile.open(path, "r:gz") as tar:
                names = tar.getnames()
                for member in ("manifest.json", "aiszx.db"):
                    if member not in names:
                        report["problems"].append(f"{member} missing from archive")
                        continue
                    data = tar.extractfile(member)
                    (Path(tmp) / member).write_bytes(data.read() if data else b"")
                unsafe = [n for n in names if n.startswith(("/", "\\")) or ".." in Path(n).parts]
                if unsafe:
                    report["problems"].append(f"unsafe paths in archive: {unsafe[:3]}")
                report["entries"] = len(names)
        except (tarfile.TarError, OSError, EOFError) as exc:
            report["problems"].append(f"archive unreadable: {exc}")
            return report
        man_path, db_path = Path(tmp) / "manifest.json", Path(tmp) / "aiszx.db"
        if man_path.is_file():
            manifest = json.loads(man_path.read_text(encoding="utf-8"))
            report["manifest"] = manifest
            if db_path.is_file() and _sha256(db_path) != manifest.get("database_sha256"):
                report["problems"].append("database hash differs from the manifest")
        if db_path.is_file():
            con = sqlite3.connect(str(db_path))
            try:
                report["database_integrity"] = con.execute("PRAGMA integrity_check").fetchone()[0]
            finally:
                con.close()
            if report["database_integrity"] != "ok":
                report["problems"].append(f"database integrity: {report['database_integrity']}")
    report["ok"] = not report["problems"]
    return report
