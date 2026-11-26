"""``workspace stats``: where the disk space goes (per engagement, target and run). Read-only."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def tree_size(path: Path) -> tuple[int, int]:
    """(bytes, files) under ``path``; symlinks are not followed."""
    total = files = 0
    for root, _dirs, names in os.walk(path, followlinks=False):
        for n in names:
            try:
                total += os.lstat(os.path.join(root, n)).st_size
                files += 1
            except OSError:
                pass
    return total, files


def workspace_stats(app, engagement_slug: str | None = None, top: int = 10) -> dict[str, Any]:
    data_dir = app.config.data_dir
    runs_by_path = {r["workspace_path"]: r for r in app.db.query(
        "SELECT workspace_path, run_id, command, status, started_at FROM executions")}
    engagements = [app.engagements().get(engagement_slug)] if engagement_slug else app.engagements().list(include_archived=True)
    out: dict[str, Any] = {"engagements": [], "largest_runs": []}
    all_runs = []
    for eng in engagements:
        e_entry = {"engagement": eng.slug, "bytes": 0, "files": 0, "targets": []}
        for t in app.targets().list(eng, include_archived=True):
            tdir = app.layout.target_dir(eng.slug, t.slug)
            t_entry = {"target": t.canonical, "bytes": 0, "files": 0, "runs": 0, "path": str(tdir)}
            if tdir.is_dir():
                t_entry["bytes"], t_entry["files"] = tree_size(tdir)
                runs_dir = tdir / "runs"
                for run in sorted(runs_dir.iterdir()) if runs_dir.is_dir() else []:
                    if not run.is_dir():
                        continue
                    size, files = tree_size(run)
                    rel = run.relative_to(data_dir).as_posix()
                    row = runs_by_path.get(rel)
                    t_entry["runs"] += 1
                    all_runs.append({"engagement": eng.slug, "target": t.canonical, "run_id": run.name,
                                     "command": row["command"] if row else "?", "status": row["status"] if row else
                                     "not in database", "bytes": size, "files": files, "path": str(run)})
            e_entry["bytes"] += t_entry["bytes"]
            e_entry["files"] += t_entry["files"]
            e_entry["targets"].append(t_entry)
        edir = app.layout.engagement_dir(eng.slug)
        if (edir / "runs").is_dir():  # range-level discovery runs
            size, files = tree_size(edir / "runs")
            e_entry["bytes"] += size
            e_entry["files"] += files
            e_entry["range_runs_bytes"] = size
        out["engagements"].append(e_entry)
    out["largest_runs"] = sorted(all_runs, key=lambda r: -r["bytes"])[:top]
    db_bytes = sum(p.stat().st_size for p in data_dir.glob("aiszx.db*") if p.is_file())
    log_bytes = tree_size(app.config.log_dir)[0] if app.config.log_dir.is_dir() else 0
    out["database_bytes"], out["log_bytes"] = db_bytes, log_bytes
    out["total_bytes"] = sum(e["bytes"] for e in out["engagements"]) + db_bytes + log_bytes
    return out


def human(n: int) -> str:
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"
