import os
import shutil
import stat
from datetime import datetime, timezone

import pytest

from aiszx.core.errors import WorkspaceError

NOW = datetime(2026, 11, 25, 16, 0, 0, tzinfo=timezone.utc)


def test_target_structure(layout, config):
    created = layout.ensure_target("default", "10.10.10.5")
    base = layout.target_dir("default", "10.10.10.5")
    assert base in created
    for sub in config.workspace.target_subdirs:
        assert (base / sub).is_dir()
    assert layout.ensure_target("default", "10.10.10.5") == []  # idempotent


def test_run_layout_and_id_format(layout, config):
    run = layout.create_target_run("default", "10.10.10.5", now=NOW)
    assert run.run_id == "2026-11-25_160000"
    for sub in config.workspace.run_subdirs:
        assert (run.path / sub).is_dir()
    for cat in config.workspace.enumeration_categories:
        assert (run.path / "enumeration" / cat).is_dir()


def test_runs_are_never_reused(layout):
    first = layout.create_target_run("default", "10.10.10.5", now=NOW)
    (first.path / "reports" / "keep.txt").write_text("evidence")
    second = layout.create_target_run("default", "10.10.10.5", now=NOW)
    third = layout.create_target_run("default", "10.10.10.5", now=NOW)
    assert [second.run_id, third.run_id] == ["2026-11-25_160000_2", "2026-11-25_160000_3"]
    assert (first.path / "reports" / "keep.txt").read_text() == "evidence"


def test_targets_and_engagements_are_isolated(layout):
    a = layout.create_target_run("default", "10.10.10.5", now=NOW)
    b = layout.create_target_run("default", "10.10.10.6", now=NOW)
    c = layout.create_target_run("other", "10.10.10.5", now=NOW)
    assert len({a.path, b.path, c.path}) == 3
    assert layout.engagement_dir("other") in c.path.parents


def test_engagement_level_run(layout):
    run = layout.create_engagement_run("default", now=NOW)
    assert run.path.parent == layout.engagement_dir("default") / "runs"


def test_verify_detects_and_repairs_missing_dirs(layout):
    run = layout.create_target_run("default", "10.10.10.5", now=NOW)
    shutil.rmtree(run.path / "enumeration" / "smb")
    shutil.rmtree(layout.target_dir("default", "10.10.10.5") / "history")
    (run.path / "logs" / "module.log").write_text("keep me")

    report = layout.verify_target("default", "10.10.10.5")
    assert not report.ok and len(report.missing) == 2

    repaired = layout.verify_target("default", "10.10.10.5", repair=True)
    assert repaired.ok and len(repaired.repaired) == 2
    assert (run.path / "enumeration" / "smb").is_dir()
    assert (run.path / "logs" / "module.log").read_text() == "keep me"


def test_verify_reports_unexpected_entries(layout):
    layout.ensure_target("default", "10.10.10.5")
    (layout.target_runs_dir("default", "10.10.10.5") / "random-file.txt").write_text("x")
    report = layout.verify_target("default", "10.10.10.5", repair=True)
    assert any("unexpected entry" in p for p in report.problems)


@pytest.mark.parametrize("bad", ["..", "a/b", "a\\b", ""])
def test_unsafe_slugs_rejected(layout, bad):
    with pytest.raises(WorkspaceError):
        layout.target_dir("default", bad)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_protected_dir_permissions(layout):
    run = layout.create_target_run("default", "10.10.10.5", now=NOW)
    protected = run.path / "evidence" / "protected"
    assert stat.S_IMODE(protected.stat().st_mode) == 0o700
    os.chmod(protected, 0o755)
    assert not layout.verify_target("default", "10.10.10.5").ok
    layout.verify_target("default", "10.10.10.5", repair=True)
    assert stat.S_IMODE(protected.stat().st_mode) == 0o700
