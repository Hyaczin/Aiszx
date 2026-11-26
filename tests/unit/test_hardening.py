"""Milestone 9: crash recovery with a real killed process, disk-space preflight, corrupted results,
doctor, workspace stats and backups."""

import json
import os
import signal
import subprocess
import sys
import tarfile
import time
from collections import namedtuple
from pathlib import Path

import pytest

from aiszx.app import AppContext
from aiszx.assessment.engine import Assessor
from aiszx.assessment.knowledge import gather
from aiszx.core.errors import WorkspaceError
from aiszx.maintenance.backup import create_backup, verify_backup
from aiszx.maintenance.doctor import FAIL, OK, WARN, Doctor
from aiszx.maintenance.stats import workspace_stats
from aiszx.modules.registry import discover
from aiszx.orchestrator.orchestrator import Orchestrator
from aiszx.orchestrator.planner import ToolResolution
from aiszx.orchestrator.state import ExecutionStore

TESTS = Path(__file__).resolve().parents[1]
FAKE_NMAP, CRASH_DRIVER = str(TESTS / "fake_nmap.py"), str(TESTS / "crash_driver.py")
TARGET = "10.129.73.247"
Usage = namedtuple("Usage", "total used free")


def resolver(names):
    return {n: (ToolResolution("ok", [sys.executable, FAKE_NMAP], "7.95", detail={"privileges": {"mode": "capabilities"}})
                if n == "nmap" else ToolResolution("missing", [])) for n in names}


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    for var in ("FAKE_NMAP_HANG", "FAKE_NMAP_WIDE", "FAKE_NMAP_PIDFILE"):
        monkeypatch.delenv(var, raising=False)
    ctx = AppContext.create(data_dir=tmp_path / "data", config_dir=tmp_path / "cfg")
    ctx.layout.ensure_data_dir()
    ctx.open_db(migrate_schema=True)
    eng, _ = ctx.engagements().ensure("default")
    ctx.scope().add(eng, "10.129.0.0/16")
    ctx.targets().add("default", TARGET)
    yield ctx
    ctx.close()


def orch(app):
    return Orchestrator(app, registry=discover(), resolve_tools=resolver, handle_signals=False)


# --- crash recovery with a real process ------------------------------------------

def _stop(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass


def test_hard_kill_mid_scan_then_resume(app, tmp_path):
    """The Aiszx process dies without any cleanup (SIGKILL / TerminateProcess) while nmap is running."""
    pidfile = tmp_path / "nmap.pid"
    env = dict(os.environ, FAKE_NMAP_HANG="1", FAKE_NMAP_PIDFILE=str(pidfile))
    proc = subprocess.Popen([sys.executable, CRASH_DRIVER, str(tmp_path / "data"), str(tmp_path / "cfg"), TARGET,
                             "recon.tcp_ports", "recon.service_id"],
                            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 60
        while not pidfile.exists():
            if proc.poll() is not None:
                pytest.fail(f"driver exited early: {proc.stderr.read().decode(errors='replace')}")
            assert time.monotonic() < deadline, "scan never started"
            time.sleep(0.1)
        while app.db.query_one("SELECT COUNT(*) FROM module_executions WHERE state = 'RUNNING'")[0] == 0:
            assert time.monotonic() < deadline, "unit never recorded as RUNNING"
            time.sleep(0.05)
        proc.kill()  # SIGKILL on POSIX, TerminateProcess on Windows: no finally blocks, no handlers
        proc.wait(timeout=30)

        ex = app.db.query_one("SELECT * FROM executions")
        assert ex["status"] == "RUNNING"  # nothing was cleaned up
        assert app.db.query_one("SELECT COUNT(*) FROM locks")[0] >= 1
        unit = app.db.query_one("SELECT * FROM module_executions WHERE module_id = 'recon.tcp_ports'")
        assert unit["state"] == "RUNNING"

        report = orch(app).resume("default", TARGET)
        assert any("was interrupted" in m for m in report.messages)
        assert any("stale lock" in m for m in report.messages)
        assert report.status == "COMPLETED"
        units = {u["module_id"]: u for u in ExecutionStore(app.db).units(ex["id"])}
        assert units["recon.tcp_ports"]["state"] == "COMPLETED" and units["recon.tcp_ports"]["attempt"] == 2
        assert units["recon.service_id"]["state"] == "COMPLETED"
        run_dir = tmp_path / "data" / ex["workspace_path"]
        crashed = run_dir / "reconnaissance" / "recon.tcp_ports" / "host" / "attempt-01" / "raw"
        assert (crashed / "tcp.nmap").read_text() == "partial\n"  # the killed attempt's output is untouched
        assert (crashed.parent.parent / "attempt-02" / "raw" / "tcp.resumed").is_file()  # nmap --resume was used
        assert app.db.query_one("SELECT COUNT(*) FROM locks")[0] == 0
        assert app.db.query_one("SELECT COUNT(*) FROM discovered_ports WHERE execution_id = ?", (ex["id"],))[0] > 0
    finally:
        if proc.poll() is None:
            proc.kill()
        if pidfile.exists():
            _stop(int(pidfile.read_text()))  # the orphaned scanner (it runs in its own process group)


def test_crash_before_attempt_was_recorded_never_overwrites(app, monkeypatch):
    """A crash between "tool started" and "attempt recorded": the DB says PENDING, the disk has attempt-01."""
    monkeypatch.setenv("FAKE_NMAP_HANG", "1")
    import threading

    cancel = threading.Event()
    threading.Timer(1.5, cancel.set).start()
    first = Orchestrator(app, registry=discover(), resolve_tools=resolver, handle_signals=False,
                         cancel_event=cancel).start("default", TARGET, ["recon.tcp_ports"])
    unit = ExecutionStore(app.db).units(first.execution_id)[0]
    attempt1 = first.run_dir / unit["output_dir"]
    # roll the database back to "never started", as if the process died before recording the attempt
    app.db.execute("UPDATE module_executions SET state = 'PENDING', attempt = 0, output_dir = NULL WHERE id = ?",
                   (unit["id"],))
    app.db.execute("DELETE FROM module_attempts WHERE module_execution_id = ?", (unit["id"],))
    before = {p.name: p.read_bytes() for p in (attempt1 / "raw").iterdir()}

    monkeypatch.delenv("FAKE_NMAP_HANG")
    report = orch(app).resume("default", TARGET)
    assert report.status == "COMPLETED"
    unit = ExecutionStore(app.db).units(first.execution_id)[0]
    assert unit["output_dir"].endswith("attempt-02")
    assert {p.name: p.read_bytes() for p in (attempt1 / "raw").iterdir()} == before  # untouched
    assert (first.run_dir / unit["output_dir"] / "raw" / "tcp.resumed").is_file()  # leftover used for --resume


# --- disk space ------------------------------------------------------------------

def test_runs_refused_when_disk_is_nearly_full(app, monkeypatch):
    monkeypatch.setattr("aiszx.core.diskspace.shutil.disk_usage", lambda p: Usage(10**9, 10**9, 50 * 1024 * 1024))
    with pytest.raises(WorkspaceError, match="refusing to start a run"):
        orch(app).start("default", TARGET, ["recon.tcp_ports"])
    assert app.db.query_one("SELECT COUNT(*) FROM executions")[0] == 0  # nothing created
    checks = Doctor(app, tools=False).run()
    assert any(c.area == "disk" and c.status == FAIL for c in checks)


# --- corrupted state -------------------------------------------------------------

def test_corrupted_result_falls_back_and_is_reported(app):
    first = orch(app).start("default", TARGET, ["recon.tcp_ports"])
    second = orch(app).start("default", TARGET, ["recon.tcp_ports"])
    unit = ExecutionStore(app.db).units(second.execution_id)[0]
    (second.run_dir / unit["output_dir"] / "parsed" / "result.json").write_text('{"truncated": ')  # e.g. disk full
    k = gather(app.db, app.config.data_dir, app.targets().get(app.engagements().get("default"), TARGET).id, TARGET)
    assert k.runs_used == [first.run_id]  # older valid result used
    assert len(k.unreadable) == 1 and second.run_id in k.unreadable[0]
    report = Assessor(app, searchsploit=lambda: None).run("default", TARGET)
    assert any("could not be read" in n for n in report.limitations)


# --- doctor ----------------------------------------------------------------------

def test_doctor_healthy_and_interrupted_run(app):
    checks = Doctor(app, tools=False).run()
    assert not [c for c in checks if c.status == FAIL], [c for c in checks if c.status == FAIL]
    assert {c.area for c in checks} >= {"python", "dependencies", "configuration", "data", "disk", "database",
                                       "runs", "workspaces"}
    assert any(c.area == "database" and c.status == OK and "integrity: ok" in c.message for c in checks)

    report = orch(app).start("default", TARGET, ["recon.tcp_ports"])
    app.db.execute("UPDATE executions SET status = 'RUNNING', owner_pid = 999999999 WHERE id = ?", (report.execution_id,))
    checks = Doctor(app, tools=False).run()
    crashed = [c for c in checks if c.area == "runs" and c.status == WARN]
    assert crashed and "resume" in crashed[0].fix


def test_doctor_detects_bad_config_and_missing_run_dirs(app, tmp_path):
    report = orch(app).start("default", TARGET, ["recon.tcp_ports"])
    import shutil

    shutil.rmtree(report.run_dir)
    (tmp_path / "cfg").mkdir(exist_ok=True)
    (tmp_path / "cfg" / "reporting.yaml").write_text("reporting:\n  formats: [pdf]\n")
    checks = Doctor(app, tools=False).run()
    assert any(c.area == "configuration" and c.status == FAIL and "reporting.yaml" in c.message for c in checks)
    assert any(c.area == "workspaces" and "no directory on disk" in c.message for c in checks)


def test_doctor_cli(cli, capsys):
    assert cli("init") == 0
    capsys.readouterr()
    code = cli("doctor", "--no-tools")
    out = capsys.readouterr().out
    assert code == 0 and "[ OK ]" in out and "failure(s)" in out
    assert cli("doctor", "--no-tools", "--json") == 0
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["fail"] == 0 and data["checks"]


# --- workspace stats -------------------------------------------------------------

def test_workspace_stats(app, cli, capsys):
    orch(app).start("default", TARGET, ["recon.tcp_ports"])
    stats = workspace_stats(app)
    target = stats["engagements"][0]["targets"][0]
    assert target["target"] == TARGET and target["runs"] == 1 and target["bytes"] > 0
    assert stats["largest_runs"][0]["command"] == "run" and stats["total_bytes"] >= target["bytes"]


# --- backup ----------------------------------------------------------------------

def test_backup_create_and_verify(app, tmp_path):
    orch(app).start("default", TARGET, ["recon.tcp_ports"])
    res = create_backup(app, tmp_path / "bk")
    assert res.path.is_file() and res.path.name.startswith("aiszx-backup-") and not res.warnings
    if os.name == "posix":
        assert (res.path.stat().st_mode & 0o777) == 0o600
    with tarfile.open(res.path) as tar:
        names = tar.getnames()
        manifest = json.loads(tar.extractfile("manifest.json").read())
    assert "aiszx.db" in names and any(n.startswith("engagements/default/targets/") for n in names)
    assert manifest["counts"]["executions"] == 1 and manifest["schema_version"] == app.db.user_version()
    assert verify_backup(res.path)["ok"]

    with res.path.open("ab") as fh:  # tamper
        fh.write(b"x")
    bad = verify_backup(res.path)
    assert not bad["ok"] and bad["archive_hash"] == "MISMATCH"

    with pytest.raises(WorkspaceError, match="outside the data directory"):
        create_backup(app, tmp_path / "data" / "backups")
