import json
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from aiszx.app import AppContext
from aiszx.core.errors import ScopeError
from aiszx.modules.base import Command, Safety
from aiszx.modules.registry import discover
from aiszx.orchestrator.locks import LockManager
from aiszx.orchestrator.orchestrator import Orchestrator
from aiszx.orchestrator.planner import ToolResolution
from aiszx.orchestrator.procutil import Owner
from aiszx.orchestrator.settings import ModuleSettings, Profile
from aiszx.orchestrator.state import ExecutionStore
from aiszx.orchestrator.toolrunner import ScopeGuard, ScopeViolation, ToolRunner
from aiszx.targets.scope import INCLUDE, ScopePolicy, ScopeRule

TARGET = "127.0.0.1"


def fake_tools(names):
    return {n: ToolResolution("ok", [sys.executable], "3") if n == "py" else ToolResolution("missing", [])
            for n in names}


def settings(**modules):
    profiles = {
        "conservative": Profile("conservative", "", Safety.ACTIVE_SAFE),
        "standard": Profile("standard", "", Safety.ACTIVE_NOISY),
        "comprehensive": Profile("comprehensive", "", Safety.INTRUSIVE),
    }
    return ModuleSettings(modules=dict(modules), profiles=profiles, sources=[])


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    ctx = AppContext.create(data_dir=tmp_path / "data", config_dir=tmp_path / "cfg")
    ctx.layout.ensure_data_dir()
    ctx.open_db(migrate_schema=True)
    eng, _ = ctx.engagements().ensure("default")
    ctx.scope().add(eng, "127.0.0.0/8")
    ctx.targets().add("default", TARGET)
    yield ctx
    ctx.close()


@pytest.fixture
def registry():
    return discover(["tests.orch_modules"])


def make(app, registry, *, mods=None, approve=None, confirm=None, cancel=None):
    lines = []
    orch = Orchestrator(app, registry=registry, settings=mods or settings(), resolve_tools=fake_tools,
                        approve=approve, confirm=confirm, progress=lines.append, cancel_event=cancel,
                        handle_signals=False)
    orch.lines = lines
    return orch


def units_by_module(app, report):
    return {r["module_id"]: r for r in ExecutionStore(app.db).units(report.execution_id)}


# --- successful run, checkpoints and evidence --------------------------------------

def test_run_produces_outputs_evidence_manifest_and_logs(app, registry):
    report = make(app, registry).start("default", TARGET, ["test.echo"])
    assert report.status == "COMPLETED"
    unit = units_by_module(app, report)["test.echo"]
    assert unit["state"] == "COMPLETED" and unit["attempt"] == 1 and unit["summary"] == f"hello {TARGET}"
    adir = report.run_dir / unit["output_dir"]
    assert adir.name == "attempt-01" and "reconnaissance" in adir.parts
    assert (adir / "raw" / "echo.stdout.txt").read_text().strip() == f"hello {TARGET}"
    assert json.loads((adir / "parsed" / "result.json").read_text())["summary"] == f"hello {TARGET}"
    outputs = json.loads(unit["outputs_json"])
    assert {o["path"].rsplit("/", 1)[-1] for o in outputs} >= {"echo.stdout.txt", "echo.cmd.txt", "result.json"}
    assert ExecutionStore(app.db).evidence_count(report.execution_id) == len(outputs)
    manifest = json.loads((report.run_dir / "manifest.json").read_text())
    assert manifest["units"][0]["state"] == "COMPLETED"
    scope_rec = json.loads((report.run_dir / "scope" / "scope.json").read_text())
    assert scope_rec["pinned_address"] == TARGET and scope_rec["decision"]["in_scope"]
    assert (report.run_dir / "logs" / "run.log").is_file()
    assert (report.run_dir / "logs" / "modules" / "test.echo__host.log").is_file()
    ex = ExecutionStore(app.db).execution(report.execution_id)
    assert ex["status"] == "COMPLETED" and json.loads(ex["summary_json"]) == {"COMPLETED": 1}


def test_failure_is_isolated_and_dependents_skip(app, registry):
    report = make(app, registry).start("default", TARGET, ["test.fail", "test.echo", "test.after"])
    u = units_by_module(app, report)
    assert u["test.fail"]["state"] == "FAILED" and u["test.fail"]["error_class"] == "permanent"
    assert "exited with 3" in u["test.fail"]["error_message"]
    assert u["test.echo"]["state"] == "COMPLETED"
    assert u["test.after"]["state"] == "SKIPPED" and "upstream test.fail" in u["test.after"]["skip_reason"]
    assert report.status == "PARTIAL"
    # failed output is preserved as evidence
    assert (report.run_dir / u["test.fail"]["output_dir"] / "raw" / "fail.stderr.txt").read_text().strip() == "boom"


def test_transient_failure_is_retried(app, registry, tmp_path):
    mods = settings(**{"test.flaky": {"options": {"marker": str(tmp_path / "marker")}}})
    report = make(app, registry, mods=mods).start("default", TARGET, ["test.flaky"])
    unit = units_by_module(app, report)["test.flaky"]
    assert unit["state"] == "COMPLETED" and unit["attempt"] == 2
    attempts = ExecutionStore(app.db).attempts(unit["id"])
    assert [(a["status"], a["error_class"]) for a in attempts] == [("failed", "transient"), ("ok", None)]
    assert (report.run_dir / attempts[0]["output_dir"] / "raw" / "flaky.stderr.txt").is_file()  # kept


def test_timeout_kills_the_tool(app, registry):
    mods = settings(**{"test.slow": {"timeout": 1, "retry": {"max_attempts": 1}}})
    t0 = time.monotonic()
    report = make(app, registry, mods=mods).start("default", TARGET, ["test.slow"])
    assert time.monotonic() - t0 < 15
    unit = units_by_module(app, report)["test.slow"]
    assert unit["state"] == "FAILED" and unit["error_class"] == "timeout"


def test_upstream_results_are_available(app, registry):
    report = make(app, registry).start("default", TARGET, ["test.after_echo", "test.echo"])
    u = units_by_module(app, report)
    assert u["test.after_echo"]["summary"] == f"saw hello {TARGET}"
    assert "enumeration" in Path(u["test.after_echo"]["output_dir"]).parts and "http" in u["test.after_echo"]["output_dir"]


# --- scope and safety --------------------------------------------------------------

def test_scope_guard_refuses_out_of_scope_command(app, registry):
    report = make(app, registry).start("default", TARGET, ["test.offscope"])
    unit = units_by_module(app, report)["test.offscope"]
    assert unit["state"] == "FAILED" and unit["error_class"] == "scope"
    assert "8.8.8.8 is not in scope" in unit["error_message"]
    assert not list((report.run_dir / unit["output_dir"] / "raw").glob("leak.*"))  # nothing executed


def test_expired_engagement_refuses_to_start(app, registry):
    app.engagements().update("default", valid_from="2020-01-01", valid_until="2020-12-31")
    with pytest.raises(ScopeError, match="expired"):
        make(app, registry).start("default", TARGET, ["test.echo"])


def test_safety_ceiling_and_rules_of_engagement(app, registry):
    report = make(app, registry).start("default", TARGET, ["test.noisy", "test.echo"], profile="conservative")
    u = units_by_module(app, report)
    assert u["test.noisy"]["state"] == "SKIPPED" and "exceeds the profile 'conservative' ceiling" in u["test.noisy"]["skip_reason"]
    assert u["test.echo"]["state"] == "COMPLETED"

    app.engagements().update("default", max_safety="passive")
    report = make(app, registry).start("default", TARGET, ["test.echo"])
    assert "rules of engagement" in units_by_module(app, report)["test.echo"]["skip_reason"]


def test_prohibited_and_missing_tools_are_skipped(app, registry):
    report = make(app, registry).start("default", TARGET, ["test.prohibited", "test.needs_missing"])
    u = units_by_module(app, report)
    assert "prohibited" in u["test.prohibited"]["skip_reason"]
    assert "required tool unavailable: nonexistent (missing)" in u["test.needs_missing"]["skip_reason"]
    assert report.status == "COMPLETED"  # nothing failed; skips carry their reasons


@pytest.mark.parametrize("granted, state", [(False, "SKIPPED"), (True, "COMPLETED")])
def test_intrusive_requires_approval(app, registry, granted, state):
    report = make(app, registry, approve=lambda pu: granted).start(
        "default", TARGET, ["test.intrusive"], profile="comprehensive")
    assert units_by_module(app, report)["test.intrusive"]["state"] == state
    row = app.db.query_one("SELECT decision, action FROM approvals")
    assert (row["decision"], row["action"]) == ("approved" if granted else "denied", "module:test.intrusive")


# --- interruption, crash recovery and resume ---------------------------------------

def test_cancel_interrupts_and_resume_completes(app, registry):
    cancel = threading.Event()
    threading.Timer(1.0, cancel.set).start()
    t0 = time.monotonic()
    report = make(app, registry, cancel=cancel).start("default", TARGET, ["test.slow", "test.echo"])
    assert time.monotonic() - t0 < 15
    assert report.status == "INTERRUPTED"
    slow = units_by_module(app, report)["test.slow"]
    assert slow["state"] == "INTERRUPTED"
    assert (report.run_dir / slow["output_dir"] / "raw" / "sleep.cmd.txt").is_file()  # partial output kept

    fast = settings(**{"test.slow": {"options": {"seconds": 0}}})
    resumed = make(app, registry, mods=fast).resume("default", TARGET)
    assert resumed.run_id == report.run_id and resumed.status == "COMPLETED"
    slow = units_by_module(app, resumed)["test.slow"]
    assert slow["state"] == "COMPLETED" and slow["attempt"] == 2
    assert (report.run_dir / slow["output_dir"]).name == "attempt-02"


def dead_pid():
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    return proc.pid


def test_crash_is_detected_and_resumed(app, registry):
    report = make(app, registry).start("default", TARGET, ["test.echo"])
    pid = dead_pid()
    app.db.execute("UPDATE executions SET status = 'RUNNING', owner_pid = ? WHERE id = ?", (pid, report.execution_id))
    app.db.execute("UPDATE module_executions SET state = 'RUNNING' WHERE execution_id = ?", (report.execution_id,))
    orch = make(app, registry)
    messages = orch.reconcile()
    assert any("was interrupted" in m for m in messages)
    assert ExecutionStore(app.db).execution(report.execution_id)["status"] == "INTERRUPTED"
    resumed = orch.resume("default", TARGET)
    assert resumed.status == "COMPLETED"
    assert next(pu for pu in resumed.units).decision == "rerun"


def test_resume_reuses_verified_outputs(app, registry, tmp_path):
    log = tmp_path / "runs.log"
    mods = settings(**{"test.echo": {"options": {"log": str(log)}}})
    make(app, registry, mods=mods).start("default", TARGET, ["test.echo"])
    report = make(app, registry, mods=mods).resume("default", TARGET)
    assert report.units[0].decision == "reuse"
    assert any("nothing to resume" in m for m in report.messages)
    assert log.read_text().count("run") == 1  # not executed again


def test_resume_reruns_when_outputs_missing_or_config_changed(app, registry, tmp_path):
    log = tmp_path / "runs.log"
    mods = settings(**{"test.echo": {"options": {"log": str(log)}}})
    first = make(app, registry, mods=mods).start("default", TARGET, ["test.echo"])
    unit = units_by_module(app, first)["test.echo"]
    (first.run_dir / unit["output_dir"] / "raw" / "echo.stdout.txt").unlink()

    seen = {}
    second = make(app, registry, mods=mods, confirm=lambda units: seen.setdefault("d", units[0].decision) or True
                  ).resume("default", TARGET)
    assert seen["d"] == "recover" and second.status == "COMPLETED"
    assert (first.run_dir / unit["output_dir"]).is_dir()  # attempt-01 kept

    changed = settings(**{"test.echo": {"options": {"log": str(log), "greeting": "hi"}}})
    third = make(app, registry, mods=changed).resume("default", TARGET)
    assert third.units[0].decision == "rerun" and "configuration changed" in third.units[0].decision_reason
    assert log.read_text().count("run") == 3


def test_declined_resume_marks_recovery_required(app, registry):
    first = make(app, registry).start("default", TARGET, ["test.echo"])
    unit = units_by_module(app, first)["test.echo"]
    (first.run_dir / unit["output_dir"] / "parsed" / "result.json").write_text("tampered")
    report = make(app, registry, confirm=lambda units: False).resume("default", TARGET)
    assert any("cancelled" in m for m in report.messages)
    row = units_by_module(app, first)["test.echo"]
    assert row["state"] == "RECOVERY_REQUIRED" and "modified" in row["error_message"]


def test_missing_run_directories_are_recreated(app, registry):
    import shutil

    report = make(app, registry).start("default", TARGET, ["test.echo"])
    shutil.rmtree(report.run_dir / "findings")
    make(app, registry).resume("default", TARGET)
    assert (report.run_dir / "findings").is_dir()


# --- locks and the tool runner -----------------------------------------------------

def test_locks_block_live_owners_and_reap_dead_ones(app):
    me = Owner.current()
    other_live = Owner(pid=me.pid, host=me.host, boot=me.boot)
    assert LockManager(app.db, me, 60).acquire("k", "e1") == (True, None)
    ok, why = LockManager(app.db, Owner(pid=dead_pid(), host=me.host, boot=me.boot), 60).acquire("k", "e2")
    assert not ok and "held by pid" in why  # the current process is alive
    app.db.execute("UPDATE locks SET owner_pid = ?", (dead_pid(),))
    assert LockManager(app.db, other_live, 60).acquire("k", "e2") == (True, None)  # stale lock taken over


def runner_for(tmp_path, cancel=None):
    policy = ScopePolicy([ScopeRule(INCLUDE, "cidr", "127.0.0.0/8")])
    eng = type("E", (), {"validity": lambda self: "active", "slug": "x"})()
    guard = ScopeGuard(policy, eng, lambda h: [])
    return ToolRunner(guard, {"py": [sys.executable]}, cancel or threading.Event(), kill_grace=1, poll_interval=0.05)


def test_runner_redacts_secrets(tmp_path):
    res = runner_for(tmp_path).run(Command("x", ["-c", "print('ok')", "--password", "S3cret!"], tool="py"),
                                   tmp_path, 10)
    assert res.exit_code == 0
    stored = (tmp_path / "x.cmd.txt").read_text()
    assert "S3cret!" in stored  # not listed for redaction → visible
    res = runner_for(tmp_path).run(Command("y", ["-c", "print('ok')", "--password", "S3cret!"], tool="py",
                                           redact=["S3cret!"]), tmp_path, 10)
    assert "S3cret!" not in (tmp_path / "y.cmd.txt").read_text() and "***" in res.argv_redacted


def test_runner_scope_guard_and_cancel(tmp_path):
    with pytest.raises(ScopeViolation):
        runner_for(tmp_path).run(Command("z", ["-c", "pass"], tool="py", targets=["10.0.0.1"]), tmp_path, 10)
    assert not (tmp_path / "z.cmd.txt").exists()

    cancel = threading.Event()
    threading.Timer(0.5, cancel.set).start()
    t0 = time.monotonic()
    res = runner_for(tmp_path, cancel).run(Command("s", ["-c", "import time; time.sleep(30)"], tool="py"), tmp_path, 60)
    assert res.cancelled and time.monotonic() - t0 < 10


def test_runner_reports_unstartable_program(tmp_path):
    runner = runner_for(tmp_path)
    runner.tool_launch["ghost"] = [str(tmp_path / "does-not-exist")]
    res = runner.run(Command("g", [], tool="ghost"), tmp_path, 5)
    assert res.error and res.exit_code is None
