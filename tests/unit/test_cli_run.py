import json

import pytest

from aiszx.modules.registry import discover
from tests.unit.test_orchestrator import fake_tools


@pytest.fixture
def run_cli(cli, monkeypatch):
    monkeypatch.setattr("aiszx.app.AppContext.module_registry", lambda self: discover(["tests.orch_modules"]))
    monkeypatch.setattr("aiszx.orchestrator.orchestrator.inventory_tool_resolver", lambda app: fake_tools)
    assert cli("init") == 0
    assert cli("scope", "add", "127.0.0.0/8") == 0
    assert cli("target", "add", "127.0.0.1") == 0
    return cli


def test_run_history_and_resume(run_cli, capsys):
    capsys.readouterr()
    assert run_cli("run", "127.0.0.1", "-m", "test.echo", "-m", "test.fail", "-m", "test.after") == 1
    out = capsys.readouterr().out
    assert "ACTION" in out and "[ ok ] test.echo [host]" in out and "[FAIL] test.fail [host]" in out
    assert "[skip] test.after [host]: upstream test.fail" in out and ": PARTIAL (" in out
    run_id = out.split("Run ", 1)[1].split(":", 1)[0]

    assert run_cli("history", "127.0.0.1") == 0
    out = capsys.readouterr().out
    assert run_id in out and "PARTIAL" in out

    assert run_cli("history", "127.0.0.1", "--run", run_id) == 0
    out = capsys.readouterr().out
    assert "test.fail" in out and "exited with 3" in out and "evidence files" in out

    assert run_cli("history", "127.0.0.1", "--run", run_id, "--json") == 0
    data = json.loads(capsys.readouterr().out)
    assert {u["module_id"]: u["state"] for u in data["units"]}["test.echo"] == "COMPLETED"

    # resume: the failed unit is re-run (still fails), the completed one is reused
    assert run_cli("resume", "127.0.0.1", "--yes") == 1
    out = capsys.readouterr().out
    assert "Resume plan" in out and "reuse" in out and "rerun" in out


def test_intrusive_needs_explicit_approval_even_with_yes(run_cli, capsys):
    capsys.readouterr()
    assert run_cli("run", "127.0.0.1", "-m", "test.intrusive", "--profile", "comprehensive", "--yes") == 0
    assert "not approved" in capsys.readouterr().out
    assert run_cli("run", "127.0.0.1", "-m", "test.intrusive", "--profile", "comprehensive",
                   "--approve", "test.intrusive") == 0
    assert "approved by --approve" in capsys.readouterr().out


def test_run_requires_registered_in_scope_target(run_cli, capsys):
    assert run_cli("run", "10.10.10.10", "-m", "test.echo") == 4  # not registered
    assert run_cli("run", "127.0.0.1", "-m", "nope.module") == 4
    assert "unknown module" in capsys.readouterr().err


def test_modules_and_engagement_update(run_cli, capsys):
    capsys.readouterr()
    assert run_cli("modules", "list") == 0
    assert "test.echo" in capsys.readouterr().out
    assert run_cli("modules", "show", "test.flaky") == 0
    assert "3 attempt(s) on transient, timeout" in capsys.readouterr().out
    assert run_cli("engagement", "update", "--max-safety", "passive") == 0
    assert "max safety (RoE) : passive" in capsys.readouterr().out
    assert run_cli("run", "127.0.0.1", "-m", "test.echo") == 0
    assert "rules of engagement" in capsys.readouterr().out


def test_history_without_runs(run_cli, capsys):
    capsys.readouterr()
    assert run_cli("history", "127.0.0.1") == 0
    assert "No runs yet" in capsys.readouterr().out
