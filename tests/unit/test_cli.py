import json


def test_requires_init(cli, capsys):
    assert cli("target", "list") == 1
    assert "not initialised" in capsys.readouterr().err


def test_init_is_idempotent(cli, capsys):
    assert cli("init") == 0
    out = capsys.readouterr().out
    assert "initialised" in out and "applied 0001_foundation" in out
    assert cli("init") == 0
    assert "up to date" in capsys.readouterr().out


def test_end_to_end_workflow(cli, capsys, tmp_path):
    assert cli("init") == 0
    assert cli("scope", "add", "10.10.10.0/24", "--note", "lab") == 0
    assert cli("scope", "add", "10.10.10.1", "--exclude") == 0
    assert cli("target", "add", "10.10.10.5") == 0
    out = capsys.readouterr().out
    assert "Registered 10.10.10.5" in out and "IN SCOPE" in out

    assert cli("target", "add", "10.10.10.1") == 3
    assert "excluded" in capsys.readouterr().err

    assert cli("target", "add", "app.lab.local") == 0  # FakeResolver → 10.10.10.20
    assert "10.10.10.20" in capsys.readouterr().out

    assert cli("target", "list", "--json") == 0
    listed = json.loads(capsys.readouterr().out)
    assert {t["canonical_id"] for t in listed} == {"10.10.10.5", "app.lab.local"}

    assert cli("scope", "show", "10.10.10.5") == 0
    assert cli("scope", "check", "10.10.99.9") == 3
    capsys.readouterr()

    assert cli("target", "show", "10.10.10.5", "--json") == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown["workspace_ok"] is True and shown["scope"]["in_scope"] is True

    assert cli("workspace", "verify") == 0
    assert cli("target", "remove", "10.10.10.5") == 0
    assert "Archived" in capsys.readouterr().out
    assert cli("target", "remove", "10.10.10.5", "--purge", "--confirm", "wrong") == 1
    assert cli("target", "remove", "10.10.10.5", "--purge", "--confirm", "10.10.10.5") == 0
    assert "Purged" in capsys.readouterr().out


def test_global_options_after_command(cli, capsys):
    assert cli("init") == 0
    assert cli("engagement", "add", "htb", "--auth-ref", "HTB Academy") == 0
    assert cli("target", "add", "10.10.10.5", "--scope", "-e", "htb") == 0
    assert "include ip 10.10.10.5" in capsys.readouterr().out
    assert cli("-e", "htb", "target", "list") == 0
    assert "10.10.10.5" in capsys.readouterr().out
    assert cli("target", "list") == 0  # default engagement is separate
    assert "No targets" in capsys.readouterr().out


def test_scope_change_warns_about_registered_targets(cli, capsys):
    cli("init")
    cli("scope", "add", "10.10.10.0/24")
    cli("target", "add", "10.10.10.5")
    capsys.readouterr()
    assert cli("scope", "remove", "10.10.10.0/24") == 0
    assert "now OUT of scope" in capsys.readouterr().out


def test_invalid_input_exit_code(cli, capsys):
    cli("init")
    assert cli("target", "add", "10.10.10.0/24") == 2
    assert "scope add" in capsys.readouterr().err


def test_bad_user_config_reported(cli, capsys, tmp_path):
    (tmp_path / "cfg").mkdir()
    (tmp_path / "cfg" / "framework.yaml").write_text("logging:\n  levle: INFO\n", encoding="utf-8")
    assert cli("config", "show") == 2
    assert "unknown key" in capsys.readouterr().err


def test_group_without_action_prints_help(cli, capsys):
    assert cli("target") == 2
    assert "ACTION" in capsys.readouterr().out


def test_logs_written(cli, tmp_path):
    cli("init")
    cli("scope", "add", "10.10.10.0/24")
    cli("target", "add", "10.10.10.5")
    central = (tmp_path / "data" / "logs" / "aiszx.log").read_text(encoding="utf-8").splitlines()
    assert any(json.loads(line)["message"] == "target create: 10.10.10.5" for line in central)
    target_log = tmp_path / "data" / "engagements" / "default" / "targets" / "10.10.10.5" / "logs" / "target.log"
    entry = json.loads(target_log.read_text(encoding="utf-8").splitlines()[-1])
    assert entry["target"] == "10.10.10.5" and entry["engagement"] == "default"
