import json

import pytest

from tests.unit.test_tools import GETCAP_NEW, build_lab


@pytest.fixture
def tools_cli(cli, monkeypatch, fakehost, fakerunner, test_registry_dir):
    """CLI with a fake host, fake subprocesses and the test registry."""
    from aiszx.tools import registry as registry_mod

    build_lab(fakehost, fakerunner)
    for exe in ("getcap", "apt-get", "apt-cache", "pipx"):
        fakehost.exe(fakehost.bin / exe)
    fakerunner.on("getcap", stdout="")
    fakerunner.on("apt-cache", "policy", stdout="whatweb:\n  Candidate: 0.5.5-1\neyewitness:\n  Candidate: 2023-1\n")
    for key, value in fakehost.env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr("aiszx.app.ProcessRunner", lambda: fakerunner)
    monkeypatch.setattr("aiszx.app.load_registry",
                        lambda **kw: registry_mod.load_registry(shipped_dir=test_registry_dir, **kw))
    assert cli("init") == 0
    return cli


def test_init_is_up_to_date_after_all_migrations(tools_cli, capsys):
    from aiszx.db.migrate import latest_version

    assert tools_cli("init") == 0
    assert f"schema v{latest_version()} (up to date)" in capsys.readouterr().out


def test_tools_inventory(tools_cli, capsys, tmp_path):
    capsys.readouterr()
    assert tools_cli("tools", "inventory") == 0
    out = capsys.readouterr().out
    assert "Tool inventory (" in out and " ok, " in out and " broken, " in out
    assert "nmap" in out and "pipx" in out and "Python interpreters" in out
    assert "nmap privileges: unprivileged" in out
    assert (tmp_path / "data" / "global" / "tools" / "latest.json").is_file()

    assert tools_cli("tools", "inventory", "nmap", "--json") == 0
    data = json.loads(capsys.readouterr().out)
    assert list(data["tools"]) == ["nmap"] and data["complete"] is False


def test_tools_check_exit_code_and_capabilities(tools_cli, capsys):
    capsys.readouterr()
    assert tools_cli("tools", "check") == 1  # whatweb/eyewitness broken
    out = capsys.readouterr().out
    assert "recon.nmap" in out and "degraded" in out
    assert "whatweb [broken]" in out


def test_tools_missing_explains(tools_cli, capsys):
    capsys.readouterr()
    assert tools_cli("tools", "missing") == 0
    out = capsys.readouterr().out
    assert "whatweb: broken" in out
    assert "sudo apt-get install --reinstall whatweb" in out
    assert "needed by : http.content" in out


def test_tools_install_dry_run_and_confirmed(tools_cli, capsys, fakerunner):
    capsys.readouterr()
    assert tools_cli("tools", "install", "--dry-run") == 0
    assert "Dry run" in capsys.readouterr().out
    assert fakerunner.interactive_calls == []

    assert tools_cli("tools", "install", "whatweb") == 1  # no TTY and no --yes → refused
    assert "needs confirmation" in capsys.readouterr().err
    assert fakerunner.interactive_calls == []

    assert tools_cli("tools", "install", "whatweb", "--yes") == 0
    assert fakerunner.interactive_calls == [("sudo", "apt-get", "install", "--reinstall", "whatweb")]
    assert tools_cli("tools", "install", "nmap") == 0
    assert "already installed and working" in capsys.readouterr().out


def test_tools_show(tools_cli, capsys):
    capsys.readouterr()
    assert tools_cli("tools", "show", "legacy") == 0
    out = capsys.readouterr().out
    assert "commit abcdef123456" in out and "2.7.18" in out
    assert tools_cli("tools", "show", "nope") == 4


def test_nmap_caps_apply(tools_cli, capsys, fakerunner):
    capsys.readouterr()
    assert tools_cli("tools", "nmap-caps") == 0
    assert "mode        : unprivileged" in capsys.readouterr().out

    fakerunner.interactive_hook = lambda argv: fakerunner.on("getcap", stdout=GETCAP_NEW)
    assert tools_cli("tools", "nmap-caps", "--apply", "--yes") == 0
    out = capsys.readouterr().out
    assert "Security note" in out and "nmap mode is now: capabilities" in out
    assert fakerunner.interactive_calls[-1][:3] == ("sudo", "setcap", "cap_net_raw,cap_net_admin,cap_net_bind_service+eip")

    assert tools_cli("tools", "nmap-caps", "--apply", "--yes") == 0
    assert "already set" in capsys.readouterr().out
