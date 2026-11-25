import json
import sys
import threading
from pathlib import Path

import pytest

from aiszx.app import AppContext
from aiszx.core.errors import ScopeError
from aiszx.modules.registry import discover
from aiszx.orchestrator.orchestrator import Orchestrator, layers
from aiszx.orchestrator.planner import ToolResolution
from aiszx.orchestrator.settings import load_settings
from aiszx.orchestrator.state import ExecutionStore
from aiszx.recon.range_discovery import RangeDiscovery
from aiszx.recon.store import ReconStore

FAKE_NMAP = str(Path(__file__).resolve().parents[1] / "fake_nmap.py")
TARGET = "10.129.73.247"
RECON = ["core.connectivity", "recon"]


def resolver(mode="capabilities"):
    def resolve(names):
        out = {}
        for n in names:
            if n == "nmap":
                out[n] = ToolResolution("ok", [sys.executable, FAKE_NMAP], "7.95",
                                        detail={"privileges": {"mode": mode}})
            else:
                out[n] = ToolResolution("missing", [])
        return out
    return resolve


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("FAKE_NMAP_LOG", str(tmp_path / "nmap.log"))
    monkeypatch.delenv("FAKE_NMAP_HANG", raising=False)
    ctx = AppContext.create(data_dir=tmp_path / "data", config_dir=tmp_path / "cfg")
    ctx.layout.ensure_data_dir()
    ctx.open_db(migrate_schema=True)
    eng, _ = ctx.engagements().ensure("default")
    ctx.scope().add(eng, "10.129.0.0/16")
    ctx.scope().add(eng, "10.10.10.0/24")
    ctx.targets().add("default", TARGET)
    yield ctx
    ctx.close()


def orch(app, mode="capabilities", cancel=None, settings=None):
    lines = []
    o = Orchestrator(app, registry=discover(), resolve_tools=resolver(mode), progress=lines.append,
                     cancel_event=cancel, handle_signals=False, settings=settings)
    o.lines = lines
    return o


def nmap_calls(tmp_path):
    return [json.loads(line) for line in (tmp_path / "nmap.log").read_text().splitlines()]


def units(app, report):
    return {r["module_id"]: r for r in ExecutionStore(app.db).units(report.execution_id)}


def test_layers_order_stages_and_dependencies():
    reg = discover()
    order = [[m.meta.id for m in layer] for layer in layers(reg.select(RECON))]
    assert order == [["core.connectivity"], ["recon.host_discovery", "recon.tcp_ports", "recon.udp"],
                     ["recon.service_id"]]


def test_full_recon_pipeline(app, tmp_path):
    report = orch(app).start("default", TARGET, RECON, profile="standard", command="recon")
    u = units(app, report)
    assert u["core.connectivity"]["state"] == "SKIPPED"  # ping not available in the test resolver
    for mid in ("recon.host_discovery", "recon.tcp_ports", "recon.service_id", "recon.udp"):
        assert u[mid]["state"] == "COMPLETED", (mid, u[mid]["error_message"])
    assert report.status == "COMPLETED"

    calls = {tuple(c[:2]): c for c in nmap_calls(tmp_path)}
    tcp = next(c for c in calls.values() if "-p-" in c)
    assert {"-Pn", "-sS", "--privileged", "--min-rate", "-T4", "-oA"} <= set(tcp) and tcp[-1] == TARGET
    svc = next(c for c in calls.values() if "-sV" in c and "-sU" not in c)
    assert svc[svc.index("-p") + 1] == "22,80,443,445,5985" and "-sC" in svc and "-O" not in svc
    udp = next(c for c in calls.values() if "-sU" in c)
    assert udp[udp.index("--top-ports") + 1] == "20"

    store = ReconStore(app.db)
    services = {s.key: s for s in store.services_for_execution(report.execution_id)}
    assert set(services) == {"tcp/22", "tcp/80", "tcp/443", "tcp/445", "tcp/5985", "udp/53"}
    assert services["tcp/443"].categories == ["https"]
    assert services["tcp/5985"].categories == ["http", "winrm"]
    assert services["tcp/22"].product == "OpenSSH" and "ssh-hostkey" in services["tcp/22"].scripts
    ports = {(p["protocol"], p["port"]): p["state"] for p in store.ports_for_execution(report.execution_id)}
    assert ports[("udp", 161)] == "open|filtered" and ports[("tcp", 445)] == "open"
    assert "udp/161" not in services  # uncertain ports are not services
    hosts = store.hosts_for_execution(report.execution_id)
    assert any(json.loads(h["os_json"]) for h in hosts)

    tcp_unit = u["recon.tcp_ports"]
    adir = report.run_dir / tcp_unit["output_dir"]
    assert {f.name for f in (adir / "raw").iterdir()} >= {"tcp.xml", "tcp.nmap", "tcp.gnmap", "tcp.cmd.txt"}
    assert "5 open TCP port(s) of all 65535 TCP ports" in tcp_unit["summary"]
    assert "UDP top 20: 1 open (53/domain), 2 open|filtered (uncertain)" in u["recon.udp"]["summary"]


def test_unprivileged_nmap_uses_connect_scan_and_skips_udp(app, tmp_path):
    report = orch(app, mode="unprivileged").start("default", TARGET, RECON, profile="comprehensive")
    u = units(app, report)
    assert u["recon.udp"]["state"] == "SKIPPED" and "raw sockets" in u["recon.udp"]["skip_reason"]
    tcp = next(c for c in nmap_calls(tmp_path) if "-p-" in c)
    assert "-sT" in tcp and "--unprivileged" in tcp and "-sS" not in tcp
    svc = next(c for c in nmap_calls(tmp_path) if "-sV" in c)
    assert "-O" not in svc and "--version-all" in svc  # OS detection needs raw sockets
    result = json.loads((report.run_dir / units(app, report)["recon.service_id"]["output_dir"] / "parsed" / "result.json").read_text())
    assert any("OS detection skipped" in lim for lim in result["limitations"])


def test_conservative_profile(app, tmp_path):
    report = orch(app).start("default", TARGET, RECON, profile="conservative")
    u = units(app, report)
    assert "disabled in this profile" in u["recon.udp"]["skip_reason"]
    tcp = next(c for c in nmap_calls(tmp_path) if "--top-ports" in c and "-sU" not in c)
    assert tcp[tcp.index("--top-ports") + 1] == "1000" and "-T3" in tcp
    svc = next(c for c in nmap_calls(tmp_path) if "-sV" in c)
    assert "-sC" not in svc


def test_service_id_fails_when_tcp_fails(app, monkeypatch):
    monkeypatch.setenv("FAKE_NMAP_FAIL", "1")
    report = orch(app).start("default", TARGET, ["recon.tcp_ports", "recon.service_id"])
    u = units(app, report)
    assert u["recon.tcp_ports"]["state"] == "FAILED"
    assert "raw-socket privileges" in u["recon.tcp_ports"]["error_message"]
    assert u["recon.service_id"]["state"] == "SKIPPED"
    assert "upstream recon.tcp_ports did not complete" in u["recon.service_id"]["skip_reason"]


def test_service_id_alone_uses_latest_known_services(app, tmp_path):
    orch(app).start("default", TARGET, ["recon.tcp_ports", "recon.service_id"])
    report = orch(app).start("default", TARGET, ["recon.service_id"])
    inputs = json.loads(units(app, report)["recon.service_id"]["inputs_json"])
    assert inputs["ports"] == [22, 80, 443, 445, 5985]


def test_interrupted_tcp_scan_resumes_with_nmap_resume(app, tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_NMAP_HANG", "1")
    cancel = threading.Event()
    threading.Timer(1.5, cancel.set).start()
    first = orch(app, cancel=cancel).start("default", TARGET, ["recon.tcp_ports", "recon.service_id"])
    assert first.status == "INTERRUPTED"
    u = units(app, first)
    assert u["recon.tcp_ports"]["state"] == "INTERRUPTED"
    old_attempt = first.run_dir / u["recon.tcp_ports"]["output_dir"]
    assert (old_attempt / "raw" / "tcp.gnmap").is_file()

    monkeypatch.delenv("FAKE_NMAP_HANG")
    resumed = orch(app).resume("default", TARGET)
    assert resumed.status == "COMPLETED"
    u = units(app, resumed)
    new_attempt = first.run_dir / u["recon.tcp_ports"]["output_dir"]
    assert new_attempt.name == "attempt-02"
    assert ["--resume", str(new_attempt / "raw" / "tcp.gnmap")] == nmap_calls(tmp_path)[-2][:2]
    # nmap --resume wrote into the NEW attempt; the interrupted attempt is untouched
    assert (new_attempt / "raw" / "tcp.resumed").read_text() == str(new_attempt / "raw" / "tcp")
    assert not (old_attempt / "raw" / "tcp.resumed").exists()
    assert "resumed from an interrupted attempt" in (new_attempt / "parsed" / "result.json").read_text()
    # ports found after the resume (grepable output) feed service identification
    assert json.loads(u["recon.service_id"]["inputs_json"])["ports"] == [22, 80, 443, 445, 5985, 8080]


def test_resume_reruns_service_id_when_ports_change(app, tmp_path):
    first = orch(app).start("default", TARGET, ["recon.tcp_ports", "recon.service_id"])
    u = units(app, first)
    # simulate a changed port list: tamper with the tcp result so tcp_ports must re-run
    (first.run_dir / u["recon.tcp_ports"]["output_dir"] / "raw" / "tcp.xml").write_text("changed")
    report = orch(app).resume("default", TARGET)
    decisions = {pu.module.meta.id: pu.decision for pu in report.units}
    assert decisions["recon.tcp_ports"] == "recover"
    # same ports after the re-run → service identification is reused, not repeated
    assert decisions["recon.service_id"] == "reuse"
    assert len(ReconStore(app.db).services_for_execution(first.execution_id)) == 5


def test_profile_change_changes_fingerprint(app, tmp_path):
    report = orch(app).start("default", TARGET, ["recon.tcp_ports"], profile="standard")
    cfg = tmp_path / "cfg"
    cfg.mkdir(exist_ok=True)
    (cfg / "profiles.yaml").write_text("profiles:\n  standard:\n    nmap: {min_rate: 5000}\n", encoding="utf-8")
    s = load_settings(user_config_dir=cfg, engagement_dir=None)
    resumed = orch(app, settings=s).resume("default", TARGET)
    pu = resumed.units[0]
    assert pu.decision == "rerun" and "configuration changed" in pu.decision_reason
    assert report.run_id == resumed.run_id


# --- range discovery --------------------------------------------------------------------

def test_range_discovery_passes_exclusions_and_records_hosts(app, tmp_path):
    eng = app.engagements().get("default")
    app.scope().add(eng, "10.10.10.1", "exclude")
    disc = RangeDiscovery(app, resolve_tools=resolver(), handle_signals=False)
    result = disc.run("default", "10.10.10.0/24")
    assert result.status == "COMPLETED" and result.excluded == ["10.10.10.1"]
    assert [h.address for h in result.hosts] == ["10.10.10.5", "10.10.10.7"]
    call = nmap_calls(tmp_path)[-1]
    assert call[call.index("--exclude") + 1] == "10.10.10.1" and call[-1] == "10.10.10.0/24"
    assert (result.run_dir / "scope" / "scope.json").is_file()
    assert ExecutionStore(app.db).evidence_count(result.execution_id) >= 2

    disc.register("default", result.execution_id, ["10.10.10.7"])
    assert app.targets().find(eng, "10.10.10.7") is not None
    hist = disc.history("default")
    assert hist[0]["registered"] == ["10.10.10.7"] and hist[0]["hosts"] == ["10.10.10.5", "10.10.10.7"]


def test_range_discovery_refuses_ranges_outside_scope(app, tmp_path):
    disc = RangeDiscovery(app, resolve_tools=resolver(), handle_signals=False)
    with pytest.raises(ScopeError, match="out of scope"):
        disc.run("default", "10.10.0.0/16")
    with pytest.raises(ScopeError, match="split ranges"):
        disc.run("default", "10.0.0.0/8")
    assert not (tmp_path / "nmap.log").exists()  # nmap never started


# --- CLI ------------------------------------------------------------------------------

@pytest.fixture
def recon_cli(cli, monkeypatch, tmp_path):
    monkeypatch.setenv("FAKE_NMAP_LOG", str(tmp_path / "nmap.log"))
    monkeypatch.setattr("aiszx.orchestrator.orchestrator.inventory_tool_resolver", lambda app: resolver())
    monkeypatch.setattr("aiszx.recon.range_discovery.inventory_tool_resolver", lambda app: resolver())
    assert cli("init") == 0
    assert cli("scope", "add", "10.129.0.0/16") == 0
    assert cli("scope", "add", "10.10.10.0/24") == 0
    assert cli("target", "add", TARGET) == 0
    return cli


def test_cli_recon_services_and_force(recon_cli, capsys, monkeypatch):
    capsys.readouterr()
    assert recon_cli("recon", TARGET) == 0
    out = capsys.readouterr().out
    assert "stage recon:" in out and "recon.service_id" in out and f"services {TARGET}" in out
    assert recon_cli("services", TARGET) == 0
    out = capsys.readouterr().out
    assert "tcp/5985" in out and "http, winrm" in out and "Uncertain" in out and "udp/161" in out.replace("161/udp", "udp/161")
    assert "OS guess" in out and "ssh-hostkey" in out

    monkeypatch.setenv("FAKE_NMAP_FAIL", "1")
    assert recon_cli("recon", TARGET) == 1
    capsys.readouterr()
    monkeypatch.delenv("FAKE_NMAP_FAIL")
    assert recon_cli("recon", TARGET) == 1
    assert "resume" in capsys.readouterr().err
    assert recon_cli("recon", TARGET, "--force") == 0


def test_cli_discover_and_full(recon_cli, capsys):
    capsys.readouterr()
    assert recon_cli("discover", "10.10.10.0/24", "--register", "--yes") == 0
    out = capsys.readouterr().out
    assert "2 live host(s)" in out and "Registered 2 target(s)" in out
    assert recon_cli("discover", "--list") == 0
    assert "10.10.10.0/24" in capsys.readouterr().out
    assert recon_cli("full", TARGET) == 0
    assert "`full` currently covers reconnaissance" in capsys.readouterr().out
