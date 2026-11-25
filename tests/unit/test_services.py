import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from aiszx.app import AppContext
from aiszx.modules import _svc
from aiszx.modules.base import PlanContext
from aiszx.modules.dns.dig import candidate_domains, parse_axfr
from aiszx.modules.ftp.anonymous import parse_session
from aiszx.modules.nfs.showmount import parse_exports
from aiszx.modules.nse.service_info import ServiceInfo
from aiszx.modules.registry import discover
from aiszx.modules.smb.enum4linux_ng import summarise
from aiszx.modules.smb.netexec import parse_banner, parse_shares
from aiszx.modules.smb.smbclient import parse_grepable
from aiszx.modules.snmp.walk import SnmpWalk, parse_walk
from aiszx.modules.ssh.audit import weak_algorithms
from aiszx.orchestrator.orchestrator import Orchestrator, _effective_dict
from aiszx.orchestrator.planner import ToolResolution
from aiszx.orchestrator.settings import load_settings
from aiszx.orchestrator.state import ExecutionStore
from tests import fake_svc as F

TESTS = Path(__file__).resolve().parents[1]
FAKE_NMAP, FAKE_SVC = str(TESTS / "fake_nmap.py"), str(TESTS / "fake_svc.py")
TARGET = "10.129.73.247"
SVC_TOOLS = ("netexec", "enum4linux-ng", "smbclient", "dig", "ssh-audit", "ldapsearch", "showmount", "snmpwalk", "curl")


# --- parsers --------------------------------------------------------------------------

def test_netexec_banner_and_shares():
    info = parse_banner(F.NXC_BANNER)
    assert info == {"os": "Windows Server 2019 Build 17763 x64", "name": "DC01", "domain": "corp.local",
                    "signing": "False", "smbv1": "True"}
    null = parse_shares(F.NXC_NULL)
    assert null["authenticated"] is True
    assert [(s["name"], s["permissions"]) for s in null["shares"]] == [("ADMIN$", ""), ("Public", "READ"), ("IPC$", "READ")]
    guest = parse_shares(F.NXC_GUEST)
    assert guest["authenticated"] is False and "STATUS_ACCOUNT_DISABLED" in guest["error"]


def test_enum4linux_summary_and_smbclient():
    s = summarise(F.E4L)
    assert s["null_session"] and s["signing_required"] is False and s["domain"] == "corp.local"
    assert s["users"] == ["Administrator", "svc_backup"] and s["groups"] == ["Domain Admins"]
    assert s["shares"]["Public"]["access"]["listing"] == "OK"
    assert summarise({}) ["users"] == []
    assert parse_grepable("Disk|Public|files\nIPC|IPC$|Remote IPC\nnoise") == [
        {"type": "Disk", "name": "Public", "comment": "files"}, {"type": "IPC", "name": "IPC$", "comment": "Remote IPC"}]


def test_dns_parsers_and_domains():
    axfr = parse_axfr(F.AXFR)
    assert axfr["allowed"] and {r["name"] for r in axfr["records"]} == {"corp.local.", "dev.corp.local."}
    assert not parse_axfr("; Transfer failed.")["allowed"]
    target = SimpleNamespace(identity=SimpleNamespace(is_ip=False), canonical="dc01.corp.local")
    ctx = PlanContext(None, target, TARGET, {"domains": ["extra.htb"], "max_domains": 3},
                      run_params={"vhosts": ["dev.box.htb"]})
    assert candidate_domains(ctx) == ["extra.htb", "corp.local", "dc01.corp.local"]
    ctx.upstream = {"ldap.rootdse": [{"artifacts": {"domain": "ad.lab"}}]}
    assert candidate_domains(ctx)[:2] == ["extra.htb", "ad.lab"]


def test_ssh_ftp_ldap_nfs_snmp_parsers():
    weak = weak_algorithms(F.SSH_AUDIT)
    assert [w["algorithm"] for w in weak["kex"]] == ["diffie-hellman-group14-sha1"] and weak["key"][0]["warn"]
    session = parse_session("< 220 (vsFTPd 3.0.3)\n< 331 pw\n< 230 Login successful.")
    assert session == {"banner": "(vsFTPd 3.0.3)", "anonymous": True, "denied": False, "codes": ["220", "331", "230"]}
    assert parse_session("< 220 x\n< 530 Login incorrect.")["denied"]
    entries = _svc.parse_ldif(F.ROOTDSE)
    assert entries[0]["namingContexts"] == ["DC=corp,DC=local", "CN=Configuration,DC=corp,DC=local"]
    assert entries[0]["serverName"][0].endswith("DC=corp,DC=local")  # folded line joined
    assert _svc.parse_ldif("dn: x\ncn:: aGVsbG8=\n")[0]["cn"] == ["hello"]
    assert _svc.dn_to_domain("DC=corp,DC=local") == "corp.local" and _svc.dn_to_domain(None) is None
    exports = parse_exports("Export list for x:\n/srv/share *\n/home 10.0.0.0/24,10.0.1.5")
    assert exports[0]["world"] and exports[1]["clients"] == ["10.0.0.0/24", "10.0.1.5"]
    assert parse_walk('.1.3.6.1.2.1.1.1.0 = STRING: "Linux box"\n.1.3.6.1.2.1.1.9.0 = OID: .1.3') == {
        "sysDescr": "Linux box", "1.3.6.1.2.1.1.9.0": ".1.3"}
    assert _svc.strip_ansi("\x1b[1;34mSMB\x1b[0m x") == "SMB x"


def test_nse_refuses_non_informational_scripts():
    mod = ServiceInfo()
    ctx = PlanContext(None, None, TARGET, {"scripts": {"mysql": ["mysql-info", "mysql-brute"]}})
    assert "mysql-brute" in mod.unavailable_reason(ctx)
    for bad in ("smb-vuln-ms17-010", "http-slowloris-dos", "ftp-vsftpd-backdoor", "smtp-enum-users", "x;rm"):
        assert mod.unavailable_reason(PlanContext(None, None, TARGET, {"scripts": {"x": [bad]}})) is not None
    assert mod.unavailable_reason(PlanContext(None, None, TARGET, {"scripts": {"mysql": ["mysql-info"]}})) is None


def test_snmp_secrets_are_redacted_and_masked(tmp_path):
    mod = SnmpWalk()
    assert "does not guess" in mod.unavailable_reason(PlanContext(None, None, TARGET, {"communities": []}))
    unit = SimpleNamespace(inputs={"address": TARGET, "port": 161})
    ctx = SimpleNamespace(options={"communities": ["s3cretComm"], "version": "2c"})
    [cmd] = mod.build_commands(unit, ctx)
    assert cmd.redact == ["s3cretComm"]
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "modules.yaml").write_text("modules:\n  snmp.walk:\n    options: {communities: [s3cretComm]}\n", encoding="utf-8")
    eff = _effective_dict(load_settings(user_config_dir=cfg, engagement_dir=None), mod)
    assert eff["options"]["communities"] == "***"


# --- end to end ----------------------------------------------------------------------

def resolver(names):
    out = {}
    for n in names:
        if n == "nmap":
            out[n] = ToolResolution("ok", [sys.executable, FAKE_NMAP], "7.95", detail={"privileges": {"mode": "capabilities"}})
        elif n in SVC_TOOLS:
            out[n] = ToolResolution("ok", [sys.executable, FAKE_SVC, n], "1.0")
        else:
            out[n] = ToolResolution("missing", [])
    return out


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("FAKE_NMAP_WIDE", "1")
    monkeypatch.setenv("FAKE_SVC_LOG", str(tmp_path / "svc.log"))
    ctx = AppContext.create(data_dir=tmp_path / "data", config_dir=tmp_path / "cfg")
    ctx.layout.ensure_data_dir()
    ctx.open_db(migrate_schema=True)
    eng, _ = ctx.engagements().ensure("default")
    ctx.scope().add(eng, "10.129.0.0/16")
    ctx.targets().add("default", TARGET)
    yield ctx
    ctx.close()


def enumeration_ids():
    return [mid for mid, m in discover().modules.items() if m.meta.stage.value == "enumeration"]


def test_full_service_enumeration(app, tmp_path):
    orch = Orchestrator(app, registry=discover(), resolve_tools=resolver, handle_signals=False)
    orch.start("default", TARGET, ["recon.tcp_ports", "recon.service_id"])
    report = Orchestrator(app, registry=discover(), resolve_tools=resolver, handle_signals=False).start(
        "default", TARGET, enumeration_ids(), command="enumerate")
    units = ExecutionStore(app.db).units(report.execution_id)
    states = {(u["module_id"], u["unit_key"]): u["state"] for u in units}
    expected = {("smb.netexec", "tcp/445"), ("smb.enum4linux_ng", "host"), ("smb.smbclient", "tcp/445"),
                ("dns.dig", "dns"), ("ssh.audit", "tcp/22"), ("ftp.anonymous", "tcp/21"), ("ldap.rootdse", "tcp/389"),
                ("ldap.anonymous", "tcp/389"), ("nfs.showmount", "host"), ("rservices.exposure", "host"),
                ("nse.service_info", "tcp/445"), ("nse.service_info", "tcp/3306"), ("nse.service_info", "tcp/2049"),
                ("nse.service_info", "tcp/21")}
    assert expected <= set(states), set(states)
    failed = {k: s for k, s in states.items() if s not in ("COMPLETED",) and k in expected}
    assert not failed, failed
    assert not any(m.startswith("snmp.") for m, _ in states)  # no SNMP service → nothing planned

    def result(mid, key):
        u = next(u for u in units if u["module_id"] == mid and u["unit_key"] == key)
        return json.loads((report.run_dir / u["output_dir"] / "parsed" / "result.json").read_text())

    obs = {o["key"]: o["value"] for mid, key in expected for o in result(mid, key)["observations"]}
    assert obs["smb.signing_required"] is False and obs["smb.smbv1_enabled"] is True
    assert obs["smb.null_session"] is True and obs["smb.null_readable_shares"] == ["Public", "IPC$"]
    assert obs["dns.zone_transfer_allowed"] == {"domain": "corp.local", "records": 4}   # domain learned via LDAP/SMB
    assert obs["dns.version_disclosed"].startswith('"9.18')
    assert obs["ssh.weak_algorithms"]["kex"] == ["diffie-hellman-group14-sha1"]
    assert obs["ftp.anonymous_login"] is True
    assert obs["ldap.domain"] == "corp.local" and obs["ldap.anonymous_read"] == {"readable": True, "entries": 2}
    assert obs["nfs.world_mountable"] == ["/srv/share"]
    assert obs["rservices.exposed"][0]["service"] == "rexec"
    assert obs["nse.mysql-info"] == "info from mysql-info"
    ldap_anon = next(u for u in units if u["module_id"] == "ldap.anonymous")
    assert json.loads(ldap_anon["inputs_json"])["base"] == "DC=corp,DC=local"   # planned from rootdse in this run

    from tests import fakelog
    calls = fakelog.read(tmp_path / "svc.log")
    nxc = [a for t, a in calls if t == "netexec"]
    assert ["smb", TARGET, "--port", "445", "-u", "", "-p", "", "--shares"] in nxc
    assert not any("-p" in a and a[a.index("-p") + 1] not in ("",) and "-u" in a and a[a.index("-u") + 1] not in ("", "guest")
                   for a in nxc)  # only null and guest, never other credentials


def test_cli_observations(cli, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("FAKE_NMAP_WIDE", "1")
    monkeypatch.setattr("aiszx.orchestrator.orchestrator.inventory_tool_resolver", lambda app: resolver)
    assert cli("init") == 0 and cli("scope", "add", "10.129.0.0/16") == 0 and cli("target", "add", TARGET) == 0
    assert cli("observations", TARGET) == 0
    assert "none recorded yet" in capsys.readouterr().out
    assert cli("run", TARGET, "-m", "recon.tcp_ports", "-m", "recon.service_id") == 0
    assert cli("enumerate", TARGET, "-m", "smb", "-m", "rservices") == 0
    capsys.readouterr()
    assert cli("observations", TARGET) == 0
    out = capsys.readouterr().out
    assert "smb.null_session" in out and "rservices.exposed" in out, out
    assert cli("observations", TARGET, "--json") == 0
    assert json.loads(capsys.readouterr().out)["observations"]
