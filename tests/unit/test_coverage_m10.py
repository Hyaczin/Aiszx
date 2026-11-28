"""Milestone 10: host-name hints and accepted virtual hosts, vhost discovery, AD SRV, dnsrecon, rpcdump,
Elasticsearch, more NSE services and the new rules. No network: fake tools only."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from aiszx.app import AppContext
from aiszx.assessment.hints import cert_names, clean, collect, ntlm_names
from aiszx.assessment.knowledge import Knowledge, gather
from aiszx.classify.classifier import Classifier
from aiszx.core.errors import ScopeError
from aiszx.modules.base import PlanContext
from aiszx.modules.dns.ad_srv import parse_srv
from aiszx.modules.dns.dnsrecon import DnsRecon, parse_dnsrecon_json
from aiszx.modules.elasticsearch.info import parse_cat_indices
from aiszx.modules.http.vhost_discovery import (
    VhostDiscovery,
    base_domains,
    drop_catch_all,
    parse_ffuf,
    parse_gobuster_vhost,
)
from aiszx.modules.nse.service_info import DEFAULT_SCRIPTS, ServiceInfo
from aiszx.modules.records import ServiceRecord
from aiszx.modules.registry import discover
from aiszx.modules.rpc.endpoints import notable, parse_rpcdump
from aiszx.orchestrator.orchestrator import Orchestrator
from aiszx.orchestrator.planner import ToolResolution
from aiszx.orchestrator.settings import load_settings
from aiszx.orchestrator.state import ExecutionStore
from tests import fake_svc as F
from tests.unit.test_assessment import obs, run_rules

TESTS = Path(__file__).resolve().parents[1]
FAKE_NMAP, FAKE_SVC = str(TESTS / "fake_nmap.py"), str(TESTS / "fake_svc.py")
TARGET = "10.129.73.247"
TOOLS = ("netexec", "enum4linux-ng", "smbclient", "dig", "ldapsearch", "curl", "dnsrecon", "impacket-rpcdump",
         "ffuf", "gobuster")


# --- parsers ---------------------------------------------------------------------------

def test_vhost_parsers_and_catch_all_filter():
    ffuf = json.dumps({"results": [{"input": {"FUZZ": "Dev"}, "status": 200, "length": 10, "words": 2},
                                   {"input": {}, "status": 200, "length": 1}]})
    assert parse_ffuf(ffuf, "box.htb") == [{"name": "dev.box.htb", "status": 200, "length": 10, "words": 2,
                                            "redirect": None}]
    assert parse_ffuf("not json", "box.htb") == []
    lines = ("Found: dev.box.htb Status: 200 [Size: 5120]\n"
             "Found: old.box.htb (Status: 302) [Size: 0]\nProgress: 100\n")  # gobuster 3.6 and 3.1 formats
    assert [(f["name"], f["status"], f["length"]) for f in parse_gobuster_vhost(lines)] == [
        ("dev.box.htb", 200, 5120), ("old.box.htb", 302, 0)]
    found = [{"name": f"{w}.box.htb", "status": 200, "length": 1000} for w in ("a", "b", "c")]
    found.append({"name": "dev.box.htb", "status": 200, "length": 5120})
    kept, noisy = drop_catch_all(found)
    assert [f["name"] for f in kept] == ["dev.box.htb"] and noisy == [(200, 1000)]
    assert drop_catch_all(found[:2])[0] == found[:2]  # two alike are not enough to call it a catch-all


def test_srv_dnsrecon_rpcdump_and_elasticsearch_parsers():
    assert parse_srv("0 100 389 DC01.corp.local.\n;; noise\n") == [
        {"priority": 0, "weight": 100, "port": 389, "target": "dc01.corp.local"}]
    recs = parse_dnsrecon_json(json.dumps(F.DNSRECON))
    assert [r["type"] for r in recs] == ["SOA", "NS", "A", "A", "SRV"]  # ScanInfo dropped
    assert recs[0]["mname"] == "dc01.corp.local" and parse_dnsrecon_json("{bad") == []
    data = parse_rpcdump(F.RPCDUMP)
    assert data["received"] == 4 and len(data["endpoints"]) == 3  # MS-RPRN listed twice, merged
    rprn = next(e for e in data["endpoints"] if e["uuid"] == "12345678-1234-ABCD-EF00-0123456789AB")
    assert rprn["provider"] == "spoolsv.exe" and len(rprn["bindings"]) == 3
    assert next(e for e in data["endpoints"] if e["uuid"].startswith("0B6E"))["protocol"] is None
    assert [n["name"] for n in notable(data["endpoints"])] == ["MS-RPRN (print spooler)"]
    assert parse_rpcdump("[-] Could not connect: timed out")["error"] == "Could not connect: timed out"
    table = "health status index uuid pri rep docs.count docs.deleted store.size pri.store.size\n" \
            "green open users abc 1 0 42 0 10kb 10kb\n"
    assert parse_cat_indices(table) == [{"health": "green", "status": "open", "index": "users", "uuid": "abc",
                                         "pri": "1", "rep": "0", "docs.count": "42", "docs.deleted": "0",
                                         "store.size": "10kb", "pri.store.size": "10kb"}]
    assert parse_cat_indices('{"error": "x"}') == []


def test_new_categories_and_nse_scripts_are_informational():
    c = Classifier.load()
    def cats(port, name, product=None):
        return c.classify(ServiceRecord(TARGET, "tcp", port, name=name, product=product)).categories
    assert cats(6379, "redis") == ["redis"] and cats(27017, "mongodb") == ["mongodb"]
    assert cats(11211, "memcache") == ["memcached"] and cats(873, "rsync") == ["rsync"]
    assert cats(2375, "docker", "Docker") == ["docker"]
    assert set(cats(9200, "http", "Elasticsearch REST API")) == {"http", "elasticsearch"}
    assert ServiceInfo().unavailable_reason(PlanContext(None, None, TARGET, {"scripts": DEFAULT_SCRIPTS})) is None
    assert {"redis", "mongodb", "memcached", "rsync", "docker"} <= set(ServiceInfo.meta.categories)


def test_vhost_discovery_bases_only_from_scope_checked_names():
    ip_target = SimpleNamespace(identity=SimpleNamespace(is_ip=True), canonical=TARGET)
    ctx = PlanContext(None, ip_target, TARGET, {"max_domains": 3})
    assert base_domains(ctx) == []  # nothing accepted: nothing to fuzz under
    ctx.run_params = {"vhosts": ["box.htb", "Box.HTB", "intranet"]}
    assert base_domains(ctx) == ["box.htb"]  # single-label names are not domains
    svc = ServiceRecord(TARGET, "tcp", 80, name="http", categories=["http"])
    winrm = ServiceRecord(TARGET, "tcp", 5985, name="http", categories=["http", "winrm"])
    ctx.services, ctx.tool_details = [svc, winrm], {"ffuf": {}}
    ctx.options = {**VhostDiscovery.meta.config_defaults, "wordlists": [__file__]}
    [unit] = VhostDiscovery().plan(ctx)
    assert unit.key == "tcp/80@box.htb" and unit.inputs["tool"] == "ffuf"
    [cmd] = VhostDiscovery().build_commands(unit, SimpleNamespace(options=ctx.options))
    assert cmd.targets == [TARGET, "box.htb"] and "Host: FUZZ.box.htb" in cmd.argv and "-ac" in cmd.argv
    assert cmd.argv[cmd.argv.index("-u") + 1] == f"http://{TARGET}/"


def test_dnsrecon_switches_off_checks_that_contact_other_servers():
    unit = SimpleNamespace(inputs={"address": TARGET, "domains": ["corp.local"]})
    [cmd] = DnsRecon().build_commands(unit, SimpleNamespace(options={"lifetime": 3}))
    assert cmd.targets == [TARGET] and cmd.argv[cmd.argv.index("-n") + 1] == TARGET
    assert {"--disable_check_recursion", "--disable_check_bindversion"} <= set(cmd.argv)
    assert cmd.argv[cmd.argv.index("-t") + 1] == "std" and "brt" not in cmd.argv and "-a" not in cmd.argv


# --- hints ---------------------------------------------------------------------------

def test_hint_name_cleaning_and_sources():
    assert clean("DC01.Corp.Local.") == "dc01.corp.local"
    assert [clean(x) for x in ("*.corp.local", "10.0.0.1", "localhost", None, "fe80::1")] == [None] * 5
    assert ntlm_names("DNS_Domain_Name: corp.local\nDNS_Computer_Name: dc01.corp.local") == ["corp.local", "dc01.corp.local"]
    assert cert_names("Subject: commonName=a.box.htb\nSubject Alternative Name: DNS:a.box.htb, DNS:b.box.htb, IP Address:1.2.3.4") \
        == ["a.box.htb", "a.box.htb", "b.box.htb"]
    k = Knowledge(TARGET, results={
        ("http.probe", "http://x:80"): {"artifacts": {"endpoint": {"location": "http://Box.htb/login",
                                                                    "tls": {"certificate": {"san": ["box.htb", "*.box.htb"]}}}}},
        ("ldap.rootdse", "tcp/389"): {"artifacts": {"dnsHostName": "dc01.corp.local", "domain": "corp.local"}},
        ("smb.netexec", "tcp/445"): {"artifacts": {"host": {"name": "DC01", "domain": "corp.local"}}},
        ("dns.dig", "dns"): {"artifacts": {"reverse": ["dc01.corp.local."], "domains": {"corp.local": {
            "SOA": ["dc01.corp.local. hostmaster.corp.local. 1 2 3 4 5"], "MX": ["10 mail.corp.local."], "NS": [],
            "AXFR": {"records": [{"name": "dev.corp.local."}]}}}}},
        ("http.vhost_discovery", "tcp/80@box.htb"): {"artifacts": {"found": [{"name": "staging.box.htb"}]}}},
        services=[ServiceRecord(TARGET, "tcp", 3389, scripts={"rdp-ntlm-info": "DNS_Computer_Name: ws01.corp.local"})])
    hints = {h.name: h.sources for h in collect(k, exclude=[TARGET, "corp.local"])}
    assert set(hints) == {"box.htb", "dc01.corp.local", "mail.corp.local", "dev.corp.local", "staging.box.htb",
                          "ws01.corp.local"}
    assert any(s.startswith("HTTP redirect") for s in hints["box.htb"]) and any(
        s.startswith("TLS certificate") for s in hints["box.htb"])
    assert len(hints["dc01.corp.local"]) == 4  # RootDSE, SMB banner, reverse DNS, SOA


# --- rules ---------------------------------------------------------------------------

def test_milestone10_rules():
    k = Knowledge(TARGET, observations=[
        obs("http.vhost_found", ["dev.box.htb"], url="http://10.129.73.247/"),
        obs("dns.ad_srv", {"domain": "corp.local", "domain_controllers": ["dc01.corp.local"], "services": ["ldap_dc"]},
            url="dns://10.129.73.247"),
        obs("rpc.notable_interfaces", [{"uuid": "x", "name": "MS-RPRN (print spooler)"}], url="tcp://10.129.73.247:135"),
        obs("nse.rdp-enum-encryption", "Security layer\n  CredSSP (NLA): SUCCESS\n  SSL: SUCCESS",
            url="tcp://10.129.73.247:3389"),
        obs("nse.redis-info", "Version: 7.0.11\nOperating System: Linux", url="tcp://10.129.73.247:6379"),
        obs("nse.mongodb-databases", "ERROR: Script execution failed: not authorized", url="tcp://10.129.73.247:27017"),
        obs("nse.docker-version", "Version: 24.0.7\nApiVersion: 1.43", url="tcp://10.129.73.247:2375"),
        obs("elasticsearch.unauthenticated", {"cluster_name": "es", "version": "7.17.9", "indices": 3},
            url="http://10.129.73.247:9200/")],
        services=[ServiceRecord(TARGET, "tcp", 5985, name="http", categories=["http", "winrm"])])
    by_rule, drafts = run_rules(k)
    assert {"VHOST-001", "AD-001", "RPC-001", "RDP-001", "REDIS-001", "DOCKER-001", "ES-001", "WINRM-001"} <= set(by_rule)
    assert "MONGO-001" not in by_rule  # an authorisation error is not unauthenticated access
    assert by_rule["DOCKER-001"].severity == "critical" and by_rule["REDIS-001"].service_key == "tcp/6379"
    assert by_rule["RDP-001"].service_key == "tcp/3389" and by_rule["WINRM-001"].severity == "info"
    assert "hints accept" in by_rule["VHOST-001"].next_steps[0]
    nla_only = Knowledge(TARGET, observations=[obs("nse.rdp-enum-encryption", "CredSSP (NLA): SUCCESS",
                                                   url="tcp://10.129.73.247:3389")])
    assert "RDP-001" not in run_rules(nla_only)[0]


# --- accepted virtual hosts ------------------------------------------------------------

def resolver(names):
    out = {}
    for n in names:
        if n == "nmap":
            out[n] = ToolResolution("ok", [sys.executable, FAKE_NMAP], "7.95", detail={"privileges": {"mode": "capabilities"}})
        elif n in TOOLS:
            out[n] = ToolResolution("ok", [sys.executable, FAKE_SVC, n], "1.0")
        else:
            out[n] = ToolResolution("missing", [])
    return out


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("FAKE_NMAP_M10", "1")
    monkeypatch.setenv("FAKE_SVC_LOG", str(tmp_path / "svc.log"))
    words = tmp_path / "subdomains.txt"
    words.write_text("dev\nstaging\nwww\n")
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "modules.yaml").write_text(f"modules:\n  http.vhost_discovery:\n    options:\n      wordlists: ['{words.as_posix()}']\n",
                                      encoding="utf-8")
    ctx = AppContext.create(data_dir=tmp_path / "data", config_dir=cfg)
    ctx.layout.ensure_data_dir()
    ctx.open_db(migrate_schema=True)
    eng, _ = ctx.engagements().ensure("default")
    ctx.scope().add(eng, "10.129.0.0/16")
    ctx.targets().add("default", TARGET)
    yield ctx
    ctx.close()


def orch(app):
    return Orchestrator(app, registry=discover(), resolve_tools=resolver, handle_signals=False,
                        settings=load_settings(user_config_dir=app.config.user_config_dir, engagement_dir=None))


def target(app):
    return app.targets().get(app.engagements().get("default"), TARGET)


def test_accepted_vhosts_are_scope_checked_stored_and_used(app):
    mgr = app.targets()
    eng = app.engagements().get("default")
    app.scope().add(eng, "evil.corp.local", "exclude")
    with pytest.raises(ScopeError):
        mgr.accept_vhosts(target(app), {"evil.corp.local": "manual"})
    assert mgr.accept_vhosts(target(app), {"corp.local": "manual"}) == ["corp.local"]
    assert mgr.accept_vhosts(target(app), {"corp.local": "manual"}) == []  # idempotent
    mirror = app.layout.target_dir("default", target(app).slug) / "target.yaml"
    assert "corp.local" in mirror.read_text()

    orch(app).start("default", TARGET, ["recon.tcp_ports", "recon.service_id"])
    report = orch(app).start("default", TARGET, ["http.probe"], command="enumerate")
    assert any("accepted virtual host(s) included: corp.local" in m for m in report.messages)
    keys = {pu.unit.key for pu in report.units}
    assert "http://corp.local:80" in keys and f"http://{TARGET}:80" in keys
    snap = json.loads(app.db.query_one("SELECT config_snapshot FROM executions WHERE id = ?",
                                       (report.execution_id,))["config_snapshot"])
    assert snap["run_params"]["vhosts"] == ["corp.local"]   # recorded, so `resume` presents the same names

    app.scope().add(eng, "corp.local", "exclude")             # scope narrowed after accepting
    report = orch(app).start("default", TARGET, ["http.probe"], command="enumerate")
    assert any("not used: no longer in scope" in m for m in report.messages)
    assert "http://corp.local:80" not in {pu.unit.key for pu in report.units}
    assert mgr.remove_vhosts(target(app), ["corp.local"]) == ["corp.local"] and mgr.vhost_names(target(app)) == []


def test_milestone10_enumeration_end_to_end(app, tmp_path):
    app.targets().accept_vhosts(target(app), {"corp.local": "manual"})
    orch(app).start("default", TARGET, ["recon.tcp_ports", "recon.service_id"])
    mods = ["ldap.rootdse", "smb.netexec", "dns.dig", "dns.ad_srv", "dns.dnsrecon", "rpc.endpoints", "nse.service_info",
            "http.vhost_discovery", "elasticsearch.info"]
    report = orch(app).start("default", TARGET, mods, command="enumerate")
    units = ExecutionStore(app.db).units(report.execution_id)
    states = {(u["module_id"], u["unit_key"]): u["state"] for u in units}
    expected = {("dns.ad_srv", "dns"), ("dns.dnsrecon", "dns"), ("rpc.endpoints", "tcp/135"),
                ("http.vhost_discovery", "tcp/80@corp.local"), ("http.vhost_discovery", "tcp/9200@corp.local"),
                ("elasticsearch.info", "tcp/9200"), ("nse.service_info", "tcp/6379"), ("nse.service_info", "tcp/27017"),
                ("nse.service_info", "tcp/11211"), ("nse.service_info", "tcp/873"), ("nse.service_info", "tcp/2375")}
    assert expected <= set(states), set(states) - expected
    assert all(states[k] == "COMPLETED" for k in expected), {k: states[k] for k in expected}
    assert not any(k[1].startswith("tcp/5985@") for k in states)  # WinRM is not a website

    def result(mid, key):
        u = next(u for u in units if u["module_id"] == mid and u["unit_key"] == key)
        return json.loads((report.run_dir / u["output_dir"] / "parsed" / "result.json").read_text())

    srv = result("dns.ad_srv", "dns")
    assert srv["artifacts"]["domains"]["corp.local"]["ldap_dc"][0]["target"] == "dc01.corp.local"
    vh = result("http.vhost_discovery", "tcp/80@corp.local")
    assert [f["name"] for f in vh["artifacts"]["found"]] == ["dev.corp.local", "staging.corp.local"]
    assert result("rpc.endpoints", "tcp/135")["observations"][-1]["key"] == "rpc.notable_interfaces"

    from tests import fakelog
    calls = fakelog.read(tmp_path / "svc.log")
    ffuf = next(a for t, a in calls if t == "ffuf")
    assert ffuf[ffuf.index("-u") + 1].startswith(f"http://{TARGET}")  # connects to the pinned address
    recon_args = [a for t, a in calls if t == "dnsrecon"]
    assert recon_args and all("--disable_check_recursion" in a for a in recon_args)
    assert not any(t == "impacket-rpcdump" and any("@" in x for x in a) for t, a in calls)  # no credentials

    k = gather(app.db, app.config.data_dir, target(app).id, TARGET)
    names = {h.name for h in collect(k, exclude=[TARGET])}
    assert {"dc01.corp.local", "intranet.corp.local", "dev.corp.local", "staging.corp.local"} <= names

    from aiszx.assessment.engine import Assessor
    rules = {f.draft.rule_id for f in Assessor(app).run("default", TARGET, exploitdb_lookup=False).findings}
    assert {"AD-001", "RPC-001", "WINRM-001", "VHOST-001", "REDIS-001", "DOCKER-001"} <= rules, rules


def test_cli_hints(cli, monkeypatch, capsys):
    monkeypatch.setenv("FAKE_NMAP_M10", "1")
    monkeypatch.setattr("aiszx.orchestrator.orchestrator.inventory_tool_resolver", lambda app: resolver)
    assert cli("init") == 0 and cli("scope", "add", "10.129.0.0/16") == 0 and cli("target", "add", TARGET) == 0
    assert cli("scope", "add", "--exclude", "evil.corp.local") == 0
    assert cli("hints", "list", TARGET) == 0
    assert "none seen yet" in capsys.readouterr().out
    assert cli("run", TARGET, "-m", "recon.tcp_ports", "-m", "recon.service_id") == 0
    assert cli("enumerate", TARGET, "-m", "ldap.rootdse") == 0
    capsys.readouterr()
    assert cli("hints", "list", TARGET, "--json") == 0
    rows = {r["name"]: r for r in json.loads(capsys.readouterr().out)["hints"]}
    assert rows["dc01.corp.local"]["status"] == "in scope" and len(rows["dc01.corp.local"]["sources"]) >= 2
    assert cli("hints", "accept", TARGET, "corp.local") == 1          # no terminal and no --yes: nothing accepted
    assert cli("hints", "accept", TARGET, "corp.local", "evil.corp.local", "-y") == 1   # one refused
    out = capsys.readouterr().out
    assert "refused: evil.corp.local is out of scope" in out and "accepted: corp.local" in out
    assert cli("hints", "list", TARGET) == 0
    assert "accepted" in capsys.readouterr().out
    assert cli("hints", "accept", TARGET, TARGET, "-y") == 2           # the target itself is not a vhost
    assert cli("hints", "remove", TARGET, "corp.local") == 0
    assert cli("hints", "remove", TARGET, "corp.local") == 1
