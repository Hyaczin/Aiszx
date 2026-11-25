import json

import pytest

from aiszx.app import AppContext
from aiszx.assessment import exploitdb
from aiszx.assessment.engine import Assessor
from aiszx.assessment.knowledge import Knowledge, Observation
from aiszx.assessment.model import CONFIRMED, HYPOTHESIS, MANUAL, POTENTIAL, FindingDraft, finding_id, priority
from aiszx.assessment.rules import RULES
from aiszx.core.errors import AiszxError
from aiszx.modules.records import ServiceRecord
from aiszx.modules.registry import discover
from aiszx.orchestrator.orchestrator import Orchestrator
from tests.unit.test_services import resolver

TARGET = "10.129.73.247"


def obs(key, value, module="m", url="smb://10.129.73.247:445"):
    return Observation(module, "u", key, value, url, "run1", ["a/raw/x.txt"])


def run_rules(k):
    out = []
    for fn in RULES.values():
        out += fn(k)
    return {d.rule_id: d for d in out}, out


# --- rules -----------------------------------------------------------------------------

def test_open_ports_alone_produce_no_findings():
    k = Knowledge(TARGET, services=[ServiceRecord(TARGET, "tcp", 22, name="ssh", categories=["ssh"]),
                                    ServiceRecord(TARGET, "tcp", 80, name="http", categories=["http"])])
    assert run_rules(k)[1] == []


def test_smb_rules_and_agreement_raises_confidence():
    k = Knowledge(TARGET, observations=[
        obs("smb.signing_required", False, "smb.netexec"), obs("smb.signing_required", False, "smb.enum4linux_ng"),
        obs("smb.null_session", True), obs("smb.null_readable_shares", ["Public", "IPC$"]),
        obs("smb.users_enumerable", ["admin", "bob"]), obs("smb.smbv1_enabled", True),
        obs("ldap.domain", "corp.local", url="ldap://x:389")])
    by_rule, all_drafts = run_rules(k)
    assert by_rule["SMB-001"].confidence == "high" and by_rule["SMB-001"].classification == POTENTIAL
    assert by_rule["SMB-003"].classification == CONFIRMED
    shares = [d for d in all_drafts if d.rule_id == "SMB-004"]
    assert [d.discriminator for d in shares] == ["Public"]           # IPC$ is not a finding
    assert by_rule["SMB-006"].details["users"] == ["admin", "bob"]
    assert by_rule["COR-001"].classification == MANUAL                # correlation: AD + signing off
    single = run_rules(Knowledge(TARGET, observations=[obs("smb.signing_required", False, "smb.netexec")]))[0]
    assert single["SMB-001"].confidence == "medium" and "COR-001" not in single


def test_web_rules_only_flag_session_cookies_and_keep_nikto_as_hypothesis():
    url = "http://10.129.73.247/"
    k = Knowledge(TARGET, observations=[
        obs("http.cookie_flags", [{"cookie": "PHPSESSID", "missing": ["httponly", "samesite"]},
                                  {"cookie": "theme", "missing": ["httponly"]}], url=url),
        obs("http.login_form", True, url=url), obs("nikto.item", {"msg": "X-Frame-Options missing"}, url=url),
        obs("http.hostname_hints", ["box.htb"], url=url)],
        resources=[{"path": "/admin", "url": url + "admin", "status_code": 301, "source_tool": "feroxbuster"},
                   {"path": "/images", "url": url + "images", "status_code": 301, "source_tool": "feroxbuster"},
                   {"path": "/backup", "url": url + "backup", "status_code": None, "source_tool": "robots.txt"}])
    by_rule, all_drafts = run_rules(k)
    cookies = [d for d in all_drafts if d.rule_id == "HTTP-001"]
    assert [d.discriminator for d in cookies] == ["PHPSESSID"]
    assert by_rule["HTTP-007"].classification == HYPOTHESIS and by_rule["HTTP-007"].confidence == "low"
    assert sorted(d.discriminator for d in all_drafts if d.rule_id == "HTTP-006") == ["/admin", "/backup"]
    assert "--vhost box.htb" in by_rule["HTTP-008"].next_steps[0]
    assert by_rule["HTTP-005"].classification == MANUAL


def test_exposure_and_rservices_rules():
    k = Knowledge(TARGET, services=[ServiceRecord(TARGET, "tcp", 3306, name="mysql", product="MySQL", version="8.0",
                                                  categories=["mysql"])],
                  observations=[obs("rservices.exposed", [{"service": "rexec", "port": 512}], url="tcp://x"),
                                obs("dns.zone_transfer_allowed", {"domain": "corp.local", "records": 4}, url="dns://x")])
    by_rule, _ = run_rules(k)
    assert by_rule["SVC-001"].severity == "low" and "not a vulnerability by itself" in by_rule["SVC-001"].impact
    assert by_rule["RSVC-001"].classification == MANUAL and "NOT been tested" in by_rule["RSVC-001"].impact
    assert by_rule["DNS-001"].discriminator == "corp.local"


def test_fingerprint_priority_and_paths():
    d1 = FindingDraft("SMB-004", "t", "medium", "high", CONFIRMED, "d", service_key="tcp/445", discriminator="Public",
                      next_steps=["review Public"])
    d2 = FindingDraft("SMB-004", "t", "medium", "high", CONFIRMED, "d", service_key="tcp/445", discriminator="Data")
    assert d1.fingerprint(TARGET) != d2.fingerprint(TARGET)
    assert d1.fingerprint(TARGET) == FindingDraft("SMB-004", "other title", "low", "low", POTENTIAL, "x",
                                                  service_key="tcp/445", discriminator="Public").fingerprint(TARGET)
    assert finding_id(d1.fingerprint(TARGET)).startswith("F-")
    assert priority("high", "high", CONFIRMED) > priority("high", "high", HYPOTHESIS) > priority("low", "low", MANUAL)
    with pytest.raises(ValueError):
        FindingDraft("X", "t", "severe", "high", CONFIRMED, "d")


def test_exploitdb_hypotheses(fakerunner):
    k = Knowledge(TARGET, services=[ServiceRecord(TARGET, "tcp", 22, name="ssh", product="OpenSSH",
                                                  version="8.9p1 Ubuntu 3ubuntu0.13")],
                  technologies=[{"name": "JQuery", "version": "3.6.0", "endpoint_url": "http://x/"},
                                {"name": "Bootstrap", "version": None, "endpoint_url": "http://x/"}])
    assert exploitdb.search_terms("Apache httpd", "2.4.52") == ["Apache", "2.4"]
    assert exploitdb.search_terms("OpenSSH", "8.9p1 Ubuntu") == ["OpenSSH", "8.9"]
    assert exploitdb.search_terms("nginx", "") is None
    fakerunner.on("searchsploit", "--json", "OpenSSH", stdout=json.dumps({"RESULTS_EXPLOIT": [
        {"Title": "OpenSSH 8.x - something", "EDB-ID": "1", "Type": "remote"}]}))
    fakerunner.on("searchsploit", "--json", "JQuery", stdout=json.dumps({"RESULTS_EXPLOIT": []}))
    drafts, notes = exploitdb.lookup(fakerunner, ["searchsploit"], k)
    assert len(drafts) == 1 and drafts[0].classification == HYPOTHESIS and drafts[0].confidence == "low"
    assert drafts[0].service_key == "tcp/22" and "text match only" in drafts[0].description


def test_exploitdb_merges_same_product_from_nmap_and_whatweb():
    # Seen on a real box: nmap says "Apache httpd 2.4.52", WhatWeb says "Apache 2.4.52" → one hypothesis.
    k = Knowledge(TARGET, services=[ServiceRecord(TARGET, "tcp", 80, name="http", product="Apache httpd",
                                                  version="2.4.52")],
                  technologies=[{"name": "Apache", "version": "2.4.52", "endpoint_url": "http://10.129.73.247/"},
                                {"name": "Apache", "version": "2.4.52", "endpoint_url": "http://10.129.73.247/"},
                                {"name": "Apache", "version": "2.4.58", "endpoint_url": "http://other/"}])
    ps = exploitdb.products(k)
    assert [(p.name, p.version, p.where) for p in ps] == [("Apache httpd", "2.4.52", "tcp/80"),
                                                         ("Apache", "2.4.58", "http://other/")]
    assert ps[0].also == ("http://10.129.73.247/",)


# --- engine end to end -------------------------------------------------------------------

@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("FAKE_NMAP_WIDE", "1")
    monkeypatch.delenv("FAKE_SVC_SIGNING", raising=False)
    ctx = AppContext.create(data_dir=tmp_path / "data", config_dir=tmp_path / "cfg")
    ctx.layout.ensure_data_dir()
    ctx.open_db(migrate_schema=True)
    eng, _ = ctx.engagements().ensure("default")
    ctx.scope().add(eng, "10.129.0.0/16")
    ctx.targets().add("default", TARGET)
    yield ctx
    ctx.close()


def scan(app, *tokens):
    return Orchestrator(app, registry=discover(), resolve_tools=resolver, handle_signals=False).start(
        "default", TARGET, list(tokens))


def assessor(app):
    return Assessor(app, searchsploit=lambda: None)


def test_assessment_lifecycle(app, monkeypatch):
    scan(app, "recon.tcp_ports", "recon.service_id")
    scan(app, "smb", "ldap", "dns", "ftp", "nfs", "rservices")
    first = assessor(app).run("default", TARGET)
    rules = {f.draft.rule_id for f in first.findings}
    assert {"SMB-001", "SMB-003", "SMB-004", "SMB-006", "DNS-001", "LDAP-001", "LDAP-002", "FTP-001", "NFS-001",
            "RSVC-001", "SVC-001", "COR-001"} <= rules
    assert all(f.new for f in first.findings)
    assert any("searchsploit not available" in n for n in first.limitations)
    smb1 = next(f for f in first.findings if f.draft.rule_id == "SMB-001")
    assert smb1.draft.evidence and smb1.draft.evidence[0].files  # evidence references raw files
    assert (first.run_dir / "findings" / "findings.json").is_file()
    assert first.paths and first.paths[0]["priority"] >= first.paths[-1]["priority"]

    # same data → same IDs, nothing new
    second = assessor(app).run("default", TARGET)
    assert {f.id for f in second.findings} == {f.id for f in first.findings} and not any(f.new for f in second.findings)

    # analyst decision survives re-assessment and leaves the investigation list
    app.db.execute("UPDATE findings SET analyst_classification = 'false_positive' WHERE id = ?", (smb1.id,))
    third = assessor(app).run("default", TARGET)
    f3 = next(f for f in third.findings if f.id == smb1.id)
    assert f3.classification == "false_positive" and f3.draft.classification == POTENTIAL
    assert smb1.id not in {p["finding"] for p in third.paths}

    # a later scan where signing is enforced: the finding is not reproduced, but kept
    monkeypatch.setenv("FAKE_SVC_SIGNING", "1")
    scan(app, "smb")
    fourth = assessor(app).run("default", TARGET)
    assert smb1.id in fourth.not_reproduced
    row = app.db.query_one("SELECT status, analyst_classification FROM findings WHERE id = ?", (smb1.id,))
    assert (row["status"], row["analyst_classification"]) == ("not_reproduced", "false_positive")
    snapshots = app.db.query("SELECT COUNT(DISTINCT assessment_id) AS n FROM assessment_results WHERE finding_id = ?",
                             (smb1.id,))
    assert snapshots[0]["n"] == 3


def test_resume_skips_assessment_runs(app):
    scan(app, "recon.tcp_ports")
    assessor(app).run("default", TARGET)
    orch = Orchestrator(app, registry=discover(), resolve_tools=resolver, handle_signals=False)
    report = orch.resume("default", TARGET)  # resumes the recon run, not the newer assess run
    assert report.run_id != "" and any("nothing to resume" in m for m in report.messages)
    assess_run = app.db.query_one("SELECT run_id FROM executions WHERE command = 'assess'")["run_id"]
    with pytest.raises(AiszxError, match="not resumable"):
        orch.resume("default", TARGET, run_id=assess_run)


def test_cli_assess_findings_mark(cli, monkeypatch, capsys):
    monkeypatch.setenv("FAKE_NMAP_WIDE", "1")
    monkeypatch.setattr("aiszx.orchestrator.orchestrator.inventory_tool_resolver", lambda app: resolver)
    monkeypatch.setattr("aiszx.assessment.engine.Assessor._searchsploit_launch", lambda self: None)
    assert cli("init") == 0 and cli("scope", "add", "10.129.0.0/16") == 0 and cli("target", "add", TARGET) == 0
    assert cli("findings", "list", TARGET) == 0
    assert "No findings" in capsys.readouterr().out
    assert cli("run", TARGET, "-m", "recon.tcp_ports", "-m", "recon.service_id") == 0
    assert cli("enumerate", TARGET, "-m", "smb", "-m", "ftp") == 0
    capsys.readouterr()
    assert cli("assess", TARGET) == 0
    out = capsys.readouterr().out
    assert "SMB signing not required" in out and "Investigate next" in out and "* " in out
    fid = next(line.split()[0] for line in out.splitlines() if "SMB signing not required" in line)
    assert cli("findings", "show", fid) == 0
    out = capsys.readouterr().out
    assert "potential_vulnerability" in out and "Evidence:" in out and "Next steps:" in out
    assert cli("findings", "mark", fid, "--as", "false_positive", "--note", "lab default") == 0
    assert "marked as false_positive" in capsys.readouterr().out
    assert cli("findings", "list", TARGET) == 0
    assert fid not in capsys.readouterr().out
    assert cli("findings", "list", TARGET, "--all", "--json") == 0
    rows = json.loads(capsys.readouterr().out)
    assert next(r for r in rows if r["id"] == fid)["analyst_notes"] == "lab default"
    assert cli("findings", "show", "F-nope") == 4
