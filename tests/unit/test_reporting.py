import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote

import pytest

from aiszx.app import AppContext
from aiszx.assessment.engine import Assessor
from aiszx.core.errors import ConfigError
from aiszx.modules.registry import discover
from aiszx.orchestrator.orchestrator import Orchestrator
from aiszx.orchestrator.planner import ToolResolution
from aiszx.reporting import render as R
from aiszx.reporting.builder import SECTIONS
from aiszx.reporting.compare import Comparator
from aiszx.reporting.redact import MASK, Redactor
from aiszx.reporting.service import Reporter, compare_and_store
from aiszx.reporting.settings import load_report_settings

pytest.importorskip("jinja2")

TESTS = Path(__file__).resolve().parents[1]
FAKE_NMAP, FAKE_SVC, FAKE_WEB = (str(TESTS / n) for n in ("fake_nmap.py", "fake_svc.py", "fake_web.py"))
SVC_TOOLS = ("netexec", "enum4linux-ng", "smbclient", "dig", "ssh-audit", "ldapsearch", "showmount", "snmpwalk")
WEB_TOOLS = ("curl", "whatweb", "feroxbuster", "gobuster", "nikto", "eyewitness", "openssl")
TARGET = "10.129.73.247"
HOSTILE = '<script>alert(1)</script> | **bold** [x](javascript:alert(1)) `tick`'


def resolver(names):
    out = {}
    for n in names:
        if n == "nmap":
            out[n] = ToolResolution("ok", [sys.executable, FAKE_NMAP], "7.95", detail={"privileges": {"mode": "capabilities"}})
        elif n in SVC_TOOLS:
            out[n] = ToolResolution("ok", [sys.executable, FAKE_SVC, n], "1.0")
        elif n in WEB_TOOLS:
            out[n] = ToolResolution("ok", [sys.executable, FAKE_WEB, n], "1.0")
        else:
            out[n] = ToolResolution("missing", [])
    return out


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.delenv("FAKE_NMAP_WIDE", raising=False)
    monkeypatch.delenv("FAKE_SVC_SIGNING", raising=False)
    ctx = AppContext.create(data_dir=tmp_path / "data", config_dir=tmp_path / "cfg")
    ctx.layout.ensure_data_dir()
    ctx.open_db(migrate_schema=True)
    eng, _ = ctx.engagements().ensure("default")
    ctx.scope().add(eng, "10.129.0.0/16")
    ctx.scope().add(eng, "10.129.73.250", action="exclude")
    ctx.targets().add("default", TARGET)
    yield ctx
    ctx.close()


def scan(app, *tokens, profile=None):
    return Orchestrator(app, registry=discover(), resolve_tools=resolver, handle_signals=False).start(
        "default", TARGET, list(tokens), **({"profile": profile} if profile else {}))


def assess(app):
    return Assessor(app, searchsploit=lambda: None).run("default", TARGET)


# --- redaction -------------------------------------------------------------------

def test_redactor_patterns():
    r = Redactor()
    cases = {
        "ftp://admin:S3cretPass@10.0.0.1/": "ftp://admin:" + MASK + "@10.0.0.1/",
        "login password=hunter2 ok": "login password=" + MASK + " ok",
        '{"api_key": "abcd1234efgh"}': '{"api_key": ' + MASK + '}',
        "Authorization: Basic YWRtaW46YWRtaW4=": "Authorization: Basic " + MASK,
        "Set-Cookie: PHPSESSID=deadbeef1234; path=/; HttpOnly": "Set-Cookie: PHPSESSID=" + MASK + "; path=/; HttpOnly",
        "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::":
            "Administrator:500:" + MASK + ":::",
    }
    for raw, expected in cases.items():
        assert r.text(raw) == expected, raw
    key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\n-----END OPENSSH PRIVATE KEY-----"
    assert r.text(f"found:\n{key}\nend") == f"found:\n{MASK}\nend"
    assert MASK in r.text("token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
    assert r.text("SSH fingerprint SHA256:abc, Minimum password length: 7") == "SSH fingerprint SHA256:abc, Minimum password length: 7"
    assert r.count == 8


def test_redactor_structured_and_literals():
    r = Redactor(literals=["Zx9communityQ", "public"], extra_secret_keys=["pin"])
    data = {"password": "x", "Minimum password length": 7, "communities": ["a", "b"], "pin": 1234,
            "headers": {"set-cookie": ["PHPSESSID=abc123; path=/", "lang=en"], "server": "Apache"},
            "note": "community Zx9communityQ worked; Public files share", "fingerprints": [{"hash": "SHA256:x"}]}
    out = r.value(data)
    assert out["password"] == MASK and out["Minimum password length"] == 7 and out["communities"] == [MASK, MASK]
    assert out["pin"] == MASK and out["headers"]["server"] == "Apache"
    assert out["headers"]["set-cookie"] == ["PHPSESSID=" + MASK + "; path=/", "lang=" + MASK]
    assert out["note"] == f"community {MASK} worked; Public files share"  # default literal 'public' not masked
    assert out["fingerprints"] == [{"hash": "SHA256:x"}]


# --- markdown / html escaping ----------------------------------------------------

def test_markdown_escaping_and_code():
    esc = R.md_escape(HOSTILE + "\nsecond line")
    assert "<" not in esc.replace("\\<", "") and "|" not in esc.replace("\\|", "") and "\n" not in esc
    assert "\\[x\\]" in esc and "\\*\\*bold\\*\\*" in esc
    assert R.md_escape("# heading") == "\\# heading" and R.md_escape("&lt;b&gt;") == "&amp;lt;b&amp;gt;"
    assert R.md_code("a`b") == "``a`b``" and R.md_code("`x`") == "`` `x` ``"
    assert R.href("../../..", "runs/r 1/a#b.txt") == "../../../runs/r%201/a%23b.txt"
    for bad in ("/etc/passwd", "javascript:alert(1)", "runs/../../x", "C:/x"):
        assert R.href("..", bad) is None


def test_missing_jinja_is_explained(monkeypatch):
    monkeypatch.setitem(sys.modules, "jinja2", None)
    with pytest.raises(R.MissingDependency, match="install.sh"):
        R.render({"meta": {}}, "markdown")


# --- settings --------------------------------------------------------------------

def test_report_settings_layering(tmp_path):
    eng_dir = tmp_path / "eng"
    eng_dir.mkdir()
    (eng_dir / "overrides.yaml").write_text("reporting:\n  formats: [json]\n  include_hypotheses: false\n")
    s = load_report_settings(user_config_dir=None, engagement_dir=eng_dir)
    assert s.formats == ("json",) and s.include_hypotheses is False and s.max_table_rows == 300
    from aiszx.orchestrator.settings import load_settings
    load_settings(user_config_dir=None, engagement_dir=eng_dir)  # the `reporting:` key is accepted there too
    user = tmp_path / "user"
    user.mkdir()
    (user / "reporting.yaml").write_text("reporting:\n  redaction:\n    extra_patterns: ['([']\n")
    with pytest.raises(ConfigError, match="not a valid regex"):
        load_report_settings(user_config_dir=user, engagement_dir=None)


# --- end to end ------------------------------------------------------------------

def _links(text: str, pattern: str) -> list[str]:
    return [unquote(h) for h in re.findall(pattern, text)]


def test_full_report(app, tmp_path, monkeypatch):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\nuploads\n")
    (tmp_path / "cfg").mkdir(exist_ok=True)
    (tmp_path / "cfg" / "modules.yaml").write_text(
        f"modules:\n  http.content_discovery:\n    options:\n      wordlists: ['{wordlist.as_posix()}']\n")
    scan(app, "recon.tcp_ports", "recon.service_id")
    scan(app, "smb", "http")
    assess(app)
    # hostile target data and secrets that must never reach a report
    app.db.execute("UPDATE web_endpoints SET title = ?, headers_json = ?", (
        HOSTILE, json.dumps({"set-cookie": ["PHPSESSID=s3ssionSecretXYZ; path=/"], "server": "Apache"})))
    app.db.execute("UPDATE findings SET description = description || ' (seen password=hunter2xyz)'"
                   " WHERE rule_id = 'SMB-001'")

    res = Reporter(app).run("default", TARGET)
    assert set(res.files) == {"markdown", "html", "json"} and all(p.is_file() for p in res.files.values())
    assert res.files["html"].parent == res.run_dir / "reports" and set(res.consolidated) == set(res.files)
    md, html, js = (res.files[f].read_text(encoding="utf-8") for f in ("markdown", "html", "json"))
    model = json.loads(js)

    # all 15 sections, in order, in every format
    assert [s["title"] for s in model["meta"]["sections"]] == [t for _k, t in SECTIONS]
    for n, (_k, title) in enumerate(SECTIONS, 1):
        assert f"## {n}. {title}" in md and f"<h2>{n}. {title}</h2>" in html

    # redaction everywhere, cookie name kept
    for text in (md, html, js):
        assert "s3ssionSecretXYZ" not in text and "hunter2xyz" not in text
    assert model["meta"]["redactions"] >= 2 and "PHPSESSID" in js
    assert any("redacted" in line for line in model["limitations"]["entries"])

    # hostile banner escaped in HTML and Markdown
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert 'href="javascript' not in html and "[x](javascript" not in md  # brackets escaped: no link
    assert "\\<script\\>" in md

    # verified results are separated from hypotheses; scope, exclusions and evidence are present
    labels = [g["label"] for g in model["findings"]["groups"]]
    assert labels == ["Confirmed observations", "Potential vulnerabilities", "Requires manual validation",
                      "Unverified hypotheses"]
    assert any(f["rule_id"] == "SMB-001" for g in model["findings"]["groups"] for f in g["entries"])
    assert model["scope"]["excludes"][0]["value"] == "10.129.73.250"
    assert model["ports"]["coverage"][1] == {"protocol": "udp", "scanned": False, "run_id": None, "profile": None}
    assert any("UDP ports were not scanned" in x for x in model["limitations"]["entries"])
    assert model["web"]["endpoints"] and model["services"]["entries"] and model["investigation"]["steps"]
    assert {u["module"] for f in model["enumeration"]["families"] for u in f["units"]} >= {"smb.netexec", "http.probe"}
    assert model["evidence"]["entries"] and all(e["sha256"] for e in model["evidence"]["entries"])

    # every evidence link resolves to a real file, from both the run and the consolidated copy
    for path, pattern in ((res.files["html"], r'href="(\.\.[^"#]+)"'), (res.files["markdown"], r"\]\((\.\.[^)]+)\)"),
                          (res.consolidated["html"], r'href="(\.\.[^"#]+)"')):
        links = _links(path.read_text(encoding="utf-8"), pattern)
        assert links, path
        assert all((path.parent / link).resolve().is_file() for link in links), path

    # the report is a run of its own with registered evidence; earlier runs are untouched
    rows = app.db.query("SELECT v.kind, v.rel_path FROM evidence v JOIN executions e ON e.id = v.execution_id"
                        " WHERE e.command = 'report'")
    assert {r["kind"] for r in rows} == {"report"} and len(rows) == 3
    assert Reporter(app).run("default", TARGET, ("json",)).run_id != res.run_id
    assert res.files["markdown"].is_file()


def test_report_reclassifies_old_scan_results(app):
    # services stored before a service_map change carry old categories; the report uses the current map
    scan(app, "recon.tcp_ports", "recon.service_id")
    app.db.execute("UPDATE services SET categories_json = '[]'")
    model = Reporter(app).run("default", TARGET, ("json",)).model
    cats = {a["category"] for a in model["attack_surface"]["areas"]}
    assert "smb" in cats and "other" not in cats


def test_report_without_data_and_stale_warning(app):
    res = Reporter(app).run("default", TARGET, ("markdown",))
    model = res.model
    assert model["summary"]["stale_warning"].startswith("No assessment")
    assert "No services identified yet" in res.files["markdown"].read_text(encoding="utf-8")
    scan(app, "recon.tcp_ports", "recon.service_id")
    assess(app)
    scan(app, "recon.service_id")
    model = Reporter(app).run("default", TARGET, ("json",)).model
    assert "newer than the last assessment" in model["summary"]["stale_warning"]


# --- comparison ------------------------------------------------------------------

def test_compare_latest(app, monkeypatch):
    first = Comparator(app.db, app.targets().get(app.engagements().get("default"), TARGET).id).compare()
    assert all(not c["compared"] for c in first["categories"].values())

    scan(app, "recon.tcp_ports", "recon.service_id", "smb")
    assess(app)
    monkeypatch.setenv("FAKE_NMAP_WIDE", "1")
    monkeypatch.setenv("FAKE_SVC_SIGNING", "1")
    scan(app, "recon.tcp_ports", "recon.service_id", "smb", profile="comprehensive")
    assess(app)

    result, path = compare_and_store(app, "default", TARGET)
    assert path.parent.name == "history" and path.is_file()
    ports = result["categories"]["ports"]
    assert ports["protocols"] == ["tcp"]
    assert {p["port"] for p in ports["opened"]} >= {21, 53, 389} and {p["port"] for p in ports["closed"]} >= {80, 443}
    assert any("different profiles" in n for n in ports["notes"])
    svc = result["categories"]["services"]
    assert {s["service"] for s in svc["new"]} >= {"tcp/21"} and {s["service"] for s in svc["removed"]} >= {"tcp/80"}
    findings = result["categories"]["findings"]
    assert any(f["title"].startswith("SMB signing") for f in findings["not_reproduced"])
    assert result["categories"]["web"]["compared"] is False
    assert any("no longer reproduced" in line for line in result["summary"]["lines"])

    # pinned runs: an assessment run has no port data
    runs = app.db.query("SELECT run_id, command FROM executions ORDER BY started_at, run_id")
    recon = [r["run_id"] for r in runs if r["command"] == "run"]
    assess_run = next(r["run_id"] for r in runs if r["command"] == "assess")
    pinned, _ = compare_and_store(app, "default", TARGET, recon[0], assess_run)
    assert pinned["categories"]["ports"]["compared"] is False and "no port scan" in pinned["categories"]["ports"]["reason"]
    with pytest.raises(LookupError):
        compare_and_store(app, "default", TARGET, recon[0], "1999-01-01_000000")


# --- CLI -------------------------------------------------------------------------

def test_cli_report_compare_history(cli, monkeypatch, capsys):
    monkeypatch.setattr("aiszx.orchestrator.orchestrator.inventory_tool_resolver", lambda app: resolver)
    monkeypatch.setattr("aiszx.assessment.engine.Assessor._searchsploit_launch", lambda self: None)
    assert cli("init") == 0 and cli("scope", "add", "10.129.0.0/16") == 0 and cli("target", "add", TARGET) == 0
    assert cli("run", TARGET, "-m", "recon.tcp_ports", "-m", "recon.service_id") == 0
    assert cli("assess", TARGET) == 0
    capsys.readouterr()
    assert cli("report", TARGET, "-f", "md,json") == 0
    out = capsys.readouterr().out
    assert "report.md" in out and "report.json" in out and "report.html" not in out
    assert cli("report", TARGET, "-f", "pdf") == 2
    assert cli("compare", TARGET, "--latest") == 0
    assert "Ports: not compared" in capsys.readouterr().out
    assert cli("compare", TARGET, "--from", "x") == 2
    assert cli("history", TARGET) == 0
    out = capsys.readouterr().out
    assert "report" in out and "assess" in out
    report_run = next(line.split()[0] for line in out.splitlines() if " report " in line)
    assert cli("history", TARGET, "--run", report_run) == 0
    assert "command" in capsys.readouterr().out
