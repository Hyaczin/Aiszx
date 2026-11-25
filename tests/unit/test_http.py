import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from aiszx.app import AppContext
from aiszx.modules.base import PlanContext
from aiszx.modules.http import _web as web
from aiszx.modules.http.content_discovery import parse_ferox, parse_gobuster
from aiszx.modules.http.nikto import load_nikto
from aiszx.modules.http.probe import parse_ssl_cert_script, parse_tls
from aiszx.modules.http.whatweb import load_whatweb
from aiszx.modules.records import ServiceRecord
from aiszx.modules.registry import discover
from aiszx.orchestrator.orchestrator import Orchestrator
from aiszx.orchestrator.planner import ToolResolution
from aiszx.orchestrator.settings import load_settings
from aiszx.orchestrator.state import ExecutionStore
from aiszx.recon.store import ReconStore

TESTS = Path(__file__).resolve().parents[1]
FAKE_NMAP, FAKE_WEB = str(TESTS / "fake_nmap.py"), str(TESTS / "fake_web.py")
TARGET = "10.129.73.247"
WEB_TOOLS = ("curl", "whatweb", "feroxbuster", "gobuster", "nikto", "eyewitness", "openssl")


# --- helpers ------------------------------------------------------------------------

def svc(port, cats, tunnel=None, key_proto="tcp"):
    return ServiceRecord(TARGET, key_proto, port, categories=list(cats), tunnel=tunnel)


def pctx(services, *, hostname=None, vhosts=(), options=None):
    identity = SimpleNamespace(is_ip=hostname is None)
    target = SimpleNamespace(identity=identity, canonical=hostname or TARGET)
    return PlanContext(None, target, TARGET, options or {}, services=services, run_params={"vhosts": list(vhosts)})


def test_build_url_and_endpoints():
    assert web.build_url("http", "box.htb", 80) == "http://box.htb/"
    assert web.build_url("https", "10.0.0.1", 8443, "/x") == "https://10.0.0.1:8443/x"
    assert web.build_url("http", "2001:db8::1", 8080) == "http://[2001:db8::1]:8080/"
    services = [svc(80, ["http"]), svc(443, ["https"]), svc(8443, ["http"], tunnel="ssl"),
                svc(5985, ["http", "winrm"]), svc(22, ["ssh"])]
    eps = web.endpoints(pctx(services, vhosts=["box.htb"]))
    assert [(e.scheme, e.host, e.port) for e in eps] == [
        ("http", TARGET, 80), ("http", "box.htb", 80), ("https", TARGET, 443), ("https", "box.htb", 443),
        ("https", TARGET, 8443), ("https", "box.htb", 8443)]            # WinRM and SSH excluded
    vh = eps[1]
    assert vh.is_vhost and web.resolve_args(vh) == ["--resolve", f"box.htb:80:{TARGET}"]
    assert web.host_header(vh) == ["-H", "Host: box.htb"] and vh.address_url == f"http://{TARGET}/"
    assert web.targets(vh) == [TARGET, "box.htb"]
    # a hostname target is presented by name automatically
    assert [e.host for e in web.endpoints(pctx([svc(80, ["http"])], hostname="box.htb"))] == [TARGET, "box.htb"]


def test_parse_headers_last_block_wins():
    text = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nServer: nginx\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2; HttpOnly\r\n\r\n"
    r = web.parse_headers(text)
    assert r.status == 200 and r.first("server") == "nginx" and r.headers["set-cookie"] == ["a=1", "b=2; HttpOnly"]
    assert web.parse_headers("garbage").status is None


def test_small_parsers():
    assert web.title_of("<TITLE>\n Admin &amp; Login </title>") == "Admin & Login"
    assert web.title_of("no title") is None
    assert web.cookie_issues(["PHPSESSID=x; path=/"], https=False) == [{"cookie": "PHPSESSID", "missing": ["httponly", "samesite"]}]
    assert web.cookie_issues(["s=1; Secure; HttpOnly; SameSite=Lax"], https=True) == []
    assert web.robots_entries("User-agent: *\nDisallow: /admin # x\nSitemap: http://a/s.xml\nDisallow:\n") == [
        ("disallow", "/admin"), ("sitemap", "http://a/s.xml")]
    assert web.sitemap_urls("<urlset><url><loc> http://a/x </loc></url></urlset>") == ["http://a/x"]
    assert web.host_of("http://Box.HTB:8080/a") == "box.htb" and web.host_of("/relative") is None
    assert web.is_ip("10.0.0.1") and not web.is_ip("box.htb")


def test_tool_output_parsers():
    assert parse_tls("Protocol version: TLSv1.3\nCiphersuite: TLS_AES_128\nVerification: OK")["protocol"] == "TLSv1.3"
    cert = parse_ssl_cert_script("Subject: commonName=box.htb\nSubject Alternative Name: DNS:box.htb, DNS:dev.box.htb\n"
                                 "Not valid after:  2027-01-01T00:00:00")
    assert cert == {"subject": "commonName=box.htb", "san": ["box.htb", "dev.box.htb"], "not_after": "2027-01-01T00:00:00"}
    assert load_whatweb('[{"plugins": {"Apache": {}}}]')[0]["plugins"] == {"Apache": {}}
    assert len(load_whatweb('{"plugins": {"A": {}}},\n{"plugins": {"B": {}}}\n')) == 2  # line-per-object format
    assert load_whatweb("") == []
    ferox = parse_ferox('{"type":"response","url":"http://a/x","status":200}\n{"type":"statistics"}\nnot json\n')
    assert [f["url"] for f in ferox] == ["http://a/x"]
    gob = parse_gobuster("/admin (Status: 301) [Size: 312] [--> http://a/admin/]\n/x (Status: 200)\nnoise\n")
    assert gob == [{"path": "/admin", "status": 301, "content_length": 312, "location": "http://a/admin/"},
                   {"path": "/x", "status": 200, "content_length": None, "location": None}]
    assert load_nikto('[{"vulnerabilities": [{"id": "1", "msg": "m"}]}]')[0]["msg"] == "m"
    assert load_nikto('{"broken": "json", "msg": "fallback item"')[0]["msg"] == "fallback item"


# --- end to end with fake tools --------------------------------------------------------

def resolver(missing=()):
    def resolve(names):
        out = {}
        for n in names:
            if n == "nmap":
                out[n] = ToolResolution("ok", [sys.executable, FAKE_NMAP], "7.95", detail={"privileges": {"mode": "capabilities"}})
            elif n in WEB_TOOLS and n not in missing:
                out[n] = ToolResolution("ok", [sys.executable, FAKE_WEB, n], "1.0")
            else:
                out[n] = ToolResolution("missing", [])
        return out
    return resolve


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("FAKE_WEB_LOG", str(tmp_path / "web.log"))
    monkeypatch.setenv("FAKE_NMAP_LOG", str(tmp_path / "nmap.log"))
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\nuploads\n")
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "modules.yaml").write_text(f"modules:\n  http.content_discovery:\n    options:\n      wordlists: ['{wordlist.as_posix()}']\n",
                                      encoding="utf-8")
    ctx = AppContext.create(data_dir=tmp_path / "data", config_dir=cfg)
    ctx.layout.ensure_data_dir()
    ctx.open_db(migrate_schema=True)
    eng, _ = ctx.engagements().ensure("default")
    ctx.scope().add(eng, "10.129.0.0/16")
    ctx.targets().add("default", TARGET)
    yield ctx
    ctx.close()


def orch(app, missing=()):
    return Orchestrator(app, registry=discover(), resolve_tools=resolver(missing), handle_signals=False,
                        settings=load_settings(user_config_dir=app.config.user_config_dir, engagement_dir=None))


def web_calls(tmp_path, tool):
    return [args for t, args in (json.loads(x) for x in (tmp_path / "web.log").read_text().splitlines()) if t == tool]


def http_modules():
    return [mid for mid in discover().modules if mid.startswith("http.")]


def test_full_runs_recon_then_web_enumeration(app, tmp_path):
    report = orch(app).start("default", TARGET, ["recon", *http_modules()], command="full",
                             run_params={"vhosts": ["box.htb"]})
    units = ExecutionStore(app.db).units(report.execution_id)
    states = {(u["module_id"], u["unit_key"]): u["state"] for u in units}
    assert states[("http.probe", f"http://{TARGET}:80")] == "COMPLETED"
    assert states[("http.probe", "https://box.htb:443")] == "COMPLETED"
    assert not any(k[1].endswith(":5985") for k in states)          # WinRM is not treated as a website
    assert all(s == "COMPLETED" for (m, _), s in states.items() if m.startswith("http.")), states
    assert report.status == "COMPLETED"

    store = ReconStore(app.db)
    w = store.web_for_execution(report.execution_id)
    ep = next(e for e in w["endpoints"] if e["url"] == f"http://{TARGET}/")
    assert (ep["status_code"], ep["title"], ep["server"], ep["location"]) == (302, "Admin & Login",
                                                                             "Apache/2.4.52 (Ubuntu)", "http://box.htb/")
    tls_ep = next(e for e in w["endpoints"] if e["url"] == "https://box.htb/")
    assert json.loads(tls_ep["tls_json"])["protocol"] == "TLSv1.3"
    paths = {(r["path"], r["source_tool"]) for r in w["resources"]}
    assert {("/admin/", "robots.txt"), ("/backup", "robots.txt"), ("/admin", "feroxbuster"), ("/uploads", "feroxbuster")} <= paths
    assert {t["name"] for t in w["technologies"]} >= {"Apache", "PHP", "PasswordField", "HTTPServer"}
    assert "Country" not in {t["name"] for t in w["technologies"]}

    # virtual host handling: connect to the IP, present the name
    vh_curl = next(a for a in web_calls(tmp_path, "curl") if a[-1] == "http://box.htb/")
    assert vh_curl[vh_curl.index("--resolve") + 1] == f"box.htb:80:{TARGET}"
    vh_ferox = next(a for a in web_calls(tmp_path, "feroxbuster") if "Host: box.htb" in a)
    assert vh_ferox[vh_ferox.index("-u") + 1] == f"http://{TARGET}/"
    nikto_vh = next(a for a in web_calls(tmp_path, "nikto") if "-vhost" in a)
    assert nikto_vh[nikto_vh.index("-h") + 1] == TARGET

    # probe observations and hostname hints
    probe = next(u for u in units if u["module_id"] == "http.probe" and u["unit_key"] == f"http://{TARGET}:80")
    result = json.loads((report.run_dir / probe["output_dir"] / "parsed" / "result.json").read_text())
    keys = {o["key"] for o in result["observations"]}
    assert {"http.missing_security_headers", "http.cookie_flags", "http.server_version_disclosed", "http.login_form",
            "http.redirect", "http.hostname_hints"} <= keys
    assert result["artifacts"]["hostname_hints"] == ["box.htb"]

    # screenshots: only non-vhost URLs; PNGs registered as screenshot evidence
    shot = next(u for u in units if u["module_id"] == "http.screenshots")
    urls = (report.run_dir / shot["output_dir"] / "raw" / "urls.txt").read_text().split()
    assert urls == [f"http://{TARGET}/", f"https://{TARGET}/"]
    kinds = {r["kind"] for r in app.db.query("SELECT kind FROM evidence WHERE module_execution_id = ?", (shot["id"],))}
    assert "screenshot" in kinds


def test_enumerate_uses_latest_recon_and_profile_gates_noisy_modules(app, tmp_path):
    orch(app).start("default", TARGET, ["recon.tcp_ports", "recon.service_id"])
    report = orch(app).start("default", TARGET, http_modules(), profile="conservative", command="enumerate")
    by_mod = {}
    for u in ExecutionStore(app.db).units(report.execution_id):
        by_mod.setdefault(u["module_id"], set()).add(u["state"])
    assert by_mod["http.probe"] == {"COMPLETED"}
    assert by_mod["http.content_discovery"] == {"SKIPPED"} and by_mod["http.nikto"] == {"SKIPPED"}


def test_content_discovery_falls_back_to_gobuster(app, tmp_path):
    orch(app).start("default", TARGET, ["recon.tcp_ports", "recon.service_id"])
    report = orch(app, missing=("feroxbuster",)).start("default", TARGET, ["http.content_discovery"])
    res = ReconStore(app.db).web_for_execution(report.execution_id)["resources"]
    assert {r["source_tool"] for r in res} == {"gobuster"} and "/index.php" in {r["path"] for r in res}
    report = orch(app, missing=("feroxbuster", "gobuster")).start("default", TARGET, ["http.content_discovery"])
    unit = ExecutionStore(app.db).units(report.execution_id)[0]
    assert unit["state"] == "SKIPPED" and "needs feroxbuster or gobuster" in unit["skip_reason"]


def test_cli_enumerate_and_web(cli, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("FAKE_WEB_LOG", str(tmp_path / "web.log"))
    monkeypatch.setattr("aiszx.orchestrator.orchestrator.inventory_tool_resolver", lambda app: resolver())
    assert cli("init") == 0 and cli("scope", "add", "10.129.0.0/16") == 0 and cli("target", "add", TARGET) == 0
    assert cli("enumerate", TARGET) == 1
    assert "run `recon" in capsys.readouterr().err
    assert cli("recon", TARGET, "--profile", "conservative") == 0
    capsys.readouterr()
    assert cli("enumerate", TARGET, "-m", "http.probe", "-m", "http.whatweb", "--vhost", "Box.HTB") == 0
    out = capsys.readouterr().out
    assert "Using services from run" in out and "https://box.htb:443" in out
    assert cli("web", TARGET) == 0
    out = capsys.readouterr().out
    assert "Admin & Login" in out and "Apache 2.4.52" in out and "/backup" in out
    assert "http.cookie_flags" in out
    assert cli("enumerate", TARGET, "--vhost", "bad_host") == 2


def test_clip_list_at_item_boundary():
    from aiszx.cli.commands.enum_cmd import _clip

    techs = "Apache 2.4.52, Bootstrap, Cookies, HTTPServer, JQuery 3.6.0, PasswordField"
    assert _clip(techs, 100) == techs
    assert _clip(techs, 60) == "Apache 2.4.52, Bootstrap, Cookies, HTTPServer, JQuery 3.6.0 …"
