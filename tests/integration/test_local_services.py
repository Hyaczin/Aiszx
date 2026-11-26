"""End-to-end against REAL tools and a local web server on 127.0.0.1 (Linux only, opt-in).

Run on the Parrot VM:   .venv/bin/python -m pytest -m integration -v

Nothing leaves the machine: the only target is 127.0.0.1, which the test puts in scope itself, and
only the port of a web server started by the test is scanned. Requires nmap and curl on PATH;
the test is skipped otherwise. Uses whatever nmap privileges are configured (unprivileged works).
"""

import json
import shutil
import sys
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not sys.platform.startswith("linux"), reason="integration tests run on Linux (Parrot)"),
    pytest.mark.skipif(not (shutil.which("nmap") and shutil.which("curl")), reason="needs nmap and curl"),
]

SECRET = "s3cr3tSessionValue42"
PAGE = b"""<!doctype html><html><head><title>Integration Login</title></head>
<body><form method="post"><input name="user"><input type="password" name="pass"></form></body></html>"""


class Handler(SimpleHTTPRequestHandler):
    server_version = "AiszxTestServer/1.0"

    def do_GET(self):  # noqa: N802
        if self.path not in ("/", "/index.html"):
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", f"PHPSESSID={SECRET}; path=/")
        self.send_header("Content-Length", str(len(PAGE)))
        self.end_headers()
        self.wfile.write(PAGE)

    def log_message(self, *args):
        pass


@pytest.fixture
def web_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def test_recon_enumerate_assess_report_against_local_web_server(cli, web_server, tmp_path, capsys):
    port = web_server
    cfg = tmp_path / "cfg"
    cfg.mkdir(exist_ok=True)
    (cfg / "profiles.yaml").write_text(
        "profiles:\n  itest:\n    description: integration test, one local port\n    max_safety: active_noisy\n"
        f"    nmap:\n      tcp_ports: \"{port}\"\n      discovery_probes: [\"-PS{port}\"]\n      timing: 4\n"
        "      scripts: false\n      version_all: false\n      os_detection: false\n      udp_top_ports: 0\n")
    assert cli("init") == 0
    assert cli("scope", "add", "127.0.0.1") == 0
    assert cli("target", "add", "127.0.0.1") == 0
    assert cli("doctor", "--no-tools") == 0

    def json_of(*argv):
        """Run a --json command and parse ONLY its output (earlier commands' output is discarded first)."""
        capsys.readouterr()
        assert cli(*argv, "--json") == 0
        return json.loads(capsys.readouterr().out)

    assert cli("recon", "127.0.0.1", "--profile", "itest") in (0, 1)  # 1 = some unit (e.g. ping) not completed
    services = json_of("services", "127.0.0.1")
    svc = next(s for s in services["services"] if s["port"] == port)
    if "http" not in svc["categories"]:  # show what each recon unit did, from the stored run history
        runs = json_of("history", "127.0.0.1")
        detail = json_of("history", "127.0.0.1", "--run", runs[0]["run_id"])
        units = [(u["module_id"], u["state"], u["summary"] or u["error_message"] or u["skip_reason"])
                 for u in detail["units"]]
        pytest.fail(f"service on port {port} identified as {svc['name']!r} {svc['categories']}; units: {units}")

    assert cli("enumerate", "127.0.0.1", "-m", "http.probe") == 0
    findings = json_of("assess", "127.0.0.1", "--no-exploitdb")["findings"]
    rules = {f["rule_id"] for f in findings}
    assert {"HTTP-001", "HTTP-005"} <= rules  # session cookie without HttpOnly, login form

    files = json_of("report", "127.0.0.1")["files"]
    for path in files.values():
        text = open(path, encoding="utf-8").read()
        assert SECRET not in text and "Integration Login" in text
    assert cli("compare", "127.0.0.1") == 0
    assert cli("backup", "--out", str(tmp_path / "bk")) == 0
