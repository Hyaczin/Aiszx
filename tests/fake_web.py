"""Stand-in for curl / whatweb / feroxbuster / gobuster / nikto / eyewitness / openssl in tests.

Invoked as: python fake_web.py <tool> <args...>. Writes outputs where the real tool would
(relative paths land in the working directory, which the runner sets to the attempt's raw/).
FAKE_WEB_LOG: append one JSON line [tool, args] per call.
"""

import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT_HEADERS = ("HTTP/1.1 302 Found\r\nDate: Tue, 25 Nov 2026 12:00:00 GMT\r\nServer: Apache/2.4.52 (Ubuntu)\r\n"
                "Location: http://box.htb/\r\nSet-Cookie: PHPSESSID=abc123; path=/\r\n"
                "Content-Type: text/html; charset=UTF-8\r\n\r\n")
ROOT_BODY = "<html><head><title>Admin &amp; Login</title></head><body><form><input type='password' name='p'></form>"


def opt(args, name):
    return args[args.index(name) + 1]


def main() -> int:
    tool, args = sys.argv[1], sys.argv[2:]
    if os.environ.get("FAKE_WEB_LOG"):
        with open(os.environ["FAKE_WEB_LOG"], "a", encoding="utf-8") as fh:
            fh.write(json.dumps([tool, args]) + "\n")

    if tool == "curl":
        path = urlsplit(args[-1]).path
        if path == "/":
            headers, body, code = ROOT_HEADERS, ROOT_BODY, 302
        elif path == "/robots.txt":
            headers, body, code = "HTTP/1.1 200 OK\r\n\r\n", "User-agent: *\nDisallow: /admin/\nDisallow: /backup\n", 200
        else:
            headers, body, code = "HTTP/1.1 404 Not Found\r\n\r\n", "nope", 404
        Path(opt(args, "-D")).write_text(headers)
        Path(opt(args, "-o")).write_text(body)
        print(json.dumps({"http_code": code, "size_download": len(body)}))
    elif tool == "whatweb":
        log = next(a.split("=", 1)[1] for a in args if a.startswith("--log-json="))
        Path(log).write_text(json.dumps([{"target": args[-1], "http_status": 302, "plugins": {
            "Apache": {"version": ["2.4.52"]}, "HTTPServer": {"os": ["Ubuntu Linux"], "string": ["Apache/2.4.52 (Ubuntu)"]},
            "PasswordField": {"string": ["p"]}, "Country": {"string": ["RESERVED"]}, "PHP": {}}}]))
    elif tool == "feroxbuster":
        base = opt(args, "-u").rstrip("/")
        lines = [{"type": "configuration"},
                 {"type": "response", "url": base + "/admin", "path": "/admin", "status": 301, "content_length": 0,
                  "headers": {"location": base + "/admin/"}},
                 {"type": "response", "url": base + "/uploads", "path": "/uploads", "status": 403, "content_length": 277},
                 {"type": "statistics", "requests": 4614}]
        Path(opt(args, "-o")).write_text("\n".join(json.dumps(x) for x in lines) + "\n")
    elif tool == "gobuster":
        Path(opt(args, "-o")).write_text("/admin                (Status: 301) [Size: 312] [--> http://x/admin/]\n"
                                         "/index.php            (Status: 200) [Size: 1024]\n")
    elif tool == "nikto":
        Path(opt(args, "-o")).write_text(json.dumps({"host": opt(args, "-h"), "port": opt(args, "-p"), "vulnerabilities": [
            {"id": "999103", "method": "GET", "url": "/", "msg": "The anti-clickjacking X-Frame-Options header is not present."}]}))
    elif tool == "eyewitness":
        out = Path(opt(args, "-d"))
        (out / "screens").mkdir(parents=True)
        for i, url in enumerate(Path(opt(args, "-f")).read_text().split()):
            (out / "screens" / f"shot{i}.png").write_bytes(b"\x89PNG\r\n\x1a\nfake")
        (out / "report.html").write_text("<html>report</html>")
    elif tool == "openssl":
        print("CONNECTION ESTABLISHED\nProtocol version: TLSv1.3\nCiphersuite: TLS_AES_256_GCM_SHA384\n"
              "Peer certificate: CN = box.htb\nVerification error: self-signed certificate")
    else:
        print(f"unknown fake tool {tool}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
