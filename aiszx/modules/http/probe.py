"""http.probe: status, title, headers, cookies, robots.txt, sitemap.xml and TLS for every web endpoint.

Uses curl (and ``openssl s_client`` for HTTPS) through the tool runner, so every request is
scope-checked. Redirects are recorded, not followed. Host names seen in redirects and certificate
SANs are reported as *hints*: they are not tested until you add them (``--vhost`` / scope).
"""

from __future__ import annotations

import json
import re

from aiszx.modules.base import (
    Command,
    CommandResult,
    Module,
    ModuleMeta,
    ModuleResult,
    PlanContext,
    RetryPolicy,
    RunContext,
    Safety,
    Stage,
    ToolRequirement,
    WorkUnit,
)
from aiszx.modules.http import _web as web
from aiszx.modules.records import WebEndpointRecord, WebResourceRecord

ANY_EXIT = tuple(range(0, 100))  # robots/sitemap: a failed fetch is a result, not an error


def _label(path: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", path.lower()).strip("_") or "root"


def parse_tls(text: str) -> dict:
    tls = {}
    for key, pattern in (("protocol", r"Protocol version:\s*(\S+)"), ("cipher", r"Ciphersuite:\s*(\S+)"),
                         ("peer", r"Peer certificate:\s*(.+)"), ("verification", r"Verification(?: error)?:\s*(.+)")):
        m = re.search(pattern, text)
        if m:
            tls[key] = m.group(1).strip()
    return tls


def parse_ssl_cert_script(output: str) -> dict:
    """Extract subject, SANs and validity from nmap's ssl-cert NSE output."""
    cert: dict = {}
    m = re.search(r"Subject:\s*(.+)", output)
    if m:
        cert["subject"] = m.group(1).strip()
    m = re.search(r"Subject Alternative Name:\s*(.+)", output)
    if m:
        cert["san"] = [x.split(":", 1)[1].strip() for x in m.group(1).split(",") if x.strip().startswith("DNS:")]
    m = re.search(r"Not valid after:\s*(\S+)", output)
    if m:
        cert["not_after"] = m.group(1).strip()
    return cert


class HttpProbe(Module):
    meta = ModuleMeta(
        id="http.probe",
        version="1",
        description="Status, title, headers, cookies, robots.txt, sitemap.xml and TLS for each web endpoint (curl)",
        stage=Stage.ENUMERATION,
        safety=Safety.ACTIVE_SAFE,
        timeout_seconds=120,
        tools=(ToolRequirement("curl"), ToolRequirement("openssl", optional=True)),
        categories=("http", "https"),
        retry=RetryPolicy(max_attempts=2, backoff_seconds=5),
        config_defaults={"user_agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
                         "timeout": 15, "paths": ["/robots.txt", "/sitemap.xml"], "vhosts": [],
                         "skip_categories": ["winrm"]},
    )

    def plan(self, ctx: PlanContext) -> list[WorkUnit]:
        return [WorkUnit(self.meta.id, ep.key, ep.inputs()) for ep in web.endpoints(ctx)]

    def _curl(self, ep: web.Endpoint, path: str, label: str, ctx: RunContext) -> list[str]:
        return ["-sS", "-k", "--max-time", str(int(ctx.options["timeout"])), "--max-filesize", "2000000",
                "-A", str(ctx.options["user_agent"]), "-o", f"{label}.body", "-D", f"{label}.headers",
                "-w", "%{json}", *web.resolve_args(ep), web.build_url(ep.scheme, ep.host, ep.port, path)]

    def build_commands(self, unit: WorkUnit, ctx: RunContext) -> list[Command]:
        ep = web.Endpoint.from_inputs(dict(unit.inputs))
        cmds = [Command("root", self._curl(ep, "/", "root", ctx), tool="curl", targets=web.targets(ep))]
        for path in ctx.options["paths"]:
            label = _label(path)
            cmds.append(Command(label, self._curl(ep, path, label, ctx), tool="curl", targets=web.targets(ep),
                                ok_exit_codes=ANY_EXIT))
        if ep.scheme == "https" and "openssl" in ctx.tool_launch:
            cmds.append(Command("tls", ["s_client", "-connect", f"{web._fmt_host(ep.address)}:{ep.port}",
                                        "-servername", ep.host, "-brief"],
                                tool="openssl", targets=[ep.address], ok_exit_codes=(0, 1), timeout=20))
        return cmds

    def parse(self, unit: WorkUnit, results: list[CommandResult], ctx: RunContext) -> ModuleResult:
        ep = web.Endpoint.from_inputs(dict(unit.inputs))
        raw = ctx.attempt_dir / "raw"
        res = ModuleResult(evidence_descriptions={"root.headers": "HTTP response headers of /",
                                                  "root.body": "HTTP response body of /"})

        def read(name: str, limit: int = 2_000_000) -> str:
            try:
                return (raw / name).read_bytes()[:limit].decode("utf-8", errors="replace")
            except OSError:
                return ""

        resp = web.parse_headers(read("root.headers"))
        body = read("root.body")
        try:
            curl_info = json.loads(next((r for r in results if r.label == "root")).stdout() or "{}")
        except (ValueError, StopIteration):
            curl_info = {}
        title = web.title_of(body)
        location = resp.first("location")
        endpoint = WebEndpointRecord(
            url=ep.url, scheme=ep.scheme, host=ep.host, port=ep.port, address=ep.address, service_key=ep.service_key,
            status=resp.status, title=title, server=resp.first("server"), location=location,
            content_type=resp.first("content-type"),
            content_length=int(curl_info["size_download"]) if str(curl_info.get("size_download", "")).isdigit() else None,
            headers={k: v if len(v) > 1 else v[0] for k, v in resp.headers.items()},
        )
        obs = res.observations
        hints: set[str] = set()

        # TLS: live handshake + nmap's ssl-cert script for the same port (SANs, expiry)
        if ep.scheme == "https":
            tls_cmd = next((r for r in results if r.label == "tls"), None)
            if tls_cmd is not None:
                endpoint.tls.update(parse_tls(tls_cmd.stdout() + "\n" + tls_cmd.stderr()))
            else:
                res.limitations.append("openssl not available: TLS handshake details skipped")
            svc = next((s for s in ctx.services if s.key == ep.service_key), None)
            if svc and "ssl-cert" in svc.scripts:
                endpoint.tls["certificate"] = parse_ssl_cert_script(svc.scripts["ssl-cert"])
                hints.update(n.lower() for n in endpoint.tls["certificate"].get("san", []) if not n.startswith("*"))

        # Observations for the assessment stage (Milestone 7)
        if resp.status is None:
            res.limitations.append("no HTTP response parsed from the endpoint")
        else:
            missing = [h for h in web.SECURITY_HEADERS if h not in resp.headers]
            if ep.scheme == "https" and "strict-transport-security" not in resp.headers:
                missing.append("strict-transport-security")
            if missing:
                obs.append({"key": "http.missing_security_headers", "value": missing, "url": ep.url})
            issues = web.cookie_issues(resp.headers.get("set-cookie", []), ep.scheme == "https")
            if issues:
                obs.append({"key": "http.cookie_flags", "value": issues, "url": ep.url})
            server = resp.first("server")
            if server and re.search(r"\d", server):
                obs.append({"key": "http.server_version_disclosed", "value": server, "url": ep.url})
            if resp.first("x-powered-by"):
                obs.append({"key": "http.powered_by", "value": resp.first("x-powered-by"), "url": ep.url})
            if re.search(r"<input[^>]+type=[\"']?password", body, re.IGNORECASE):
                obs.append({"key": "http.login_form", "value": True, "url": ep.url})
            if title and title.lower().startswith("index of"):
                obs.append({"key": "http.directory_listing", "value": True, "url": ep.url})
            if location:
                obs.append({"key": "http.redirect", "value": location, "url": ep.url})
                rhost = web.host_of(location)
                if rhost and not web.is_ip(rhost) and rhost != ep.host:
                    hints.add(rhost)

        # robots.txt / sitemap.xml
        for path in ctx.options["paths"]:
            label = _label(path)
            pr = web.parse_headers(read(f"{label}.headers"))
            if pr.status != 200:
                continue
            text = read(f"{label}.body", 500_000)
            if path.endswith("robots.txt"):
                entries = web.robots_entries(text)
                res.artifacts["robots"] = entries
                for kind, value in entries:
                    if kind in ("disallow", "allow") and value.startswith("/"):
                        res.resources.append(WebResourceRecord(ep.url, web.build_url(ep.scheme, ep.host, ep.port, value),
                                                               value, None, source="robots.txt"))
            elif path.endswith(".xml"):
                urls = web.sitemap_urls(text)
                res.artifacts["sitemap"] = urls
                for u in urls:
                    path_part = re.sub(r"^[a-z]+://[^/]+", "", u) or "/"
                    res.resources.append(WebResourceRecord(ep.url, u, path_part, None, source="sitemap.xml"))

        hints.discard(ep.host)
        res.endpoints.append(endpoint)
        res.artifacts.update(endpoint=endpoint.to_dict(), hostname_hints=sorted(hints), curl=curl_info)
        if hints:
            obs.append({"key": "http.hostname_hints", "value": sorted(hints), "url": ep.url})
            res.limitations.append(f"host name(s) {', '.join(sorted(hints))} referenced but not tested; add them to "
                                   f"scope and use `enumerate --vhost <name>` (or register them as targets)")
        bits = [str(resp.status or "no response")]
        if title:
            bits.append(f"'{title}'")
        if endpoint.server:
            bits.append(f"({endpoint.server})")
        if location:
            bits.append(f"-> {location}")
        if res.resources:
            bits.append(f"{len(res.resources)} path(s) from robots/sitemap")
        res.summary = " ".join(bits)
        return res
