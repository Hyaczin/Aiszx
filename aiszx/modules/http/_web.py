"""Shared web helpers: which endpoints to test, URL building, HTTP response parsing.

Endpoints = every open TCP service classified ``http``/``https`` (WinRM excluded) × every host name
to present: the target address, the target hostname (if the target was registered by name), and
virtual hosts given per run (``enumerate --vhost``) or in the module options. Connections always go
to the pinned in-scope address; virtual hosts are sent as the Host header / SNI (``curl --resolve``),
so nothing depends on editing /etc/hosts.
"""

from __future__ import annotations

import html
import re
from dataclasses import asdict, dataclass
from typing import Any, Iterable

from aiszx.modules.base import PlanContext
from aiszx.modules.records import ServiceRecord

DEFAULT_PORTS = {"http": 80, "https": 443}
SECURITY_HEADERS = ("content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy")
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title\s*>", re.IGNORECASE | re.DOTALL)
_STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d{3})")


@dataclass(frozen=True)
class Endpoint:
    url: str
    scheme: str
    host: str
    port: int
    address: str
    service_key: str

    @property
    def key(self) -> str:
        return f"{self.scheme}://{_fmt_host(self.host)}:{self.port}"

    @property
    def is_vhost(self) -> bool:
        return self.host != self.address

    @property
    def address_url(self) -> str:
        """Same URL addressed by IP (used with an explicit Host header)."""
        return build_url(self.scheme, self.address, self.port)

    def inputs(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_inputs(cls, data: dict[str, Any]) -> "Endpoint":
        return cls(**{k: data[k] for k in ("url", "scheme", "host", "port", "address", "service_key")})


def _fmt_host(host: str) -> str:
    return f"[{host}]" if ":" in host else host


def build_url(scheme: str, host: str, port: int, path: str = "/") -> str:
    port_part = "" if DEFAULT_PORTS.get(scheme) == port else f":{port}"
    return f"{scheme}://{_fmt_host(host)}{port_part}{path}"


def web_services(services: Iterable[ServiceRecord], skip_categories: Iterable[str] = ("winrm",)) -> list[ServiceRecord]:
    skip = set(skip_categories)
    return [s for s in services
            if s.protocol == "tcp" and s.state == "open" and ({"http", "https"} & set(s.categories))
            and not (skip & set(s.categories))]


def host_names(ctx: PlanContext) -> list[str]:
    names = [ctx.address]
    if not ctx.target.identity.is_ip:
        names.append(ctx.target.canonical)
    for v in [*ctx.run_params.get("vhosts", []), *ctx.options.get("vhosts", [])]:
        if v not in names:
            names.append(v)
    return names


def endpoints(ctx: PlanContext) -> list[Endpoint]:
    out = []
    for svc in web_services(ctx.services, ctx.options.get("skip_categories", ("winrm",))):
        scheme = "https" if "https" in svc.categories or (svc.tunnel or "") == "ssl" else "http"
        for host in host_names(ctx):
            out.append(Endpoint(build_url(scheme, host, svc.port), scheme, host, svc.port, ctx.address, svc.key))
    return out


def resolve_args(ep: Endpoint) -> list[str]:
    if not ep.is_vhost:
        return []
    return ["--resolve", f"{ep.host}:{ep.port}:{_fmt_host(ep.address)}"]


def targets(ep: Endpoint) -> list[str]:
    return [ep.address] + ([ep.host] if ep.is_vhost else [])


def host_header(ep: Endpoint, flag: str = "-H") -> list[str]:
    return [flag, f"Host: {ep.host}"] if ep.is_vhost else []


# --- response parsing ----------------------------------------------------------------

@dataclass
class HttpResponse:
    status: int | None
    headers: dict[str, list[str]]

    def first(self, name: str) -> str | None:
        values = self.headers.get(name.lower())
        return values[0] if values else None


def parse_headers(text: str) -> HttpResponse:
    """Parse curl -D output; with several blocks (100 Continue, proxies) the last one wins."""
    blocks = [b for b in re.split(r"\r?\n\r?\n", text) if _STATUS_RE.match(b.strip())]
    if not blocks:
        return HttpResponse(None, {})
    lines = blocks[-1].strip().splitlines()
    status = int(_STATUS_RE.match(lines[0]).group(1))
    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers.setdefault(k.strip().lower(), []).append(v.strip())
    return HttpResponse(status, headers)


def title_of(body: str) -> str | None:
    m = _TITLE_RE.search(body)
    if not m:
        return None
    return re.sub(r"\s+", " ", html.unescape(m.group(1))).strip()[:200] or None


def cookie_issues(set_cookies: list[str], https: bool) -> list[dict[str, Any]]:
    issues = []
    for raw in set_cookies:
        name = raw.split("=", 1)[0].strip()
        attrs = {a.strip().split("=", 1)[0].lower() for a in raw.split(";")[1:]}
        missing = [flag for flag in ("httponly", "secure") if flag not in attrs and (flag != "secure" or https)]
        if "samesite" not in attrs:
            missing.append("samesite")
        if missing:
            issues.append({"cookie": name, "missing": missing})
    return issues


def robots_entries(text: str) -> list[tuple[str, str]]:
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        key, value = (x.strip() for x in line.split(":", 1))
        if key.lower() in ("disallow", "allow", "sitemap") and value:
            out.append((key.lower(), value))
    return out


def sitemap_urls(text: str, limit: int = 200) -> list[str]:
    return re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", text, re.IGNORECASE)[:limit]


def host_of(url: str | None) -> str | None:
    if not url:
        return None
    m = re.match(r"^[a-z][a-z0-9+.-]*://(\[[^\]]+\]|[^/:?#]+)", url, re.IGNORECASE)
    return m.group(1).strip("[]").lower() if m else None


def is_ip(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True
