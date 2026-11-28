"""Host-name hints: every DNS name the modules saw for a target, with where it was seen.

Sources (latest completed result of each module unit across the target's runs, see ``knowledge.gather``):
TLS certificate names and redirect targets (http.probe, nmap ssl-cert), NTLM information (``*-ntlm-info``
NSE scripts), LDAP RootDSE, SMB host and domain names (netexec, enum4linux-ng), DNS answers (dig,
dnsrecon, AD SRV records) and virtual-host discovery.

Hints are never used automatically. ``hints accept`` stores a name for the target after a scope check
and confirmation; from then on runs present it as Host header / SNI to the target's pinned address.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from aiszx.assessment.knowledge import Knowledge
from aiszx.targets.identity import normalise_hostname

_NTLM_RE = re.compile(r"DNS_(?:Domain|Computer|Tree)_Name:\s*(\S+)")
_CN_RE = re.compile(r"commonName=([^/,\s]+)")
_SAN_RE = re.compile(r"Subject Alternative Name:\s*(.+)")


@dataclass
class Hint:
    name: str
    sources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "sources": self.sources}


def clean(name: Any) -> str | None:
    """A usable DNS name (lower case, no trailing dot, at least two labels, no wildcard), else None."""
    if not isinstance(name, str):
        return None
    name = name.strip().rstrip(".").lower()
    if not name or "*" in name or "." not in name or re.fullmatch(r"[\d.]+", name) or ":" in name:
        return None
    try:
        return normalise_hostname(name)
    except Exception:
        return None


def cert_names(output: str) -> list[str]:
    """Subject CN and DNS SANs from nmap ssl-cert output."""
    names = _CN_RE.findall(output)
    m = _SAN_RE.search(output)
    if m:
        names += [x.split(":", 1)[1].strip() for x in m.group(1).split(",") if x.strip().startswith("DNS:")]
    return names


def ntlm_names(output: str) -> list[str]:
    return _NTLM_RE.findall(output)


class _Collector:
    def __init__(self, exclude: Iterable[str]) -> None:
        self.exclude = {e.lower() for e in exclude}
        self.hints: dict[str, Hint] = {}

    def add(self, names: Iterable[Any], source: str) -> None:
        for raw in names:
            name = clean(raw)
            if not name or name in self.exclude:
                continue
            hint = self.hints.setdefault(name, Hint(name))
            if source not in hint.sources:
                hint.sources.append(source)


def collect(k: Knowledge, exclude: Iterable[str] = ()) -> list[Hint]:
    c = _Collector(exclude)
    for (module, unit), data in sorted(k.results.items()):
        art = data.get("artifacts") or {}
        where = f"{module} {unit}"
        if module == "http.probe":
            ep = art.get("endpoint") or {}
            cert = (ep.get("tls") or {}).get("certificate") or {}
            c.add(cert.get("san", []), f"TLS certificate ({where})")
            loc = ep.get("location")
            m = re.match(r"^[a-z][a-z0-9+.-]*://\[?([^/:?#\]]+)", loc or "", re.IGNORECASE)
            if m:
                c.add([m.group(1)], f"HTTP redirect ({where})")
        elif module == "ldap.rootdse":
            c.add([art.get("dnsHostName"), art.get("domain")], f"LDAP RootDSE ({where})")
        elif module == "smb.netexec":
            host = art.get("host") or {}
            domain, name = host.get("domain"), host.get("name")
            c.add([domain, f"{name}.{domain}" if name and domain else None], f"SMB banner ({where})")
        elif module == "smb.enum4linux_ng":
            c.add([art.get("domain")], f"enum4linux-ng ({where})")
        elif module == "nse.service_info":
            for sid, output in (art.get("scripts") or {}).items():
                if sid.endswith("-ntlm-info"):
                    c.add(ntlm_names(output or ""), f"NTLM info, {sid} ({where})")
                elif sid == "ssl-cert":
                    c.add(cert_names(output or ""), f"TLS certificate ({where})")
        elif module == "dns.dig":
            c.add(art.get("reverse", []), f"reverse DNS ({where})")
            for domain, d in (art.get("domains") or {}).items():
                for rtype in ("SOA", "NS", "MX"):
                    for answer in d.get(rtype, []):
                        fields = answer.split()
                        c.add(fields[-1:] if rtype == "MX" else fields[:1], f"DNS {rtype} of {domain} ({where})")
                for rec in (d.get("AXFR") or {}).get("records", []):
                    c.add([rec.get("name")], f"zone transfer of {domain} ({where})")
        elif module == "dns.dnsrecon":
            for rec in art.get("records", []):
                c.add([rec.get("name"), rec.get("target"), rec.get("exchange"), rec.get("mname")],
                      f"dnsrecon {rec.get('type', '?')} record ({where})")
        elif module == "dns.ad_srv":
            for service, recs in (art.get("records") or {}).items():
                c.add([r.get("target") for r in recs], f"DNS SRV {service} ({where})")
        elif module == "http.vhost_discovery":
            c.add([f.get("name") for f in art.get("found", [])], f"virtual-host discovery ({where})")
    # names in nmap's own script output from service identification (ssl-cert, rdp-ntlm-info, ...)
    for svc in k.services:
        for sid, output in (svc.scripts or {}).items():
            if sid == "ssl-cert":
                c.add(cert_names(output or ""), f"TLS certificate (nmap {svc.key})")
            elif sid.endswith("-ntlm-info"):
                c.add(ntlm_names(output or ""), f"NTLM info, {sid} (nmap {svc.key})")
    return sorted(c.hints.values(), key=lambda h: (len(h.name.split(".")), h.name))
