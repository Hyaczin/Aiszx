"""Nmap XML (-oX / -oA) parser.

Parsing is incremental (``XMLPullParser``): when a scan was interrupted and the XML is
truncated, every ``<host>`` element completed before the cut is still returned, and
``complete`` is False. Completion requires ``<runstats><finished exit="success">``.

The XML is produced locally by nmap; Python's expat does not resolve external entities.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class NmapService:
    name: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    tunnel: str | None = None
    method: str | None = None
    conf: int | None = None
    cpes: list[str] = field(default_factory=list)


@dataclass
class NmapPort:
    protocol: str
    port: int
    state: str
    reason: str | None = None
    service: NmapService | None = None
    scripts: dict[str, str] = field(default_factory=dict)


@dataclass
class NmapHost:
    addresses: dict[str, str] = field(default_factory=dict)    # ipv4/ipv6/mac → value
    status: str = "unknown"
    reason: str | None = None
    hostnames: list[str] = field(default_factory=list)
    ports: list[NmapPort] = field(default_factory=list)
    extraports: list[tuple[str, int]] = field(default_factory=list)  # (state, count)
    os_matches: list[dict] = field(default_factory=list)

    @property
    def address(self) -> str | None:
        return self.addresses.get("ipv4") or self.addresses.get("ipv6")


@dataclass
class NmapRun:
    args: str = ""
    version: str | None = None
    start: str | None = None
    hosts: list[NmapHost] = field(default_factory=list)
    complete: bool = False
    exit_status: str | None = None
    error: str | None = None
    elapsed: float | None = None
    summary: str | None = None
    parse_error: str | None = None
    scaninfo: list[dict] = field(default_factory=list)

    def host(self, address: str) -> NmapHost | None:
        return next((h for h in self.hosts if address in h.addresses.values()), None)


def _int(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def _host(el: ET.Element) -> NmapHost:
    h = NmapHost()
    for a in el.findall("address"):
        h.addresses[a.get("addrtype", "ipv4")] = a.get("addr", "")
    st = el.find("status")
    if st is not None:
        h.status, h.reason = st.get("state", "unknown"), st.get("reason")
    h.hostnames = [hn.get("name", "") for hn in el.findall("hostnames/hostname") if hn.get("name")]
    for ep in el.findall("ports/extraports"):
        h.extraports.append((ep.get("state", "?"), _int(ep.get("count")) or 0))
    for p in el.findall("ports/port"):
        state = p.find("state")
        port = NmapPort(
            protocol=p.get("protocol", "tcp"), port=_int(p.get("portid")) or 0,
            state=state.get("state", "unknown") if state is not None else "unknown",
            reason=state.get("reason") if state is not None else None,
        )
        svc = p.find("service")
        if svc is not None:
            port.service = NmapService(
                name=svc.get("name"), product=svc.get("product"), version=svc.get("version"),
                extrainfo=svc.get("extrainfo"), tunnel=svc.get("tunnel"), method=svc.get("method"),
                conf=_int(svc.get("conf")), cpes=[c.text for c in svc.findall("cpe") if c.text],
            )
        for sc in p.findall("script"):
            port.scripts[sc.get("id", "?")] = sc.get("output", "")
        h.ports.append(port)
    for m in el.findall("os/osmatch"):
        h.os_matches.append({"name": m.get("name"), "accuracy": _int(m.get("accuracy"))})
    return h


def parse_nmap_xml(data: bytes | str) -> NmapRun:
    run = NmapRun()
    parser = ET.XMLPullParser(events=("start", "end"))
    try:
        parser.feed(data)
        for event, el in _events(parser):
            if event == "start" and el.tag == "nmaprun":
                run.args, run.version, run.start = el.get("args", ""), el.get("version"), el.get("startstr")
            elif event == "end" and el.tag == "scaninfo":
                run.scaninfo.append(dict(el.attrib))
            elif event == "end" and el.tag == "host":
                run.hosts.append(_host(el))
                el.clear()
            elif event == "end" and el.tag == "finished":
                run.exit_status = el.get("exit")
                run.error = el.get("errormsg")
                run.summary = el.get("summary")
                try:
                    run.elapsed = float(el.get("elapsed", ""))
                except ValueError:
                    pass
        parser.close()
    except ET.ParseError as exc:
        run.parse_error = str(exc)
    run.complete = run.exit_status == "success" and run.parse_error is None
    return run


def _events(parser: ET.XMLPullParser):
    # read_events() raises ParseError lazily; surface it to the caller's try block
    yield from parser.read_events()


def parse_nmap_xml_file(path: Path) -> NmapRun:
    try:
        data = path.read_bytes()
    except OSError as exc:
        run = NmapRun(parse_error=f"cannot read {path.name}: {exc.strerror}")
        return run
    if not data.strip():
        return NmapRun(parse_error=f"{path.name} is empty")
    return parse_nmap_xml(data)


# --- grepable fallback (used only after `nmap --resume`, whose XML may be incomplete) ---------

_GNMAP_PORT = re.compile(r"(\d+)/([^/]*)/([^/]*)/[^/]*/([^/]*)/")


def parse_gnmap_ports(text: str) -> dict[str, list[NmapPort]]:
    """address → ports from grepable output lines ``Host: <ip> (...)\\tPorts: 22/open/tcp//ssh///, ...``."""
    out: dict[str, list[NmapPort]] = {}
    for line in text.splitlines():
        if not line.startswith("Host:") or "Ports:" not in line:
            continue
        address = line.split()[1]
        ports_part = line.split("Ports:", 1)[1].split("\t", 1)[0]
        for m in _GNMAP_PORT.finditer(ports_part):
            port, state, proto, name = m.groups()
            out.setdefault(address, []).append(
                NmapPort(protocol=proto or "tcp", port=int(port), state=state,
                         service=NmapService(name=name or None)))
    return out
