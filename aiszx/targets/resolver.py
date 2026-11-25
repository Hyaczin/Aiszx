"""Hostname resolution via the system resolver (honours /etc/hosts, as HTB workflows expect)."""

from __future__ import annotations

import ipaddress
import socket


def resolve_host(hostname: str) -> list[str]:
    """Return sorted, de-duplicated addresses for ``hostname``; empty list when it does not resolve."""
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    found = set()
    for info in infos:
        raw = str(info[4][0]).split("%", 1)[0]
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        found.add(ip)
    return [str(ip) for ip in sorted(found, key=lambda a: (a.version, int(a)))]
