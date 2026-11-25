"""Target identity normalisation.

Every target gets a *canonical id* (stored in the database, used for de-duplication)
and a *slug* (its directory name). Examples:

=====================  ==================  ===================
input                  canonical           slug
=====================  ==================  ===================
``10.10.10.5``         ``10.10.10.5``      ``10.10.10.5``
``[2001:DB8::0001]``   ``2001:db8::1``     ``2001_db8__1``
``::ffff:10.0.0.1``    ``10.0.0.1``        ``10.0.0.1``
``DC01.Corp.Local.``   ``dc01.corp.local`` ``dc01.corp.local``
``bücher.example``     ``xn--bcher-kva.example``  (same)
=====================  ==================  ===================

Slugs cannot collide: hostnames may not contain ``_`` and may not be purely numeric,
while IPv6 slugs always contain ``_``.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from aiszx.core.errors import ValidationError

KIND_IPV4 = "ipv4"
KIND_IPV6 = "ipv6"
KIND_HOSTNAME = "hostname"

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_NUMERIC_RE = re.compile(r"^[0-9.]+$")
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
_BROADCAST_V4 = ipaddress.IPv4Address("255.255.255.255")


@dataclass(frozen=True)
class TargetIdentity:
    kind: str
    canonical: str
    slug: str

    @property
    def is_ip(self) -> bool:
        return self.kind in (KIND_IPV4, KIND_IPV6)


def parse_ip(value: str) -> IPAddress | None:
    """Parse an IP address (IPv6 may be bracketed). Returns None when ``value`` is not an IP."""
    v = value[1:-1] if value.startswith("[") and value.endswith("]") else value
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.scope_id:
            raise ValidationError(f"{value!r}: IPv6 zone IDs (%iface) are not supported in target identities")
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
    return ip


def normalise_hostname(value: str) -> str:
    h = value.strip().rstrip(".").lower()
    if not h:
        raise ValidationError("hostname must not be empty")
    if _NUMERIC_RE.fullmatch(h):
        raise ValidationError(f"{value!r} is neither a valid IP address nor a valid hostname")
    try:
        ascii_h = h.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValidationError(f"{value!r} is not a valid hostname ({exc})") from None
    if len(ascii_h) > 253 or not all(_LABEL_RE.fullmatch(label) for label in ascii_h.split(".")):
        raise ValidationError(
            f"{value!r} is not a valid hostname (labels: a-z, 0-9 and '-', max 63 characters each)"
        )
    return ascii_h


def normalise_target(raw: str) -> TargetIdentity:
    value = (raw or "").strip()
    if not value:
        raise ValidationError("target must not be empty")
    if "://" in value:
        host = urlsplit(value).hostname or "<host>"
        raise ValidationError(f"{raw!r} looks like a URL; register only the host, e.g. `target add {host}`")
    if "/" in value:
        raise ValidationError(
            f"{raw!r} is a network range. Ranges belong to the engagement scope "
            f"(`scope add {value}`); individual hosts are registered as targets"
        )

    ip = parse_ip(value)
    if ip is not None:
        if ip.is_unspecified or ip.is_multicast or ip == _BROADCAST_V4:
            raise ValidationError(f"{raw!r} is an unspecified, broadcast or multicast address, not a host")
        canonical = str(ip)
        if ip.version == 4:
            return TargetIdentity(KIND_IPV4, canonical, canonical)
        return TargetIdentity(KIND_IPV6, canonical, canonical.replace(":", "_"))

    if ":" in value:
        host, _, port = value.rpartition(":")
        if port.isdigit() and host:
            raise ValidationError(f"ports are not part of a target's identity; register `{host}` instead")
        raise ValidationError(f"{raw!r} is not a valid IP address or hostname")

    host = normalise_hostname(value)
    return TargetIdentity(KIND_HOSTNAME, host, host)


def normalise_slug(raw: str, what: str = "engagement") -> str:
    s = (raw or "").strip().lower()
    if not _SLUG_RE.fullmatch(s):
        raise ValidationError(
            f"invalid {what} name {raw!r}: use 1-63 characters from a-z, 0-9, '-' and '_', starting with a letter or digit"
        )
    return s
