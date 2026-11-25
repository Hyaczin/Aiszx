"""Version extraction and comparison without third-party dependencies.

Debian versions such as ``1:7.94+git20230807.3be01efb1+dfsg-3+b1`` are reduced to their
leading numeric upstream part (``7.94``) for comparison.
"""

from __future__ import annotations

import re

_LEADING = re.compile(r"(\d+(?:\.\d+)*)")
_GENERIC = re.compile(r"\b(\d+\.\d+(?:\.\d+)*)")


def parse_version(value: str | None) -> tuple[int, ...] | None:
    if not value:
        return None
    v = value.strip()
    if re.match(r"^\d+:", v):  # Debian epoch
        v = v.split(":", 1)[1]
    v = v.lstrip("vV")
    m = _LEADING.match(v)
    if not m:
        return None
    return tuple(int(part) for part in m.group(1).split("."))


def upstream_version(value: str | None) -> str | None:
    """Debian package version → upstream part: ``1:2.6.0-0parrot2`` → ``2.6.0``.

    Strips the epoch and the final ``-revision``; pipx/PyPI versions pass through unchanged.
    """
    if not value:
        return value
    v = value.strip()
    v = re.sub(r"^\d+:", "", v)
    if "-" in v:
        v = v.rsplit("-", 1)[0]
    return v or value


def compare(a: str, b: str) -> int:
    pa, pb = parse_version(a), parse_version(b)
    if pa is None or pb is None:
        raise ValueError(f"cannot compare versions {a!r} and {b!r}")
    width = max(len(pa), len(pb))
    pa, pb = pa + (0,) * (width - len(pa)), pb + (0,) * (width - len(pb))
    return (pa > pb) - (pa < pb)


def satisfies(version: str | None, minimum: str | None) -> bool | None:
    """True/False when both are comparable; None when the version is unknown."""
    if not minimum:
        return True
    if parse_version(version) is None:
        return None
    return compare(version, minimum) >= 0  # type: ignore[arg-type]


def extract_version(text: str, regex: str | None = None) -> str | None:
    if regex:
        m = re.search(regex, text, re.MULTILINE)
        if not m:
            return None
        return m.group(1) if m.groups() else m.group(0)
    m = _GENERIC.search(text)
    return m.group(1) if m else None
