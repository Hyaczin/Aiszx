import pytest

from aiszx.core.errors import ValidationError
from aiszx.targets.identity import normalise_slug, normalise_target


@pytest.mark.parametrize(
    "raw, kind, canonical, slug",
    [
        ("10.10.10.5", "ipv4", "10.10.10.5", "10.10.10.5"),
        ("  10.10.10.5  ", "ipv4", "10.10.10.5", "10.10.10.5"),
        ("2001:DB8:0:0::0001", "ipv6", "2001:db8::1", "2001_db8__1"),
        ("[2001:db8::1]", "ipv6", "2001:db8::1", "2001_db8__1"),
        ("::ffff:10.0.0.1", "ipv4", "10.0.0.1", "10.0.0.1"),
        ("127.0.0.1", "ipv4", "127.0.0.1", "127.0.0.1"),
        ("DC01.Corp.Local.", "hostname", "dc01.corp.local", "dc01.corp.local"),
        ("bücher.example", "hostname", "xn--bcher-kva.example", "xn--bcher-kva.example"),
        ("localhost", "hostname", "localhost", "localhost"),
    ],
)
def test_normalise_valid(raw, kind, canonical, slug):
    ident = normalise_target(raw)
    assert (ident.kind, ident.canonical, ident.slug) == (kind, canonical, slug)


@pytest.mark.parametrize(
    "raw, fragment",
    [
        ("", "empty"),
        ("10.10.10.0/24", "network range"),
        ("http://10.10.10.5/", "URL"),
        ("10.10.10.5:8080", "ports are not part"),
        ("0.0.0.0", "unspecified"),
        ("255.255.255.255", "broadcast"),
        ("224.0.0.1", "multicast"),
        ("10.10.10", "neither a valid IP"),
        ("bad_host.local", "not a valid hostname"),
        ("-bad.local", "not a valid hostname"),
        ("a..b", "not a valid hostname"),
        ("fe80::1%eth0", "zone"),
        ("a" * 64 + ".local", "not a valid hostname"),
    ],
)
def test_normalise_invalid(raw, fragment):
    with pytest.raises(ValidationError) as exc:
        normalise_target(raw)
    assert fragment in str(exc.value)


def test_case_and_format_variants_share_identity():
    assert normalise_target("APP.LAB.LOCAL").canonical == normalise_target("app.lab.local.").canonical
    assert normalise_target("2001:db8::1").slug == normalise_target("2001:0db8:0000::1").slug


@pytest.mark.parametrize("raw", ["default", "HTB-Lab", "client_2026"])
def test_slug_valid(raw):
    assert normalise_slug(raw) == raw.lower()


@pytest.mark.parametrize("raw", ["", "-x", "has space", "a/b", "..", "x" * 64])
def test_slug_invalid(raw):
    with pytest.raises(ValidationError):
        normalise_slug(raw)
