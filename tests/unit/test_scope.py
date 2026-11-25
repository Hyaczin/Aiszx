import pytest

from aiszx.core.errors import ValidationError
from aiszx.targets.identity import normalise_target
from aiszx.targets.scope import EXCLUDE, INCLUDE, ScopePolicy, ScopeRule, parse_rule_value


def rule(action, raw):
    rule_type, value, _ = parse_rule_value(raw)
    return ScopeRule(action, rule_type, value)


def policy(*rules, strict=True):
    return ScopePolicy(list(rules), strict_hostname_resolution=strict)


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("10.10.10.5", ("ip", "10.10.10.5")),
        ("10.10.10.0/24", ("cidr", "10.10.10.0/24")),
        ("10.10.10.7/24", ("cidr", "10.10.10.0/24")),
        ("2001:db8::/32", ("cidr", "2001:db8::/32")),
        ("Corp.Local", ("hostname", "corp.local")),
        ("*.Corp.Local", ("domain_suffix", "*.corp.local")),
    ],
)
def test_parse_rule_value(raw, expected):
    assert parse_rule_value(raw)[:2] == expected


def test_parse_rule_reports_host_bit_normalisation():
    assert "normalised" in parse_rule_value("10.10.10.7/24")[2]


@pytest.mark.parametrize("raw", ["", "10.10.10.0/33", "not_valid"])
def test_parse_rule_invalid(raw):
    with pytest.raises(ValidationError):
        parse_rule_value(raw)


def test_no_include_rules_means_nothing_in_scope():
    d = policy().evaluate(normalise_target("10.10.10.5"))
    assert not d.in_scope and "no include rules" in d.reasons[0]


def test_ip_included_by_cidr():
    d = policy(rule(INCLUDE, "10.10.10.0/24")).evaluate(normalise_target("10.10.10.5"))
    assert d.in_scope


def test_ip_outside_cidr():
    assert not policy(rule(INCLUDE, "10.10.10.0/24")).evaluate(normalise_target("10.10.11.5")).in_scope


def test_exclusion_wins_over_inclusion():
    p = policy(rule(INCLUDE, "10.10.10.0/24"), rule(EXCLUDE, "10.10.10.1"))
    assert not p.evaluate(normalise_target("10.10.10.1")).in_scope
    assert p.evaluate(normalise_target("10.10.10.2")).in_scope


def test_ipv4_rule_does_not_match_ipv6():
    assert not policy(rule(INCLUDE, "0.0.0.0/0")).evaluate(normalise_target("2001:db8::1")).in_scope


def test_hostname_all_addresses_in_scope_but_name_unlisted_warns():
    d = policy(rule(INCLUDE, "10.10.10.0/24")).evaluate(normalise_target("app.lab"), ["10.10.10.20"])
    assert d.in_scope
    assert any("not listed" in w for w in d.warnings)


def test_hostname_strict_requires_every_address_covered():
    p = policy(rule(INCLUDE, "app.lab"), rule(INCLUDE, "10.10.10.0/24"))
    d = p.evaluate(normalise_target("app.lab"), ["10.10.10.20", "8.8.8.8"])
    assert not d.in_scope
    assert "8.8.8.8" in d.reasons[0]


def test_hostname_lenient_allows_hostname_rule():
    p = policy(rule(INCLUDE, "app.lab"), strict=False)
    d = p.evaluate(normalise_target("app.lab"), ["8.8.8.8"])
    assert d.in_scope
    assert any("strict_hostname_resolution is off" in w for w in d.warnings)


def test_hostname_excluded_address_always_out_even_when_lenient():
    p = policy(rule(INCLUDE, "app.lab"), rule(EXCLUDE, "10.10.10.1"), strict=False)
    assert not p.evaluate(normalise_target("app.lab"), ["10.10.10.1"]).in_scope


def test_hostname_excluded_by_name():
    p = policy(rule(INCLUDE, "*.lab"), rule(EXCLUDE, "secret.lab"), rule(INCLUDE, "10.0.0.0/8"))
    assert not p.evaluate(normalise_target("secret.lab"), ["10.0.0.5"]).in_scope
    assert p.evaluate(normalise_target("app.lab"), ["10.0.0.6"]).in_scope


def test_domain_suffix_matches_subdomains_only():
    p = policy(rule(INCLUDE, "*.corp.local"))
    assert p.evaluate(normalise_target("dc01.corp.local")).in_scope
    assert not p.evaluate(normalise_target("corp.local")).in_scope
    assert not p.evaluate(normalise_target("evilcorp.local")).in_scope


def test_unresolved_hostname_in_scope_by_name_with_warning():
    d = policy(rule(INCLUDE, "app.lab")).evaluate(normalise_target("app.lab"), [])
    assert d.in_scope and any("no resolved addresses" in w for w in d.warnings)


def test_unresolved_hostname_not_listed_is_out():
    assert not policy(rule(INCLUDE, "10.0.0.0/8")).evaluate(normalise_target("app.lab"), []).in_scope


def test_address_allowed():
    p = policy(rule(INCLUDE, "10.10.10.0/24"), rule(EXCLUDE, "10.10.10.1"))
    assert p.address_allowed("10.10.10.9")
    assert not p.address_allowed("10.10.10.1")
    assert not p.address_allowed("not-an-ip")
