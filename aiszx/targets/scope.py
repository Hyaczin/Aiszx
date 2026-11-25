"""Scope rules and evaluation (pure logic, no I/O).

Rule types
    ``ip``             exact address               ``10.10.10.5``
    ``cidr``           network                     ``10.10.10.0/24``
    ``hostname``       exact hostname              ``app.example.htb``
    ``domain_suffix``  any *sub*domain             ``*.example.htb`` (does not match ``example.htb`` itself)

Evaluation
    * There must be at least one include rule, otherwise nothing is in scope.
    * **Exclusions always win.**
    * IP target: in scope iff an include rule matches and no exclude rule matches.
    * Hostname target: never in scope if the name or any resolved address is excluded. Otherwise:

      - every resolved address is covered by an address include rule → in scope
        (warning if the name itself is not listed);
      - some address is not covered → out of scope when ``strict_hostname_resolution``
        is on (default). With it off, a hostname include rule is sufficient;
      - no resolved addresses → in scope only through a hostname rule (warning: an
        address is required before reconnaissance).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Iterable

from aiszx.core.errors import ValidationError
from aiszx.targets.identity import IPAddress, TargetIdentity, normalise_hostname, parse_ip

INCLUDE = "include"
EXCLUDE = "exclude"
ACTIONS = (INCLUDE, EXCLUDE)
RULE_TYPES = ("ip", "cidr", "hostname", "domain_suffix")


@dataclass(frozen=True)
class ScopeRule:
    action: str
    rule_type: str
    value: str
    note: str | None = None
    id: str | None = None

    def __post_init__(self) -> None:
        if self.action not in ACTIONS:
            raise ValidationError(f"invalid scope action {self.action!r}")
        if self.rule_type not in RULE_TYPES:
            raise ValidationError(f"invalid scope rule type {self.rule_type!r}")

    @property
    def is_address_rule(self) -> bool:
        return self.rule_type in ("ip", "cidr")

    def matches_address(self, addr: IPAddress) -> bool:
        if self.rule_type == "ip":
            return addr == ipaddress.ip_address(self.value)
        if self.rule_type == "cidr":
            net = ipaddress.ip_network(self.value)
            return addr.version == net.version and addr in net
        return False

    def matches_hostname(self, host: str) -> bool:
        if self.rule_type == "hostname":
            return host == self.value
        if self.rule_type == "domain_suffix":
            suffix = self.value[1:]  # "*.corp.local" -> ".corp.local"
            return host.endswith(suffix) and len(host) > len(suffix)
        return False

    def describe(self) -> str:
        return f"{self.action} {self.rule_type} {self.value}"

    def to_dict(self) -> dict[str, Any]:
        return {"action": self.action, "type": self.rule_type, "value": self.value, "note": self.note}


def parse_rule_value(raw: str) -> tuple[str, str, str | None]:
    """Detect the rule type and normalise the value. Returns (rule_type, value, normalisation_note)."""
    v = (raw or "").strip()
    if not v:
        raise ValidationError("scope value must not be empty")
    if v.startswith("*."):
        return "domain_suffix", f"*.{normalise_hostname(v[2:])}", None
    if "/" in v:
        try:
            net = ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise ValidationError(f"{raw!r} is not a valid CIDR network") from None
        note = None if str(net) == v.lower() else f"normalised {v} to {net} (host bits cleared)"
        return "cidr", str(net), note
    ip = parse_ip(v)
    if ip is not None:
        return "ip", str(ip), None
    return "hostname", normalise_hostname(v), None


@dataclass(frozen=True)
class AddressDecision:
    address: str
    in_scope: bool
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"address": self.address, "in_scope": self.in_scope, "reason": self.reason}


@dataclass
class ScopeDecision:
    value: str
    in_scope: bool
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    addresses: list[AddressDecision] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "in_scope": self.in_scope,
            "reasons": self.reasons,
            "warnings": self.warnings,
            "addresses": [a.to_dict() for a in self.addresses],
        }


def _join(rules: list[ScopeRule]) -> str:
    return "; ".join(r.describe() for r in rules)


class ScopePolicy:
    def __init__(self, rules: Iterable[ScopeRule], *, strict_hostname_resolution: bool = True) -> None:
        self.rules = list(rules)
        self.strict = strict_hostname_resolution
        self.includes = [r for r in self.rules if r.action == INCLUDE]
        self.excludes = [r for r in self.rules if r.action == EXCLUDE]

    def _match_address(self, addr: IPAddress) -> tuple[list[ScopeRule], list[ScopeRule]]:
        return ([r for r in self.includes if r.matches_address(addr)], [r for r in self.excludes if r.matches_address(addr)])

    def _match_hostname(self, host: str) -> tuple[list[ScopeRule], list[ScopeRule]]:
        return ([r for r in self.includes if r.matches_hostname(host)], [r for r in self.excludes if r.matches_hostname(host)])

    def address_allowed(self, address: str) -> bool:
        """Plain address check, used by later milestones' execution-time scope guard."""
        ip = parse_ip(address)
        if ip is None:
            return False
        inc, exc = self._match_address(ip)
        return bool(inc) and not exc

    def evaluate(self, identity: TargetIdentity, addresses: Iterable[str] = ()) -> ScopeDecision:
        decision = ScopeDecision(value=identity.canonical, in_scope=False)
        if not self.includes:
            decision.reasons.append("the engagement has no include rules; add one with `scope add`")
            return decision
        if identity.is_ip:
            return self._evaluate_ip(identity, decision)
        return self._evaluate_hostname(identity, list(dict.fromkeys(addresses)), decision)

    def _evaluate_ip(self, identity: TargetIdentity, decision: ScopeDecision) -> ScopeDecision:
        inc, exc = self._match_address(ipaddress.ip_address(identity.canonical))
        if exc:
            reason = f"excluded by {_join(exc)}"
        elif inc:
            reason = f"included by {_join(inc)}"
        else:
            reason = "not covered by any include rule"
        decision.in_scope = bool(inc) and not exc
        decision.reasons.append(reason)
        decision.addresses.append(AddressDecision(identity.canonical, decision.in_scope, reason))
        return decision

    def _evaluate_hostname(self, identity: TargetIdentity, addresses: list[str], decision: ScopeDecision) -> ScopeDecision:
        host = identity.canonical
        name_inc, name_exc = self._match_hostname(host)
        any_excluded = False
        uncovered: list[str] = []
        for address in addresses:
            ip = ipaddress.ip_address(address)
            inc, exc = self._match_address(ip)
            if exc:
                any_excluded = True
                ad = AddressDecision(address, False, f"excluded by {_join(exc)}")
            elif inc:
                ad = AddressDecision(address, True, f"included by {_join(inc)}")
            elif name_inc and not self.strict:
                ad = AddressDecision(address, True, "covered only by the hostname rule (strict_hostname_resolution is off)")
                uncovered.append(address)
            else:
                ad = AddressDecision(address, False, "not covered by any address include rule")
                uncovered.append(address)
            decision.addresses.append(ad)

        if name_exc:
            decision.reasons.append(f"hostname excluded by {_join(name_exc)}")
            return decision
        if any_excluded:
            bad = ", ".join(a.address for a in decision.addresses if not a.in_scope and a.reason.startswith("excluded"))
            decision.reasons.append(f"hostname resolves to excluded address(es): {bad}")
            return decision
        if not addresses:
            if name_inc:
                decision.in_scope = True
                decision.reasons.append(f"hostname included by {_join(name_inc)}")
                decision.warnings.append("hostname has no resolved addresses; an address is required before reconnaissance")
            else:
                decision.reasons.append("hostname is not covered by any rule and has no resolved addresses")
            return decision
        if all(a.in_scope for a in decision.addresses):
            decision.in_scope = True
            if name_inc:
                decision.reasons.append(f"hostname included by {_join(name_inc)}")
            else:
                decision.reasons.append("every resolved address is in scope")
                decision.warnings.append("the hostname itself is not listed in scope; it is included only through its addresses")
            if uncovered:
                decision.warnings.append(
                    f"address(es) {', '.join(uncovered)} are not covered by address rules "
                    "(allowed because strict_hostname_resolution is off)"
                )
            return decision
        decision.reasons.append(
            f"resolved address(es) {', '.join(uncovered)} are outside the address scope"
            + (" (strict_hostname_resolution)" if name_inc else "")
        )
        return decision
