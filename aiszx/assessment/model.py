"""Finding model, scales and stable fingerprints."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any

from aiszx.assessment.knowledge import Observation

SEVERITIES = ("info", "low", "medium", "high", "critical")
CONFIDENCES = ("low", "medium", "high")
CONFIRMED = "confirmed_observation"
POTENTIAL = "potential_vulnerability"
HYPOTHESIS = "unverified_hypothesis"
FALSE_POSITIVE = "false_positive"
MANUAL = "requires_manual_validation"
CLASSIFICATIONS = (CONFIRMED, POTENTIAL, HYPOTHESIS, FALSE_POSITIVE, MANUAL)

SCALE_HELP = {
    "severity": "info < low < medium < high < critical: impact if the issue is real and exploitable",
    "confidence": "low < medium < high: how strongly the evidence supports the finding",
    CONFIRMED: "directly observed fact (e.g. anonymous login accepted)",
    POTENTIAL: "configuration known to enable attacks; impact depends on context",
    HYPOTHESIS: "inferred (e.g. from a version number); unverified",
    MANUAL: "needs a human to validate before it can be relied on",
    FALSE_POSITIVE: "dismissed by an analyst",
}


@dataclass
class FindingDraft:
    rule_id: str
    title: str
    severity: str
    confidence: str
    classification: str
    description: str
    impact: str = ""
    recommendation: str = ""
    next_steps: list[str] = field(default_factory=list)
    service_key: str | None = None
    location: str | None = None
    discriminator: str = ""                       # what makes this instance unique (share name, path, ...)
    evidence: list[Observation] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES or self.confidence not in CONFIDENCES or self.classification not in CLASSIFICATIONS:
            raise ValueError(f"invalid scale value in {self.rule_id}")

    def fingerprint(self, target: str) -> str:
        raw = "|".join([self.rule_id, target, self.service_key or "", self.location or "", self.discriminator])
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def evidence_refs(self) -> list[dict[str, Any]]:
        return [o.ref() for o in self.evidence]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["evidence"] = self.evidence_refs()
        return d


def finding_id(fingerprint: str) -> str:
    return "F-" + fingerprint[:10]


def priority(severity: str, confidence: str, classification: str) -> int:
    """Higher = investigate first. Hypotheses and false positives sink; confirmed facts rise."""
    if classification == FALSE_POSITIVE:
        return -1
    weight = {CONFIRMED: 3, POTENTIAL: 2, MANUAL: 2, HYPOTHESIS: 0}[classification]
    return SEVERITIES.index(severity) * 10 + CONFIDENCES.index(confidence) * 3 + weight
