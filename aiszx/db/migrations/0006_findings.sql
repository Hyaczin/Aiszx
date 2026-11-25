-- Milestone 7: findings (current state per target, stable fingerprint) and per-assessment snapshots.
-- Findings are never deleted when they stop reproducing: status becomes 'not_reproduced'.

CREATE TABLE findings (
    id                      TEXT PRIMARY KEY,           -- F-<10 hex of fingerprint>
    target_id               TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    fingerprint             TEXT NOT NULL,
    rule_id                 TEXT NOT NULL,
    title                   TEXT NOT NULL,
    service_key             TEXT,
    location                TEXT,
    description             TEXT NOT NULL,
    impact                  TEXT,
    recommendation          TEXT,
    next_steps_json         TEXT NOT NULL DEFAULT '[]',
    severity                TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    confidence              TEXT NOT NULL CHECK (confidence IN ('low', 'medium', 'high')),
    classification          TEXT NOT NULL CHECK (classification IN ('confirmed_observation', 'potential_vulnerability',
                              'unverified_hypothesis', 'false_positive', 'requires_manual_validation')),
    analyst_classification  TEXT CHECK (analyst_classification IN ('confirmed_observation', 'potential_vulnerability',
                              'unverified_hypothesis', 'false_positive', 'requires_manual_validation')),
    analyst_notes           TEXT,
    analyst_updated_at      TEXT,
    status                  TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'not_reproduced')),
    evidence_json           TEXT NOT NULL DEFAULT '[]',
    details_json            TEXT NOT NULL DEFAULT '{}',
    first_seen_at           TEXT NOT NULL,
    last_seen_at            TEXT NOT NULL,
    last_assessment_id      TEXT REFERENCES executions(id) ON DELETE SET NULL,
    UNIQUE (target_id, fingerprint)
);
CREATE INDEX ix_findings_target ON findings (target_id, status);

CREATE TABLE assessment_results (
    assessment_id   TEXT NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
    finding_id      TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    severity        TEXT NOT NULL,
    confidence      TEXT NOT NULL,
    classification  TEXT NOT NULL,
    PRIMARY KEY (assessment_id, finding_id)
);
