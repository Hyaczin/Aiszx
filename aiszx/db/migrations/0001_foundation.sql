-- Milestone 1: engagements, scope, targets, addresses, audit trail.
-- Conventions: TEXT ids (uuid hex), UTC ISO-8601 timestamps ending in 'Z'.

CREATE TABLE engagements (
    id                TEXT PRIMARY KEY,
    slug              TEXT NOT NULL UNIQUE,
    name              TEXT NOT NULL,
    description       TEXT,
    authorisation_ref TEXT,
    valid_from        TEXT,
    valid_until       TEXT,
    roe_json          TEXT NOT NULL DEFAULT '{}',
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    archived_at       TEXT
);

CREATE TABLE scope_rules (
    id            TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    action        TEXT NOT NULL CHECK (action IN ('include', 'exclude')),
    rule_type     TEXT NOT NULL CHECK (rule_type IN ('ip', 'cidr', 'hostname', 'domain_suffix')),
    value         TEXT NOT NULL,
    note          TEXT,
    created_at    TEXT NOT NULL,
    UNIQUE (engagement_id, action, rule_type, value)
);
CREATE INDEX ix_scope_rules_engagement ON scope_rules (engagement_id, action);

CREATE TABLE targets (
    id             TEXT PRIMARY KEY,
    engagement_id  TEXT NOT NULL REFERENCES engagements(id),
    canonical_id   TEXT NOT NULL,
    kind           TEXT NOT NULL CHECK (kind IN ('ipv4', 'ipv6', 'hostname')),
    slug           TEXT NOT NULL,
    source         TEXT NOT NULL CHECK (source IN ('manual', 'discovered')),
    status         TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'archived')),
    notes          TEXT,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    archived_at    TEXT,
    UNIQUE (engagement_id, canonical_id),
    UNIQUE (engagement_id, slug)
);
CREATE INDEX ix_targets_engagement_status ON targets (engagement_id, status);

CREATE TABLE target_addresses (
    id          TEXT PRIMARY KEY,
    target_id   TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    address     TEXT NOT NULL,
    family      INTEGER NOT NULL CHECK (family IN (4, 6)),
    source      TEXT NOT NULL CHECK (source IN ('self', 'dns', 'manual', 'discovered')),
    in_scope    INTEGER NOT NULL CHECK (in_scope IN (0, 1)),
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    UNIQUE (target_id, address)
);
CREATE INDEX ix_target_addresses_address ON target_addresses (address);

CREATE TABLE audit_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,
    actor         TEXT NOT NULL,
    engagement_id TEXT REFERENCES engagements(id) ON DELETE SET NULL,
    target_id     TEXT REFERENCES targets(id) ON DELETE SET NULL,
    action        TEXT NOT NULL,
    detail_json   TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX ix_audit_events_engagement ON audit_events (engagement_id, ts);
