-- Milestone 4: reconnaissance results. Each row is owned by the module execution that produced
-- it (module_execution_id), so re-running a unit replaces exactly its own records.

CREATE TABLE discovered_hosts (
    id                  TEXT PRIMARY KEY,
    execution_id        TEXT NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
    engagement_id       TEXT NOT NULL REFERENCES engagements(id),
    target_id           TEXT REFERENCES targets(id) ON DELETE CASCADE,
    module_execution_id TEXT REFERENCES module_executions(id) ON DELETE CASCADE,
    address             TEXT NOT NULL,
    hostnames_json      TEXT NOT NULL DEFAULT '[]',
    status              TEXT NOT NULL CHECK (status IN ('up', 'down', 'unknown')),
    method              TEXT NOT NULL,
    reason              TEXT,
    os_json             TEXT NOT NULL DEFAULT '[]',
    in_scope            INTEGER NOT NULL DEFAULT 1,
    promoted_target_id  TEXT REFERENCES targets(id) ON DELETE SET NULL,
    discovered_at       TEXT NOT NULL
);
CREATE INDEX ix_discovered_hosts_execution ON discovered_hosts (execution_id);
CREATE INDEX ix_discovered_hosts_target ON discovered_hosts (target_id);

CREATE TABLE discovered_ports (
    id                  TEXT PRIMARY KEY,
    execution_id        TEXT NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
    target_id           TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    module_execution_id TEXT REFERENCES module_executions(id) ON DELETE CASCADE,
    address             TEXT NOT NULL,
    protocol            TEXT NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    port                INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    state               TEXT NOT NULL,          -- open | open|filtered | filtered | closed
    reason              TEXT,
    discovered_at       TEXT NOT NULL,
    UNIQUE (module_execution_id, address, protocol, port)
);
CREATE INDEX ix_discovered_ports_target ON discovered_ports (target_id, protocol, port);
CREATE INDEX ix_discovered_ports_execution ON discovered_ports (execution_id);

CREATE TABLE services (
    id                  TEXT PRIMARY KEY,
    execution_id        TEXT NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
    target_id           TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    module_execution_id TEXT REFERENCES module_executions(id) ON DELETE CASCADE,
    address             TEXT NOT NULL,
    protocol            TEXT NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    port                INTEGER NOT NULL,
    service_key         TEXT NOT NULL,          -- "tcp/445"
    state               TEXT NOT NULL,
    name                TEXT,
    product             TEXT,
    version             TEXT,
    extrainfo           TEXT,
    tunnel              TEXT,
    cpe_json            TEXT NOT NULL DEFAULT '[]',
    confidence          INTEGER,                -- nmap service confidence 0-10
    detection_method    TEXT,                   -- probed | table
    categories_json     TEXT NOT NULL DEFAULT '[]',
    category_confidence TEXT,                   -- high | medium | low
    scripts_json        TEXT NOT NULL DEFAULT '{}',
    enumeration_status  TEXT NOT NULL DEFAULT 'PENDING',
    discovered_at       TEXT NOT NULL,
    UNIQUE (module_execution_id, address, service_key)
);
CREATE INDEX ix_services_target ON services (target_id, service_key);
CREATE INDEX ix_services_execution ON services (execution_id);

ALTER TABLE evidence ADD COLUMN service_id TEXT REFERENCES services(id) ON DELETE SET NULL;
