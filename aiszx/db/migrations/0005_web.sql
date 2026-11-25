-- Milestone 5: web endpoints, discovered resources and technologies. Owned per unit, like hosts/ports/services.

CREATE TABLE web_endpoints (
    id                  TEXT PRIMARY KEY,
    execution_id        TEXT NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
    target_id           TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    module_execution_id TEXT REFERENCES module_executions(id) ON DELETE CASCADE,
    service_key         TEXT,                   -- "tcp/80"
    url                 TEXT NOT NULL,          -- http://box.htb:80/
    scheme              TEXT NOT NULL,
    host                TEXT NOT NULL,          -- Host header used (IP or virtual host)
    port                INTEGER NOT NULL,
    address             TEXT NOT NULL,          -- IP actually connected to
    status_code         INTEGER,
    title               TEXT,
    server              TEXT,
    location            TEXT,                   -- redirect target, if any
    content_type        TEXT,
    content_length      INTEGER,
    headers_json        TEXT NOT NULL DEFAULT '{}',
    tls_json            TEXT NOT NULL DEFAULT '{}',
    discovered_at       TEXT NOT NULL,
    UNIQUE (module_execution_id, url)
);
CREATE INDEX ix_web_endpoints_target ON web_endpoints (target_id);
CREATE INDEX ix_web_endpoints_execution ON web_endpoints (execution_id);

CREATE TABLE web_resources (
    id                  TEXT PRIMARY KEY,
    execution_id        TEXT NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
    target_id           TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    module_execution_id TEXT REFERENCES module_executions(id) ON DELETE CASCADE,
    endpoint_url        TEXT NOT NULL,
    url                 TEXT NOT NULL,
    path                TEXT NOT NULL,
    status_code         INTEGER,
    content_length      INTEGER,
    redirect            TEXT,
    source_tool         TEXT NOT NULL,
    discovered_at       TEXT NOT NULL,
    UNIQUE (module_execution_id, url)
);
CREATE INDEX ix_web_resources_execution ON web_resources (execution_id);

CREATE TABLE technologies (
    id                  TEXT PRIMARY KEY,
    execution_id        TEXT NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
    target_id           TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    module_execution_id TEXT REFERENCES module_executions(id) ON DELETE CASCADE,
    endpoint_url        TEXT NOT NULL,
    name                TEXT NOT NULL,
    version             TEXT,
    detail              TEXT,
    source_tool         TEXT NOT NULL,
    confidence          TEXT,
    discovered_at       TEXT NOT NULL
);
CREATE INDEX ix_technologies_execution ON technologies (execution_id);
