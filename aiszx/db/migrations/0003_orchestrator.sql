-- Milestone 3: module catalogue, executions (runs), per-unit state, attempts, evidence,
-- approvals, locks and lifecycle logs.

CREATE TABLE modules (
    id              TEXT PRIMARY KEY,
    version         TEXT NOT NULL,
    stage           TEXT NOT NULL,
    safety_class    TEXT NOT NULL,
    categories_json TEXT NOT NULL DEFAULT '[]',
    description     TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE TABLE executions (
    id                 TEXT PRIMARY KEY,
    run_id             TEXT NOT NULL,                    -- directory name, e.g. 2026-11-25_160000
    engagement_id      TEXT NOT NULL REFERENCES engagements(id),
    target_id          TEXT REFERENCES targets(id) ON DELETE CASCADE,
    command            TEXT NOT NULL,
    profile            TEXT NOT NULL,
    status             TEXT NOT NULL CHECK (status IN
                         ('RUNNING', 'COMPLETED', 'PARTIAL', 'FAILED', 'INTERRUPTED', 'RECOVERY_REQUIRED')),
    pinned_address     TEXT,
    config_fingerprint TEXT NOT NULL,
    config_snapshot    TEXT NOT NULL,
    framework_version  TEXT NOT NULL,
    owner_pid          INTEGER,
    owner_host         TEXT,
    boot_id            TEXT,
    heartbeat_at       TEXT,
    started_at         TEXT NOT NULL,
    ended_at           TEXT,
    workspace_path     TEXT NOT NULL,
    summary_json       TEXT NOT NULL DEFAULT '{}',
    UNIQUE (target_id, run_id)
);
CREATE INDEX ix_executions_target ON executions (target_id, started_at);
CREATE INDEX ix_executions_status ON executions (status);

CREATE TABLE module_executions (
    id                 TEXT PRIMARY KEY,
    execution_id       TEXT NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
    module_id          TEXT NOT NULL REFERENCES modules(id),
    target_id          TEXT REFERENCES targets(id) ON DELETE CASCADE,
    unit_key           TEXT NOT NULL,
    state              TEXT NOT NULL CHECK (state IN
                         ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'SKIPPED', 'INTERRUPTED', 'RECOVERY_REQUIRED')),
    attempt            INTEGER NOT NULL DEFAULT 0,
    skip_reason        TEXT,
    needs_approval     INTEGER NOT NULL DEFAULT 0,
    module_version     TEXT NOT NULL,
    inputs_json        TEXT NOT NULL DEFAULT '{}',
    input_fingerprint  TEXT NOT NULL,
    config_fingerprint TEXT NOT NULL,
    depends_on_json    TEXT NOT NULL DEFAULT '[]',
    tools_json         TEXT NOT NULL DEFAULT '{}',       -- tool -> {path, version} used
    exit_code          INTEGER,
    error_class        TEXT,
    error_message      TEXT,
    output_dir         TEXT,                             -- relative to the run directory
    outputs_json       TEXT NOT NULL DEFAULT '[]',       -- [{path, sha256, size}] of the successful attempt
    summary            TEXT,
    heartbeat_at       TEXT,
    started_at         TEXT,
    ended_at           TEXT,
    UNIQUE (execution_id, module_id, unit_key)
);
CREATE INDEX ix_module_executions_state ON module_executions (execution_id, state);

CREATE TABLE module_attempts (
    id                  TEXT PRIMARY KEY,
    module_execution_id TEXT NOT NULL REFERENCES module_executions(id) ON DELETE CASCADE,
    attempt             INTEGER NOT NULL,
    status              TEXT NOT NULL CHECK (status IN ('running', 'ok', 'failed', 'interrupted')),
    commands_json       TEXT NOT NULL DEFAULT '[]',      -- redacted command lines and exit codes
    exit_code           INTEGER,
    error_class         TEXT,
    error_message       TEXT,
    duration_s          REAL,
    output_dir          TEXT NOT NULL,
    started_at          TEXT NOT NULL,
    ended_at            TEXT,
    UNIQUE (module_execution_id, attempt)
);

CREATE TABLE evidence (
    id                  TEXT PRIMARY KEY,
    execution_id        TEXT NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
    target_id           TEXT REFERENCES targets(id) ON DELETE CASCADE,
    module_execution_id TEXT REFERENCES module_executions(id) ON DELETE CASCADE,
    attempt             INTEGER,
    tool                TEXT,
    kind                TEXT NOT NULL CHECK (kind IN ('raw', 'parsed', 'screenshot', 'log', 'supporting', 'report')),
    rel_path            TEXT NOT NULL,
    sha256              TEXT,
    size_bytes          INTEGER,
    sensitive           INTEGER NOT NULL DEFAULT 0,
    description         TEXT,
    created_at          TEXT NOT NULL,
    UNIQUE (execution_id, rel_path)
);
CREATE INDEX ix_evidence_unit ON evidence (module_execution_id);

CREATE TABLE approvals (
    id           TEXT PRIMARY KEY,
    execution_id TEXT REFERENCES executions(id) ON DELETE CASCADE,
    target_id    TEXT REFERENCES targets(id) ON DELETE SET NULL,
    action       TEXT NOT NULL,
    safety_class TEXT,
    decision     TEXT NOT NULL CHECK (decision IN ('approved', 'denied')),
    decided_by   TEXT NOT NULL,
    decided_at   TEXT NOT NULL,
    note         TEXT
);

CREATE TABLE locks (
    resource_key TEXT PRIMARY KEY,
    execution_id TEXT,
    owner_pid    INTEGER NOT NULL,
    owner_host   TEXT NOT NULL,
    boot_id      TEXT,
    acquired_at  TEXT NOT NULL,
    heartbeat_at TEXT NOT NULL
);

CREATE TABLE execution_logs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    execution_id        TEXT REFERENCES executions(id) ON DELETE CASCADE,
    module_execution_id TEXT REFERENCES module_executions(id) ON DELETE CASCADE,
    ts                  TEXT NOT NULL,
    level               TEXT NOT NULL,
    event               TEXT NOT NULL,
    message             TEXT,
    context_json        TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX ix_execution_logs_execution ON execution_logs (execution_id, ts);
