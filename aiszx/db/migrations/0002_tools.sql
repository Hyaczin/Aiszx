-- Milestone 2: tool inventory (current state per tool) and capability dependency status.
-- Full point-in-time snapshots are kept as JSON under <data>/global/tools/.

CREATE TABLE tool_inventory (
    name         TEXT PRIMARY KEY,
    status       TEXT NOT NULL CHECK (status IN ('ok', 'missing', 'broken', 'incompatible')),
    path         TEXT,
    version      TEXT,
    source       TEXT,
    package      TEXT,
    launch_json  TEXT NOT NULL DEFAULT '[]',
    detail_json  TEXT NOT NULL DEFAULT '{}',
    checked_at   TEXT NOT NULL
);

-- Keyed by capability (module group) for now; module-level rows arrive with the
-- module catalogue in Milestone 3.
CREATE TABLE dependency_status (
    capability   TEXT NOT NULL,
    tool_name    TEXT NOT NULL,
    requirement  TEXT NOT NULL CHECK (requirement IN ('required', 'any_of', 'optional')),
    status       TEXT NOT NULL CHECK (status IN ('satisfied', 'missing', 'broken', 'incompatible')),
    state        TEXT NOT NULL CHECK (state IN ('ready', 'degraded', 'unavailable')),
    message      TEXT,
    checked_at   TEXT NOT NULL,
    PRIMARY KEY (capability, tool_name)
);
