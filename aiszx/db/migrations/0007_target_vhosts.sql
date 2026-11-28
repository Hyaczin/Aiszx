-- Milestone 10: virtual host names accepted for a target (`hints accept`).
-- Every later run of the target presents them as Host header / SNI to the target's pinned in-scope
-- address. Each name passed the scope check when it was accepted and is checked again at run start.

CREATE TABLE target_vhosts (
    id           TEXT PRIMARY KEY,
    target_id    TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,              -- normalised host name
    source       TEXT,                       -- where the name was seen (hint sources) or 'manual'
    accepted_at  TEXT NOT NULL,
    accepted_by  TEXT,
    UNIQUE (target_id, name)
);

CREATE INDEX idx_target_vhosts_target ON target_vhosts (target_id);
