# Aiszx — Architecture Review & Design

**Status:** Approved 2026-11-25. Milestones 1 to 8 implemented. Implementation notes are in §13 to §18.
**Date:** 2026-11-25
**Scope of this document:** Section 21 of the project specification — architecture review, improvements, final layout, schema, module interface, orchestration, recovery, tool detection, challenges and phased plan.

Aiszx is a human-in-the-loop reconnaissance, enumeration and assessment framework for authorised testing on Parrot Security OS. It automates repetitive collection and organisation work. It never exploits, attacks credentials or performs destructive actions on its own.

---

## 1. Architectural weaknesses & missing requirements in the specification

The specification is solid. The gaps below are the ones that would cause rework later if not decided now.

### 1.1 Scope & authorisation

| # | Gap | Why it matters | Proposed resolution |
|---|-----|----------------|---------------------|
| S1 | Scope is validated at *registration* only. | A module can still emit a command against an out-of-scope host (e.g. a hostname that now resolves elsewhere, a DNS module following an NS record, a web crawler following a redirect). | **Scope is enforced at the subprocess boundary.** Every `Command` declares its target(s); the `ToolRunner` re-validates them against the engagement scope immediately before execution and refuses otherwise. Registration-time validation is a convenience, not the control. |
| S2 | No authorisation record. | Reports and audit need to show *why* testing was permitted. | `engagements` carry an authorisation reference, validity window (`valid_from`/`valid_until`) and rules of engagement (allowed safety classes, testing windows, rate limits). Execution refuses outside the validity window. |
| S3 | Exclusions not modelled. | Spec mentions "scope and exclusions" in reports only. | `scope_rules` table with `include`/`exclude` rules (IP, CIDR, hostname, domain suffix). Exclusions always win. Nmap range scans receive `--excludefile` generated from the rules. |
| S4 | Hostname resolution drift. | `app.example.htb` may resolve to a different IP between runs (or to an out-of-scope IP). | Resolve at run start, record in `target_addresses` with timestamps, validate each resolved IP against scope, and pin the scanned IP for the run. |
| S5 | Discovered-but-unregistered assets. | DNS/LDAP/TLS SANs/redirects reveal new hostnames and IPs. | Record as **candidate assets** (`discovered_hosts` with `promoted_target_id = NULL`). Never auto-scan. The analyst promotes with `target add`. |

### 1.2 Identity & workspace

| # | Gap | Resolution |
|---|-----|------------|
| W1 | **IP reuse across labs.** In HTB, `10.10.10.5` is a different machine in different labs and over time. A global `targets/10.10.10.5/` merges unrelated history. | Target identity is **scoped to an engagement**: `engagements/<engagement>/targets/<target>/`. A `default` engagement exists so `target add 10.10.10.5` still works with no extra flags. *This deviates from the spec's example tree, see §3.* |
| W2 | Filesystem-safe identifiers not specified. | Canonical ID (e.g. `10.10.10.5`, `2001:db8::1`, `dc01.corp.local`) is stored in the DB; the **slug** used on disk is derived deterministically (`2001_db8__1`). Hostnames are lower-cased and IDNA-normalised. CIDRs are never targets; they belong to engagement scope. |
| W3 | Network-range runs have no home in the per-target tree. | Range-level host discovery runs live under `engagements/<e>/runs/<run-id>/`; each live host is registered as a target (if in scope and confirmed by the analyst or `--auto-register`) and gets its own per-target runs. |
| W4 | "Resume" vs "never overwrite" conflict. | **Resume continues the same run ID** (same directory). Each module attempt writes to its own `attempt-NN/` subdirectory, so nothing is overwritten. `--force` creates a *new* run. |
| W5 | Target removal semantics. | Default is **archive** (soft delete, workspace kept, hidden from lists). Hard deletion requires `--purge` plus typed confirmation, because evidence is an engagement record. |

### 1.3 Web-specific modelling

| # | Gap | Resolution |
|---|-----|------------|
| H1 | Web services are not just `host:port`. Virtual hosts are essential (HTB especially). | Model a **web endpoint** as `(scheme, address, port, vhost)`. One HTTP service can yield several endpoints (IP, discovered hostnames). |
| H2 | HTB workflow typically edits `/etc/hosts`. | That is a system-wide modification, so it is **not done automatically**. Modules pass the vhost to tools (`Host:` header, `--resolve`, tool-specific options). The framework *recommends* `/etc/hosts` lines and can apply them only with explicit approval. |
| H3 | "Newly discovered resources" needs a data model for comparison. | Add a `web_resources` table (URL, status, length, content type, source tool). |

### 1.4 Execution & safety

| # | Gap | Resolution |
|---|-----|------------|
| E1 | **Privileges.** SYN scans, UDP scans and OS detection need root (or `cap_net_raw`). Running the whole framework as root is a bad idea. | Framework runs unprivileged. Nmap privileged scans run through `sudo -n nmap …` *only if* the analyst opted in (config + approval), else fall back to `-sT` with a recorded limitation. Granting `setcap` to nmap is offered as a documented, approval-gated option. **Decision required (see §11).** |
| E2 | Safety classification is binary (intrusive / non-intrusive). | Four classes: `passive`, `active_safe`, `active_noisy` (content discovery, Nikto — safe but loud), `intrusive` (requires per-execution approval). A fifth, `prohibited_auto`, marks capabilities the framework will never schedule automatically (credential attacks, exploitation, post-exploitation). |
| E3 | Unit of work undefined. | The unit of execution and checkpointing is **module × target × service instance** (e.g. `http.whatweb` on `tcp/80` and `tcp/8080` are two independent units). Retries and resume operate per unit. |
| E4 | Timeouts don't kill child processes. | EyeWitness (Chromium), NetExec, etc. spawn children. Runner starts each tool in its **own process group** and terminates the group (SIGTERM → grace period → SIGKILL). |
| E5 | Credentials for authenticated enumeration not covered. | Optional per-engagement credential file (`0600`, never in the DB, never in reports). Runner **redacts** secrets from logged command lines. Note: secrets in argv are visible in `ps`; modules prefer env vars or temp files (`0600`) where the tool supports them. |
| E6 | Rate/load controls. | Global and per-target concurrency limits, plus per-profile nmap timing. Avoid DoSing fragile lab hosts. |
| E7 | VPN drops (tun0) mid-run are common in labs. | Runner classifies "network unreachable" / "no route to host" as **transient**, so they are retried under policy. A pre-flight check verifies a route to the target before each stage. |

### 1.5 Data, integrity & reporting

| # | Gap | Resolution |
|---|-----|------------|
| D1 | No structured "facts" layer between enumeration and assessment. | Add an **observations** table: typed facts emitted by modules (`smb.signing = not_required`, `ftp.anonymous_login = true`). Assessment rules consume observations, not raw text. This is the backbone for correlation and keeps rules testable. |
| D2 | Findings need stable identity across runs for comparison. | Every finding has a deterministic **fingerprint** = hash(rule_id, target, service key, discriminator). History compares fingerprints. |
| D3 | **Tool output is untrusted input.** Banners, titles and headers come from the target. | All HTML rendering autoescapes (Jinja2 autoescape). Parsers are defensive and never `eval`. File names derived from target data are sanitised. Markdown output escapes HTML in table cells. |
| D4 | Time handling unspecified. | All timestamps are **UTC ISO-8601** in the DB. Run IDs use UTC. Reports show UTC with an optional local offset. |
| D5 | Evidence integrity. | SHA-256 per evidence file plus a `manifest.json` per run (path, size, hash). Used both for reporting and for resume validation. |
| D6 | Disk growth (feroxbuster, screenshots). | Per-module output caps where tools support them, and a `workspace stats` command. No automatic deletion. |
| D7 | Version-based "outdated software" claims are weak. | Version matches (e.g. via offline `searchsploit --json`, which ships with Parrot) are classed at most as **Unverified hypothesis / Requires manual validation**, never "Confirmed". |

### 1.6 Development environment

The current workspace is on **Windows**, while the runtime target is **Parrot OS**. Consequences:

- All core code uses `pathlib` and avoids POSIX-only calls outside the runner and locking layers, which are abstracted.
- Unit tests (mocked subprocess, fixture XML) must pass on Windows *and* Linux.
- Integration tests (real nmap against local test services) run only on Linux/Parrot and are marked `@pytest.mark.integration`.
- Signal handling and process groups have a POSIX implementation and a degraded Windows implementation for development only.

---

## 2. Recommended improvements (summary)

1. Enforce scope at the subprocess boundary, not just at registration (S1).
2. Engagement-scoped target identity and workspaces (W1).
3. Observations layer as the contract between enumeration and assessment (D1).
4. Stable fingerprints for services and findings to make history comparison reliable (D2).
5. Separate each module into *plan → build commands → execute → parse* so everything except "execute" is a pure, fixture-testable function.
6. Data-driven service classification (`config/service_map.yaml`) instead of hardcoded `if` chains.
7. An approval record table: every approval-gated action is auditable.
8. Keep dependencies minimal: **PyYAML + Jinja2** at runtime (both are Parrot APT packages), **pytest** for development. Everything else from the standard library (`argparse`, `sqlite3`, `xml.etree`, `concurrent.futures`, `logging`, `hashlib`, `ipaddress`, `shutil.which`).
9. Resolve tools to **absolute paths** at execution time (from the inventory), not via `PATH` lookup inside modules.
10. Use Nmap's native `--resume` for interrupted long scans.

---

## 3. Final directory structure

### 3.1 Source tree

```
Aiszx/
├── pentest.py                      # Thin entry point → aiszx.cli.main:main()
├── install.sh                      # Parrot bootstrap: venv, deps, init, tool check (no silent installs)
├── requirements.txt                # PyYAML, Jinja2
├── requirements-dev.txt            # pytest
├── README.md
├── docs/
│   ├── ARCHITECTURE.md             # This document
│   ├── MODULE_DEVELOPMENT.md       # How to write a module
│   ├── TOOLS.md                    # Tool inventory & installation guidance
│   └── CLI.md                      # Command reference + deviations from spec
│
├── config/                         # Shipped defaults (read-only at runtime)
│   ├── framework.yaml              # Paths, concurrency, timeouts, logging
│   ├── profiles.yaml               # conservative / standard / comprehensive
│   ├── service_map.yaml            # nmap service → category → modules
│   ├── modules.yaml                # Per-module defaults (wordlists, flags, enable/disable)
│   ├── tools.yaml                  # Tool registry (spec: tools/registry.yaml, see note)
│   ├── reporting.yaml              # Sections, redaction patterns, formats
│   ├── assessment.yaml             # Severity/confidence scales, rule toggles
│   └── templates/
│       ├── engagement.example.yaml
│       ├── scope.example.yaml
│       └── credentials.example.yaml
│
├── aiszx/                          # Importable package
│   ├── __init__.py                 # __version__
│   ├── cli/
│   │   ├── main.py                 # argparse root, global flags
│   │   └── commands/               # init, target, scope, engagement, tools, recon,
│   │                               # enumerate, assess, report, full, resume,
│   │                               # history, compare, approve
│   ├── core/
│   │   ├── config.py               # Layered YAML loading + validation
│   │   ├── models.py               # Dataclasses: Target, Service, Command, WorkUnit, ...
│   │   ├── errors.py               # Error taxonomy (Transient/Permanent/Scope/Dependency)
│   │   ├── logging.py              # Central/target/run/module log handlers
│   │   ├── fingerprint.py          # Canonical JSON + SHA-256 helpers
│   │   ├── runner.py               # ToolRunner: scope guard, process groups, timeouts, capture
│   │   ├── orchestrator.py         # Run lifecycle, stage sequencing
│   │   ├── planner.py              # Module selection + dependency DAG
│   │   ├── executor.py             # Thread pool, concurrency limits, retries
│   │   ├── state.py                # Module execution state machine (DB-backed)
│   │   ├── recovery.py             # Startup reconciliation, resume decisions, summaries
│   │   ├── locks.py                # Per-target/module execution locks
│   │   └── approvals.py            # Interactive approval gate + audit
│   ├── targets/
│   │   ├── identity.py             # Normalisation, canonical IDs, slugs
│   │   ├── scope.py                # Scope rules evaluation
│   │   ├── manager.py              # Register/list/archive/resolve targets
│   │   └── workspace.py            # Workspace + run directory creation/repair
│   ├── tools/
│   │   ├── registry.py             # Load config/tools.yaml
│   │   ├── inventory.py            # Detection across apt/dpkg/PATH/pipx/go/git/venv
│   │   ├── dependency_checker.py   # Module → tool requirements, version constraints
│   │   ├── health_check.py         # Functional smoke checks
│   │   └── installer.py            # Install *plans*; executes only after confirmation
│   ├── modules/
│   │   ├── base.py                 # Module ABC, ModuleMeta, RetryPolicy, Safety
│   │   ├── registry.py             # Discovery (pkgutil) + validation
│   │   ├── recon/                  # host_discovery, tcp_ports, service_id, udp, web_probe
│   │   ├── http/                   # whatweb, eyewitness, feroxbuster, gobuster, nikto, http_basics
│   │   ├── smb/                    # netexec, enum4linux_ng, smbclient, nmap_smb
│   │   ├── dns/  ldap/  ssh/  ftp/  database/  mail/  remote/  nfs/  snmp/
│   │   └── ...
│   ├── parsers/
│   │   ├── nmap_xml.py             # Nmap XML → models
│   │   └── ...                     # whatweb JSON, enum4linux-ng JSON, ssh-audit JSON, ...
│   ├── classify/
│   │   └── classifier.py           # Service → categories, driven by service_map.yaml
│   ├── evidence/
│   │   ├── store.py                # Evidence registration, hashing, paths
│   │   ├── manifest.py             # Per-run manifest read/write/verify
│   │   └── redact.py               # Secret detection & redaction
│   ├── assessment/
│   │   ├── engine.py               # Runs rules over observations
│   │   ├── rules/                  # One file per service family; rule IDs e.g. SMB-001
│   │   └── prioritise.py           # Attack-surface investigation paths
│   ├── reporting/
│   │   ├── builder.py              # Assemble report data model from DB
│   │   ├── render_markdown.py
│   │   ├── render_html.py
│   │   ├── render_json.py
│   │   ├── compare.py              # Run-to-run diff
│   │   └── templates/              # Jinja2 (autoescape on)
│   └── db/
│       ├── connection.py           # WAL, foreign_keys, busy_timeout, transactions
│       ├── migrate.py              # PRAGMA user_version-based migrations
│       ├── migrations/0001_initial.sql
│       └── repo/                   # Thin repository functions per aggregate
│
└── tests/
    ├── unit/
    ├── integration/                # Linux-only, local services
    └── fixtures/                   # nmap XML, tool JSON outputs, fake tool scripts
```

**Note on `tools/`:** the spec asks for `tools/registry.yaml` alongside the Python files. I propose code in `aiszx/tools/` and the registry in `config/tools.yaml`, so it follows the same layered override mechanism as every other configuration file. If you prefer the spec's layout exactly, it's a trivial change.

### 3.2 Runtime data tree (default `~/.local/share/aiszx`, see §11.6)

```
~/.local/share/aiszx/
├── aiszx.db                                 # SQLite (WAL)
├── logs/aiszx.log                           # Central application log (JSON lines)
├── global/                                  # Tool inventory snapshots, cached health checks
└── engagements/
    └── default/
        ├── engagement.yaml                  # Authorisation, validity, RoE
        ├── scope.yaml                       # Include/exclude rules (mirrored in DB)
        ├── overrides.yaml                   # Per-engagement config overrides
        ├── credentials.yaml                 # Optional, 0600, never reported
        ├── runs/                            # Range-level discovery runs
        └── targets/
            └── 10.10.10.5/
                ├── target.yaml              # Identity, addresses, notes
                ├── history/                 # Comparison outputs
                ├── consolidated/            # Cross-run consolidated findings/inventory
                └── runs/
                    └── 2026-11-25_160000/
                        ├── manifest.json    # Evidence index with hashes
                        ├── run.yaml         # Effective config snapshot + fingerprint
                        ├── scope/           # Scope validation record for this run
                        ├── reconnaissance/
                        │   └── <module>/<unit>/attempt-01/{raw,parsed}/
                        ├── enumeration/
                        │   ├── http/ smb/ dns/ ldap/ ssh/ ftp/ other/
                        │   │   └── <module>/<unit>/attempt-01/{raw,parsed}/
                        ├── evidence/
                        │   ├── screenshots/
                        │   ├── supporting/
                        │   └── protected/   # 0700, secrets; excluded from reports
                        ├── findings/
                        ├── assessment/
                        ├── logs/            # run.log + modules/<module>__<unit>.log
                        └── reports/         # report.md, report.html, report.json
```

Run IDs follow the spec format `YYYY-MM-DD_HHMMSS` in UTC, with a `_2`, `_3` suffix on collision.

---

## 4. SQLite schema

Conventions: `TEXT` UUIDs (or prefixed readable IDs for evidence/findings), UTC ISO-8601 timestamps, `PRAGMA foreign_keys=ON`, `PRAGMA journal_mode=WAL`, `busy_timeout=5000`. Migrations are numbered SQL files applied in order and tracked with `PRAGMA user_version`.

```sql
-- ===== Engagement & scope =====
CREATE TABLE engagements (
    id                TEXT PRIMARY KEY,
    slug              TEXT NOT NULL UNIQUE,
    name              TEXT NOT NULL,
    description       TEXT,
    authorisation_ref TEXT,                      -- contract / lab / ticket reference
    valid_from        TEXT,
    valid_until       TEXT,
    roe_json          TEXT NOT NULL DEFAULT '{}', -- allowed safety classes, windows, rate limits
    created_at        TEXT NOT NULL,
    archived_at       TEXT
);

CREATE TABLE scope_rules (
    id            TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    action        TEXT NOT NULL CHECK (action IN ('include','exclude')),
    rule_type     TEXT NOT NULL CHECK (rule_type IN ('ip','cidr','hostname','domain_suffix')),
    value         TEXT NOT NULL,
    note          TEXT,
    created_at    TEXT NOT NULL,
    UNIQUE (engagement_id, action, rule_type, value)
);

-- ===== Targets =====
CREATE TABLE targets (
    id             TEXT PRIMARY KEY,
    engagement_id  TEXT NOT NULL REFERENCES engagements(id),
    canonical_id   TEXT NOT NULL,                 -- 10.10.10.5 | dc01.corp.local
    kind           TEXT NOT NULL CHECK (kind IN ('ipv4','ipv6','hostname')),
    slug           TEXT NOT NULL,                 -- filesystem-safe
    source         TEXT NOT NULL CHECK (source IN ('manual','discovered')),
    status         TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','archived')),
    notes          TEXT,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    archived_at    TEXT,
    UNIQUE (engagement_id, canonical_id),
    UNIQUE (engagement_id, slug)
);

CREATE TABLE target_addresses (
    id          TEXT PRIMARY KEY,
    target_id   TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    address     TEXT NOT NULL,
    family      INTEGER NOT NULL CHECK (family IN (4,6)),
    source      TEXT NOT NULL CHECK (source IN ('self','dns','manual','discovered')),
    in_scope    INTEGER NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    UNIQUE (target_id, address)
);

-- ===== Executions =====
CREATE TABLE executions (
    id                  TEXT PRIMARY KEY,         -- run id: 2026-11-25_160000
    engagement_id       TEXT NOT NULL REFERENCES engagements(id),
    target_id           TEXT REFERENCES targets(id),  -- NULL for range-level runs
    command             TEXT NOT NULL,            -- recon | enumerate | full | ...
    profile             TEXT,
    status              TEXT NOT NULL CHECK (status IN
                          ('PENDING','RUNNING','COMPLETED','FAILED','INTERRUPTED','RECOVERY_REQUIRED','PARTIAL')),
    pinned_address      TEXT,                     -- IP actually scanned for hostname targets
    config_fingerprint  TEXT NOT NULL,
    config_snapshot     TEXT NOT NULL,            -- effective config JSON
    framework_version   TEXT NOT NULL,
    owner_pid           INTEGER,
    owner_host          TEXT,
    started_at          TEXT NOT NULL,
    ended_at            TEXT,
    workspace_path      TEXT NOT NULL             -- relative to data root
);
CREATE INDEX ix_exec_target ON executions(target_id, started_at);

CREATE TABLE modules (                            -- catalogue snapshot of registered modules
    id            TEXT PRIMARY KEY,               -- e.g. smb.enum4linux_ng
    version       TEXT NOT NULL,
    stage         TEXT NOT NULL,
    category      TEXT,
    safety_class  TEXT NOT NULL,
    description   TEXT,
    updated_at    TEXT NOT NULL
);

CREATE TABLE module_executions (
    id                  TEXT PRIMARY KEY,
    execution_id        TEXT NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
    module_id           TEXT NOT NULL REFERENCES modules(id),
    target_id           TEXT REFERENCES targets(id),
    service_id          TEXT REFERENCES services(id),
    unit_key            TEXT NOT NULL,            -- 'tcp/445', 'host', 'http://10.10.10.5:8080|vhost'
    state               TEXT NOT NULL CHECK (state IN
                          ('PENDING','RUNNING','COMPLETED','FAILED','SKIPPED','INTERRUPTED','RECOVERY_REQUIRED')),
    attempt             INTEGER NOT NULL DEFAULT 0,
    skip_reason         TEXT,
    input_fingerprint   TEXT,
    config_fingerprint  TEXT,
    tool_name           TEXT,
    tool_path           TEXT,
    tool_version        TEXT,
    exit_code           INTEGER,
    error_class         TEXT,                     -- transient | permanent | timeout | scope | dependency
    error_message       TEXT,
    output_dir          TEXT,                     -- relative to run dir
    depends_on_json     TEXT NOT NULL DEFAULT '[]',
    heartbeat_at        TEXT,
    started_at          TEXT,
    ended_at            TEXT,
    UNIQUE (execution_id, module_id, unit_key)
);
CREATE INDEX ix_modexec_state ON module_executions(execution_id, state);

CREATE TABLE module_attempts (                    -- one row per try; preserves retry history
    id                  TEXT PRIMARY KEY,
    module_execution_id TEXT NOT NULL REFERENCES module_executions(id) ON DELETE CASCADE,
    attempt             INTEGER NOT NULL,
    command_redacted    TEXT,
    exit_code           INTEGER,
    error_class         TEXT,
    error_message       TEXT,
    duration_s          REAL,
    max_rss_kb          INTEGER,
    output_dir          TEXT NOT NULL,
    started_at          TEXT NOT NULL,
    ended_at            TEXT,
    UNIQUE (module_execution_id, attempt)
);

-- ===== Discovery results =====
CREATE TABLE discovered_hosts (
    id                  TEXT PRIMARY KEY,
    execution_id        TEXT NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
    engagement_id       TEXT NOT NULL REFERENCES engagements(id),
    address             TEXT,
    hostname            TEXT,
    status              TEXT NOT NULL CHECK (status IN ('up','down','unknown','candidate')),
    method              TEXT NOT NULL,            -- icmp-echo, arp, tcp-syn-ping, dns, ldap, tls-san ...
    reason              TEXT,
    in_scope            INTEGER NOT NULL,
    promoted_target_id  TEXT REFERENCES targets(id),
    discovered_at       TEXT NOT NULL
);
CREATE INDEX ix_dhosts_exec ON discovered_hosts(execution_id);

CREATE TABLE discovered_ports (
    id                  TEXT PRIMARY KEY,
    execution_id        TEXT NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
    target_id           TEXT NOT NULL REFERENCES targets(id),
    address             TEXT NOT NULL,
    protocol            TEXT NOT NULL CHECK (protocol IN ('tcp','udp')),
    port                INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    state               TEXT NOT NULL,            -- open | open|filtered | filtered | closed
    reason              TEXT,
    module_execution_id TEXT REFERENCES module_executions(id),
    discovered_at       TEXT NOT NULL,
    UNIQUE (execution_id, target_id, address, protocol, port)
);
CREATE INDEX ix_ports_target ON discovered_ports(target_id, protocol, port);

CREATE TABLE services (
    id                  TEXT PRIMARY KEY,
    execution_id        TEXT NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
    target_id           TEXT NOT NULL REFERENCES targets(id),
    port_id             TEXT NOT NULL REFERENCES discovered_ports(id) ON DELETE CASCADE,
    service_key         TEXT NOT NULL,            -- stable: 'tcp/445'
    name                TEXT,                     -- nmap service name
    product             TEXT,
    version             TEXT,
    extrainfo           TEXT,
    tunnel              TEXT,                     -- 'ssl'
    cpe_json            TEXT NOT NULL DEFAULT '[]',
    categories_json     TEXT NOT NULL DEFAULT '[]', -- ['http','https']
    confidence          INTEGER,                  -- nmap conf 0-10
    detection_method    TEXT,                     -- probed | table
    enumeration_status  TEXT NOT NULL DEFAULT 'PENDING',
    source_evidence_id  TEXT REFERENCES evidence(id),
    UNIQUE (execution_id, target_id, service_key)
);
CREATE INDEX ix_services_target ON services(target_id, service_key);

CREATE TABLE web_endpoints (
    id            TEXT PRIMARY KEY,
    execution_id  TEXT NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
    service_id    TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    url           TEXT NOT NULL,                  -- https://10.10.10.5:8443/
    vhost         TEXT,
    status_code   INTEGER,
    title         TEXT,
    server_header TEXT,
    tls_json      TEXT,
    UNIQUE (execution_id, url, vhost)
);

CREATE TABLE web_resources (
    id              TEXT PRIMARY KEY,
    execution_id    TEXT NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
    endpoint_id     TEXT NOT NULL REFERENCES web_endpoints(id) ON DELETE CASCADE,
    path            TEXT NOT NULL,
    status_code     INTEGER,
    content_length  INTEGER,
    content_type    TEXT,
    source_tool     TEXT NOT NULL,
    UNIQUE (execution_id, endpoint_id, path)
);

CREATE TABLE technologies (
    id            TEXT PRIMARY KEY,
    execution_id  TEXT NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
    service_id    TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    endpoint_id   TEXT REFERENCES web_endpoints(id),
    name          TEXT NOT NULL,
    version       TEXT,
    category      TEXT,
    source_tool   TEXT NOT NULL,
    confidence    TEXT CHECK (confidence IN ('low','medium','high')),
    evidence_id   TEXT REFERENCES evidence(id)
);
CREATE INDEX ix_tech_service ON technologies(service_id);

-- ===== Evidence, observations, findings =====
CREATE TABLE evidence (
    id                  TEXT PRIMARY KEY,         -- EV-<run>-<seq>
    execution_id        TEXT NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
    target_id           TEXT REFERENCES targets(id),
    module_execution_id TEXT REFERENCES module_executions(id),
    service_id          TEXT REFERENCES services(id),
    tool                TEXT,
    kind                TEXT NOT NULL CHECK (kind IN ('raw','parsed','screenshot','log','supporting','report')),
    rel_path            TEXT NOT NULL,            -- relative to run dir
    sha256              TEXT,
    size_bytes          INTEGER,
    sensitive           INTEGER NOT NULL DEFAULT 0,
    description         TEXT,
    created_at          TEXT NOT NULL,
    UNIQUE (execution_id, rel_path)
);
CREATE INDEX ix_evidence_exec ON evidence(execution_id, module_execution_id);

CREATE TABLE observations (
    id                  TEXT PRIMARY KEY,
    execution_id        TEXT NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
    target_id           TEXT NOT NULL REFERENCES targets(id),
    service_id          TEXT REFERENCES services(id),
    module_execution_id TEXT REFERENCES module_executions(id),
    key                 TEXT NOT NULL,            -- 'smb.signing'
    value_json          TEXT NOT NULL,            -- '"not_required"'
    evidence_id         TEXT REFERENCES evidence(id),
    observed_at         TEXT NOT NULL
);
CREATE INDEX ix_obs_key ON observations(execution_id, key);

CREATE TABLE findings (
    id               TEXT PRIMARY KEY,            -- F-<run>-<seq>
    fingerprint      TEXT NOT NULL,               -- stable across runs
    execution_id     TEXT NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
    target_id        TEXT NOT NULL REFERENCES targets(id),
    service_id       TEXT REFERENCES services(id),
    rule_id          TEXT NOT NULL,               -- SMB-001
    title            TEXT NOT NULL,
    description      TEXT NOT NULL,
    impact           TEXT,
    severity         TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    confidence       TEXT NOT NULL CHECK (confidence IN ('low','medium','high')),
    classification   TEXT NOT NULL CHECK (classification IN
                       ('confirmed_observation','potential_vulnerability','unverified_hypothesis',
                        'false_positive','requires_manual_validation')),
    recommendation   TEXT,
    analyst_notes    TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    UNIQUE (execution_id, fingerprint)
);
CREATE INDEX ix_findings_fp ON findings(target_id, fingerprint);

CREATE TABLE finding_evidence (
    finding_id   TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    evidence_id  TEXT REFERENCES evidence(id),
    observation_id TEXT REFERENCES observations(id),
    PRIMARY KEY (finding_id, evidence_id, observation_id)
);

-- ===== Tools =====
CREATE TABLE tool_inventory (
    name           TEXT PRIMARY KEY,
    status         TEXT NOT NULL CHECK (status IN ('ok','missing','broken','incompatible')),
    path           TEXT,
    version        TEXT,
    source         TEXT,                          -- apt | pipx | venv | go | git | path
    package        TEXT,
    detail_json    TEXT NOT NULL DEFAULT '{}',
    checked_at     TEXT NOT NULL
);

CREATE TABLE dependency_status (
    module_id      TEXT NOT NULL REFERENCES modules(id),
    tool_name      TEXT NOT NULL,
    requirement    TEXT,                          -- '>=3.0'
    status         TEXT NOT NULL CHECK (status IN ('satisfied','missing','incompatible','optional_missing')),
    message        TEXT,
    checked_at     TEXT NOT NULL,
    PRIMARY KEY (module_id, tool_name)
);

-- ===== Control & audit =====
CREATE TABLE approvals (
    id             TEXT PRIMARY KEY,
    execution_id   TEXT REFERENCES executions(id),
    target_id      TEXT REFERENCES targets(id),
    action         TEXT NOT NULL,                 -- 'module:http.nikto' | 'install:apt:feroxbuster' | 'sudo:nmap'
    safety_class   TEXT,
    decision       TEXT NOT NULL CHECK (decision IN ('approved','denied')),
    decided_by     TEXT NOT NULL,                 -- local username
    decided_at     TEXT NOT NULL,
    note           TEXT
);

CREATE TABLE locks (
    resource_key   TEXT PRIMARY KEY,              -- 'target:<id>:module:<module_id>'
    owner_pid      INTEGER NOT NULL,
    owner_host     TEXT NOT NULL,
    boot_id        TEXT,                          -- detects reboot → stale lock
    acquired_at    TEXT NOT NULL,
    heartbeat_at   TEXT NOT NULL
);

CREATE TABLE execution_logs (                     -- lifecycle + WARNING/ERROR only; full logs on disk
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    execution_id        TEXT REFERENCES executions(id) ON DELETE CASCADE,
    module_execution_id TEXT REFERENCES module_executions(id),
    ts                  TEXT NOT NULL,
    level               TEXT NOT NULL,
    event               TEXT NOT NULL,
    message             TEXT,
    context_json        TEXT
);
CREATE INDEX ix_logs_exec ON execution_logs(execution_id, ts);
```

Tables added beyond the spec: `scope_rules`, `module_attempts`, `web_endpoints`, `web_resources`, `observations`, `finding_evidence`, `approvals`, `locks`, and `audit_events` (who changed scope or registered/removed targets, and when). Each closes a gap from §1.

The schema is introduced incrementally: each milestone adds a numbered migration for the tables it needs. Milestone 1 ships `0001_foundation.sql` (engagements, scope_rules, targets, target_addresses, audit_events). It also adds an `updated_at` column to `engagements`.

---

## 5. Plugin / module interface

Every module is a Python class in `aiszx/modules/<family>/`. Its lifecycle is split so only one step touches the outside world:

```
applies_to()  →  plan()  →  build_commands()  →  [ToolRunner executes]  →  parse()  →  validate_outputs()
   pure          pure          pure                 side effects              pure          pure (fs read)
```

```python
# aiszx/modules/base.py (interface sketch — final code in Milestone 3)

class Safety(enum.Enum):
    PASSIVE = "passive"            # no packets to target (e.g. parsing existing data)
    ACTIVE_SAFE = "active_safe"    # standard enumeration, low request volume
    ACTIVE_NOISY = "active_noisy"  # content discovery, vuln scanners — enabled per profile
    INTRUSIVE = "intrusive"        # needs per-execution approval
    PROHIBITED_AUTO = "prohibited_auto"  # never scheduled automatically

@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 2
    backoff_seconds: float = 15.0
    backoff_factor: float = 2.0
    retry_on: tuple[str, ...] = ("transient", "timeout")

@dataclass(frozen=True)
class ToolRequirement:
    name: str                      # logical name in config/tools.yaml
    min_version: str | None = None
    optional: bool = False

@dataclass(frozen=True)
class ModuleMeta:
    id: str                        # 'smb.enum4linux_ng'
    version: str                   # bump when output format/semantics change → invalidates checkpoints
    description: str
    stage: Stage                   # RECON | ENUMERATION | ASSESSMENT
    categories: tuple[str, ...]    # service categories it handles: ('smb',)
    tools: tuple[ToolRequirement, ...]
    depends_on: tuple[str, ...]    # module ids or stage markers: ('recon.service_id',)
    safety: Safety
    timeout_seconds: int
    retry: RetryPolicy
    resumable: bool = False        # can continue from partial output (e.g. nmap --resume)
    config_defaults: Mapping[str, Any] = field(default_factory=dict)
    produces: tuple[str, ...] = () # observation keys / record types it can emit (documentation + validation)

class Module(abc.ABC):
    meta: ClassVar[ModuleMeta]

    def applies_to(self, service: Service, ctx: RunContext) -> bool:
        """Extra predicate beyond category match (e.g. only if SMB signing unknown). Default True."""
        return True

    def plan(self, ctx: RunContext) -> list[WorkUnit]:
        """Return units of work. Default: one unit per matching service."""

    @abc.abstractmethod
    def build_commands(self, unit: WorkUnit, ctx: RunContext) -> list[Command]:
        """Pure. Returns argv lists, declared targets, output paths, env, secrets-to-redact."""

    @abc.abstractmethod
    def parse(self, unit: WorkUnit, results: list[CommandResult], ctx: RunContext) -> ModuleResult:
        """Pure. Converts raw output into structured records. Must tolerate partial/garbled output."""

    def validate_outputs(self, unit: WorkUnit, output_dir: Path) -> ValidationResult:
        """Checks expected files exist and are parseable. Used by resume."""
```

**Input schema:** the `WorkUnit` (target, pinned address, service record, endpoint, module config) plus a read-only `RunContext` (prior results for the run, tool paths, workspace paths). The **input fingerprint** is derived from exactly the `WorkUnit` fields the module consumes.

**Output schema:** `ModuleResult` is a typed container. Modules never write to the DB directly; the orchestrator persists results in one transaction.

```python
@dataclass
class ModuleResult:
    ports: list[PortRecord] = ...
    services: list[ServiceRecord] = ...
    endpoints: list[WebEndpoint] = ...
    resources: list[WebResource] = ...
    technologies: list[Technology] = ...
    observations: list[Observation] = ...      # feeds assessment
    candidates: list[CandidateAsset] = ...     # new hostnames/IPs — never auto-scanned
    evidence: list[EvidenceItem] = ...         # raw/parsed/screenshot files to register
    limitations: list[str] = ...               # e.g. "UDP top-100 only", "scan incomplete"
```

**`Command`** carries `argv`, `targets` (for the scope guard), `timeout`, `env`, `stdin`, `redact` (secret strings), `expected_outputs`, and `privileged` (needs sudo, which triggers the approval gate). Modules never call `subprocess` directly. This is enforced by code review and a unit test that greps module sources.

**Honesty rule:** a module that can't do its job (missing tool, unsupported version) is marked `SKIPPED` with a reason. There are no stub modules that pretend to work.

---

## 6. Module discovery & selection

### 6.1 Discovery
1. `modules/registry.py` walks the `aiszx.modules` package with `pkgutil.walk_packages`, imports each submodule and collects `Module` subclasses that define `meta`.
2. Each `meta` is validated: unique id, known categories, known tools, `depends_on` resolvable, no dependency cycles.
3. The catalogue is upserted into the `modules` table.
4. `config/modules.yaml` plus profile and engagement overrides set `enabled`, per-module config and any safety-class ceiling.

### 6.2 Classification
`classify/classifier.py` maps each service to one or more **categories** using `config/service_map.yaml`:

```yaml
categories:
  http:
    nmap_names: [http, http-alt, http-proxy, "http-*"]
    ports_hint: [80, 8080, 8000, 8008]
  https:
    nmap_names: [https, https-alt, ssl/http]
    tunnel: ssl            # tunnel=ssl + http name ⇒ https
    ports_hint: [443, 8443]
  smb:
    nmap_names: [microsoft-ds, netbios-ssn]
    ports_hint: [139, 445]
  ldap:
    nmap_names: [ldap, ldapssl, "globalcatLDAP*"]
    ports_hint: [389, 636, 3268, 3269]
  # ... kerberos, mssql, mysql, postgresql, rdp, winrm, nfs, snmp, smtp, dns, ssh, ftp
```

Priority: nmap service name (probed) → tunnel → product heuristics → port hint (low confidence, flagged). Unmatched services go to `other`. A service can carry several categories (e.g. WinRM is `winrm` + `http`).

### 6.3 Planning
For an `enumerate` run, the planner:

1. Loads the services of the latest completed recon in this run (or the referenced run).
2. For each enabled module whose `categories` intersect the service's categories and whose `applies_to()` returns true → `plan()` → work units.
3. Filters by **safety ceiling** (profile + engagement RoE). `INTRUSIVE` units go to `PENDING_APPROVAL` and are listed for `approve`. `PROHIBITED_AUTO` units are never created.
4. Checks **dependencies** against the tool inventory. Missing or incompatible tools mark the unit `SKIPPED` with an actionable reason (`feroxbuster missing — install: sudo apt install feroxbuster`).
5. Builds a DAG from `depends_on` and topologically sorts it. Units whose upstream failed are `SKIPPED (upstream failed)`; unrelated branches continue (failure isolation).
6. `--module smb` restricts planning to modules in the `smb` family (or an exact module id).

### 6.4 Execution
- `concurrent.futures.ThreadPoolExecutor`: the work is subprocess-bound, so threads are sufficient and simpler than asyncio.
- Limits: `max_workers` globally, `max_per_target`, plus per-tool limits (e.g. one EyeWitness at a time, one nmap per target).
- **Single DB writer:** worker threads return results to the orchestrator thread, which persists them. This avoids SQLite write contention.

---

## 7. Checkpointing & recovery

### 7.1 State machine

```
              ┌──────────► SKIPPED (dependency/safety/upstream/inapplicable)
              │
PENDING ──► RUNNING ──► COMPLETED
              │  ▲
              │  └── retry (transient/timeout, attempts < max) ──┐
              ├──► FAILED  ◄──────────────────────────────────────┘ (attempts exhausted / permanent)
              ├──► INTERRUPTED (SIGINT/SIGTERM, or found RUNNING with dead owner at startup)
              └──► RECOVERY_REQUIRED (inconsistent artifacts, needs analyst decision)
```

### 7.2 What happens around each unit

**Before execution** (one transaction):
- Acquire the lock `target:<id>:module:<module_id>:<unit_key>`. Refuse if it's held by a live owner.
- Set `state=RUNNING`, `attempt += 1`, `started_at`, the input and config fingerprints, and the tool path/version.
- Create `…/<module>/<unit>/attempt-NN/{raw,parsed}/`.

**During execution:**
- The runner streams stdout/stderr to `raw/` files (never only in memory, so partial output survives a crash).
- A heartbeat updates `heartbeat_at` every 30 s.

**After execution:**
1. Parse → `ModuleResult`.
2. Hash all output files and register evidence.
3. One transaction persists records, sets `state=COMPLETED`, `exit_code`, `ended_at`, `output_dir`, then updates `manifest.json` (written to a temp file, then atomic rename).
4. Release the lock.

Failed attempts keep their `attempt-NN/` directory and a `module_attempts` row. Failed output is never discarded.

### 7.3 Error taxonomy → retry policy

| Class | Examples | Default |
|-------|----------|---------|
| `transient` | network unreachable, connection reset, tun0 down, tool exit codes known to mean "try again" | retry with exponential backoff |
| `timeout` | exceeded `timeout_seconds` | retry once (configurable), then FAILED |
| `permanent` | bad arguments, parse error, tool crash with a deterministic error | FAILED, no retry |
| `dependency` | tool missing/incompatible at run time | SKIPPED |
| `scope` | command target fails the scope guard | FAILED and run aborted for that target (it's a bug or a scope change) |

### 7.4 Startup reconciliation (self-healing)
On every command that touches executions:
1. Find `RUNNING` units whose owner PID is dead, whose host differs, whose `boot_id` changed or whose heartbeat is stale → mark `INTERRUPTED`.
2. Release stale locks.
3. Verify run workspace directories exist and recreate missing *structure* (never content).
4. Re-check the tool inventory for tools used by pending/interrupted units.

### 7.5 Intelligent resume decision table
`resume TARGET [--last-run | --run ID]` evaluates each unit:

| Prior state | Checks | Decision |
|-------------|--------|----------|
| COMPLETED | outputs present, readable, hashes match manifest, `validate_outputs` OK, input fingerprint same, config fingerprint same, module version same, tool version compatible | **Skip (reuse)** |
| COMPLETED | any check fails | **Re-run** (reason recorded: e.g. "input changed: new service version on tcp/80") |
| COMPLETED | output missing *and* records exist in DB | **RECOVERY_REQUIRED**: analyst chooses re-run or accept |
| INTERRUPTED, `resumable` | partial output valid (e.g. nmap `.gnmap` present) | **Resume** (e.g. `nmap --resume`) |
| INTERRUPTED / FAILED | — | **Re-run** in a new attempt dir |
| PENDING / SKIPPED(dependency) | dependency now satisfied? | Run / keep skipped |

Input changes propagate: if recon is re-run and a service's fingerprint changes, downstream units for that service are invalidated. Units for unchanged services are reused.

Before continuing, the CLI prints a **recovery summary** (counts plus per-unit reason) and asks for confirmation (`--yes` for non-interactive use).

### 7.6 Fingerprints
- **Config fingerprint** = SHA-256 of canonical JSON (sorted keys, normalised types) of {module id, module version, effective module config, relevant profile parameters}.
- **Input fingerprint** = SHA-256 of canonical JSON of the consumed `WorkUnit` fields (e.g. for HTTP: address, port, scheme, vhost, service name/product/version).

### 7.7 Graceful shutdown
First SIGINT sets a cancel event: no new units start, running process groups get SIGTERM, then SIGKILL after a grace period. Units are marked `INTERRUPTED`, partial output is registered, and the run is marked `INTERRUPTED`. A second SIGINT forces an immediate exit; startup reconciliation handles the rest.

---

## 8. Parrot OS tool detection & reuse

Implementation notes (Milestone 2): see [TOOLS.md](TOOLS.md). Additions beyond this section:
- pipx metadata is read directly from `pipx_metadata.json`.
- `{git_root}` placeholders are supported in `known_paths`.
- pyenv interpreters are supported with `interpreter: pyenv:X.Y`.
- Capability readiness is stored in `dependency_status`, keyed by capability (migration `0002_tools.sql`).
- Point-in-time JSON snapshots are written to `global/tools/`.

### 8.1 Registry (`config/tools.yaml`)

```yaml
tools:
  nmap:
    description: Network scanner
    binaries: [nmap]
    apt: nmap
    version_cmd: ["{bin}", "--version"]
    version_regex: 'Nmap version ([\d.]+)'
    min_version: "7.80"
    health_cmd: ["{bin}", "--version"]
    install_preference: [apt]
  netexec:
    binaries: [nxc, netexec]
    apt: netexec
    pipx: netexec
    version_cmd: ["{bin}", "--version"]
    version_regex: '([\d.]+)'
    install_preference: [apt, pipx]
  impacket:
    # Debian/Parrot package installs 'impacket-<tool>' wrappers; pip installs '<tool>.py'
    binaries: [impacket-GetADUsers, GetADUsers.py]
    apt: python3-impacket
    pipx: impacket
  eyewitness:
    binaries: [eyewitness, EyeWitness.py]
    apt: eyewitness
    known_paths: [/usr/share/eyewitness/EyeWitness.py, /opt/EyeWitness/Python/EyeWitness.py]
    health_requires: [chromium | firefox-esr+geckodriver]
  feroxbuster:
    binaries: [feroxbuster]
    apt: feroxbuster
    known_paths: [~/.cargo/bin/feroxbuster]
  # whatweb, gobuster, nikto, enum4linux-ng, smbclient, dig, dnsrecon, dnsenum,
  # ldapsearch (ldap-utils), ssh-audit, searchsploit (exploitdb), showmount (nfs-common),
  # snmpwalk (snmp), onesixtyone, smtp-user-enum (detection only, never auto-run user enumeration) ...
```

### 8.2 Detection order (first working hit wins; all hits recorded)
1. **PATH**: `shutil.which()` for each binary name (equivalent to `command -v`).
2. **dpkg**: `dpkg-query -W -f='${Status}\t${Version}' <pkg>` confirms the APT origin and package version.
3. **pipx**: `pipx list --json` (if pipx exists) → venv and app paths.
4. **Go**: `$(go env GOPATH)/bin`, `~/go/bin`.
5. **Cargo**: `~/.cargo/bin`.
6. **Git/opt installs**: `known_paths` plus configured search roots (`/opt`, `~/tools`); `git -C <dir> rev-parse HEAD` records the commit.
7. **Configured venvs**: paths from `framework.yaml` → `tools.venvs`.

For each hit: resolve the absolute path (following symlinks), run `version_cmd` with a short timeout, parse the version, compare it with `min_version`, then optionally run `health_cmd`. The result is stored in `tool_inventory` with source, path, version and status (`ok | missing | broken | incompatible`).

### 8.3 Reuse & installation policy
- Modules reference **logical tool names**. At execution time the runner uses the **absolute path** from inventory, which is reproducible and immune to PATH changes mid-run.
- `tools missing` explains *why* each tool matters (which modules need it) and recommends a method following the spec's priority: existing → APT → pipx → venv → Go → Git.
- `tools install --interactive` builds an **install plan** and shows the exact commands. Each item needs explicit confirmation, and approvals are recorded. Never `sudo pip`, never `curl | sh`, never modify system Python. `pipx` and venvs stay user-local.
- If a tool exists in two places (e.g. APT and pipx NetExec), the framework reports the duplicate and uses the configured preference. It does not install a third copy.

---

## 9. Reconnaissance design notes (Nmap)

Profiles (`config/profiles.yaml`) parameterise every stage. Nothing is hardcoded in modules.

| Stage | Module | Conservative | Standard | Comprehensive |
|-------|--------|--------------|----------|---------------|
| Host discovery | `recon.host_discovery` | `-sn` default probes | `-sn` + TCP ping 22,80,443,445 | + `-PE -PP` |
| TCP ports | `recon.tcp_ports` | top 1000, `-T3` | all ports `-p-`, `-T4 --min-rate 1000` (configurable) | all ports, `--max-retries 2` |
| Service ID | `recon.service_id` | `-sV` on open ports | `-sV -sC` on open ports | `-sV -sC -O --version-all` |
| UDP | `recon.udp` | disabled | top 20 | top 100, separate timing |
| Web probe | `recon.web_probe` | HTTP(S) basics | + TLS details | + vhost probing for known hostnames |

- Always `-oA <base>` plus `--stats-every`, and XML parsed with `xml.etree.ElementTree` (stdlib; modern expat mitigates entity-expansion attacks, and the XML is produced locally).
- Validation: XML well-formed, `<runstats><finished exit="success">` present. If not, the scan is recorded as **incomplete** with a limitation note.
- Single-host targets skip host discovery by default (`-Pn` for the port stage), because HTB hosts often drop ICMP. The choice is recorded.
- `open|filtered` UDP results are stored as such and reported as uncertain, never as open.

---

## 10. Implementation challenges

| Challenge | Mitigation |
|-----------|------------|
| Root needed for SYN/UDP/OS scans | Opt-in `sudo -n` with approval, `-sT` fallback, limitation recorded (decision §11). |
| Long all-port and UDP scans vs timeouts | Generous per-profile timeouts, `--stats-every` progress parsing for the heartbeat, `nmap --resume` for interrupted scans. |
| Tool output formats change between versions | Prefer machine formats (nmap XML, `whatweb --log-json`, `enum4linux-ng -oJ`, `ssh-audit -j`, `nikto -Format json`, `feroxbuster --json`). Parsers are versioned, and fixture tests are pinned to captured real output. |
| NetExec has no stable machine-readable stdout | Parse its line format defensively. Keep the raw output as primary evidence and emit only high-confidence observations. Treat parse failure as non-fatal. |
| EyeWitness headless browser fragility | Health-check browser dependencies, run one instance at a time, accept a missing screenshot as a limitation, and feed it only identified web endpoints. |
| Impacket naming differs (APT vs pip) | Registry lists both name forms. Inventory resolves the actual one. |
| Child-process cleanup | Process groups (`start_new_session=True`) and group kill. |
| SQLite concurrency | WAL, a single writer thread, short transactions, `busy_timeout`. |
| Vhosts / `/etc/hosts` | Pass vhosts per tool. Recommend hosts entries but never auto-edit. |
| Untrusted output in reports | Autoescaped templates, sanitised filenames, no shell=True anywhere. |
| Secrets leaking into logs/reports | Redaction at the runner (argv) and reporting (pattern-based). Protected evidence dir with `0700`. |
| Windows development vs Linux runtime | pathlib, OS-abstracted runner and locks, unit tests runnable on both, integration tests Linux-only. |
| Large outputs | Streaming to disk, configurable caps, never loading huge files into memory for hashing (chunked SHA-256). |

---

## 11. Decisions (resolved 2026-11-25)

Runtime environment: Parrot OS in a VMware virtual machine.

1. **Workspace layout:** engagement-scoped workspaces, `<data>/engagements/<e>/targets/<t>/`, with a `default` engagement.
2. **Nmap privileges:** a one-time, approval-gated `setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip <nmap>` step (Milestone 2, `tools` command). Consequences, handled in M2/M4:
   - Nmap must then be invoked with `--privileged` (or `NMAP_PRIVILEGED=1`) when not root.
   - Any local user can then send raw packets through nmap. That is acceptable on a single-user testing VM, and the trade-off is documented.
   - An `apt upgrade` of nmap drops the capability. The tool health check detects this with `getcap` and the framework falls back to `-sT`, recording a limitation, until it is re-applied.
3. **Python:** follow the project's *Python Version Management on Parrot OS* guide. System Python is never modified (no `sudo pip`). `install.sh` prefers a pyenv-managed 3.11+ interpreter and falls back to Parrot's `python3` (3.11+). Dependencies are installed into a project `.venv` with `.venv/bin/python -m pip`. Python CLI security tools are expected via APT or **pipx** (with `--python` pointing at a pyenv interpreter when needed). Legacy Python 2.7 tools run through their pyenv interpreter; the M2 inventory detects pyenv versions and pipx apps.
4. **Minimum Python:** 3.11. Unit tests run on 3.11 and newer.
5. **Tool registry:** `config/tools.yaml`, with Python code in `aiszx/tools/`. Same layered-override mechanism as every other configuration file.
6. **Data location:** XDG Base Directory layout. Code, data and configuration stay separate:
   - data: `$AISZX_DATA_DIR` → `paths.data_dir` → `$XDG_DATA_HOME/aiszx` → `~/.local/share/aiszx`
   - user config: `$AISZX_CONFIG_DIR` → `$XDG_CONFIG_HOME/aiszx` → `~/.config/aiszx`

   Keeping data on the VM's local disk also avoids SQLite locking problems on VMware shared folders.

Runtime dependencies are introduced when first needed: **PyYAML** in M1, **Jinja2** in M8 (reporting).

---

## 12. Phased development plan

Each milestone ends with: working code, tests passing on Windows and Linux (unit level), README/doc updates, explicit limitations, and a pause for your approval.

| # | Milestone | Deliverables | Key tests |
|---|-----------|--------------|-----------|
| **1** | **Foundation** | `pentest.py`, CLI skeleton (`init`, `engagement add/list`, `target add/list/show/archive`, `scope show/add/check`), layered config loader + validation, identity normalisation, scope engine, workspace generator + repair, SQLite connection + migration 0001, central/target logging. | target registration & dedup, IPv4/IPv6/hostname normalisation, scope include/exclude precedence, workspace isolation, directory creation/repair, migrations idempotent, FK enforcement. |
| **2** | **Tool management** | `config/tools.yaml`, inventory (PATH/dpkg/pipx/go/cargo/git/venv), version parsing + constraints, health checks, `tools inventory/check/missing`, install *plans* + interactive confirmed install. | detection with mocked `which`/`dpkg-query`/`pipx` output, version comparison, missing-dependency reasons, no install without confirmation. |
| **3** | **Orchestrator** | Module ABC, registry discovery, ToolRunner (scope guard, process groups, timeouts, redaction, streaming capture), planner/DAG, executor, state machine, checkpoints, fingerprints, retries, locks, startup reconciliation, `resume` with recovery summary, graceful shutdown. Uses a built-in test module that runs a fake tool, not a placeholder security module. | failed-unit isolation, retry/backoff, timeout kill, interrupted→resume, fingerprint invalidation, stale lock recovery, scope guard refusal. |
| **4** | **Nmap recon** | host discovery, TCP ports, service ID, UDP, nmap XML parser, port/service persistence, classifier + `service_map.yaml`, profiles, `recon` command, `--force`. | XML parsing against fixtures (incl. incomplete scans, `open|filtered`), port extraction, classification, profile → argv building. |
| **5** | **HTTP** | web_probe (stdlib `http.client`/`ssl` for headers, TLS, robots.txt, sitemap), WhatWeb, EyeWitness, feroxbuster/gobuster (`active_noisy`), Nikto (`active_noisy`), web endpoints/resources/technologies, vhost handling. | parser fixtures, endpoint derivation, EyeWitness input file only contains web endpoints. |
| **6** | **Service enumeration** | SMB (NetExec, enum4linux-ng, smbclient, nmap smb scripts), DNS (dig, dnsrecon, AXFR attempt only against in-scope authorised NS), SSH (ssh-audit, nmap), FTP (anonymous check), LDAP/AD (RootDSE, naming contexts, anonymous bind check), MSSQL/MySQL/PostgreSQL metadata, NFS (showmount), SNMP (public-community check only if RoE allows), SMTP, RDP, WinRM. Observations emitted for each. | parser fixtures per tool, observation emission, safety-class gating. |
| **7** | **Assessment** | Rule engine over observations, rule library (SMB signing, anonymous FTP/LDAP/SMB, exposed DB, directory listing, outdated-version hypotheses via offline searchsploit), confidence/severity scoring, fingerprints, attack-surface prioritisation, `assess` command. | rule unit tests, classification correctness (port ≠ vuln), fingerprint stability. |
| **8** | **Reporting & history** | Report data model, Markdown/HTML/JSON renderers (all 15 sections), redaction, evidence index, `history`, `compare --latest`, consolidated target view. | snapshot tests of reports, HTML escaping of hostile banners, diff correctness (new/closed ports, changed versions, new/irreproducible findings). |
| **9** | **Hardening & deployment** | `install.sh` (venv, deps, init, tool check, no silent installs), integration tests with local services (python http.server, a local SSH/FTP/SMB where available), recovery chaos tests (kill -9 mid-run), docs, fresh Parrot validation checklist. | integration suite, kill/resume tests, installer dry-run. |

`full TARGET --profile X` is available from Milestone 4 (recon only) and grows as each stage lands.

---

## 13. Milestone 3 implementation notes (deviations and refinements)

- **Package layout.** The orchestrator lives in `aiszx/orchestrator/` (planner, executor, toolrunner, state, locks, recovery, settings, runlog, fingerprint, procutil) instead of `aiszx/core/`, to keep `core` free of execution logic.
- **Schema.** Migration `0003_orchestrator.sql` adds `modules`, `executions`, `module_executions`, `module_attempts`, `evidence`, `approvals`, `locks` and `execution_logs`.
  - `executions.id` is a UUID; the directory name is in `run_id`.
  - `evidence` has no `service_id` yet; Milestone 4 adds it with `ALTER TABLE` once `services` exists.
  - `module_executions` gains `needs_approval`, `inputs_json`, `outputs_json` (path, SHA-256 and size of the successful attempt) and `summary`.
- **Resume** continues the same run (same `run_id` and directory). Re-runs always use a new `attempt-NN` directory. Completed units are reused only when §7.5's checks pass.
- **Built-in module.** `core.connectivity` (`ip route get` plus `ping`) is a real pre-flight check rather than a placeholder. The tools `ping` and `ip` were added to `config/tools.yaml`.
- **Configuration.**
  - `config/modules.yaml` and `config/profiles.yaml` are layered as shipped, then user, then `<engagement>/overrides.yaml`.
  - Profiles carry only `max_safety` for now; scan parameters arrive with Nmap.
  - Rules of engagement can lower the ceiling: `engagement update --max-safety`.
- **Approvals.** `intrusive` units need an interactive approval or `--approve <module>`; `--yes` never approves them. Every decision is stored in `approvals`.
- **Observations** are written to `parsed/result.json` for now; a database table follows in Milestone 7.
- **CLI.** Milestone 3 adds `run`, `resume`, `history`, `modules list|show` and `engagement update`.

---

## 14. Milestone 4 implementation notes

- **Layered execution.** Modules are grouped by (stage, dependency depth). Each layer is planned only after the previous layers finish, so units can take their inputs from the same run. For example, `recon.service_id` plans with the ports just found. Those ports are part of its input fingerprint, so resume re-runs it only when they change. A module whose in-run dependency did not complete is skipped at planning time. Dependencies may not point to a later stage; this is validated at discovery.
- **Schema.** Migration `0004_recon.sql` adds `discovered_hosts`, `discovered_ports` and `services`, plus `evidence.service_id`. Each row belongs to the module execution that produced it, and a re-run replaces exactly those rows. Services are keyed by `protocol/port` and are not tied to port rows by foreign key, so ownership stays simple.
- **Module interface additions.**
  - `PlanContext` gains `profile_params`, `tool_details`, `upstream` and `services`.
  - `RunContext` gains `attempt_dir`, `profile_params`, `tool_details` and `services`.
  - `ModuleMeta.profile_sections` puts the relevant profile keys into the config fingerprint.
  - `Module.unavailable_reason()` gives plan-time skips with a reason, e.g. UDP without raw sockets.
  - `ModuleResult` gains `hosts`, `ports` and `services`.
- **Classification** happens centrally: an executor post-processing hook applies `config/service_map.yaml` before results are written. A service can have several categories, e.g. WinRM on 5985 is both `http` and `winrm`.
- **Nmap privileges** come from the tool inventory. `capabilities` adds `--privileged`, `root` adds nothing, and anything else adds `--unprivileged`, uses connect scans, skips UDP and OS detection, and records the reason.
- **Resumable TCP scan.** `recon.tcp_ports` copies the interrupted attempt's output into the new attempt, rewrites the `-oA` base inside it, and runs `nmap --resume`. The interrupted attempt is never modified.
- **Range discovery** is an engagement-level run (`executions.target_id` is NULL) under `<engagement>/runs/`.
  - The scope guard now validates CIDR targets address by address (up to /16), together with `Command.exclude`, which holds the scope exclusions passed to nmap.
  - Hosts are registered as targets only on request.
- **Web probe deferral.** The spec's "Stage 5: web service identification" (titles, headers, TLS) moves to Milestone 5 with the HTTP modules. Milestone 4 identifies and classifies web services through Nmap.

---

## 15. Milestone 5 implementation notes

- **Endpoints.** An endpoint is an (`http`/`https` service × host name) pair. Host names are the pinned address, the target's hostname for a hostname target, `--vhost` names (stored as run parameters in the run snapshot so `resume` reuses them) and `options.vhosts`. WinRM is excluded through `skip_categories`.
- **Virtual-host scope.** Connections always go to the pinned in-scope address. `--vhost` names are pinned to that address in the scope guard, so they are evaluated against scope as names served by an in-scope IP. Nothing edits `/etc/hosts`.
- **No in-process networking.** `http.probe` uses curl and `openssl s_client` through the tool runner rather than Python's `http.client`, so every request passes the scope guard and leaves raw evidence.
- **Schema.** Migration `0005_web.sql` adds `web_endpoints`, `web_resources` and `technologies`. Like the recon tables, rows belong to the unit that produced them.
- **Tool working directory.** Tools now run with their working directory set to the attempt's `raw/` folder, so files they drop there (feroxbuster state, geckodriver logs, EyeWitness output) stay with the evidence. Image files are registered as `screenshot` evidence.
- **Folder layout.** Enumeration output goes to `enumeration/<category>/<module name>/<unit>/`, without repeating the family prefix.
- **Observations** from the probe and Nikto stay in `parsed/result.json` until the assessment engine (Milestone 7) consumes them.

---

## 16. Milestone 6 implementation notes

- **Twelve service modules.** `smb.netexec`, `smb.enum4linux_ng`, `smb.smbclient`, `dns.dig`, `ssh.audit`, `ftp.anonymous`, `ldap.rootdse`, `ldap.anonymous`, `nfs.showmount`, `snmp.walk`, `nse.service_info` and `rservices.exposure`. Units are planned per matching service (or per host) from the services known when the layer is planned.
- **No credential use.**
  - Only the standard anonymous, null and guest checks are made, each a single attempt.
  - SNMP requires configured community strings. They are declared through `ModuleMeta.secret_options`, which masks them in run snapshots, and `Command.redact`, which masks them in stored command lines.
  - NSE script lists are validated against a deny pattern (brute, dos, exploit, fuzz, flood, vuln, backdoor, -enum-users).
- **`ModuleMeta.after`** is an ordering-only dependency. The module runs after those modules, if present, and sees their results, but is never skipped because they failed. `dns.dig` uses it to query the AD domain that LDAP or SMB found in the same run. `depends_on` still blocks on failure, e.g. `ldap.anonymous` on `ldap.rootdse`.
- **Re-classification at planning time.** Services loaded for planning are re-classified with the current `service_map.yaml`, so new categories (for example `rservices`) reach existing scan results without re-scanning.
- **`observations TARGET`** aggregates the observations from the latest run that has completed enumeration units. They remain in `parsed/result.json` until Milestone 7 stores them in a table.

---

## 17. Milestone 7 implementation notes

- **Knowledge consolidation.** `aiszx.assessment.knowledge.gather` takes the latest completed result of each (module, unit) across all of a target's runs, plus the latest services, endpoints, resources and technologies. Observations stay in `parsed/result.json`; a separate observations table was not needed, so the extra table proposed in §1.5 D1 was dropped.
- **Rules** are plain functions registered with `@rule("ID")`. A failing rule is recorded as a limitation and doesn't stop the assessment.
- **Fingerprint.** SHA-256 over (rule id, target, service key, location, discriminator). The ID is `F-` plus the first 10 hex characters.
- **Schema.** Migration `0006_findings.sql` adds `findings` (current state per target, with analyst classification and notes) and `assessment_results` (a per-assessment snapshot used by the Milestone 8 comparison).
  - The spec's per-run findings table is realised as these two tables, so a finding's identity is stable across runs.
  - Findings are never deleted; findings that are no longer produced get `status = not_reproduced`.
- **Assessments are runs** (`command = 'assess'`, no units) whose output files are registered as evidence. `resume` ignores them, and `recon --force` checks only look at `recon`/`full` runs.
- **Exploit-DB.** searchsploit is run locally through the plain process runner (it makes no network or target contact) with product + major.minor terms. Results are always `unverified_hypothesis` with low confidence.

---

## 18. Milestone 8 implementation notes

- **Report model.** `aiszx.reporting.builder.ReportBuilder` assembles one JSON-serialisable dict with the 15 sections. It uses the same consolidated knowledge as assessment, plus:
  - the latest port scan per protocol;
  - the latest service identification and web run;
  - all findings, grouped by effective classification (analyst decision first).

  Renderers only format the model. The JSON report *is* the model.
- **Evidence paths** in the model are relative to the target directory. Renderers turn them into links relative to the output directory, so the same model is rendered both into `runs/<run>/reports/` and into `consolidated/`. Per-finding and per-module evidence lists omit empty files and command logs. The evidence index lists everything.
- **Redaction** (`aiszx.reporting.redact`) runs on the whole model before rendering:
  - key-based for structured data, with cookie names kept;
  - pattern-based for free text;
  - literal masking for configured `secret_options` values.

  Only the count is reported. The module lives under `reporting/`, not `evidence/` as proposed in §3.1, because nothing else uses it yet.
- **Escaping.**
  - HTML: Jinja2 autoescape and a restrictive CSP meta tag. Only evidence paths become links (percent-encoded, relative, no `..`, no scheme).
  - Markdown: a `finalize` hook escapes every interpolated value. The `Raw` type marks already-formatted output (links, code spans, macro output).
- **Reports are runs** (`command='report'`), like assessments. Files are registered as evidence of kind `report`. `resume` and `recon --force` ignore them.
- **Comparison** (`aiszx.reporting.compare`) is per category, because different commands produce different data. Port protocols are compared only when both runs completed the scanning module. Technologies and resources are compared only when both runs ran whatever produces them. Findings are compared through `assessment_results` snapshots. Results are saved to `<target>/history/`.
- **Configuration.** `config/reporting.yaml` is layered like modules/profiles (shipped → user → engagement `overrides.yaml` key `reporting:`).
- **Dependency.** Jinja2 is imported lazily, so other commands keep working until `install.sh` has installed it. `report` explains what to run if it is missing.
