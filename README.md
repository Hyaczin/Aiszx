# Aiszx

A modular reconnaissance, enumeration and assessment framework for **authorised** penetration testing, HTB Academy and lab work on Parrot Security OS.

Aiszx assists a human tester. It automates the repetitive parts: target and scope bookkeeping, workspaces, reconnaissance, service enumeration, evidence handling and reporting. It never runs exploitation, credential attacks or destructive actions on its own.

> **Status: Milestone 3 (Orchestrator) complete.** You can manage engagements, scope, targets and workspaces; inventory, check and install tools; and run modules with checkpoints, retries, crash recovery and resume. The only module so far is the built-in `core.connectivity` reachability check. Reconnaissance, enumeration, assessment and reporting arrive in later milestones (see [Roadmap](#roadmap)). The design is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Tool management is described in [docs/TOOLS.md](docs/TOOLS.md), and writing modules in [docs/MODULE_DEVELOPMENT.md](docs/MODULE_DEVELOPMENT.md).

---

## Requirements

- Parrot Security OS (Debian-based; tested target: Parrot 6.x in a VMware VM)
- Python **3.11+**, either Parrot's `python3` or a pyenv-managed interpreter
- The `python3-venv` package if you use Parrot's system Python (`sudo apt install python3-venv`)

Runtime Python dependency: **PyYAML** only. Everything else uses the standard library.

## Installation

```bash
git clone <your-repo-url> Aiszx     # or copy the folder into the VM
cd Aiszx
bash install.sh                      # add --dev to also install pytest
```

`install.sh` follows the Python isolation rules of the *Python Version Management on Parrot OS* guide:

| Rule | How |
|------|-----|
| Never modify system Python | no `sudo`, no `pip` outside the project venv; refuses to run as root |
| Choose the interpreter deliberately | `$AISZX_PYTHON`, else the newest pyenv-managed **3.11+**, else Parrot's `python3` (3.11+) |
| Isolate project dependencies | creates `./.venv` and installs with `.venv/bin/python -m pip install -r requirements.txt` |
| No silent OS changes | missing OS packages (e.g. `python3-venv`) are reported with the command to run; apt is never called |

Options:

- `--dev`: install test dependencies.
- `--recreate`: rebuild `.venv`, for example after switching interpreter.
- `--system-site-packages`: reuse APT's `python3-yaml`, for an offline install.

You don't need to activate the venv. `python3 pentest.py …` re-executes itself inside `./.venv` automatically. Set `AISZX_NO_VENV_REEXEC=1` to disable this.

To pin a pyenv interpreter explicitly:

```bash
AISZX_PYTHON=~/.pyenv/versions/3.11.11/bin/python bash install.sh --recreate
```

### VMware notes
- Keep the **data directory on the VM's local disk** (the default `~/.local/share/aiszx` is). SQLite locking is unreliable on VMware shared folders (`/mnt/hgfs`), and `init` warns if WAL mode is unavailable.
- If you edit the code on the host and share it into the VM, that's fine for the code. Create `.venv` from inside the VM.

## Where things live

| What | Default location | Override |
|------|------------------|----------|
| Code | this repository | — |
| Shipped defaults | `config/framework.yaml`, `config/tools.yaml` | — (don't edit; override instead) |
| Your overrides | `~/.config/aiszx/framework.yaml`, `~/.config/aiszx/tools.yaml` | `--config-dir`, `$AISZX_CONFIG_DIR`, `$XDG_CONFIG_HOME` |
| Data (DB, logs, workspaces) | `~/.local/share/aiszx/` | `--data-dir`, `$AISZX_DATA_DIR`, `paths.data_dir`, `$XDG_DATA_HOME` |

Precedence, highest first: CLI flag → environment variable → user config → XDG default.

```
~/.local/share/aiszx/
├── aiszx.db                         # SQLite: engagements, scope, targets, audit trail
├── logs/aiszx.log                   # central JSON-lines log (rotated)
└── engagements/<engagement>/
    ├── engagement.yaml  scope.yaml  # human-readable mirrors of the database
    ├── runs/                        # range-level runs (later milestones)
    └── targets/<target>/
        ├── target.yaml
        ├── history/ runs/ consolidated/ logs/target.log
        └── runs/<YYYY-MM-DD_HHMMSS>/  scope/ reconnaissance/ enumeration/{http,smb,...}/
                                       evidence/{screenshots,supporting,protected}/ findings/
                                       assessment/ logs/ reports/
```

The mirrors (`*.yaml` under engagements) are regenerated from the database. Edits to them are not read back. Use the CLI, or `scope import` for scope files.

## Configuration

See what's in effect, and check that it's valid:

```bash
python3 pentest.py config show
```

Override only what you need. Copy [config/templates/framework.user.example.yaml](config/templates/framework.user.example.yaml) to `~/.config/aiszx/framework.yaml`. Mappings merge and lists replace. Unknown keys and wrong types are errors, so typos don't fail silently.

Key settings:

| Key | Default | Meaning |
|-----|---------|---------|
| `engagements.default_slug` | `default` | engagement used when `-e` is not given |
| `scope.resolve_hostnames` | `true` | resolve hostname targets at registration (system resolver, honours `/etc/hosts`) |
| `scope.strict_hostname_resolution` | `true` | a hostname is in scope only if **every** resolved address is covered by an IP/CIDR include rule |
| `workspace.*` | see file | directory layout and permissions (`evidence/protected` is `0700`) |
| `logging.*` | INFO to file, WARNING to console | `-v`, `-vv` and `-q` adjust the console |

## Usage

Global options work before or after the command: `--data-dir`, `--config-dir`, `-e/--engagement`, `-v`, `-q`, `-y/--yes`.

### First run

```bash
python3 pentest.py init
```
```
Aiszx 0.1.0 initialised
  data directory : /home/user/.local/share/aiszx
  database       : /home/user/.local/share/aiszx/aiszx.db — schema v1 (applied 0001_foundation)
  journal mode   : wal
  configuration  : /home/user/Aiszx/config/framework.yaml
  user overrides : /home/user/.config/aiszx/framework.yaml (not present)
  engagement     : default (created)
  workspaces     : 0 target(s) checked, 0 director(y/ies) repaired

Next: define scope, e.g. `python3 pentest.py scope add 10.10.10.0/24`, then `target add <ip>`.
```

`init` is idempotent. Re-run it after upgrading Aiszx: it migrates the database (backing it up first) and recreates any missing workspace directories.

### Engagements

An engagement groups scope and targets. IPs are reused across HTB labs, so the same IP in two engagements gets two separate workspaces.

```bash
python3 pentest.py engagement add htb-academy --name "HTB Academy CPTS" \
    --auth-ref "HTB Academy lab" --valid-until 2026-12-31 \
    --scope-file config/templates/scope.example.yaml
python3 pentest.py engagement list
python3 pentest.py engagement show htb-academy
```

### Scope

Nothing is in scope until you add include rules. Exclusions always win.

```bash
python3 pentest.py scope add 10.10.10.0/24 --note "HTB lab"
python3 pentest.py scope add 10.10.10.1 --exclude --note "gateway"
python3 pentest.py scope add '*.inlanefreight.htb'     # subdomains only
python3 pentest.py scope show
python3 pentest.py scope check 10.10.10.9             # exit 0 = in scope, 3 = out
python3 pentest.py scope import scope.yaml [--replace]
python3 pentest.py scope remove 10.10.10.1 --exclude
```
```
$ python3 pentest.py scope show
Scope for engagement 'default'
  validity            : active
  valid from          : -
  valid until         : -
  hostname resolution : strict
ACTION   TYPE  VALUE          NOTE
-------  ----  -------------  -------
include  cidr  10.10.10.0/24  HTB lab
exclude  ip    10.10.10.1
```
If a scope change leaves a registered target out of scope, you get a warning. Every scope change is written to the audit trail.

### Targets

```bash
python3 pentest.py target add 10.10.10.5
python3 pentest.py target add app.inlanefreight.htb     # resolved now; addresses recorded with timestamps
python3 pentest.py target add 10.129.2.15 --scope       # also adds an include rule for exactly this IP
python3 pentest.py target list [--all] [--json]
python3 pentest.py target show 10.10.10.5 [--json]
python3 pentest.py scope show 10.10.10.5                 # scope decision with reasons
python3 pentest.py target remove 10.10.10.5             # archive (workspace kept; `target add` reactivates)
python3 pentest.py target remove 10.10.10.5 --purge     # irreversible; asks you to type the target
```
```
$ python3 pentest.py target add 10.10.10.5
Registered 10.10.10.5 in engagement 'default'
  kind      : ipv4
  workspace : /home/user/.local/share/aiszx/engagements/default/targets/10.10.10.5
  10.10.10.5: IN SCOPE
    reason : included by include cidr 10.10.10.0/24

$ python3 pentest.py target add 10.10.10.1
error: 10.10.10.1 is out of scope for engagement 'default':
  - excluded by exclude ip 10.10.10.1
add a covering rule with `scope add <ip|cidr|hostname>`, or rerun with --scope to include exactly this target
```

Target identities are normalised, so `DC01.Corp.Local.` and `dc01.corp.local` are the same target. IPv6 is compressed, and IPv4-mapped IPv6 becomes IPv4. CIDRs, URLs and `host:port` are rejected with a hint.

### Tools

```bash
python3 pentest.py tools inventory          # what is installed, versions, sources (apt/pipx/go/git/venv)
python3 pentest.py tools check              # health + readiness of each capability (exit 1 if broken/outdated)
python3 pentest.py tools missing            # why each tool is missing, what needs it, how to install it
python3 pentest.py tools install whatweb    # shows the command, asks before running it
python3 pentest.py tools nmap-caps --apply  # one-time: lets nmap do SYN/UDP/OS scans without root
```
See [docs/TOOLS.md](docs/TOOLS.md) for detection rules, the install policy, the nmap capability trade-offs and how to add your own tools (including pyenv Python 2.7 tools).

### Running modules, history and resume

```bash
python3 pentest.py modules list                                  # available modules, safety class, tools
python3 pentest.py -e htb-box-reset run 10.129.73.247 -m core.connectivity
python3 pentest.py -e htb-box-reset history 10.129.73.247        # all runs of the target
python3 pentest.py -e htb-box-reset history 10.129.73.247 --run 2026-11-25_160000
python3 pentest.py -e htb-box-reset resume 10.129.73.247         # continue the last run
```
```
$ python3 pentest.py -e htb-box-reset run 10.129.73.247 -m core.connectivity
Run 2026-11-25_160000: 10.129.73.247 (engagement htb-box-reset, profile standard)
  address   : 10.129.73.247
  workspace : /home/user/.local/share/aiszx/engagements/htb-box-reset/targets/10.129.73.247/runs/2026-11-25_160000
  MODULE             UNIT  SAFETY       ACTION  NOTE
  -----------------  ----  -----------  ------  ----
  core.connectivity  host  active_safe  run

[ ok ] core.connectivity [host] (1.2s): route via tun0 (src 10.10.14.5); ICMP 2/2 replies, avg 26.05 ms

Run 2026-11-25_160000: COMPLETED (1 completed)
```

What happens on every run:
- **Preflight.** The engagement must be inside its validity window. The target is re-resolved and re-checked against scope, and the address used is pinned and recorded in `<run>/scope/scope.json`.
- **Plan.** Each module is checked against the safety ceiling (profile `max_safety`, lowered by `engagement update --max-safety`) and against its required tools. Anything that can't run is **skipped with the reason shown**. `intrusive` modules need explicit approval every run: an interactive prompt, or `--approve MODULE`. `--yes` deliberately does **not** approve them.
- **Execute.**
  - Every command is checked against scope immediately before it starts.
  - Output streams to `attempt-NN/raw/`.
  - Timeouts kill the whole process tree.
  - Transient errors (e.g. "Network is unreachable") are retried with backoff.
  - A failed module doesn't stop unrelated ones; only modules that depend on it are skipped.
- **Checkpoint and evidence.** Unit states are stored in SQLite as they change. Every output file (failed attempts included) is hashed and registered as evidence, and `<run>/manifest.json` is updated.
- **Ctrl+C.** The first press stops running tools, keeps partial output and marks the run `INTERRUPTED`. A second press forces an exit.

`resume` verifies every completed unit before reusing it: files present, SHA-256 unchanged, same inputs, options and module version. It shows what it will reuse or re-run and asks first. Runs whose process died (crash, reboot, killed terminal) are detected automatically and marked `INTERRUPTED`. Nothing is ever overwritten: re-runs go to a new `attempt-NN` directory.

Profiles: `conservative` (up to `active_safe`), `standard` (default, up to `active_noisy`) and `comprehensive` (up to `intrusive`, still with approval). They are defined in `config/profiles.yaml`. Module options go in `config/modules.yaml`, or in `~/.config/aiszx/modules.yaml`, or per engagement in `<data>/engagements/<e>/overrides.yaml`.

### Workspaces

```bash
python3 pentest.py workspace verify [TARGET] [--repair]
```
`--repair` recreates missing directories and tightens protected-directory permissions. It never modifies or deletes files.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | success |
| 1 | general error / cancelled / not initialised |
| 2 | invalid input or configuration |
| 3 | out of scope |
| 4 | not found |
| 5 | database problem (e.g. schema needs `init`) |
| 6 | workspace problem |

## Differences from the original specification (by design)

- Workspaces are grouped by engagement: `engagements/<e>/targets/<t>/`, not a global `targets/<t>/` (see ARCHITECTURE §1.2 W1).
- Runtime data lives in `~/.local/share/aiszx`, not inside the repository.
- The tool registry is `config/tools.yaml` (overridable like every other config file), with code in `aiszx/tools/`.
- `tools nmap-caps` is an extra command for the one-time nmap capability setup.
- `run TARGET -m MODULE` is the generic way to run modules. `recon`, `enumerate` and `full` will be shortcuts over it from Milestone 4.
- `history TARGET` currently lists runs and their details; run-to-run comparison (`compare`) arrives in Milestone 8.
- Commands not yet implemented (`recon`, `enumerate`, `assess`, `report`, `full`, `compare`) are **not registered**. They appear in the CLI in their milestones rather than as placeholders.

## Development

```bash
bash install.sh --dev
.venv/bin/python -m pytest            # unit tests; no network, no external targets
```
Unit tests use temporary directories and a fake DNS resolver. They run on Linux and Windows on Python 3.11+.

Project layout:

```
pentest.py            entry point (re-execs into .venv)
aiszx/app.py          composition root (config → DB → services)
aiszx/cli/            argparse CLI; one module per command group
aiszx/core/           config, logging, errors, time/ids/fs helpers, audit trail
aiszx/db/             SQLite connection, migrations (aiszx/db/migrations/NNNN_*.sql)
aiszx/targets/        identity, scope rules, engagements, target manager, workspace layout
aiszx/tools/          tool registry, inventory/probes, health checks, capabilities, installer, nmap caps
aiszx/modules/        module interface (base.py), discovery (registry.py), built-in modules (core/)
aiszx/orchestrator/   planner, executor, tool runner + scope guard, state, locks, recovery/resume, settings
config/               shipped defaults (framework, tools, modules, profiles) + templates
tests/unit/           pytest suite
docs/ARCHITECTURE.md  design, schema, module interface, recovery strategy, roadmap
```

## Roadmap

| # | Milestone | Status |
|---|-----------|--------|
| 1 | Foundation: CLI, engagements, scope, targets, workspaces, SQLite, logging | **done** |
| 2 | Tool management: Parrot tool inventory (APT/dpkg/PATH/pipx/pyenv/go/git), versions, health checks, install plans, nmap `setcap` step | **done** |
| 3 | Orchestrator: module interface, execution states, checkpoints, retries, resume, locks | **done** |
| 4 | Nmap reconnaissance: host discovery, TCP/UDP, service ID, XML parsing | next |
| 5 | HTTP: web probe, WhatWeb, EyeWitness, content discovery | |
| 6 | Service enumeration: SMB, DNS, SSH, FTP, LDAP/AD, databases, others | |
| 7 | Assessment: findings, correlation, confidence, investigation paths | |
| 8 | Reporting and history: Markdown/HTML/JSON, run comparison | |
| 9 | Hardening and deployment | |

## Upgrading an existing installation

After pulling a new version, run `python3 pentest.py init`. It applies new database migrations (Milestone 2 adds schema v2) after backing up the database. Until you do, other commands stop and tell you to run it.

## Current limitations (Milestone 3)

- The only module is `core.connectivity`. Port scanning and service enumeration modules arrive in Milestones 4 to 6.
- Module observations are stored in each unit's `parsed/result.json`. They move into a database table when the assessment engine needs them (Milestone 7).
- The engagement validity window and per-command scope are enforced at run time. Scope rules are not yet applied to CIDR-range discovery runs (Milestone 4).
- Resource usage is recorded as duration per command. CPU and memory per tool are not measured.
- On a forced exit (second Ctrl+C or a killed terminal) the units that were running are marked `INTERRUPTED` on the next start. Their partial raw output is always kept.
- POSIX permission checks are skipped when running on Windows (development only).
