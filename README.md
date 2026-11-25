# Aiszx

A modular reconnaissance, enumeration and assessment framework for **authorised** penetration testing, HTB Academy and lab work on Parrot Security OS.

Aiszx assists a human tester. It automates the repetitive parts: target and scope bookkeeping, workspaces, reconnaissance, service enumeration, evidence handling and reporting. It never runs exploitation, credential attacks or destructive actions on its own.

> **Status: Milestone 6 (service enumeration) complete.** Aiszx does reconnaissance with Nmap, then enumerates web, SMB, DNS, SSH, FTP, LDAP/AD, NFS, SNMP and r-services, plus MSSQL, MySQL, RDP, SMTP and VNC through information-only NSE scripts. It never guesses credentials or exploits anything. Everything runs on top of engagements, scope, workspaces, tool management and the orchestrator (checkpoints, retries, crash recovery and resume).

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

### Reconnaissance

```bash
python3 pentest.py -e htb-box-reset recon 10.129.73.247                    # standard profile
python3 pentest.py -e htb-box-reset recon 10.129.73.247 --profile comprehensive
python3 pentest.py -e htb-box-reset services 10.129.73.247                 # ports, versions, categories, NSE
python3 pentest.py -e htb-lab discover 10.10.10.0/24 --register            # live hosts in an in-scope range
```

`recon` runs, in one run directory:

| Stage | Module | What it does |
|-------|--------|--------------|
| preflight | `core.connectivity` | Route lookup (which interface, e.g. `tun0`) and ping. |
| recon | `recon.host_discovery` | `nmap -sn` with the profile's probes. Informational only: port scans always use `-Pn`, because HTB and Windows hosts often drop ICMP. |
| recon | `recon.tcp_ports` | All TCP ports by default: a SYN scan with raw sockets, or a connect scan without. **Resumable:** an interrupted scan continues with `nmap --resume` in a new attempt directory. |
| recon | `recon.udp` | The top-N UDP ports, set by the profile. `open\|filtered` results are kept as *uncertain* and never counted as open. Needs raw sockets. |
| recon | `recon.service_id` | `-sV` on the open TCP ports just found, plus `-sC` and optionally `-O` per profile. |

Scan parameters come from the profile, never from code:

| Profile | TCP | Scripts | Version | OS detection | UDP | Timing |
|---------|-----|---------|---------|--------------|-----|--------|
| `conservative` | top 1000 | no | default | no | none | `-T3` |
| `standard` (default) | all | `-sC` | default | no | top 20 | `-T4 --min-rate 1000` |
| `comprehensive` | all | `-sC` | `--version-all` | `-O` | top 100 | `-T4 --min-rate 1000` |

Customise profiles in `~/.config/aiszx/profiles.yaml`, or per engagement in `overrides.yaml`. Discovery probes are limited to `-P…` flags. If nmap has its capabilities (`tools nmap-caps --apply`), Aiszx adds `--privileged` automatically. Without them it falls back to connect scans, skips UDP and OS detection, and records why.

All of Nmap's XML, normal and grepable output is kept as evidence in the attempt's `raw/` folder. The XML is parsed incrementally, so if a scan was cut off, the hosts it had already finished are kept and the scan is flagged as incomplete. Every service is classified (http, https, smb, ldap, kerberos, winrm, mssql and so on) using [config/service_map.yaml](config/service_map.yaml), which the enumeration modules will use from Milestone 5. If the last recon of a target was interrupted, partial or failed, `recon` points you to `resume` (use `--force` to start fresh).

```
$ python3 pentest.py -e htb-box-reset services 10.129.73.247
Services of 10.129.73.247 (run 2026-11-25_160000)
  OS guess : Linux 5.0 - 5.14 (95%)
PORT      STATE  SERVICE       VERSION                                   CATEGORY
--------  -----  ------------  ----------------------------------------  -----------
tcp/22    open   ssh           OpenSSH 8.9p1 Ubuntu (Ubuntu Linux; ...)  ssh
tcp/80    open   http          nginx 1.18.0 (Ubuntu)                     http
tcp/5985  open   http          Microsoft HTTPAPI httpd 2.0               http, winrm
udp/53    open   domain        ISC BIND 9.18.18                          dns

Uncertain (UDP open|filtered: no reply, could be open or filtered): 161/udp
```

`discover <cidr>` (an engagement-level run):
- The whole range must be inside scope. Scope exclusions are passed to nmap as `--exclude`, and the tool runner verifies the combination before nmap starts. Ranges larger than a /16 are refused.
- Live hosts are only listed. `--register` asks before adding each one as a target, and nothing else is scanned.
- `discover --list` shows previous discovery runs.

### Web enumeration

```bash
python3 pentest.py -e htb-box-reset enumerate 10.129.73.247                    # all enumeration modules
python3 pentest.py -e htb-box-reset enumerate 10.129.73.247 -m http.probe -m http.whatweb
python3 pentest.py -e htb-box-reset enumerate 10.129.73.247 --vhost box.htb    # also present a virtual host
python3 pentest.py -e htb-box-reset web 10.129.73.247                          # results
python3 pentest.py -e htb-box-reset full 10.129.73.247 --vhost box.htb         # recon + enumeration in one run
```

`enumerate` plans from the services found by the latest `recon`. `full` plans from the services found earlier in the same run. Every web service (category `http`/`https`, excluding WinRM) becomes an endpoint for each host name: the IP, the target's hostname if it was registered by name, and each `--vhost`.

| Module | Safety | What it does |
|--------|--------|--------------|
| `http.probe` | active_safe | Uses curl to collect the status, title, server and headers, Set-Cookie flags, redirects, robots.txt and sitemap.xml entries. Adds `openssl s_client` TLS details plus the certificate SANs from nmap's `ssl-cert` script. |
| `http.whatweb` | active_safe | Technology fingerprinting; the aggression level is an option. |
| `http.screenshots` | active_safe | EyeWitness screenshots, using only the URLs of identified web services, plus a report. |
| `http.content_discovery` | active_noisy | feroxbuster, or gobuster if that's what is installed. Bounded by wordlist, time limit, threads and recursion depth. |
| `http.nikto` | active_noisy | Nikto checks. Its items are unverified indicators. |

`conservative` skips the noisy modules; `standard` and `comprehensive` run them.

**Virtual hosts.** Aiszx always connects to the target's pinned in-scope IP. A virtual host name is only sent as the `Host` header and TLS server name (`curl --resolve`, `-H Host:`, `nikto -vhost`), so `/etc/hosts` is never edited. Host names that appear in redirects or certificate SANs are listed as **hints**; they are not tested until you pass them with `--vhost`. EyeWitness can't set a `Host` header, so screenshots cover the IP and a hostname target, and `--vhost` names are skipped (recorded as a limitation).

The probe also records **observations** for the assessment stage (Milestone 7): missing security headers, cookies without HttpOnly, Secure or SameSite, server version disclosure, X-Powered-By, login forms, directory listings, redirects and host name hints. `web TARGET` shows endpoints, technologies, discovered paths, observations, hints and where the EyeWitness report is.

Module options (wordlists, time limits, threads, extensions, aggression) are documented in [config/modules.yaml](config/modules.yaml). Override them in `~/.config/aiszx/modules.yaml` or per engagement in `overrides.yaml`.

### Service enumeration

```bash
python3 pentest.py -e lab enumerate 10.10.10.5                 # every applicable module
python3 pentest.py -e lab enumerate 10.10.10.5 -m smb -m ldap  # by family (or exact module id)
python3 pentest.py -e lab observations 10.10.10.5              # what the modules observed
```

Modules are planned from the services that recon identified. A module without a matching service plans no work.

| Module | Service | What it does (no credentials, no brute force) |
|--------|---------|-----------------------------------------------|
| `smb.netexec` | SMB | OS, host and domain name, signing, SMBv1. One null-session and one guest attempt to list shares. |
| `smb.enum4linux_ng` | SMB | `enum4linux-ng -A`: sessions, dialects, domain/OS info, and the shares, users and policy a null session reveals. No RID cycling. |
| `smb.smbclient` | SMB | Anonymous share list. |
| `dns.dig` | DNS | Server version, reverse lookup, SOA/NS/MX/TXT and a zone-transfer check. It queries domains from the options, the target hostname, `--vhost` names and **domains found by LDAP/SMB in the same run**. |
| `ssh.audit` | SSH | Banner, algorithms and host keys; algorithms ssh-audit flags as weak. |
| `ftp.anonymous` | FTP | Banner and the standard anonymous-login check; root listing if allowed. |
| `ldap.rootdse` | LDAP | RootDSE: naming contexts, domain, DNS host name, functional levels, DC identification. |
| `ldap.anonymous` | LDAP | Anonymous read of the default naming context: a bounded query (size limit 100) planned from RootDSE. |
| `nfs.showmount` | NFS | Exports and allowed clients. Nothing is mounted. |
| `snmp.walk` | SNMP | System MIB, **only with community strings you configure** (never guessed; masked in stored records). |
| `nse.service_info` | MSSQL, MySQL, RDP, SMTP, NFS, SMB, FTP, VNC | Information-only NSE scripts per service. Script names that suggest brute force, DoS, exploitation, fuzzing or vulnerability checks are refused. |
| `rservices.exposure` | rexec/rlogin/rsh | Passive: records the exposure for manual review. No login attempts. |

`observations TARGET` lists everything recorded, for example null sessions, signing not required, readable shares, allowed zone transfers, anonymous LDAP read, world-mountable NFS exports, weak SSH algorithms and anonymous FTP. These are unverified observations; the assessment stage (Milestone 7) turns them into findings with severity and confidence. Module options are documented in [config/modules.yaml](config/modules.yaml).

### Running modules, history and resume

```bash
python3 pentest.py modules list                                  # available modules, safety class, tools
python3 pentest.py -e htb-box-reset run 10.129.73.247 -m recon.tcp_ports -m recon.service_id
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
- `run TARGET -m MODULE` is the generic way to run modules. `recon`, `enumerate` and `full` are shortcuts over it.
- `full` runs reconnaissance and then enumeration in one run; assessment and reporting join in Milestones 7 and 8.
- `services TARGET`, `web TARGET`, `observations TARGET` and `discover CIDR` are additional commands.
- `history TARGET` currently lists runs and their details; run-to-run comparison (`compare`) arrives in Milestone 8.
- Commands not yet implemented (`assess`, `report`, `compare`) are **not registered**. They appear in the CLI in their milestones rather than as placeholders.

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
aiszx/modules/recon/  nmap modules: host_discovery, tcp_ports, service_id, udp
aiszx/modules/http/   web modules: probe, whatweb, screenshots, content_discovery, nikto
aiszx/modules/{smb,dns,ssh,ftp,ldap,nfs,snmp,nse,rservices}/   service enumeration modules
aiszx/parsers/        nmap XML (incremental, truncation-tolerant) + grepable fallback
aiszx/classify/       service → category classification
aiszx/recon/          nmap command construction, host/port/service store, range discovery
config/               shipped defaults (framework, tools, modules, profiles, service_map) + templates
tests/unit/           pytest suite
docs/ARCHITECTURE.md  design, schema, module interface, recovery strategy, roadmap
```

## Roadmap

| # | Milestone | Status |
|---|-----------|--------|
| 1 | Foundation: CLI, engagements, scope, targets, workspaces, SQLite, logging | **done** |
| 2 | Tool management: Parrot tool inventory (APT/dpkg/PATH/pipx/pyenv/go/git), versions, health checks, install plans, nmap `setcap` step | **done** |
| 3 | Orchestrator: module interface, execution states, checkpoints, retries, resume, locks | **done** |
| 4 | Nmap reconnaissance: host discovery, TCP/UDP, service ID, XML parsing | **done** |
| 5 | HTTP: web probe, WhatWeb, EyeWitness, content discovery | **done** |
| 6 | Service enumeration: SMB, DNS, SSH, FTP, LDAP/AD, databases, others | **done** |
| 7 | Assessment: findings, correlation, confidence, investigation paths | next |
| 8 | Reporting and history: Markdown/HTML/JSON, run comparison | |
| 9 | Hardening and deployment | |

## Upgrading an existing installation

After pulling a new version, run `python3 pentest.py init`. It applies new database migrations (Milestone 2 adds schema v2) after backing up the database. Until you do, other commands stop and tell you to run it.

## Current limitations (Milestone 6)

- **No authenticated enumeration.** Every module uses no credentials, or the standard anonymous, null or guest check. Supplying credentials for authenticated enumeration is not supported yet.
- **SNMP** needs community strings you were given. Guessing them is out of scope by design.
- **Kerberos, WinRM and RPC** have no dedicated module. RPC and SMB details come from enum4linux-ng; MSSQL, MySQL, RDP, SMTP and VNC metadata comes from information-only NSE scripts.
- **r-services** are documented, not tested; verifying trust relationships requires login attempts.
- Observations are unverified; findings, severity and confidence come in Milestone 7.
- **Screenshots** need EyeWitness's headless browser to work; `--vhost` names can't be screenshotted.
- **Content discovery** is bounded by its wordlist and time limit.
- **UDP** scans only the profile's top-N ports.
- POSIX permission checks are skipped when running on Windows (development only).
