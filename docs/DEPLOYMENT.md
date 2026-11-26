# Deploying Aiszx on Parrot OS

This guide takes a fresh Parrot OS machine (for example a VMware VM) to a validated Aiszx installation. It also covers upgrades, backup and restore, offline use, troubleshooting and removal.

Aiszx never installs operating-system packages or security tools by itself, and never needs `sudo` for its own installation. The single privileged step is optional: granting nmap raw-socket capabilities. It is explained and confirmed before it runs.

## 1. Requirements

| Item | Requirement |
|------|-------------|
| OS | Parrot Security OS (Debian-based); other Debian derivatives work with the same tools |
| Python | 3.11 or newer. Use a pyenv-managed interpreter, or Parrot's `python3` if it is 3.11+ |
| Disk | 2 GiB free for the data directory is comfortable. Content discovery and screenshots can use hundreds of MiB per target. |
| Network | Only for the initial `pip install` and for testing authorised targets |
| Tools | nmap and curl are required for the core workflow. Everything else is optional: modules without their tool are skipped with a reason. |

Keep the data directory (`~/.local/share/aiszx`) on the VM's own disk, not on a VMware shared folder: SQLite locking is unreliable there. `doctor` warns about this.

## 2. Fresh installation checklist

Work through the steps in order. Each one says what you should see; if you see something else, the "If not" column says what to do.

| # | Step | Expected | If not |
|---|------|----------|--------|
| 1 | `git clone https://github.com/Hyaczin/Aiszx.git ~/Aiszx && cd ~/Aiszx` | repository cloned | check network / proxy |
| 2 | `pyenv versions` (optional) | a 3.11+ interpreter is listed | `pyenv install 3.11` (see your Python guide); or use Parrot's `python3` |
| 3 | `bash install.sh --dry-run` | a list of `would run:` lines ending in `dry run complete`; nothing changes | follow the printed message (e.g. `sudo apt install python3-venv`) |
| 4 | `bash install.sh --dev` | `.venv` created, PyYAML, Jinja2 and pytest installed, `Aiszx 1.0.0 initialised`, then a `doctor` summary | read the `[FAIL]` lines; each has a fix |
| 5 | `.venv/bin/python -m pytest -q` | all tests pass (about 300) | report the failing test output |
| 6 | `python3 pentest.py doctor` | no `[FAIL]` lines. `[WARN]` for optional items is fine. | apply the `→` suggestion under each problem |
| 7 | `python3 pentest.py tools missing` | the list of optional tools you might install, each with a recommended method | install what you need. `tools install --interactive` asks before every step. |
| 8 | `python3 pentest.py tools nmap-caps` | current nmap privilege mode | to enable SYN/UDP/OS scans: `tools nmap-caps --apply` (one sudo `setcap`, asks first) |
| 9 | `.venv/bin/python -m pytest -m integration -v` | the local end-to-end test passes. It scans only a web server it starts on 127.0.0.1. | needs nmap and curl; read the assertion message |
| 10 | `python3 pentest.py backup` then `python3 pentest.py backup --verify <archive>` | `OK`, database integrity `ok` | check free space and permissions of `~/.local/share/aiszx-backups` |

Steps 9 and 10 exercise the whole pipeline: recon, enumeration, assessment, report, comparison and backup. After that the installation is validated.

## 3. First engagement (example)

```bash
python3 pentest.py engagement add htb-lab --name "HTB lab" --auth-ref "HTB Academy module X" --valid-until 2026-12-31
python3 pentest.py -e htb-lab scope add 10.129.0.0/16
python3 pentest.py -e htb-lab target add 10.129.73.247
python3 pentest.py -e htb-lab full 10.129.73.247          # recon + enumeration + assessment
python3 pentest.py -e htb-lab report 10.129.73.247
xdg-open ~/.local/share/aiszx/engagements/htb-lab/targets/10.129.73.247/consolidated/report.html
```

Only test systems you are explicitly authorised to test. Scope is enforced at the moment each command runs, but you are responsible for what you put in scope.

## 4. Upgrading

```bash
cd ~/Aiszx
python3 pentest.py backup                 # recommended before upgrades
git pull
bash install.sh                           # reuses .venv; installs new requirements if any
python3 pentest.py init                   # applies database migrations (backs up the DB first)
python3 pentest.py doctor
```

Interrupted runs from before the upgrade can still be resumed with `resume`.

## 5. Backup and restore

`backup` writes `aiszx-backup-<UTC time>.tar.gz` (mode 0600) and a `.sha256` file to `~/.local/share/aiszx-backups/`, or to `--out DIR`. The archive contains:
- a consistent database snapshot;
- all engagement workspaces;
- a `manifest.json`;
- the logs, if you add `--include-logs`.

It contains evidence, so treat it as sensitive and copy it off the VM to protect against losing the disk.

```bash
python3 pentest.py backup --out /media/usb/aiszx
python3 pentest.py backup --verify /media/usb/aiszx/aiszx-backup-20261126T101500Z.tar.gz
```

**Restoring** replaces the whole data directory, so it is a manual step:

```bash
python3 pentest.py backup --verify ARCHIVE                         # 1. check the archive first
mv ~/.local/share/aiszx ~/.local/share/aiszx.before-restore        # 2. keep the current state
mkdir -m 0750 ~/.local/share/aiszx
tar -xzf ARCHIVE -C ~/.local/share/aiszx                           # 3. unpack (aiszx.db, engagements/, manifest.json)
python3 pentest.py init                                            # 4. migrates if the backup is older
python3 pentest.py doctor                                          # 5. verify
```

Delete `~/.local/share/aiszx.before-restore` once you're satisfied.

Separately, `init` keeps automatic `aiszx.db.bak-v<N>-<time>` copies before every schema migration.

## 6. Offline use

After installation, Aiszx needs no internet access. Network traffic comes only from the modules you run against your targets. searchsploit uses its local Exploit-DB copy.

For a fully offline install:
1. Install the APT packages `python3-yaml` and `python3-jinja2`.
2. Run `bash install.sh --system-site-packages`. The venv then uses those packages and pip is skipped.

## 7. Troubleshooting

| Symptom / doctor message | Meaning | Fix |
|--------------------------|---------|-----|
| `Aiszx is not initialised` | no database yet | `python3 pentest.py init` |
| `schema vN, code expects vM` | code updated, database not migrated | `python3 pentest.py init` |
| `jinja2 is missing` | requirements changed since install | `bash install.sh` |
| `not running inside the project .venv` | `.venv` missing or broken | `bash install.sh` (or `--recreate`) |
| `run … was interrupted (process gone)` | Aiszx was killed (crash, Ctrl+C twice, VM reset) | `python3 pentest.py resume TARGET`: completed units are verified and reused, the interrupted ones continue (nmap with `--resume`) |
| `refusing to start a run` (free space) | data disk nearly full | `workspace stats` to see large runs; free space, or adjust `orchestrator.min_free_mb` |
| `nmap will run unprivileged` | no raw-socket capabilities | `tools nmap-caps --apply` (optional) |
| `data directory is on a vmhgfs filesystem` | data on a VMware shared folder | set `paths.data_dir` in `~/.config/aiszx/framework.yaml` to a local directory |
| `integrity: …` not `ok` | database damaged | restore from `backup` or an `aiszx.db.bak-*` copy (section 5) |
| report says `Unreadable result` | a module's `parsed/result.json` is damaged | re-run the module, or `resume` the run |
| `workspace(s) with missing directories` | directories deleted by hand | `workspace verify --repair` (only recreates directories) |

Logs: `~/.local/share/aiszx/logs/aiszx.log` (central, JSON lines), `<target>/logs/target.log`, and `<run>/logs/` per run and module. `-v` or `-vv` shows more on the console.

## 8. Uninstalling

```bash
python3 pentest.py backup --out ~/aiszx-final-backup     # if you want to keep the results
rm -rf ~/Aiszx                                           # code and .venv
rm -rf ~/.local/share/aiszx ~/.config/aiszx              # data and your configuration
# optional: remove nmap capabilities granted earlier
sudo setcap -r "$(readlink -f "$(command -v nmap)")"
```

Nothing else was changed on the system. Tools you installed via `tools install` remain; remove them with apt or pipx as usual.
