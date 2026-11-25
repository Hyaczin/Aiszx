# Tool management

Aiszx doesn't bundle any security tools. It finds the ones already on your Parrot system, records how each was installed and which version it is, checks that it actually runs, and tells you what is missing and why. It only installs something after you confirm.

## Commands

| Command | What it does |
|---------|--------------|
| `tools inventory [TOOL ...] [--json]` | Detect tools: status, version, install source and path. Also lists Python interpreters (pyenv and system). |
| `tools check [--json]` | Same detection, plus the readiness of each **capability** (the groups of upcoming modules). Exit code 1 if any tool is broken or outdated. |
| `tools missing [--json]` | For each missing, broken or outdated tool: why, which capabilities need it, and the recommended install command with alternatives. |
| `tools show TOOL [--json]` | Everything about one tool, including all installations found and the git commit for checkouts. |
| `tools install [TOOL ...] [--dry-run]` | Shows the plan, then asks before each tool. Without a terminal it refuses unless you pass `--yes`. |
| `tools nmap-caps [--apply \| --remove]` | Shows or changes nmap's raw-socket capabilities (the one-time setup). |

Every run is saved to the database (current state) and as a JSON snapshot in `~/.local/share/aiszx/global/tools/` (history). Installs, setcap changes and declined prompts are recorded in the audit trail.

## Status values

| Status | Meaning |
|--------|---------|
| `ok` | Found, runs, and the version is acceptable (or unknown, with a note). |
| `missing` | Not found anywhere Aiszx looks. |
| `broken` | Found but unusable: it can't execute, it hangs, a companion program is missing, its interpreter (e.g. pyenv 2.7) is missing, or the APT package is installed but its binary is gone. |
| `incompatible` | Runs, but is older than the registry's `min_version`. |

## How detection works

1. **Where it looks.** Every binary name is checked on `PATH` (the same as `command -v`) and in `settings.search_dirs`: `~/.local/bin` (pipx), `~/go/bin`, `~/.cargo/bin`, `/usr/local/bin`, `/usr/sbin`, `/sbin`, `/snap/bin`. It also checks `known_paths`, which may contain globs, and `{git_root}` expands to `/opt`, `~/tools` and `~/htb-tools`.
2. **Where it came from.** Each installation is classified, in this order:
   - **pipx**: under a pipx venv (metadata read from `pipx_metadata.json`; pipx itself doesn't need to be installed).
   - **apt**: owned by a Debian package (`dpkg-query -S`; the version comes from `dpkg-query -W`).
   - **go / cargo**: under `~/go/bin` / `$GOPATH/bin` or `~/.cargo/bin`.
   - **git**: inside a git working tree (the commit is read from `.git`).
   - **venv**: inside a Python virtual environment.
   - **path**: anything else.
3. **Which one is used.** If a tool is installed more than once, the copy on your `PATH` wins and the others are listed as a note. Aiszx never installs a second copy of something that already works.
4. **Version and health.** Aiszx runs the registry's `version_cmd` with a 10 s timeout, in parallel. If the version can't be parsed, it falls back to the dpkg or pipx package version. It then checks `health_requires` and `min_version`.
5. **Interpreters.** Python scripts run through their interpreter:
   - `interpreter: "pyenv:2.7"` picks the newest installed pyenv 2.7.x.
   - A non-executable `.py` file defaults to `python3`.
   - This is how older Python 2 tools (installed per your Python guide) are supported without touching system Python.

## Install policy

Methods are tried in each tool's `install_preference` order (default: APT, pipx, Go, git). The first method that is actually available wins.

| Method | Available when | Command |
|--------|----------------|---------|
| APT | `apt-cache policy` shows a candidate | `sudo apt-get install <pkg>` (apt asks again) |
| pipx | `pipx` is installed | `pipx install [--python <pyenv interpreter>] <pkg>` |
| Go | `go` is installed | `go install <module>@latest` |
| git | `git` is installed and the target directory doesn't exist | `git clone --depth 1 <url> ~/tools/<name>`, then **manual** setup you review |

- Outdated tools: `--only-upgrade` for APT, `pipx upgrade` for pipx; others are upgraded manually.
- Broken APT tools: `apt-get install --reinstall`.
- Never `sudo pip`. Never runs third-party install scripts. Prerequisites such as pipx, Go and git are recommended, not installed for you.

## Nmap privileges (one-time setup)

Without root or capabilities, nmap can only run TCP connect scans: no SYN scans, no UDP and no OS detection. Your chosen setup:

```bash
python3 pentest.py tools nmap-caps            # show the current mode
python3 pentest.py tools nmap-caps --apply    # runs: sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip <nmap>
python3 pentest.py tools nmap-caps --remove   # undo
```

Before applying, make sure you understand:
- **Any local user** can then send raw packets through nmap. That is fine on your single-user Parrot VM, but don't do it on shared machines.
- Nmap has to be started with `--privileged` to use the capabilities. The reconnaissance modules (Milestone 4) do this automatically when the mode is `capabilities`.
- **An `apt upgrade` of nmap removes the capabilities.** `tools check` will show `unprivileged` again; just re-run `--apply`.
- `getcap` and `setcap` come from `libcap2-bin` and live in `/usr/sbin`. Aiszx looks there even though it isn't on a normal user's PATH.

## Customising the registry

The shipped registry is [config/tools.yaml](../config/tools.yaml). Override or extend it in `~/.config/aiszx/tools.yaml`. Mappings merge and lists replace. Examples:

```yaml
settings:
  git_roots: [/opt, ~/tools, ~/htb-tools, ~/src]

tools:
  eyewitness:                       # use your own checkout instead of the APT package
    known_paths: ["~/src/EyeWitness/Python/EyeWitness.py"]
  nmap:
    min_version: "7.94"
  gopherus:                         # add a Python 2 tool managed by pyenv
    description: Gopher payload generator
    known_paths: ["~/htb-tools/Gopherus/gopherus.py"]
    interpreter: "pyenv:2.7"
```

Unknown keys, bad regexes, versions that don't parse, and capabilities that reference unknown tools are all reported as configuration errors.

## Capabilities

Capabilities summarise what the upcoming modules will be able to do:

- `ready`: everything is in place.
- `degraded`: it will run, but optional or alternative tools are missing.
- `unavailable`: a required tool is missing or unusable.

In Milestone 3 each module will declare its exact tool requirements, and the orchestrator will skip modules whose tools are unavailable, with the reason recorded.
