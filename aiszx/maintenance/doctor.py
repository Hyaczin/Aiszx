"""``doctor``: read-only health check of an installation.

Every check reports OK, INFO, WARN or FAIL with a concrete next step. Nothing is changed, installed
or repaired: fixes are suggested as commands for the user to run (``workspace verify --repair``,
``tools nmap-caps --apply``, ``resume``, ``bash install.sh`` ...).
"""

from __future__ import annotations

import importlib
import os
import shutil
import stat
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from aiszx import MIN_PYTHON, __version__
from aiszx.core.diskspace import free_mb
from aiszx.core.timeutil import parse_iso, utcnow

OK, INFO, WARN, FAIL = "ok", "info", "warn", "fail"
CORE_TOOLS = {"nmap": FAIL, "curl": WARN}           # missing → this status
SHARED_FOLDER_FS = ("vmhgfs", "fuse.vmhgfs-fuse", "vboxsf", "9p", "cifs", "nfs", "nfs4")
LOG_WARN_BYTES = 1024 ** 3


@dataclass
class Check:
    area: str
    status: str
    message: str
    fix: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _mount_fstype(path: Path) -> str | None:
    """Filesystem type of the mount holding ``path`` (Linux /proc/mounts), or None if unknown."""
    try:
        lines = Path("/proc/mounts").read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    best, fstype = "", None
    target = str(path.resolve())
    for line in lines:
        parts = line.split()
        if len(parts) >= 3:
            mount = parts[1].replace("\\040", " ")
            if (target == mount or target.startswith(mount.rstrip("/") + "/")) and len(mount) > len(best):
                best, fstype = mount, parts[2]
    return fstype


class Doctor:
    def __init__(self, app, *, tools: bool = True) -> None:
        self.app = app
        self.with_tools = tools
        self.checks: list[Check] = []

    def add(self, area: str, status: str, message: str, fix: str | None = None) -> None:
        self.checks.append(Check(area, status, message, fix))

    def run(self) -> list[Check]:
        for fn in (self.python, self.dependencies, self.configuration, self.data_dir, self.disk, self.database,
                   self.runs, self.workspaces, self.logs, self.tools):
            try:
                fn()
            except Exception as exc:  # a broken check must not hide the others
                self.add(fn.__name__, FAIL, f"check crashed: {exc.__class__.__name__}: {exc}")
        return self.checks

    # -- environment -----------------------------------------------------------
    def python(self) -> None:
        v = sys.version_info
        ok = v >= MIN_PYTHON
        self.add("python", OK if ok else FAIL, f"Python {v.major}.{v.minor}.{v.micro} ({sys.executable})",
                 None if ok else f"Python {'.'.join(map(str, MIN_PYTHON))}+ is required: see README (pyenv)")
        in_venv = sys.prefix != getattr(sys, "base_prefix", sys.prefix)
        self.add("python", OK if in_venv else WARN,
                 "running inside a virtual environment" if in_venv else "not running inside the project .venv",
                 None if in_venv else "run `bash install.sh`; pentest.py then switches into .venv automatically")

    def dependencies(self) -> None:
        for module, purpose in (("yaml", "configuration"), ("jinja2", "reports")):
            try:
                mod = importlib.import_module(module)
                self.add("dependencies", OK, f"{module} {getattr(mod, '__version__', '?')} ({purpose})")
            except ImportError:
                self.add("dependencies", FAIL, f"{module} is missing ({purpose} will not work)",
                         "run `bash install.sh` (installs requirements.txt into .venv only)")

    def configuration(self) -> None:
        from aiszx.classify.classifier import Classifier
        from aiszx.orchestrator.settings import load_settings
        from aiszx.reporting.settings import load_report_settings

        cfg = self.app.config
        eng_dir = self.app.layout.engagement_dir(cfg.default_engagement)
        loaders: list[tuple[str, Callable[[], object]]] = [
            ("framework.yaml", lambda: cfg),
            ("tools.yaml", self.app.tool_registry),
            ("modules.yaml / profiles.yaml", lambda: load_settings(user_config_dir=cfg.user_config_dir,
                                                                    engagement_dir=eng_dir)),
            ("service_map.yaml", lambda: Classifier.load(user_config_dir=cfg.user_config_dir)),
            ("reporting.yaml", lambda: load_report_settings(user_config_dir=cfg.user_config_dir,
                                                             engagement_dir=eng_dir)),
            ("module registry", self.app.module_registry),
        ]
        for name, load in loaders:
            try:
                load()
                self.add("configuration", OK, f"{name} valid")
            except Exception as exc:
                self.add("configuration", FAIL, f"{name}: {exc}", "fix the file named in the message "
                         "(`config show` prints the effective framework configuration)")
        try:
            settings = load_settings(user_config_dir=cfg.user_config_dir, engagement_dir=eng_dir)
            settings.profile(cfg.orchestrator.default_profile)
        except Exception as exc:
            self.add("configuration", FAIL, f"orchestrator.default_profile: {exc}")

    # -- storage ---------------------------------------------------------------
    def data_dir(self) -> None:
        d = self.app.config.data_dir
        if not d.is_dir():
            self.add("data", FAIL, f"data directory {d} does not exist", "run `python3 pentest.py init`")
            return
        writable = os.access(d, os.W_OK)
        self.add("data", OK if writable else FAIL, f"data directory {d}" + ("" if writable else " is not writable"),
                 None if writable else "check ownership; never run Aiszx with sudo")
        if os.name == "posix":
            st = d.stat()
            if st.st_uid != os.getuid():
                self.add("data", WARN, f"{d} is owned by uid {st.st_uid}, not you (uid {os.getuid()})",
                         "was Aiszx run with sudo? `sudo chown -R $USER: <data dir>`")
            if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                self.add("data", WARN, f"{d} is group/world-writable ({stat.S_IMODE(st.st_mode):04o})", f"chmod 0750 {d}")
            fstype = _mount_fstype(d)
            if fstype and any(fstype.startswith(x) for x in SHARED_FOLDER_FS):
                self.add("data", WARN, f"data directory is on a {fstype} filesystem (shared/network folder): SQLite "
                         "locking is unreliable there", "set paths.data_dir to a directory on the VM's local disk")

    def disk(self) -> None:
        need = self.app.config.orchestrator.min_free_mb
        free = free_mb(self.app.config.data_dir)
        if need and free < need:
            self.add("disk", FAIL, f"{free:.0f} MiB free; runs are refused below {need} MiB",
                     "free space (`workspace stats` lists the largest runs) or lower orchestrator.min_free_mb")
        elif need and free < 5 * need:
            self.add("disk", WARN, f"{free:.0f} MiB free (runs are refused below {need} MiB)",
                     "content discovery and screenshots can use hundreds of MiB per target")
        else:
            self.add("disk", OK, f"{free / 1024:.1f} GiB free")

    def database(self) -> None:
        from aiszx.db.migrate import latest_version

        path = self.app.config.db_path
        if not path.is_file():
            self.add("database", FAIL, f"{path} does not exist", "run `python3 pentest.py init`")
            return
        db = self.app.db
        version, latest = db.user_version(), latest_version()
        if version < latest:
            self.add("database", FAIL, f"schema v{version}, code expects v{latest}",
                     "run `python3 pentest.py init` (backs up, then migrates)")
        elif version > latest:
            self.add("database", FAIL, f"schema v{version} is newer than this code (v{latest})", "update the code (`git pull`)")
        else:
            self.add("database", OK, f"schema v{version}, {path.stat().st_size / 1024:.0f} KiB")
        result = db.query_one("PRAGMA quick_check")[0]
        self.add("database", OK if result == "ok" else FAIL, f"integrity: {result}",
                 None if result == "ok" else "restore from a backup (`backup` / DEPLOYMENT.md) or the automatic "
                                             "aiszx.db.bak-* files; keep the damaged file for analysis")
        fk = db.query("PRAGMA foreign_key_check")
        if fk:
            self.add("database", WARN, f"{len(fk)} row(s) violate foreign keys", "report this; do not edit the DB by hand")
        mode = db.query_one("PRAGMA journal_mode")[0]
        self.add("database", OK if mode == "wal" else WARN, f"journal mode {mode}")

    # -- state -----------------------------------------------------------------
    def runs(self) -> None:
        from aiszx.orchestrator.procutil import Owner

        db = self.app.db
        owner = Owner.current()
        stale_after = self.app.config.orchestrator.stale_after_seconds
        for ex in db.query("SELECT e.*, t.canonical_id, g.slug AS eng FROM executions e LEFT JOIN targets t"
                           " ON t.id = e.target_id JOIN engagements g ON g.id = e.engagement_id WHERE e.status = 'RUNNING'"):
            alive = owner.is_alive(ex["owner_pid"], ex["owner_host"], ex["boot_id"])
            if alive is None:
                beat = ex["heartbeat_at"] or ex["started_at"]
                alive = (utcnow() - parse_iso(beat)).total_seconds() < stale_after
            if alive:
                self.add("runs", INFO, f"run {ex['run_id']} of {ex['canonical_id']} is in progress (pid {ex['owner_pid']})")
            else:
                self.add("runs", WARN, f"run {ex['run_id']} of {ex['canonical_id']} was interrupted (process gone)",
                         f"python3 pentest.py -e {ex['eng']} resume {ex['canonical_id']}")
        rows = db.query(
            "SELECT e.run_id, e.status, t.canonical_id, g.slug AS eng FROM executions e JOIN targets t ON t.id = e.target_id"
            " JOIN engagements g ON g.id = e.engagement_id WHERE e.status IN ('INTERRUPTED', 'RECOVERY_REQUIRED', 'FAILED',"
            " 'PARTIAL') AND e.command IN ('run', 'recon', 'enumerate', 'full') AND NOT EXISTS (SELECT 1 FROM executions"
            " n WHERE n.target_id = e.target_id AND n.started_at > e.started_at AND n.command = e.command)")
        for r in rows:
            self.add("runs", INFO, f"latest {r['canonical_id']} run {r['run_id']} ended {r['status']}",
                     f"python3 pentest.py -e {r['eng']} resume {r['canonical_id']}")
        locks = db.query("SELECT * FROM locks")
        if locks:
            self.add("runs", INFO, f"{len(locks)} lock(s) held; stale ones are released automatically on the next run")
        if not any(c.area == "runs" for c in self.checks):
            self.add("runs", OK, "no interrupted or unfinished runs")

    def workspaces(self) -> None:
        missing_runs = 0
        for ex in self.app.db.query("SELECT workspace_path FROM executions"):
            if not (self.app.config.data_dir / ex["workspace_path"]).is_dir():
                missing_runs += 1
        if missing_runs:
            self.add("workspaces", WARN, f"{missing_runs} recorded run(s) have no directory on disk (deleted or moved?)",
                     "restore them from a backup; their evidence links will not resolve")
        problems = 0
        for eng in self.app.engagements().list(include_archived=True):
            reports = [self.app.layout.verify_engagement(eng.slug)]
            reports += [self.app.layout.verify_target(eng.slug, t.slug)
                        for t in self.app.targets().list(eng, include_archived=True)]
            bad = [r for r in reports if not r.ok]
            if bad:
                problems += len(bad)
                self.add("workspaces", WARN, f"engagement {eng.slug}: {len(bad)} workspace(s) with missing directories "
                         "or loose permissions", f"python3 pentest.py -e {eng.slug} workspace verify --repair")
            validity = eng.validity()
            if validity not in ("active", "archived"):
                self.add("workspaces", INFO, f"engagement {eng.slug} is {validity}: runs against it are refused",
                         f"python3 pentest.py engagement update {eng.slug} --valid-until ... (if still authorised)")
        if not problems and not missing_runs:
            self.add("workspaces", OK, "workspace directories and permissions as expected")

    def logs(self) -> None:
        d = self.app.config.log_dir
        if not d.is_dir():
            return
        size = sum(p.stat().st_size for p in d.rglob("*") if p.is_file())
        self.add("logs", OK if size < LOG_WARN_BYTES else WARN, f"central logs: {size / 1024 / 1024:.1f} MiB",
                 None if size < LOG_WARN_BYTES else "rotated logs (*.log.N) can be deleted; adjust logging.backup_count")

    def tools(self) -> None:
        if not self.with_tools:
            return
        registry = self.app.tool_registry()
        missing = []
        found: dict[str, str] = {}
        for name, spec in registry.tools.items():
            path = next((shutil.which(b) for b in spec.binaries if shutil.which(b)), None)
            path = path or next((p for p in spec.known_paths if Path(p).exists()), None)
            if path:
                found[name] = path
            else:
                missing.append(name)
        for name, status in CORE_TOOLS.items():
            if name in registry.tools and name not in found:
                self.add("tools", status, f"{name} not found", "python3 pentest.py tools missing")
        self.add("tools", OK if not missing else INFO,
                 f"{len(found)} of {len(registry.tools)} registered tools found"
                 + (f"; missing: {', '.join(sorted(missing))}" if missing else ""),
                 "modules needing a missing tool are skipped; details: `tools missing`" if missing else None)
        if "nmap" in found and os.name == "posix":
            from aiszx.tools import nmap_privileges

            priv = nmap_privileges.check(self.app.runner(), self.app.host(), os.path.realpath(found["nmap"]))
            self.add("tools", OK if priv.raw_sockets else WARN, priv.message,
                     None if priv.raw_sockets else "python3 pentest.py tools nmap-caps --apply (asks first)")


def summary(checks: list[Check]) -> dict[str, int]:
    out = {s: 0 for s in (OK, INFO, WARN, FAIL)}
    for c in checks:
        out[c.status] += 1
    return out


def version_line() -> str:
    return f"Aiszx {__version__} on Python {sys.version.split()[0]}"
