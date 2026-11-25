"""Engagement-level host discovery over an authorised network range (nmap -sn <cidr>).

* The whole range must be inside scope; scope exclusions inside the range are passed to nmap
  (``--exclude``) and the scope guard verifies the combination before nmap starts.
* Results are stored as ``discovered_hosts`` of an engagement-level run
  (``<engagement>/runs/<run-id>/``). Live hosts are never scanned further automatically:
  they become targets only when you register them (``discover --register`` asks per host).
"""

from __future__ import annotations

import ipaddress
import json
import threading
from dataclasses import dataclass, field
from typing import Callable

from aiszx import __version__
from aiszx.core.errors import AiszxError, ScopeError, ValidationError
from aiszx.core.fsutil import atomic_write_text
from aiszx.core.timeutil import iso
from aiszx.modules.base import Command
from aiszx.modules.records import HostRecord
from aiszx.orchestrator.fingerprint import fingerprint
from aiszx.orchestrator.orchestrator import install_sigint, inventory_tool_resolver, register_evidence
from aiszx.orchestrator.planner import ToolResolver
from aiszx.orchestrator.procutil import Owner
from aiszx.orchestrator.settings import load_settings
from aiszx.orchestrator.state import EXEC_COMPLETED, EXEC_FAILED, EXEC_INTERRUPTED, EXEC_RUNNING, ExecutionStore
from aiszx.orchestrator.toolrunner import ScopeGuard, ToolRunner
from aiszx.parsers.nmap_xml import parse_nmap_xml_file
from aiszx.recon import nmap
from aiszx.recon.store import ReconStore
from aiszx.targets.engagements import ACTIVE


@dataclass
class DiscoveryResult:
    execution_id: str
    run_id: str
    run_dir: object
    status: str
    network: str
    excluded: list[str]
    hosts: list[HostRecord] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


class RangeDiscovery:
    def __init__(self, app, *, resolve_tools: ToolResolver | None = None, progress: Callable[[str], None] | None = None,
                 cancel_event: threading.Event | None = None, handle_signals: bool = True) -> None:
        self.app = app
        self.store = ExecutionStore(app.db)
        self.recon = ReconStore(app.db)
        self.resolve_tools = resolve_tools or inventory_tool_resolver(app)
        self.progress = progress or (lambda s: None)
        self.cancel = cancel_event or threading.Event()
        self.handle_signals = handle_signals

    def run(self, engagement_slug: str, cidr: str, *, profile: str | None = None) -> DiscoveryResult:
        eng = self.app.engagements().get(engagement_slug)
        if eng.validity() != ACTIVE:
            raise ScopeError(f"engagement '{eng.slug}' is {eng.validity()}; testing is only allowed inside its validity window")
        try:
            net = ipaddress.ip_network(cidr.strip(), strict=False)
        except ValueError:
            raise ValidationError(f"{cidr!r} is not a valid network (e.g. 10.10.10.0/24)") from None
        policy = self.app.scope().policy(eng)
        excluded = [r.value for r in policy.excludes if r.is_address_rule
                    and ipaddress.ip_network(r.value).version == net.version
                    and ipaddress.ip_network(r.value).overlaps(net)]
        from aiszx.targets import resolver
        guard = ScopeGuard(policy, eng, resolver.resolve_host)
        guard.check([str(net)], excluded)  # fail early, before creating a run

        tool = self.resolve_tools(["nmap"])["nmap"]
        if tool.status != "ok" or not tool.launch:
            raise AiszxError(f"nmap is not usable ({tool.status}); see `python3 pentest.py tools missing`")
        settings = load_settings(user_config_dir=self.app.config.user_config_dir,
                                 engagement_dir=self.app.layout.engagement_dir(eng.slug))
        prof = settings.profile(profile or self.app.config.orchestrator.default_profile)
        p = nmap.params(prof.params)
        flags, raw, mode = nmap.privileges({"nmap": tool.detail})

        run = self.app.layout.create_engagement_run(eng.slug)
        owner = Owner.current()
        snapshot = {"command": "discover", "network": str(net), "excluded": excluded, "profile": prof.name,
                    "nmap": p, "privileges": mode}
        now = iso()
        eid = self.store.create_execution(
            run_id=run.run_id, engagement_id=eng.id, target_id=None, command="discover", profile=prof.name,
            status=EXEC_RUNNING, pinned_address=str(net), config_fingerprint=fingerprint(snapshot),
            config_snapshot=snapshot, framework_version=__version__, owner_pid=owner.pid, owner_host=owner.host,
            boot_id=owner.boot, heartbeat_at=now, started_at=now,
            workspace_path=run.path.relative_to(self.app.config.data_dir).as_posix(),
        )
        atomic_write_text(run.path / "scope" / "scope.json", json.dumps({
            "recorded_at": now, "engagement": eng.slug, "authorisation_ref": eng.authorisation_ref,
            "network": str(net), "excluded": excluded, "rules": [r.to_dict() for r in policy.rules],
        }, indent=2, sort_keys=True))

        adir = run.path / "reconnaissance" / "range_discovery" / "attempt-01"
        (adir / "raw").mkdir(parents=True, exist_ok=True)
        argv = ["-sn", *(p["discovery_probes"] if raw else []), *nmap.common(p, flags, str(net.network_address))]
        if excluded:
            argv += ["--exclude", ",".join(excluded)]
        argv += [*nmap.outputs(adir, "discovery"), str(net)]
        cmd = Command("discovery", argv, tool="nmap", targets=[str(net)], exclude=excluded)
        runner = ToolRunner(guard, {"nmap": tool.launch}, self.cancel,
                            kill_grace=self.app.config.orchestrator.kill_grace_seconds)

        self.progress(f"Discovering live hosts in {net}" + (f" (excluding {', '.join(excluded)})" if excluded else "")
                      + f" with nmap -sn ({'raw-socket probes' if raw else 'TCP connect probes only'})")
        restore = install_sigint(self.cancel, self.progress) if self.handle_signals else None
        result = DiscoveryResult(eid, run.run_id, run.path, EXEC_FAILED, str(net), excluded)
        try:
            res = runner.run(cmd, adir / "raw", 1800)
        finally:
            if restore:
                restore()
        parsed = parse_nmap_xml_file(adir / "raw" / "discovery.xml")
        if not raw:
            result.limitations.append(f"nmap privileges '{mode}': only TCP connect probes were used; "
                                      "hosts that ignore ports 80/443 may be missed")
        if parsed.parse_error or not parsed.complete:
            result.limitations.append(f"nmap output incomplete ({parsed.parse_error or parsed.error or 'no finish'})")
        for h in parsed.hosts:
            if h.status == "up" and h.address:
                result.hosts.append(HostRecord(h.address, "up", "nmap -sn", h.reason, h.hostnames))
        if res.cancelled:
            result.status = EXEC_INTERRUPTED
        elif res.error or res.timed_out or res.exit_code != 0:
            result.limitations.append(f"nmap failed: {res.error or ('timeout' if res.timed_out else f'exit {res.exit_code}')}")
        else:
            result.status = EXEC_COMPLETED
        with self.app.db.transaction():
            for h in result.hosts:
                self.recon.insert_host(execution_id=eid, engagement_id=eng.id, target_id=None, unit_id=None, host=h)
            register_evidence(self.store, eid=eid, target_id=None, unit_id=None, attempt=1, adir=adir,
                              run_dir=run.path, tools="nmap")
            self.store.update_execution(eid, status=result.status, ended_at=iso(),
                                        summary_json={"hosts_up": len(result.hosts), "excluded": len(excluded)})
        return result

    def register(self, engagement_slug: str, execution_id: str, addresses: list[str]) -> list[str]:
        """Register discovered hosts as targets and link them; returns the registered addresses."""
        done = []
        for address in addresses:
            added = self.app.targets().add(engagement_slug, address)
            self.app.db.execute(
                "UPDATE discovered_hosts SET promoted_target_id = ? WHERE execution_id = ? AND address = ?",
                (added.target.id, execution_id, address))
            done.append(address)
        return done

    def history(self, engagement_slug: str) -> list[dict]:
        eng = self.app.engagements().get(engagement_slug)
        rows = self.app.db.query(
            "SELECT * FROM executions WHERE engagement_id = ? AND target_id IS NULL AND command = 'discover'"
            " ORDER BY started_at DESC", (eng.id,))
        out = []
        for r in rows:
            hosts = self.recon.hosts_for_execution(r["id"])
            out.append({"run_id": r["run_id"], "network": r["pinned_address"], "status": r["status"],
                        "started_at": r["started_at"], "hosts": [h["address"] for h in hosts],
                        "registered": [h["address"] for h in hosts if h["promoted_target_id"]]})
        return out
