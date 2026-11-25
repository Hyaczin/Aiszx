"""Target registration, lookup, scope decisions, archiving and purging."""

from __future__ import annotations

import ipaddress
import shutil
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Callable

from aiszx.core.audit import record_event
from aiszx.core.config import ScopeConfig
from aiszx.core.errors import NotFoundError, ScopeError, ValidationError, WorkspaceError
from aiszx.core.fsutil import is_within, write_yaml
from aiszx.core.ids import new_id
from aiszx.core.logging import get_logger, target_extra
from aiszx.core.timeutil import iso, utcnow
from aiszx.db.connection import Database
from aiszx.targets.engagements import ARCHIVED, MIRROR_HEADER, Engagement, EngagementStore
from aiszx.targets.identity import KIND_HOSTNAME, TargetIdentity, normalise_target
from aiszx.targets.scope import INCLUDE, ScopeDecision
from aiszx.targets.scope_store import ScopeStore
from aiszx.targets.workspace import WorkspaceLayout

Resolver = Callable[[str], list[str]]
log = get_logger("targets")


@dataclass(frozen=True)
class TargetAddress:
    address: str
    family: int
    source: str
    in_scope: bool
    first_seen: str
    last_seen: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address, "family": self.family, "source": self.source,
            "in_scope": self.in_scope, "first_seen": self.first_seen, "last_seen": self.last_seen,
        }


@dataclass
class Target:
    id: str
    engagement: Engagement
    canonical: str
    kind: str
    slug: str
    source: str
    status: str
    notes: str | None
    created_at: str
    updated_at: str
    archived_at: str | None
    addresses: list[TargetAddress] = field(default_factory=list)

    @property
    def identity(self) -> TargetIdentity:
        return TargetIdentity(self.kind, self.canonical, self.slug)

    @property
    def current_addresses(self) -> list[str]:
        """Addresses from the most recent resolution (older ones are kept as history)."""
        if not self.addresses:
            return []
        latest = max(a.last_seen for a in self.addresses)
        return [a.address for a in self.addresses if a.last_seen == latest]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "engagement": self.engagement.slug, "canonical_id": self.canonical,
            "kind": self.kind, "slug": self.slug, "source": self.source, "status": self.status,
            "notes": self.notes, "created_at": self.created_at, "updated_at": self.updated_at,
            "archived_at": self.archived_at, "addresses": [a.to_dict() for a in self.addresses],
        }


@dataclass
class AddResult:
    target: Target
    created: bool
    reactivated: bool
    decision: ScopeDecision
    scope_rule_added: str | None = None
    resolved: bool = False


class TargetManager:
    def __init__(
        self,
        db: Database,
        layout: WorkspaceLayout,
        engagements: EngagementStore,
        scope: ScopeStore,
        scope_cfg: ScopeConfig,
        resolver: Resolver,
        actor: str,
    ) -> None:
        self.db = db
        self.layout = layout
        self.engagements = engagements
        self.scope = scope
        self.scope_cfg = scope_cfg
        self.resolver = resolver
        self.actor = actor

    # -- queries -------------------------------------------------------------
    def _load(self, engagement: Engagement, rows: list[sqlite3.Row]) -> list[Target]:
        targets = [
            Target(
                id=r["id"], engagement=engagement, canonical=r["canonical_id"], kind=r["kind"], slug=r["slug"],
                source=r["source"], status=r["status"], notes=r["notes"], created_at=r["created_at"],
                updated_at=r["updated_at"], archived_at=r["archived_at"],
            )
            for r in rows
        ]
        if targets:
            by_id = {t.id: t for t in targets}
            marks = ",".join("?" * len(by_id))
            for a in self.db.query(
                f"SELECT * FROM target_addresses WHERE target_id IN ({marks}) ORDER BY family, address", list(by_id)
            ):
                by_id[a["target_id"]].addresses.append(
                    TargetAddress(a["address"], a["family"], a["source"], bool(a["in_scope"]), a["first_seen"], a["last_seen"])
                )
        return targets

    def find(self, engagement: Engagement, raw: str) -> Target | None:
        identity = normalise_target(raw)
        rows = self.db.query(
            "SELECT * FROM targets WHERE engagement_id = ? AND canonical_id = ?", (engagement.id, identity.canonical)
        )
        loaded = self._load(engagement, rows)
        return loaded[0] if loaded else None

    def get(self, engagement: Engagement, raw: str) -> Target:
        target = self.find(engagement, raw)
        if target is None:
            raise NotFoundError(f"target '{raw}' is not registered in engagement '{engagement.slug}'")
        return target

    def list(self, engagement: Engagement, *, include_archived: bool = False) -> list[Target]:
        sql = "SELECT * FROM targets WHERE engagement_id = ?"
        if not include_archived:
            sql += " AND status = 'active'"
        rows = self.db.query(sql + " ORDER BY kind, canonical_id", (engagement.id,))
        return self._load(engagement, rows)

    def decide(self, target: Target) -> ScopeDecision:
        return self.scope.policy(target.engagement).evaluate(target.identity, target.current_addresses)

    # -- registration --------------------------------------------------------
    def _resolve(self, identity: TargetIdentity, resolve: bool) -> list[tuple[str, str]]:
        if identity.is_ip:
            return [(identity.canonical, "self")]
        if not resolve:
            return []
        return [(addr, "dns") for addr in self.resolver(identity.canonical)]

    def add(
        self,
        engagement_slug: str,
        raw: str,
        *,
        add_to_scope: bool = False,
        resolve: bool | None = None,
        notes: str | None = None,
    ) -> AddResult:
        identity = normalise_target(raw)
        engagement = self.engagements.get(engagement_slug)
        if engagement.validity() == ARCHIVED:
            raise ValidationError(f"engagement '{engagement.slug}' is archived")
        do_resolve = self.scope_cfg.resolve_hostnames if resolve is None else resolve
        addresses = self._resolve(identity, do_resolve)
        addr_values = [a for a, _ in addresses]
        rule_added: str | None = None

        with self.db.transaction():
            decision = self.scope.policy(engagement).evaluate(identity, addr_values)
            if not decision.in_scope and add_to_scope:
                outcome = self.scope.add(engagement, identity.canonical, INCLUDE, note="added by `target add --scope`")
                if outcome.created:
                    rule_added = outcome.rule.describe()
                decision = self.scope.policy(engagement).evaluate(identity, addr_values)
            if not decision.in_scope:
                lines = "\n".join(f"  - {r}" for r in decision.reasons + decision.warnings)
                hint = (
                    "add a covering rule with `scope add <ip|cidr|hostname>`"
                    + ("" if add_to_scope else ", or rerun with --scope to include exactly this target")
                )
                raise ScopeError(f"{identity.canonical} is out of scope for engagement '{engagement.slug}':\n{lines}\n{hint}")

            now = iso()
            row = self.db.query_one(
                "SELECT id, status FROM targets WHERE engagement_id = ? AND canonical_id = ?",
                (engagement.id, identity.canonical),
            )
            created = reactivated = False
            if row is None:
                target_id = new_id()
                self.db.execute(
                    "INSERT INTO targets (id, engagement_id, canonical_id, kind, slug, source, status, notes,"
                    " created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'manual', 'active', ?, ?, ?)",
                    (target_id, engagement.id, identity.canonical, identity.kind, identity.slug, notes, now, now),
                )
                created = True
            else:
                target_id = row["id"]
                reactivated = row["status"] == "archived"
                self.db.execute(
                    "UPDATE targets SET status = 'active', archived_at = NULL, updated_at = ?,"
                    " notes = COALESCE(?, notes) WHERE id = ?",
                    (now, notes, target_id),
                )

            in_scope_by_addr = {a.address: a.in_scope for a in decision.addresses}
            for address, source in addresses:
                self.db.execute(
                    "INSERT INTO target_addresses (id, target_id, address, family, source, in_scope, first_seen, last_seen)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
                    " ON CONFLICT (target_id, address) DO UPDATE SET"
                    " last_seen = excluded.last_seen, in_scope = excluded.in_scope, source = excluded.source",
                    (new_id(), target_id, address, ipaddress.ip_address(address).version, source,
                     int(in_scope_by_addr.get(address, False)), now, now),
                )
            action = "target.create" if created else ("target.reactivate" if reactivated else "target.refresh")
            record_event(
                self.db, action, actor=self.actor, engagement_id=engagement.id, target_id=target_id,
                canonical=identity.canonical, addresses=addr_values, scope_rule_added=rule_added,
            )
            self.layout.ensure_target(engagement.slug, identity.slug)

        target = self.get(engagement, identity.canonical)
        self.write_mirror(target)
        if rule_added:
            self.scope.write_mirror(engagement)
        log.info(
            "target %s: %s", action.split(".")[1], identity.canonical,
            extra=target_extra(engagement.slug, identity.canonical, self.layout.target_dir(engagement.slug, identity.slug),
                               addresses=addr_values, scope_rule_added=rule_added),
        )
        return AddResult(
            target, created, reactivated, decision, rule_added,
            resolved=identity.kind == KIND_HOSTNAME and do_resolve,
        )

    # -- removal -------------------------------------------------------------
    def archive(self, engagement: Engagement, raw: str) -> tuple[Target, bool]:
        target = self.get(engagement, raw)
        if target.status == "archived":
            return target, False
        now = iso()
        with self.db.transaction():
            self.db.execute(
                "UPDATE targets SET status = 'archived', archived_at = ?, updated_at = ? WHERE id = ?",
                (now, now, target.id),
            )
            record_event(self.db, "target.archive", actor=self.actor, engagement_id=engagement.id,
                         target_id=target.id, canonical=target.canonical)
        target = self.get(engagement, raw)
        self.write_mirror(target)
        log.info("target archived: %s", target.canonical,
                 extra=target_extra(engagement.slug, target.canonical, self.layout.target_dir(engagement.slug, target.slug)))
        return target, True

    def purge(self, engagement: Engagement, raw: str) -> Target:
        """Delete the target's database rows and its entire workspace. Irreversible."""
        target = self.get(engagement, raw)
        workspace = self.layout.target_dir(engagement.slug, target.slug)
        if not is_within(workspace, self.layout.engagements_root):
            raise WorkspaceError(f"refusing to delete {workspace}: outside the engagements directory")
        trash = self.layout.trash_dir(engagement.slug) / f"{target.slug}-{utcnow().strftime('%Y%m%dT%H%M%SZ')}"
        moved = False
        if workspace.exists():
            trash.parent.mkdir(parents=True, exist_ok=True)
            workspace.rename(trash)  # atomic on the same filesystem; undone if the DB step fails
            moved = True
        try:
            with self.db.transaction():
                self.db.execute("DELETE FROM targets WHERE id = ?", (target.id,))
                record_event(self.db, "target.purge", actor=self.actor, engagement_id=engagement.id,
                             canonical=target.canonical, workspace=str(workspace))
        except BaseException:
            if moved:
                trash.rename(workspace)
            raise
        if moved:
            shutil.rmtree(trash)
        log.warning("target purged: %s (workspace %s deleted)", target.canonical, workspace,
                    extra={"engagement": engagement.slug, "target": target.canonical})
        return target

    # -- scope maintenance ---------------------------------------------------
    def refresh_scope_flags(self, engagement: Engagement) -> list[tuple[Target, ScopeDecision]]:
        """Re-evaluate every active target after a scope change; updates per-address flags."""
        results = []
        policy = self.scope.policy(engagement)
        with self.db.transaction():
            for target in self.list(engagement):
                decision = policy.evaluate(target.identity, target.current_addresses)
                for ad in decision.addresses:
                    self.db.execute(
                        "UPDATE target_addresses SET in_scope = ? WHERE target_id = ? AND address = ?",
                        (int(ad.in_scope), target.id, ad.address),
                    )
                results.append((target, decision))
        return results

    def write_mirror(self, target: Target) -> None:
        path = self.layout.target_dir(target.engagement.slug, target.slug) / "target.yaml"
        if path.parent.is_dir():
            write_yaml(path, target.to_dict(), MIRROR_HEADER)
