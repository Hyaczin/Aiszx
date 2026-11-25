"""Persistence for engagement scope rules, plus YAML import and the ``scope.yaml`` mirror.

Scope file format (also what the mirror contains, so it round-trips)::

    include:
      - 10.10.10.0/24
      - value: dc01.corp.local
        note: domain controller
    exclude:
      - value: 10.10.10.1
        note: gateway — out of scope
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aiszx.core.audit import record_event
from aiszx.core.config import ScopeConfig, load_yaml_file
from aiszx.core.errors import ConfigError, NotFoundError, ValidationError
from aiszx.core.fsutil import write_yaml
from aiszx.core.ids import new_id
from aiszx.core.timeutil import iso
from aiszx.db.connection import Database
from aiszx.targets.engagements import MIRROR_HEADER, Engagement
from aiszx.targets.scope import ACTIONS, EXCLUDE, INCLUDE, ScopePolicy, ScopeRule, parse_rule_value
from aiszx.targets.workspace import WorkspaceLayout


@dataclass
class AddRuleResult:
    rule: ScopeRule
    created: bool
    normalisation: str | None = None


@dataclass
class ImportResult:
    added: list[ScopeRule] = field(default_factory=list)
    existing: list[ScopeRule] = field(default_factory=list)
    removed: int = 0


def parse_scope_file(path: Path) -> list[tuple[str, str, str | None]]:
    data = load_yaml_file(path)
    unknown = set(data) - set(ACTIONS)
    if unknown:
        raise ConfigError(f"{path}: unknown key(s) {', '.join(sorted(unknown))}; expected 'include' and/or 'exclude'")
    entries: list[tuple[str, str, str | None]] = []
    for action in ACTIONS:
        items = data.get(action) or []
        if not isinstance(items, list):
            raise ConfigError(f"{path}: '{action}' must be a list")
        for i, item in enumerate(items):
            if isinstance(item, str):
                entries.append((action, item, None))
            elif isinstance(item, dict) and isinstance(item.get("value"), str) and set(item) <= {"value", "note"}:
                note = item.get("note")
                entries.append((action, item["value"], None if note is None else str(note)))
            else:
                raise ConfigError(f"{path}: {action}[{i}] must be a string or a mapping with 'value' and optional 'note'")
    if not entries:
        raise ConfigError(f"{path}: no include or exclude entries found")
    return entries


class ScopeStore:
    def __init__(self, db: Database, layout: WorkspaceLayout, cfg: ScopeConfig, actor: str) -> None:
        self.db = db
        self.layout = layout
        self.cfg = cfg
        self.actor = actor

    def rules(self, engagement: Engagement) -> list[ScopeRule]:
        rows = self.db.query(
            "SELECT id, action, rule_type, value, note FROM scope_rules WHERE engagement_id = ?"
            " ORDER BY action DESC, rule_type, value",
            (engagement.id,),
        )
        return [ScopeRule(r["action"], r["rule_type"], r["value"], r["note"], r["id"]) for r in rows]

    def policy(self, engagement: Engagement) -> ScopePolicy:
        return ScopePolicy(self.rules(engagement), strict_hostname_resolution=self.cfg.strict_hostname_resolution)

    def _find(self, engagement: Engagement, action: str, rule_type: str, value: str) -> ScopeRule | None:
        r = self.db.query_one(
            "SELECT id, action, rule_type, value, note FROM scope_rules"
            " WHERE engagement_id = ? AND action = ? AND rule_type = ? AND value = ?",
            (engagement.id, action, rule_type, value),
        )
        return ScopeRule(r["action"], r["rule_type"], r["value"], r["note"], r["id"]) if r else None

    def add(self, engagement: Engagement, raw: str, action: str = INCLUDE, note: str | None = None) -> AddRuleResult:
        if action not in ACTIONS:
            raise ValidationError(f"invalid scope action {action!r}")
        rule_type, value, normalisation = parse_rule_value(raw)
        existing = self._find(engagement, action, rule_type, value)
        if existing:
            return AddRuleResult(existing, False, normalisation)
        rule = ScopeRule(action, rule_type, value, note, new_id())
        with self.db.transaction():
            self.db.execute(
                "INSERT INTO scope_rules (id, engagement_id, action, rule_type, value, note, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (rule.id, engagement.id, action, rule_type, value, note, iso()),
            )
            record_event(self.db, "scope.add", actor=self.actor, engagement_id=engagement.id, rule=rule.to_dict())
        return AddRuleResult(rule, True, normalisation)

    def remove(self, engagement: Engagement, raw: str, action: str = INCLUDE) -> ScopeRule:
        rule_type, value, _ = parse_rule_value(raw)
        existing = self._find(engagement, action, rule_type, value)
        if existing is None:
            raise NotFoundError(f"no {action} rule '{value}' in engagement '{engagement.slug}'")
        with self.db.transaction():
            self.db.execute("DELETE FROM scope_rules WHERE id = ?", (existing.id,))
            record_event(self.db, "scope.remove", actor=self.actor, engagement_id=engagement.id, rule=existing.to_dict())
        return existing

    def import_file(self, engagement: Engagement, path: Path, *, replace: bool = False) -> ImportResult:
        entries = parse_scope_file(path)
        parsed = [(action, *parse_rule_value(raw)[:2], note) for action, raw, note in entries]  # validate all first
        result = ImportResult()
        with self.db.transaction():
            if replace:
                result.removed = self.db.execute("DELETE FROM scope_rules WHERE engagement_id = ?", (engagement.id,)).rowcount
            for action, _rule_type, value, note in parsed:
                outcome = self.add(engagement, value, action, note)
                (result.added if outcome.created else result.existing).append(outcome.rule)
            record_event(
                self.db, "scope.import", actor=self.actor, engagement_id=engagement.id,
                file=str(path), replace=replace, added=len(result.added), removed=result.removed,
            )
        return result

    def write_mirror(self, engagement: Engagement) -> None:
        data: dict[str, Any] = {INCLUDE: [], EXCLUDE: []}
        for rule in self.rules(engagement):
            data[rule.action].append({"value": rule.value, "note": rule.note} if rule.note else rule.value)
        write_yaml(self.layout.engagement_dir(engagement.slug) / "scope.yaml", data, MIRROR_HEADER)
