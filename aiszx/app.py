"""Application context: the composition root that wires configuration, database, workspace and services."""

from __future__ import annotations

import getpass
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from aiszx.core.config import FrameworkConfig, load_config
from aiszx.core.errors import AiszxError
from aiszx.core.host import HostEnv
from aiszx.core.process import ProcessRunner
from aiszx.db.connection import Database
from aiszx.db.migrate import MigrationResult, migrate, require_current
from aiszx.targets import resolver
from aiszx.targets.engagements import EngagementStore
from aiszx.targets.manager import TargetManager
from aiszx.targets.scope_store import ScopeStore
from aiszx.targets.workspace import WorkspaceLayout
from aiszx.tools.inventory import ToolInventory
from aiszx.tools.registry import ToolRegistry, load_registry


def current_actor() -> str:
    try:
        return getpass.getuser()
    except Exception:  # no USER/LOGNAME and no passwd entry (containers)
        return "unknown"


@dataclass
class AppContext:
    config: FrameworkConfig
    layout: WorkspaceLayout
    actor: str
    assume_yes: bool = False
    migration: MigrationResult | None = None
    _db: Database | None = field(default=None, repr=False)

    @classmethod
    def create(
        cls,
        *,
        data_dir: str | Path | None = None,
        config_dir: str | Path | None = None,
        assume_yes: bool = False,
        env: Mapping[str, str] | None = None,
    ) -> "AppContext":
        cfg = load_config(user_config_dir=config_dir, data_dir=data_dir, env=env)
        return cls(config=cfg, layout=WorkspaceLayout(cfg.data_dir, cfg.workspace), actor=current_actor(), assume_yes=assume_yes)

    def open_db(self, *, migrate_schema: bool = False) -> Database:
        if self._db is not None:
            return self._db
        path = self.config.db_path
        if not migrate_schema and not path.exists():
            raise AiszxError(f"Aiszx is not initialised at {self.config.data_dir}; run `python3 pentest.py init` first")
        db = Database(path).connect()
        try:
            if migrate_schema:
                self.migration = migrate(db)
            else:
                require_current(db)
        except BaseException:
            db.close()
            raise
        self._db = db
        return db

    @property
    def db(self) -> Database:
        return self.open_db()

    def engagements(self) -> EngagementStore:
        return EngagementStore(self.db, self.layout, self.actor)

    def scope(self) -> ScopeStore:
        return ScopeStore(self.db, self.layout, self.config.scope, self.actor)

    def targets(self) -> TargetManager:
        return TargetManager(
            self.db, self.layout, self.engagements(), self.scope(), self.config.scope,
            resolver.resolve_host, self.actor,
        )

    # -- tools ---------------------------------------------------------------
    # Module-level names are looked up at call time so tests can substitute fakes.
    def runner(self) -> ProcessRunner:
        return ProcessRunner()

    def host(self) -> HostEnv:
        return HostEnv()

    def tool_registry(self) -> ToolRegistry:
        return load_registry(user_config_dir=self.config.user_config_dir)

    def tool_inventory(self, registry: ToolRegistry | None = None) -> ToolInventory:
        return ToolInventory(registry or self.tool_registry(), self.runner(), self.host())

    # -- orchestration -------------------------------------------------------
    def module_registry(self):
        from aiszx.modules.registry import discover

        return discover()

    def orchestrator(self, **kwargs):
        from aiszx.orchestrator.orchestrator import Orchestrator

        kwargs.setdefault("registry", self.module_registry())
        return Orchestrator(self, **kwargs)

    def close(self) -> None:
        if self._db is not None:
            self._db.close()
            self._db = None
