"""Per-run and per-module JSON-lines logs inside the run directory.

    <run>/logs/run.log                         every event of the run
    <run>/logs/modules/<module>__<unit>.log    events of one unit (commands, exit codes, errors)

Events are mirrored to the central application log.
"""

from __future__ import annotations

import json
import logging
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aiszx.core.logging import get_logger

_log = get_logger("run")


def unit_slug(module_id: str, unit_key: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", f"{module_id}__{unit_key}")


class RunLog:
    def __init__(self, run_dir: Path, run_id: str, target: str) -> None:
        self.dir = run_dir / "logs"
        self.run_id = run_id
        self.target = target
        self._lock = threading.Lock()

    def event(self, level: str, event: str, message: str, *, module: str | None = None,
              unit: str | None = None, **ctx: Any) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        rec = {"ts": ts, "level": level, "event": event, "message": message, "run_id": self.run_id}
        if module:
            rec.update(module=module, unit=unit)
        if ctx:
            rec["ctx"] = ctx
        line = json.dumps(rec, ensure_ascii=False, default=str) + "\n"
        with self._lock:
            self.dir.mkdir(parents=True, exist_ok=True)
            with (self.dir / "run.log").open("a", encoding="utf-8") as fh:
                fh.write(line)
            if module:
                mdir = self.dir / "modules"
                mdir.mkdir(exist_ok=True)
                with (mdir / f"{unit_slug(module, unit or '')}.log").open("a", encoding="utf-8") as fh:
                    fh.write(line)
        lvl = logging.getLevelName(level)
        _log.log(lvl if isinstance(lvl, int) else logging.INFO, "%s %s: %s", self.target, event, message,
                 extra={"run_id": self.run_id, "module_id": module, "target": self.target})
