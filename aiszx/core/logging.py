"""Logging setup.

* Console (stderr): human-readable, WARNING by default (``-v`` INFO, ``-vv`` DEBUG, ``-q`` ERROR).
* Central log: ``<data>/logs/aiszx.log``, JSON lines, size-rotated.
* Per-target log: any record logged with :func:`target_extra` is also written to
  ``<target workspace>/logs/target.log``.

Per-run and per-module logs are added with the orchestrator (Milestone 3).
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import sys
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aiszx.core.config import LoggingConfig

LOGGER_NAME = "aiszx"
_TARGET_DIR_ATTR = "aiszx_target_log_dir"
_CONTEXT_KEYS = ("engagement", "target", "run_id", "module_id")


def get_logger(name: str | None = None) -> logging.Logger:
    return logging.getLogger(LOGGER_NAME if not name else f"{LOGGER_NAME}.{name}")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        payload: dict[str, Any] = {
            "ts": ts,
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in _CONTEXT_KEYS:
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        ctx = getattr(record, "ctx", None)
        if ctx:
            payload["ctx"] = ctx
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


class TargetRoutingHandler(logging.Handler):
    """Writes records that carry a target log directory to ``<dir>/target.log``."""

    def __init__(self, level: int, max_open: int = 32) -> None:
        super().__init__(level)
        self._files: OrderedDict[str, logging.FileHandler] = OrderedDict()
        self._max_open = max_open
        self.setFormatter(JsonFormatter())

    def emit(self, record: logging.LogRecord) -> None:
        log_dir = getattr(record, _TARGET_DIR_ATTR, None)
        if not log_dir:
            return
        try:
            fh = self._files.get(log_dir)
            if fh is None:
                Path(log_dir).mkdir(parents=True, exist_ok=True)
                fh = logging.FileHandler(Path(log_dir) / "target.log", encoding="utf-8")
                fh.setFormatter(self.formatter)
                self._files[log_dir] = fh
                if len(self._files) > self._max_open:
                    _, oldest = self._files.popitem(last=False)
                    oldest.close()
            else:
                self._files.move_to_end(log_dir)
            fh.emit(record)
        except Exception:
            self.handleError(record)

    def close(self) -> None:
        for fh in self._files.values():
            fh.close()
        self._files.clear()
        super().close()


def target_extra(engagement_slug: str, target_canonical: str, target_dir: Path, **ctx: Any) -> dict[str, Any]:
    """``extra=`` mapping that routes a record to the target's log as well as the central log."""
    extra: dict[str, Any] = {
        _TARGET_DIR_ATTR: str(target_dir / "logs"),
        "engagement": engagement_slug,
        "target": target_canonical,
    }
    if ctx:
        extra["ctx"] = ctx
    return extra


def setup_logging(cfg: LoggingConfig, log_dir: Path | None, *, verbosity: int = 0, quiet: bool = False) -> logging.Logger:
    """(Re)configure the ``aiszx`` logger. Safe to call repeatedly (tests, multiple CLI invocations)."""
    shutdown_logging()
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    if quiet:
        console_level = logging.ERROR
    elif verbosity >= 2:
        console_level = logging.DEBUG
    elif verbosity == 1:
        console_level = logging.INFO
    else:
        console_level = logging.getLevelName(cfg.console_level)
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(console_level)
    console.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger.addHandler(console)

    if log_dir is not None:
        log_dir.mkdir(parents=True, exist_ok=True)
        file_level = logging.getLevelName(cfg.level)
        central = logging.handlers.RotatingFileHandler(
            log_dir / "aiszx.log", maxBytes=cfg.max_bytes, backupCount=cfg.backup_count, encoding="utf-8"
        )
        central.setLevel(file_level)
        central.setFormatter(JsonFormatter())
        logger.addHandler(central)
        logger.addHandler(TargetRoutingHandler(file_level))
    return logger


def shutdown_logging() -> None:
    """Close and detach all handlers (releases file handles; required on Windows before deleting dirs)."""
    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
