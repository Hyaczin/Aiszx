"""Reporting configuration, layered like the module settings:

    config/reporting.yaml                      (shipped defaults)
    ~/.config/aiszx/reporting.yaml             (user overrides)
    <engagement dir>/overrides.yaml            (key `reporting:`)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from aiszx.core import paths
from aiszx.core.config import Choice, ListOf, deep_merge, load_yaml_file, validate
from aiszx.core.errors import ConfigError

FORMATS = ("markdown", "html", "json")
EXTENSIONS = {"markdown": "md", "html": "html", "json": "json"}

REPORTING_ENTRY = {
    "formats?": ListOf(Choice(*FORMATS)),
    "max_table_rows?": int,
    "max_value_chars?": int,
    "include_hypotheses?": bool,
    "write_consolidated?": bool,
    "redaction?": {"extra_patterns?": ListOf(str), "extra_secret_keys?": ListOf(str)},
}
SCHEMA = {"version": int, "reporting": REPORTING_ENTRY}


@dataclass(frozen=True)
class ReportSettings:
    formats: tuple[str, ...]
    max_table_rows: int
    max_value_chars: int
    include_hypotheses: bool
    write_consolidated: bool
    extra_patterns: tuple[str, ...]
    extra_secret_keys: tuple[str, ...]
    sources: tuple[Path, ...]


def load_report_settings(*, user_config_dir: Path | None, engagement_dir: Path | None,
                         shipped_dir: Path | None = None) -> ReportSettings:
    shipped = (shipped_dir or paths.SHIPPED_CONFIG_DIR) / "reporting.yaml"
    data = load_yaml_file(shipped)
    sources = [shipped]
    if user_config_dir is not None and (user_config_dir / "reporting.yaml").is_file():
        data = deep_merge(data, load_yaml_file(user_config_dir / "reporting.yaml"))
        sources.append(user_config_dir / "reporting.yaml")
    validate(data, SCHEMA)
    rep = data["reporting"]
    if engagement_dir is not None and (engagement_dir / "overrides.yaml").is_file():
        ov = load_yaml_file(engagement_dir / "overrides.yaml").get("reporting") or {}
        validate(ov, REPORTING_ENTRY, "overrides.reporting")
        rep = deep_merge(rep, ov)
        sources.append(engagement_dir / "overrides.yaml")
    red = rep.get("redaction") or {}
    for pattern in red.get("extra_patterns", []):
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ConfigError(f"reporting.redaction.extra_patterns: {pattern!r} is not a valid regex ({exc})") from None
    formats = tuple(dict.fromkeys(rep.get("formats") or FORMATS))
    if not formats:
        raise ConfigError("reporting.formats must name at least one format")
    if rep.get("max_table_rows", 300) < 1 or rep.get("max_value_chars", 400) < 20:
        raise ConfigError("reporting: max_table_rows must be >= 1 and max_value_chars >= 20")
    return ReportSettings(
        formats=formats, max_table_rows=rep.get("max_table_rows", 300), max_value_chars=rep.get("max_value_chars", 400),
        include_hypotheses=rep.get("include_hypotheses", True), write_consolidated=rep.get("write_consolidated", True),
        extra_patterns=tuple(red.get("extra_patterns", [])), extra_secret_keys=tuple(red.get("extra_secret_keys", [])),
        sources=tuple(sources))
