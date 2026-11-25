"""Location resolution for shipped config, user config and runtime data (XDG Base Directory layout)."""

from __future__ import annotations

from pathlib import Path
from typing import Mapping

APP_NAME = "aiszx"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
SHIPPED_CONFIG_DIR = PROJECT_ROOT / "config"


def _xdg_dir(env: Mapping[str, str], var: str, fallback: tuple[str, ...]) -> Path:
    value = env.get(var)
    # The XDG spec says relative paths in these variables must be ignored.
    if value and Path(value).is_absolute():
        return Path(value)
    return Path.home().joinpath(*fallback)


def xdg_data_home(env: Mapping[str, str]) -> Path:
    return _xdg_dir(env, "XDG_DATA_HOME", (".local", "share"))


def xdg_config_home(env: Mapping[str, str]) -> Path:
    return _xdg_dir(env, "XDG_CONFIG_HOME", (".config",))


def resolve_user_config_dir(cli_value: str | Path | None, env: Mapping[str, str]) -> Path:
    """Precedence: --config-dir > $AISZX_CONFIG_DIR > $XDG_CONFIG_HOME/aiszx > ~/.config/aiszx."""
    for candidate in (cli_value, env.get("AISZX_CONFIG_DIR")):
        if candidate:
            return Path(candidate).expanduser().resolve()
    return (xdg_config_home(env) / APP_NAME).resolve()


def resolve_data_dir(cli_value: str | Path | None, env: Mapping[str, str], config_value: str | None) -> Path:
    """Precedence: --data-dir > $AISZX_DATA_DIR > paths.data_dir in config > $XDG_DATA_HOME/aiszx > ~/.local/share/aiszx."""
    for candidate in (cli_value, env.get("AISZX_DATA_DIR"), config_value):
        if candidate:
            return Path(candidate).expanduser().resolve()
    return (xdg_data_home(env) / APP_NAME).resolve()
