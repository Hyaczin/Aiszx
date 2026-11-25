from pathlib import Path

import pytest

from aiszx.core.config import load_config
from aiszx.core.errors import ConfigError


def write_user(tmp_path: Path, text: str) -> Path:
    d = tmp_path / "cfg"
    d.mkdir(exist_ok=True)
    (d / "framework.yaml").write_text(text, encoding="utf-8")
    return d


def test_defaults_load(tmp_path, isolated_env):
    cfg = load_config(user_config_dir=tmp_path / "cfg", data_dir=tmp_path / "data", env=isolated_env)
    assert cfg.default_engagement == "default"
    assert cfg.workspace.dir_mode == 0o750
    assert cfg.workspace.protected_dir_mode == 0o700
    assert "evidence/protected" in cfg.workspace.protected_subdirs
    assert cfg.scope.strict_hostname_resolution is True
    assert len(cfg.sources) == 1


def test_user_override_merges(tmp_path, isolated_env):
    ucd = write_user(tmp_path, "logging:\n  console_level: DEBUG\nengagements:\n  default_slug: HTB\n")
    cfg = load_config(user_config_dir=ucd, data_dir=tmp_path / "data", env=isolated_env)
    assert cfg.logging.console_level == "DEBUG"
    assert cfg.logging.level == "INFO"  # untouched sibling key survives the merge
    assert cfg.default_engagement == "htb"
    assert cfg.sources[-1] == ucd / "framework.yaml"


@pytest.mark.parametrize(
    "text, fragment",
    [
        ("logging:\n  levle: INFO\n", "unknown key"),
        ("logging:\n  max_bytes: true\n", "expected int"),
        ("logging:\n  level: LOUD\n", "must be one of"),
        ("workspace:\n  dir_mode: '9999'\n", "octal"),
        ("workspace:\n  run_subdirs: ['../escape']\n", "relative path"),
        ("workspace:\n  protected_subdirs: [secret]\n", "must also appear"),
        ("paths:\n  data_dir: relative/dir\n", "absolute"),
        ("version: 2\n", "not supported"),
        ("- just a list\n", "mapping"),
        ("logging: [\n", "invalid YAML"),
    ],
)
def test_invalid_user_config(tmp_path, isolated_env, text, fragment):
    ucd = write_user(tmp_path, text)
    with pytest.raises(ConfigError) as exc:
        load_config(user_config_dir=ucd, env=isolated_env)
    assert fragment in str(exc.value)


def test_data_dir_precedence(tmp_path, isolated_env):
    env = dict(isolated_env)
    # XDG default
    cfg = load_config(user_config_dir=tmp_path / "cfg", env=env)
    assert cfg.data_dir == (Path(env["XDG_DATA_HOME"]) / "aiszx").resolve()
    # config file beats XDG
    ucd = write_user(tmp_path, f"paths:\n  data_dir: '{(tmp_path / 'from-config').as_posix()}'\n")
    assert load_config(user_config_dir=ucd, env=env).data_dir == (tmp_path / "from-config").resolve()
    # environment beats config file
    env["AISZX_DATA_DIR"] = str(tmp_path / "from-env")
    assert load_config(user_config_dir=ucd, env=env).data_dir == (tmp_path / "from-env").resolve()
    # CLI beats environment
    assert load_config(user_config_dir=ucd, data_dir=tmp_path / "from-cli", env=env).data_dir == (tmp_path / "from-cli").resolve()


def test_relative_xdg_is_ignored(tmp_path):
    cfg = load_config(user_config_dir=tmp_path / "cfg", env={"XDG_DATA_HOME": "relative"})
    assert cfg.data_dir == (Path.home() / ".local" / "share" / "aiszx").resolve()
