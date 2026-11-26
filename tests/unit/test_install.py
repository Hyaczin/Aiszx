"""install.sh --dry-run must describe its actions without changing anything."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BASH = shutil.which("bash")


@pytest.mark.skipif(BASH is None or os.name != "posix", reason="needs bash on Linux")
def test_install_dry_run_changes_nothing():
    venv = ROOT / ".venv"
    before = venv.stat().st_mtime_ns if venv.exists() else None
    res = subprocess.run([BASH, str(ROOT / "install.sh"), "--dry-run", "--recreate", "--dev"], capture_output=True,
                         text=True, timeout=120)
    assert res.returncode == 0, res.stderr
    out = res.stdout
    assert "dry run: nothing will be changed" in out and "dry run complete" in out
    assert "would run: rm -rf .venv" in out or before is None
    assert "would run: " in out and "-m venv" in out and "pip install" in out and "pentest.py init" in out
    assert "sudo" not in out.replace("sudo apt install python3-venv", "")
    after = venv.stat().st_mtime_ns if venv.exists() else None
    assert before == after


@pytest.mark.skipif(BASH is None, reason="needs bash")
def test_install_rejects_unknown_option():
    res = subprocess.run([BASH, str(ROOT / "install.sh"), "--yolo"], capture_output=True, text=True, timeout=30)
    assert res.returncode == 2 and "unknown option" in res.stderr
