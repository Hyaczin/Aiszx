"""Runs a real scan in its own process so a test can kill it hard (no cleanup, no signal handlers).

Usage: python crash_driver.py DATA_DIR CONFIG_DIR TARGET MODULE...
Uses the fake nmap (tests/fake_nmap.py); FAKE_NMAP_HANG makes the TCP scan hang.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aiszx.app import AppContext  # noqa: E402
from aiszx.modules.registry import discover  # noqa: E402
from aiszx.orchestrator.orchestrator import Orchestrator  # noqa: E402
from aiszx.orchestrator.planner import ToolResolution  # noqa: E402

FAKE_NMAP = str(ROOT / "tests" / "fake_nmap.py")


def resolver(names):
    return {n: (ToolResolution("ok", [sys.executable, FAKE_NMAP], "7.95", detail={"privileges": {"mode": "capabilities"}})
                if n == "nmap" else ToolResolution("missing", [])) for n in names}


def main() -> int:
    data_dir, config_dir, target, *modules = sys.argv[1:]
    app = AppContext.create(data_dir=data_dir, config_dir=config_dir)
    app.open_db()
    try:
        Orchestrator(app, registry=discover(), resolve_tools=resolver, handle_signals=False).start(
            "default", target, modules)
    finally:
        app.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
