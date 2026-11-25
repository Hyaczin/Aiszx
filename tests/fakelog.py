"""Race-free call logging for the fake tools.

Parallel fake processes appending to one file can interleave lines (notably on Windows). Instead,
each call writes its own small file into ``<log>.d/``; readers return them in time order.
"""

import json
import os
import time
from pathlib import Path


def write(env_var: str, record) -> None:
    log = os.environ.get(env_var)
    if not log:
        return
    d = Path(log + ".d")
    d.mkdir(parents=True, exist_ok=True)
    name = f"{time.time_ns():020d}-{os.getpid()}.json"
    tmp = d / (name + ".tmp")
    tmp.write_text(json.dumps(record), encoding="utf-8")
    os.replace(tmp, d / name)


def read(log: Path) -> list:
    d = Path(str(log) + ".d")
    if not d.is_dir():
        return []
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(d.glob("*.json"))]
