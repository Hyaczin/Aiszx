"""Test-only modules. The "py" tool is the current Python interpreter; commands are tiny scripts."""

from __future__ import annotations

from aiszx.modules.base import (
    Command,
    Module,
    ModuleMeta,
    ModuleResult,
    RetryPolicy,
    Safety,
    Stage,
    ToolRequirement,
)

PY = (ToolRequirement("py"),)
NO_RETRY = RetryPolicy(max_attempts=1, backoff_seconds=0)

ECHO = """
import sys, pathlib
target, log = sys.argv[1], sys.argv[2]
if log:
    with open(log, "a") as fh: fh.write("run\\n")
print("hello " + target)
"""

FLAKY = """
import sys, pathlib
marker = pathlib.Path(sys.argv[1])
if not marker.exists():
    marker.write_text("1")
    print("connect: Network is unreachable", file=sys.stderr)
    sys.exit(1)
print("ok on retry")
"""

SLEEP = "import sys, time; time.sleep(float(sys.argv[1])); print('woke')"


class _Base(Module):
    def parse(self, unit, results, ctx):
        out = results[0].stdout().strip() if results else ""
        return ModuleResult(summary=out or "done", artifacts={"stdout": out})


class Echo(_Base):
    meta = ModuleMeta(id="test.echo", version="1", description="echo", stage=Stage.RECON, safety=Safety.ACTIVE_SAFE,
                      timeout_seconds=20, tools=PY, retry=NO_RETRY, config_defaults={"log": "", "greeting": "hello"})

    def build_commands(self, unit, ctx):
        return [Command("echo", ["-c", ECHO, ctx.address, ctx.options["log"]], tool="py", targets=[ctx.address])]


class Fail(_Base):
    meta = ModuleMeta(id="test.fail", version="1", description="always fails", stage=Stage.RECON,
                      safety=Safety.ACTIVE_SAFE, timeout_seconds=20, tools=PY)

    def build_commands(self, unit, ctx):
        return [Command("fail", ["-c", "import sys; print('boom', file=sys.stderr); sys.exit(3)"], tool="py")]


class After(_Base):
    meta = ModuleMeta(id="test.after", version="1", description="depends on fail", stage=Stage.ENUMERATION,
                      safety=Safety.PASSIVE, timeout_seconds=20, depends_on=("test.fail",))

    def build_commands(self, unit, ctx):
        return []


class AfterEcho(Module):
    meta = ModuleMeta(id="test.after_echo", version="1", description="reads upstream echo output",
                      stage=Stage.ENUMERATION, safety=Safety.PASSIVE, timeout_seconds=20, depends_on=("test.echo",),
                      categories=("http",))

    def build_commands(self, unit, ctx):
        return []

    def parse(self, unit, results, ctx):
        upstream = ctx.upstream.get("test.echo", [])
        return ModuleResult(summary=f"saw {upstream[0]['summary']}" if upstream else "no upstream")


class Flaky(_Base):
    meta = ModuleMeta(id="test.flaky", version="1", description="transient failure once", stage=Stage.RECON,
                      safety=Safety.ACTIVE_SAFE, timeout_seconds=20, tools=PY,
                      retry=RetryPolicy(max_attempts=3, backoff_seconds=0), config_defaults={"marker": ""})

    def build_commands(self, unit, ctx):
        return [Command("flaky", ["-c", FLAKY, ctx.options["marker"]], tool="py")]


class Slow(_Base):
    meta = ModuleMeta(id="test.slow", version="1", description="sleeps", stage=Stage.RECON, safety=Safety.ACTIVE_SAFE,
                      timeout_seconds=30, tools=PY, retry=NO_RETRY, config_defaults={"seconds": 30})

    def build_commands(self, unit, ctx):
        return [Command("sleep", ["-c", SLEEP, str(ctx.options["seconds"])], tool="py")]


class OffScope(_Base):
    meta = ModuleMeta(id="test.offscope", version="1", description="contacts an out-of-scope host",
                      stage=Stage.RECON, safety=Safety.ACTIVE_SAFE, timeout_seconds=20, tools=PY, retry=NO_RETRY)

    def build_commands(self, unit, ctx):
        return [Command("leak", ["-c", "print('should never run')"], tool="py", targets=["8.8.8.8"])]


class Noisy(_Base):
    meta = ModuleMeta(id="test.noisy", version="1", description="noisy", stage=Stage.ENUMERATION,
                      safety=Safety.ACTIVE_NOISY, timeout_seconds=20)

    def build_commands(self, unit, ctx):
        return []


class Intrusive(_Base):
    meta = ModuleMeta(id="test.intrusive", version="1", description="intrusive", stage=Stage.ENUMERATION,
                      safety=Safety.INTRUSIVE, timeout_seconds=20)

    def build_commands(self, unit, ctx):
        return []


class Prohibited(_Base):
    meta = ModuleMeta(id="test.prohibited", version="1", description="never automatic", stage=Stage.ENUMERATION,
                      safety=Safety.PROHIBITED_AUTO, timeout_seconds=20)

    def build_commands(self, unit, ctx):
        return []


class NeedsMissing(_Base):
    meta = ModuleMeta(id="test.needs_missing", version="1", description="needs a missing tool", stage=Stage.RECON,
                      safety=Safety.ACTIVE_SAFE, timeout_seconds=20, tools=(ToolRequirement("nonexistent"),))

    def build_commands(self, unit, ctx):
        return []
