# Writing a module

A module is a Python class in `aiszx/modules/<family>/<name>.py`. It is discovered automatically: there's nothing to register. The orchestrator handles scope checks, timeouts, retries, cancellation, checkpoints, evidence and resume. The module only decides **what to run** and **what the output means**.

## Skeleton

```python
from aiszx.modules.base import (Command, Module, ModuleMeta, ModuleResult, RetryPolicy,
                                Safety, Stage, ToolRequirement)


class SshAudit(Module):
    meta = ModuleMeta(
        id="ssh.audit",                       # "<family>.<name>", lowercase
        version="1",                          # bump when output meaning/format changes
        description="SSH algorithms and host keys",
        stage=Stage.ENUMERATION,
        safety=Safety.ACTIVE_SAFE,
        timeout_seconds=120,
        tools=(ToolRequirement("ssh-audit", min_version="3.0"),),
        categories=("ssh",),                  # service categories it handles (Milestone 4+)
        retry=RetryPolicy(max_attempts=2),    # retried on transient errors and timeouts
        config_defaults={"port": 22},         # user-overridable options (config/modules.yaml)
    )

    def build_commands(self, unit, ctx):
        port = str(ctx.options["port"])
        return [Command("audit", ["-j", "-p", port, ctx.address], tool="ssh-audit", targets=[ctx.address])]

    def parse(self, unit, results, ctx):
        raw = results[0].stdout()
        ...                                   # tolerate partial or garbled output
        return ModuleResult(summary="…", artifacts={...}, observations=[{"key": "ssh.weak_kex", "value": [...]}])
```

## Rules

1. **Declare every host a command contacts** in `Command.targets`. The runner checks each one against scope (and the engagement's validity window) right before the process starts, and refuses the command otherwise. A command that sends nothing (e.g. `ip route get`) declares no targets.
2. **Use logical tool names** (`tool="ssh-audit"`), never paths. The runner uses the absolute path from the tool inventory. A missing or unhealthy required tool makes the unit `SKIPPED` with the reason; it never fails mid-run.
3. **`build_commands` and `parse` must be pure.** No subprocesses, sockets or database access. In-process modules return no commands and do their work in `parse`, using `ctx` and `ctx.upstream`.
4. **Secrets** go in `Command.redact` so they never appear in stored command lines or logs. Mark output files that may contain secrets in `ModuleResult.sensitive_files`.
5. **Exit codes:** `ok_exit_codes` lists codes that are results rather than errors (e.g. `ping` exits 1 when there is no reply). Override `classify_failure` for tool-specific error detection.
6. **Safety class:**

   | Class | Meaning |
   |-------|---------|
   | `passive` | Sends nothing to the target. |
   | `active_safe` | Normal enumeration. |
   | `active_noisy` | Brute-force content discovery, vulnerability scanners. |
   | `intrusive` | Explicit approval required every run. |
   | `prohibited_auto` | Never scheduled. |

   Credential attacks and exploitation are never automated.
7. **Resumable modules** (`resumable=True`) get `ctx.previous_attempt_dir` when an interrupted unit is re-run, e.g. to continue an `nmap --resume`.
8. **`depends_on`** orders modules within one run. A dependent unit is skipped if its dependency didn't complete. Completed results of dependencies are in `ctx.upstream[module_id]`.

## What you get for free

- An output directory per attempt, `.../<module>/<unit>/attempt-NN/{raw,parsed}/`. Raw stdout and stderr are streamed to disk, so partial output survives crashes.
- `parsed/result.json` written from your `ModuleResult`.
- Every file hashed (SHA-256) and registered as evidence, including failed attempts.
- Retries with backoff, timeouts that kill the whole process tree, and Ctrl+C handling.
- Checkpoints, so `resume` re-runs your unit only if its outputs are missing or modified, or its inputs, options or `version` changed.
- Per-module log at `<run>/logs/modules/<module>__<unit>.log`.

## Testing

Put sample tool output in `tests/fixtures/` and unit-test `parse()` directly, as in [tests/unit/test_modules_and_settings.py](../tests/unit/test_modules_and_settings.py). Unit tests must not contact real targets. Orchestration behaviour is covered generically in [tests/unit/test_orchestrator.py](../tests/unit/test_orchestrator.py).
