"""Shared behaviour of the nmap modules: XML loading, failure classification."""

from __future__ import annotations

import re

from aiszx.modules.base import PERMANENT, Command, CommandResult, Module, RunContext
from aiszx.parsers.nmap_xml import NmapRun, parse_nmap_xml_file

_PRIV_RE = re.compile(r"requires root privileges|Operation not permitted|socket troubles", re.IGNORECASE)


class NmapModule(Module):
    output_name: str = "nmap"

    def load(self, ctx: RunContext) -> NmapRun:
        return parse_nmap_xml_file(ctx.attempt_dir / "raw" / f"{self.output_name}.xml")

    def classify_failure(self, command: Command, result: CommandResult):
        failure = super().classify_failure(command, result)
        if failure and failure[0] == PERMANENT and _PRIV_RE.search(result.stderr(64_000)):
            return PERMANENT, ("nmap lacks raw-socket privileges for this scan; run "
                               "`python3 pentest.py tools nmap-caps --apply` (or use a connect scan)")
        return failure

    @staticmethod
    def completeness(run: NmapRun) -> list[str]:
        problems = []
        if run.parse_error:
            problems.append(f"nmap XML incomplete ({run.parse_error}); results contain only hosts finished before the cut")
        elif not run.complete:
            problems.append(f"nmap did not report a successful finish (exit={run.exit_status}, error={run.error})")
        return problems
