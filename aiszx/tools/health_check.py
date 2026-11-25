"""Per-tool health check: can it execute, which version is it, is that version acceptable?

* Runs ``version_cmd`` (if defined) through the tool's launch command with a timeout.
  A tool that cannot start or hangs is ``broken``; non-zero exit codes are tolerated as
  long as the tool produced output (many tools exit 1 on ``--version``/``-h``).
* Falls back to the package version (dpkg/pipx) when no version can be parsed.
* Checks companion executables (``health_requires``) and ``min_version``.
* For nmap, also records the raw-socket privilege mode.
"""

from __future__ import annotations

import shlex
from typing import TYPE_CHECKING

from aiszx.core.host import HostEnv
from aiszx.core.process import ProcessRunner
from aiszx.tools import nmap_privileges
from aiszx.tools.registry import ToolSpec
from aiszx.tools.versions import extract_version, satisfies, upstream_version

if TYPE_CHECKING:
    from aiszx.tools.inventory import ToolStatus

SBIN_DIRS = nmap_privileges.SBIN_DIRS


def check_health(spec: ToolSpec, st: "ToolStatus", runner: ProcessRunner, host: HostEnv, timeout: int) -> None:
    from aiszx.tools.inventory import BROKEN, INCOMPATIBLE, OK

    inst = st.primary
    if inst is None or not inst.launch:
        return

    version: str | None = None
    if spec.version_cmd:
        argv = [*inst.launch, *spec.version_cmd]
        res = runner.run(argv, timeout=timeout)
        if res.error:
            st.status = BROKEN
            st.problems.append(f"cannot execute `{shlex.join(argv)}`: {res.error}")
        elif res.timed_out:
            st.status = BROKEN
            st.problems.append(f"`{shlex.join(argv)}` did not finish within {timeout}s")
        else:
            version = extract_version(res.output, spec.version_regex)
            if version:
                st.detail["version_source"] = "command"
            elif not res.output.strip() and res.returncode != 0:
                st.status = BROKEN
                st.problems.append(f"`{shlex.join(argv)}` exited with {res.returncode} and no output")
            else:
                st.notes.append(f"could not parse a version from `{shlex.join(argv)}`")
    if version is None and inst.package_version:
        version = upstream_version(inst.package_version)
        st.detail["version_source"] = f"{inst.source} package"
    if inst.package_version:
        st.detail["package_version"] = inst.package_version
    st.version = version

    for companion in spec.health_requires:
        if host.which(companion, SBIN_DIRS) is None:
            st.status = BROKEN
            st.problems.append(f"required companion executable `{companion}` not found")

    if st.status == OK and spec.min_version:
        ok = satisfies(version, spec.min_version)
        if ok is False:
            st.status = INCOMPATIBLE
            st.problems.append(f"version {version} is older than the required {spec.min_version}")
        elif ok is None:
            st.notes.append(f"version unknown; cannot verify minimum {spec.min_version}")

    if spec.name == "nmap" and st.status in (OK, INCOMPATIBLE):
        st.detail["privileges"] = nmap_privileges.check(runner, host, inst.real_path).to_dict()
