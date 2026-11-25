import json
from pathlib import Path

import pytest

from aiszx.core.errors import ConfigError, NotFoundError
from aiszx.tools import dependency_checker, nmap_privileges, store
from aiszx.tools.installer import Installer
from aiszx.tools.inventory import BROKEN, INCOMPATIBLE, MISSING, OK, Installation, Inventory, ToolInventory, ToolStatus
from aiszx.tools.registry import load_registry
from aiszx.tools.versions import compare, extract_version, parse_version, satisfies, upstream_version

GETCAP_NEW = "/usr/lib/nmap/nmap cap_net_admin,cap_net_bind_service,cap_net_raw=eip"
GETCAP_OLD = "/usr/bin/nmap = cap_net_raw,cap_net_admin+eip"


# --- versions ------------------------------------------------------------------

@pytest.mark.parametrize("raw, expected", [
    ("7.94", (7, 94)),
    ("1:7.94+git20230807.3be01efb1+dfsg-3+b1", (7, 94)),
    ("v2.10.4", (2, 10, 4)),
    ("4.19.5-Debian", (4, 19, 5)),
    ("abc", None),
    (None, None),
])
def test_parse_version(raw, expected):
    assert parse_version(raw) == expected


@pytest.mark.parametrize("raw, expected", [
    ("1:2.6.0-0parrot2", "2.6.0"),
    ("1:2.75-10+deb13u1+b1", "2.75"),
    ("20230525.1+git20230720-0parrot2", "20230525.1+git20230720"),
    ("1.7+parrot1", "1.7+parrot1"),
    ("1.3.0", "1.3.0"),
    (None, None),
])
def test_upstream_version(raw, expected):
    assert upstream_version(raw) == expected


def test_compare_and_satisfies():
    assert compare("7.94", "7.80") == 1
    assert compare("7.80", "7.80.0") == 0
    assert compare("7.9", "7.80") == -1
    assert satisfies("7.94", "7.80") is True
    assert satisfies("7.70", "7.80") is False
    assert satisfies(None, "7.80") is None
    assert satisfies("1.0", None) is True


def test_extract_version():
    assert extract_version("Nmap version 7.94 ( https://nmap.org )", r"Nmap version (\d+\.\d+)") == "7.94"
    assert extract_version("feroxbuster 2.10.4\n") == "2.10.4"
    assert extract_version("no digits here") is None


# --- registry ------------------------------------------------------------------

def test_shipped_registry_is_valid():
    reg = load_registry()
    assert {"nmap", "netexec", "eyewitness", "getcap"} <= set(reg.tools)
    assert reg.tools["netexec"].binaries == ("nxc", "netexec")
    assert reg.tools["nmap"].min_version == "7.80"
    assert "recon.nmap" in reg.capabilities_for("nmap")
    for cap in reg.capabilities.values():
        assert all(t in reg.tools for t in cap.tools)


def test_user_registry_override(test_registry_dir, tmp_path):
    user = tmp_path / "usercfg"
    user.mkdir()
    (user / "tools.yaml").write_text(
        "tools:\n  nmap:\n    min_version: '7.90'\n  mytool:\n    description: custom\n    binaries: [mytool]\n",
        encoding="utf-8")
    reg = load_registry(shipped_dir=test_registry_dir, user_config_dir=user)
    assert reg.tools["nmap"].min_version == "7.90"
    assert reg.tools["nmap"].apt == "nmap"  # merged, not replaced
    assert reg.tools["mytool"].install_preference == ()
    assert len(reg.sources) == 2


def test_unknown_tool_suggests(test_registry_dir):
    reg = load_registry(shipped_dir=test_registry_dir)
    with pytest.raises(NotFoundError, match="did you mean nmap"):
        reg.get("nmapp")


@pytest.mark.parametrize("override, fragment", [
    ("capabilities:\n  x: {description: d, requires: [nope]}\n", "unknown tool"),
    ("tools:\n  bad: {description: d}\n", "binaries"),
    ("tools:\n  nmap: {version_regex: '('}\n", "regular expression"),
    ("tools:\n  bad: {description: d, binaries: [b], install_preference: [pipx]}\n", "'pipx' is not set"),
    ("tools:\n  nmap: {colour: blue}\n", "unknown key"),
    ("tools:\n  nmap: {min_version: latest}\n", "not a version"),
    ("capabilities:\n  x: {description: d}\n", "requires"),
])
def test_invalid_registry(test_registry_dir, tmp_path, override, fragment):
    user = tmp_path / "usercfg"
    user.mkdir()
    (user / "tools.yaml").write_text(override, encoding="utf-8")
    with pytest.raises(ConfigError, match=fragment):
        load_registry(shipped_dir=test_registry_dir, user_config_dir=user)


# --- inventory -----------------------------------------------------------------

def build_lab(fakehost, fakerunner, *, nmap_version="7.94", pyenv27=True, geckodriver=False):
    h = fakehost
    nmap = h.exe(h.bin / "nmap")
    h.exe(h.bin / "dpkg-query")
    h.exe(h.bin / "eyewitness")
    if geckodriver:
        h.exe(h.bin / "geckodriver")
    # pipx-installed netexec
    venv = h.home / ".local/share/pipx/venvs/netexec"
    h.exe(venv / "bin" / "nxc")
    (venv / "pipx_metadata.json").write_text(json.dumps(
        {"main_package": {"package": "netexec", "package_version": "1.3.0"}, "python_version": "Python 3.11.11"}))
    h.add_path(venv / "bin")
    # go-installed gobuster (not on PATH, found via search_dirs)
    h.exe(h.home / "go" / "bin" / "gobuster")
    # git checkout of a Python 2 tool
    repo = h.home / "tools" / "legacy"
    (repo / "legacy.py").parent.mkdir(parents=True)
    (repo / "legacy.py").write_text("print 'hi'\n")
    (repo / ".git" / "refs" / "heads").mkdir(parents=True)
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (repo / ".git" / "refs" / "heads" / "main").write_text("abcdef1234567890abcdef\n")
    if pyenv27:
        h.exe(h.home / ".pyenv" / "versions" / "2.7.18" / "bin" / "python")
        h.exe(h.home / ".pyenv" / "versions" / "3.11.11" / "bin" / "python")

    fakerunner.on("dpkg-query", "-S", stdout=f"nmap: {nmap}\n")
    fakerunner.on("dpkg-query", "-W", stdout=(
        "nmap\tii \t7.94+git20230807-3\n"
        "whatweb\tii \t0.5.5-1\n"          # installed, but its binary is missing → broken
        "eyewitness\tii \t20230525.1-0kali1\n"
        "gobuster\tun \t\n"
    ))
    fakerunner.on("nmap", "--version", stdout=f"Nmap version {nmap_version} ( https://nmap.org )\n")
    return h


@pytest.fixture
def registry(test_registry_dir):
    return load_registry(shipped_dir=test_registry_dir)


def detect(registry, fakehost, fakerunner, names=None):
    return ToolInventory(registry, fakerunner, fakehost.host()).detect(names)


def test_inventory_classifies_sources(registry, fakehost, fakerunner):
    build_lab(fakehost, fakerunner)
    fakerunner.on("getcap", stdout="")
    inv = detect(registry, fakehost, fakerunner)
    t = inv.tools

    assert (t["nmap"].status, t["nmap"].source, t["nmap"].package, t["nmap"].version) == (OK, "apt", "nmap", "7.94")
    assert t["nmap"].detail["version_source"] == "command"

    assert (t["netexec"].status, t["netexec"].source, t["netexec"].version) == (OK, "pipx", "1.3.0")
    assert t["netexec"].detail["version_source"] == "pipx package"

    assert (t["gobuster"].status, t["gobuster"].source) == (OK, "go")
    assert any("not on PATH" in n for n in t["gobuster"].notes)

    legacy = t["legacy"]
    assert (legacy.status, legacy.source, legacy.primary.commit) == (OK, "git", "abcdef123456")
    assert legacy.launch[0].endswith(str(Path("2.7.18") / "bin" / "python"))

    assert t["whatweb"].status == BROKEN
    assert "installed but none of whatweb was found" in t["whatweb"].problems[0]

    assert t["eyewitness"].status == BROKEN
    assert "geckodriver" in t["eyewitness"].problems[0]

    assert inv.complete and inv.dpkg_available
    assert [i.version for i in inv.interpreters if i.kind == "pyenv"] == ["3.11.11", "2.7.18"]


def test_missing_tool_reasons(registry, fakehost, fakerunner):
    fakehost.exe(fakehost.bin / "dpkg-query")
    fakerunner.on("dpkg-query", "-W", stdout="nmap\tun \t\n")
    st = detect(registry, fakehost, fakerunner, ["nmap"]).tools["nmap"]
    assert st.status == MISSING
    assert "looked for [nmap]" in st.problems[0]
    assert "APT package nmap is not installed" in st.problems[1]
    assert st.capabilities == ["recon.nmap"]


def test_incompatible_version(registry, fakehost, fakerunner):
    build_lab(fakehost, fakerunner, nmap_version="7.70")
    st = detect(registry, fakehost, fakerunner, ["nmap"]).tools["nmap"]
    assert st.status == INCOMPATIBLE and "older than the required 7.80" in st.problems[0]


def test_tool_that_cannot_execute_is_broken(registry, fakehost, fakerunner):
    build_lab(fakehost, fakerunner)
    fakerunner.on("nmap", "--version", error="PermissionError: denied")
    st = detect(registry, fakehost, fakerunner, ["nmap"]).tools["nmap"]
    assert st.status == BROKEN and "cannot execute" in st.problems[0]
    assert st.version == "7.94+git20230807"  # falls back to the package's upstream version
    assert st.detail["package_version"] == "7.94+git20230807-3"


def test_version_from_owning_package_with_different_name(registry, fakehost, fakerunner):
    # e.g. Parrot's searchsploit binary belongs to a package other than the registry's `apt` name
    ww = fakehost.exe(fakehost.bin / "whatweb")
    fakehost.exe(fakehost.bin / "dpkg-query")
    fakerunner.on("dpkg-query", "-S", stdout=f"ruby-whatweb: {ww}\n")
    fakerunner.on("dpkg-query", "-W", stdout="whatweb\tun \t\nruby-whatweb\tii \t1:0.5.5-2\n")
    st = detect(registry, fakehost, fakerunner, ["whatweb"]).tools["whatweb"]
    assert (st.status, st.source, st.package, st.version) == (OK, "apt", "ruby-whatweb", "0.5.5")
    assert any(c[1] == "-W" and "ruby-whatweb" in c for c in fakerunner.calls)


def test_timeout_is_broken(registry, fakehost, fakerunner):
    build_lab(fakehost, fakerunner)
    fakerunner.on("nmap", "--version", timed_out=True)
    assert detect(registry, fakehost, fakerunner, ["nmap"]).tools["nmap"].status == BROKEN


def test_missing_interpreter_is_broken(registry, fakehost, fakerunner):
    build_lab(fakehost, fakerunner, pyenv27=False)
    st = detect(registry, fakehost, fakerunner, ["legacy"]).tools["legacy"]
    assert st.status == BROKEN and "pyenv:2.7" in st.problems[0]


def test_duplicate_installations_reported(registry, fakehost, fakerunner):
    build_lab(fakehost, fakerunner)
    fakehost.exe(fakehost.home / ".local" / "bin" / "nmap")
    st = detect(registry, fakehost, fakerunner, ["nmap"]).tools["nmap"]
    assert len(st.installations) == 2 and st.primary.on_path
    assert any("2 installations found" in n for n in st.notes)


def test_works_without_dpkg(registry, fakehost, fakerunner):
    fakehost.exe(fakehost.bin / "nmap")
    fakerunner.on("nmap", "--version", stdout="Nmap version 7.94\n")
    inv = detect(registry, fakehost, fakerunner, ["nmap"])
    assert inv.tools["nmap"].status == OK and inv.tools["nmap"].source == "path"
    assert not inv.dpkg_available


# --- capabilities --------------------------------------------------------------

def test_capability_readiness(registry, fakehost, fakerunner):
    build_lab(fakehost, fakerunner)
    caps = {c.name: c for c in dependency_checker.evaluate(registry, detect(registry, fakehost, fakerunner))}
    assert caps["recon.nmap"].state == dependency_checker.READY
    assert caps["http.content"].state == dependency_checker.DEGRADED  # gobuster ok, whatweb/eyewitness broken
    assert "whatweb" in caps["http.content"].message
    assert caps["legacy.cap"].state == dependency_checker.READY


def test_capability_unavailable(registry, fakehost, fakerunner):
    caps = {c.name: c for c in dependency_checker.evaluate(registry, detect(registry, fakehost, fakerunner))}
    assert caps["recon.nmap"].state == dependency_checker.UNAVAILABLE
    assert caps["http.content"].message == "needs one of gobuster, whatweb"


# --- nmap privileges -----------------------------------------------------------

@pytest.mark.parametrize("output, caps, flags", [
    (GETCAP_NEW, {"cap_net_admin", "cap_net_bind_service", "cap_net_raw"}, "eip"),
    (GETCAP_OLD, {"cap_net_raw", "cap_net_admin"}, "eip"),
    ("", set(), ""),
])
def test_parse_getcap(output, caps, flags):
    assert nmap_privileges.parse_getcap(output) == (caps, flags)


@pytest.mark.parametrize("output, mode", [
    (GETCAP_NEW, nmap_privileges.MODE_CAPS),
    (GETCAP_OLD, nmap_privileges.MODE_CAPS),
    ("/usr/bin/nmap cap_net_raw=ep", nmap_privileges.MODE_UNPRIVILEGED),  # cap_net_admin missing
    ("", nmap_privileges.MODE_UNPRIVILEGED),
])
def test_nmap_privilege_modes(fakehost, fakerunner, output, mode):
    fakehost.exe(fakehost.bin / "getcap")
    fakerunner.on("getcap", stdout=output)
    priv = nmap_privileges.check(fakerunner, fakehost.host(), "/usr/bin/nmap")
    if nmap_privileges.HostEnv.is_root():
        pytest.skip("running as root")
    assert priv.mode == mode
    assert priv.raw_sockets == (mode == nmap_privileges.MODE_CAPS)


def test_nmap_privileges_recorded_in_inventory(registry, fakehost, fakerunner):
    build_lab(fakehost, fakerunner)
    fakehost.exe(fakehost.bin / "getcap")
    fakerunner.on("getcap", stdout=GETCAP_NEW)
    st = detect(registry, fakehost, fakerunner, ["nmap"]).tools["nmap"]
    assert st.detail["privileges"]["mode"] in (nmap_privileges.MODE_CAPS, nmap_privileges.MODE_ROOT)


def test_setcap_commands():
    assert nmap_privileges.apply_command("/usr/lib/nmap/nmap") == [
        "sudo", "setcap", "cap_net_raw,cap_net_admin,cap_net_bind_service+eip", "/usr/lib/nmap/nmap"]
    assert nmap_privileges.remove_command("/x") == ["sudo", "setcap", "-r", "/x"]


# --- installer -----------------------------------------------------------------

def make_inventory(**statuses):
    tools = {}
    for name, spec in statuses.items():
        status, *rest = spec if isinstance(spec, tuple) else (spec,)
        st = ToolStatus(name, name, status=status, problems=[f"{name} is {status}"])
        if rest:
            source, package, version = rest
            st.installations = [Installation(f"/usr/bin/{name}", f"/usr/bin/{name}", True, source, package)]
            st.version = version
        tools[name] = st
    return Inventory("2026-11-25T00:00:00Z", tools, [], True, True)


@pytest.fixture
def installer_host(fakehost, fakerunner):
    for exe in ("apt-get", "apt-cache", "pipx", "git"):
        fakehost.exe(fakehost.bin / exe)
    fakerunner.on("apt-cache", "policy", stdout=(
        "whatweb:\n  Installed: (none)\n  Candidate: 0.5.5-1\n  Version table:\n"
        "netexec:\n  Installed: (none)\n  Candidate: (none)\n"
        "nmap:\n  Installed: 7.70-1\n  Candidate: 7.94+git-3\n"
    ))
    return fakehost


def test_plan_prefers_apt_when_candidate_exists(registry, installer_host, fakerunner):
    inv = make_inventory(whatweb=MISSING)
    [plan] = Installer(registry, fakerunner, installer_host.host(), inv).plan()
    assert plan.action == "install" and plan.chosen.method == "apt"
    assert plan.chosen.steps == [["sudo", "apt-get", "install", "whatweb"]]
    assert plan.chosen.privileged


def test_plan_falls_back_to_pipx(registry, installer_host, fakerunner):
    [plan] = Installer(registry, fakerunner, installer_host.host(), make_inventory(netexec=MISSING)).plan()
    assert plan.chosen.method == "pipx" and plan.chosen.steps == [["pipx", "install", "netexec"]]
    assert "no APT candidate" in plan.alternatives[0].reason


def test_plan_without_available_method(registry, installer_host, fakerunner):
    [plan] = Installer(registry, fakerunner, installer_host.host(), make_inventory(gobuster=MISSING)).plan()
    assert plan.chosen is None
    assert {a.method for a in plan.alternatives} == {"apt", "go"}
    assert any("Go toolchain not installed" in a.reason for a in plan.alternatives)


def test_plan_git_clone_never_runs_install_scripts(registry, installer_host, fakerunner):
    [plan] = Installer(registry, fakerunner, installer_host.host(), make_inventory(legacy=MISSING)).plan()
    assert plan.chosen.method == "git"
    assert plan.chosen.steps[0][:4] == ["git", "clone", "--depth", "1"]
    assert plan.chosen.steps[0][-1].endswith(str(Path("tools") / "legacy"))
    assert "does not run project install scripts" in plan.chosen.manual[0]


def test_plan_upgrade_and_repair(registry, installer_host, fakerunner):
    inv = make_inventory(nmap=(INCOMPATIBLE, "apt", "nmap", "7.70"), whatweb=(BROKEN,))
    plans = {p.tool: p for p in Installer(registry, fakerunner, installer_host.host(), inv).plan()}
    assert plans["nmap"].action == "upgrade"
    assert plans["nmap"].chosen.steps == [["sudo", "apt-get", "install", "--only-upgrade", "nmap"]]
    assert plans["whatweb"].action == "repair"
    assert plans["whatweb"].chosen.steps == [["sudo", "apt-get", "install", "--reinstall", "whatweb"]]


def test_execute_requires_confirmation(registry, installer_host, fakerunner):
    inst = Installer(registry, fakerunner, installer_host.host(), make_inventory(whatweb=MISSING, netexec=MISSING))
    plans = inst.plan()
    outcomes = inst.execute(plans, confirm=lambda p: p.tool == "netexec")
    assert {o.tool: o.result for o in outcomes} == {"whatweb": "declined", "netexec": "installed"}
    assert fakerunner.interactive_calls == [("pipx", "install", "netexec")]


def test_execute_reports_failure(registry, installer_host, fakerunner):
    inst = Installer(registry, fakerunner, installer_host.host(), make_inventory(whatweb=MISSING))
    fakerunner.interactive_rc = 100
    [outcome] = inst.execute(inst.plan(), confirm=lambda p: True)
    assert outcome.result == "failed" and "exited with 100" in outcome.detail


# --- persistence ---------------------------------------------------------------

def test_store_rows_and_snapshot(db, config, registry, fakehost, fakerunner):
    build_lab(fakehost, fakerunner)
    inv = detect(registry, fakehost, fakerunner)
    caps = dependency_checker.evaluate(registry, inv)
    store.save_inventory(db, inv)
    store.save_capabilities(db, caps, inv.checked_at)
    path = store.write_snapshot(config.data_dir, inv, caps)
    rows = {r["name"]: r for r in store.load_saved(db)}
    assert rows["nmap"]["status"] == OK and rows["whatweb"]["status"] == BROKEN
    assert rows["netexec"]["detail"]["installations"][0]["source"] == "pipx"
    states = {r["capability"]: r["state"] for r in db.query("SELECT capability, state FROM dependency_status")}
    assert states["recon.nmap"] == "ready"
    assert path.is_file() and (path.parent / "latest.json").is_file()

    # a complete re-inventory drops tools that left the registry
    db.execute("INSERT INTO tool_inventory (name, status, checked_at) VALUES ('ghost', 'ok', 'x')")
    store.save_inventory(db, inv)
    assert "ghost" not in {r["name"] for r in store.load_saved(db)}
