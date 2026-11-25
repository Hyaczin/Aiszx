import pytest

from aiszx.core.errors import ConfigError, NotFoundError, ValidationError
from aiszx.modules.base import ModuleMeta, Safety, Stage
from aiszx.modules.core.connectivity import Connectivity, parse_ping, parse_route
from aiszx.modules.registry import ModuleRegistry, _validate, discover
from aiszx.orchestrator.settings import load_settings

# --- core.connectivity parsing ------------------------------------------------------

ROUTE_TUN = "10.129.73.247 via 10.10.14.1 dev tun0 src 10.10.14.5 uid 1000 \n    cache \n"
ROUTE_LAN = "192.168.1.20 dev eth0 src 192.168.1.10 uid 1000\n"
ROUTE_NONE = "RTNETLINK answers: Network is unreachable\n"
PING_OK = """PING 10.129.73.247 (10.129.73.247) 56(84) bytes of data.
64 bytes from 10.129.73.247: icmp_seq=1 ttl=63 time=25.1 ms
64 bytes from 10.129.73.247: icmp_seq=2 ttl=63 time=27.0 ms

--- 10.129.73.247 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 25.100/26.050/27.000/0.950 ms
"""
PING_NONE = """PING 10.129.73.247 (10.129.73.247) 56(84) bytes of data.

--- 10.129.73.247 ping statistics ---
2 packets transmitted, 0 received, 100% packet loss, time 1023ms
"""


def test_parse_route():
    assert parse_route(ROUTE_TUN) | {"raw": None} == {"routable": True, "dev": "tun0", "via": "10.10.14.1",
                                                      "src": "10.10.14.5", "raw": None}
    lan = parse_route(ROUTE_LAN)
    assert (lan["dev"], lan["via"], lan["src"]) == ("eth0", None, "192.168.1.10")
    assert parse_route(ROUTE_NONE) == {"routable": False, "reason": "RTNETLINK answers: Network is unreachable"}


def test_parse_ping():
    assert parse_ping(PING_OK) == {"sent": 2, "received": 2, "rtt_min_ms": 25.1, "rtt_avg_ms": 26.05, "rtt_max_ms": 27.0}
    assert parse_ping(PING_NONE) == {"sent": 2, "received": 0}
    assert parse_ping("garbage") == {"sent": None, "received": None}


class _R:
    def __init__(self, label, out, err=""):
        self.label, self._out, self._err = label, out, err

    def stdout(self, *a):
        return self._out

    def stderr(self, *a):
        return self._err


def test_connectivity_summary_and_observations():
    mod = Connectivity()
    res = mod.parse(None, [_R("route", ROUTE_TUN), _R("ping", PING_NONE)], None)
    assert "route via tun0" in res.summary and "no ICMP reply" in res.summary and "not proof" in res.summary
    assert {o["key"]: o["value"] for o in res.observations} == {"host.routable": True, "host.icmp_reply": False}
    res = mod.parse(None, [_R("ping", PING_OK)], None)
    assert "ICMP 2/2 replies, avg 26.05 ms" in res.summary
    assert res.limitations == ["`ip` not available: route lookup skipped"]


def test_connectivity_commands_declare_targets():
    class Ctx:
        tool_launch = {"ip": ["/usr/bin/ip"], "ping": ["/usr/bin/ping"]}
        options = {"count": 2, "wait_seconds": 2}

    unit = type("U", (), {"inputs": {"address": "10.129.73.247"}})()
    route, ping = Connectivity().build_commands(unit, Ctx())
    assert route.tool == "ip" and route.targets == ()          # sends no packets
    assert ping.tool == "ping" and list(ping.targets) == ["10.129.73.247"]
    assert ping.argv[-1] == "10.129.73.247"


# --- registry -----------------------------------------------------------------------

def test_builtin_registry():
    reg = discover()
    assert "core.connectivity" in reg.modules
    assert reg.modules["core.connectivity"].meta.safety is Safety.ACTIVE_SAFE


def test_select_by_id_family_and_category_in_dependency_order():
    reg = discover(["tests.orch_modules"])
    assert [m.meta.id for m in reg.select(["test.after_echo", "test.echo"])] == ["test.echo", "test.after_echo"]
    assert {m.meta.id for m in reg.select(["test"])} == set(reg.modules)
    assert [m.meta.id for m in reg.select(["http"])] == ["test.after_echo"]
    with pytest.raises(NotFoundError, match="did you mean test.echo"):
        reg.select(["test.ech"])


def _mod(mid, deps=()):
    class M(Connectivity):
        meta = ModuleMeta(id=mid, version="1", description="", stage=Stage.RECON, safety=Safety.PASSIVE,
                          timeout_seconds=1, depends_on=deps)
    return M()


def test_registry_rejects_cycles_and_unknown_dependencies():
    with pytest.raises(ConfigError, match="cycle"):
        _validate({"a.x": _mod("a.x", ("a.y",)), "a.y": _mod("a.y", ("a.x",))})
    with pytest.raises(ConfigError, match="unknown module"):
        _validate({"a.x": _mod("a.x", ("a.z",))})
    with pytest.raises(ConfigError, match="<family>.<name>"):
        _validate({"Bad": _mod("Bad")})
    assert ModuleRegistry({}).ordered([]) == []


# --- settings layering ---------------------------------------------------------------

def test_shipped_settings_and_effective_config(tmp_path):
    s = load_settings(user_config_dir=None, engagement_dir=None)
    assert set(s.profiles) == {"conservative", "standard", "comprehensive"}
    assert s.profile("conservative").max_safety is Safety.ACTIVE_SAFE
    eff = s.effective(Connectivity())
    assert eff.enabled and eff.options == {"count": 2, "wait_seconds": 2} and eff.timeout == 30
    with pytest.raises(NotFoundError, match="available"):
        s.profile("loud")


def test_user_and_engagement_overrides(tmp_path):
    user = tmp_path / "user"
    user.mkdir()
    (user / "modules.yaml").write_text("modules:\n  core.connectivity:\n    options: {count: 4}\n", encoding="utf-8")
    eng = tmp_path / "eng"
    eng.mkdir()
    (eng / "overrides.yaml").write_text(
        "modules:\n  core.connectivity:\n    timeout: 60\n    retry: {max_attempts: 1}\n"
        "profiles:\n  standard: {description: lab rules, max_safety: active_safe}\n", encoding="utf-8")
    s = load_settings(user_config_dir=user, engagement_dir=eng)
    eff = s.effective(Connectivity())
    assert (eff.options["count"], eff.options["wait_seconds"], eff.timeout, eff.retry.max_attempts) == (4, 2, 60, 1)
    assert s.profile("standard").max_safety is Safety.ACTIVE_SAFE
    assert [x.name for x in s.sources] == ["modules.yaml", "modules.yaml", "profiles.yaml", "overrides.yaml"]


@pytest.mark.parametrize("text, fragment", [
    ("modules:\n  core.connectivity:\n    options: {colour: red}\n", "unknown option"),
    ("modules:\n  core.connectivity:\n    timeout: 0\n", "timeout must be > 0"),
    ("modules:\n  core.connectivity:\n    enable: true\n", "unknown key"),
])
def test_invalid_module_settings(tmp_path, text, fragment):
    (tmp_path / "modules.yaml").write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError, match=fragment):
        load_settings(user_config_dir=tmp_path, engagement_dir=None).effective(Connectivity())


def test_profile_cannot_allow_prohibited(tmp_path):
    (tmp_path / "profiles.yaml").write_text("profiles:\n  wild: {description: x, max_safety: prohibited_auto}\n",
                                            encoding="utf-8")
    with pytest.raises(ConfigError, match="must be one of"):
        load_settings(user_config_dir=tmp_path, engagement_dir=None)


# --- engagement update ---------------------------------------------------------------

def test_engagement_update(services):
    store = services["engagements"]
    eng = store.update("default", max_safety="active_safe", valid_until="2099-12-31", authorisation_ref="HTB")
    assert eng.roe == {"max_safety": "active_safe"} and eng.valid_until == "2099-12-31T23:59:59Z"
    eng = store.update("default", clear=("max_safety", "valid_until"))
    assert eng.roe == {} and eng.valid_until is None
    with pytest.raises(ValidationError):
        store.update("default", max_safety="prohibited_auto")
    with pytest.raises(ValidationError):
        store.update("default", valid_from="2030-01-02", valid_until="2030-01-01")
