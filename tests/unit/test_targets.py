import json

import pytest
import yaml

from aiszx.core.errors import NotFoundError, ScopeError, ValidationError
from aiszx.targets.scope import EXCLUDE


@pytest.fixture
def lab(services):
    services["scope"].add(services["default"], "10.10.10.0/24")
    return services


def test_add_ip_target_creates_records_and_workspace(lab, layout):
    result = lab["targets"].add("default", "10.10.10.5")
    t = result.target
    assert result.created and t.kind == "ipv4" and t.status == "active"
    assert [a.address for a in t.addresses] == ["10.10.10.5"] and t.addresses[0].in_scope
    ws = layout.target_dir("default", "10.10.10.5")
    assert (ws / "runs").is_dir()
    mirror = yaml.safe_load((ws / "target.yaml").read_text(encoding="utf-8"))
    assert mirror["canonical_id"] == "10.10.10.5"


def test_add_is_idempotent_and_deduplicates_variants(lab):
    first = lab["targets"].add("default", "10.10.10.5")
    second = lab["targets"].add("default", " 10.10.10.5 ")
    assert first.created and not second.created
    assert first.target.id == second.target.id
    assert len(lab["targets"].list(lab["default"])) == 1


def test_out_of_scope_refused_and_nothing_written(lab, layout):
    with pytest.raises(ScopeError, match="out of scope"):
        lab["targets"].add("default", "10.10.99.5")
    assert lab["targets"].find(lab["default"], "10.10.99.5") is None
    assert not layout.target_dir("default", "10.10.99.5").exists()


def test_excluded_target_refused(lab):
    lab["scope"].add(lab["default"], "10.10.10.1", EXCLUDE)
    with pytest.raises(ScopeError, match="excluded"):
        lab["targets"].add("default", "10.10.10.1")


def test_add_with_scope_flag_adds_exact_rule(services):
    result = services["targets"].add("default", "10.10.50.5", add_to_scope=True)
    assert result.scope_rule_added == "include ip 10.10.50.5"
    assert [r.value for r in services["scope"].rules(services["default"])] == ["10.10.50.5"]


def test_scope_flag_does_not_override_exclusion(services):
    services["scope"].add(services["default"], "10.10.50.5", EXCLUDE)
    with pytest.raises(ScopeError):
        services["targets"].add("default", "10.10.50.5", add_to_scope=True)
    # the include rule added inside the failed transaction must be rolled back
    assert [r.action for r in services["scope"].rules(services["default"])] == ["exclude"]


def test_hostname_resolution_recorded(lab, resolver):
    resolver.table["app.lab.local"] = ["10.10.10.20"]
    t = lab["targets"].add("default", "App.Lab.Local").target
    assert t.canonical == "app.lab.local"
    assert [(a.address, a.source, a.in_scope) for a in t.addresses] == [("10.10.10.20", "dns", True)]


def test_hostname_resolving_out_of_scope_refused(lab, resolver):
    lab["scope"].add(lab["default"], "app.lab.local")
    resolver.table["app.lab.local"] = ["10.10.10.20", "93.184.216.34"]
    with pytest.raises(ScopeError, match="93.184.216.34"):
        lab["targets"].add("default", "app.lab.local")


def test_hostname_readdress_keeps_history(lab, resolver):
    resolver.table["app.lab.local"] = ["10.10.10.20"]
    lab["targets"].add("default", "app.lab.local")
    resolver.table["app.lab.local"] = ["10.10.10.21"]
    # force a later timestamp for the second resolution
    lab["targets"].db.execute("UPDATE target_addresses SET last_seen = '2000-01-01T00:00:00Z'")
    t = lab["targets"].add("default", "app.lab.local").target
    assert {a.address for a in t.addresses} == {"10.10.10.20", "10.10.10.21"}
    assert t.current_addresses == ["10.10.10.21"]


def test_no_resolve_skips_dns(lab, resolver):
    lab["scope"].add(lab["default"], "app.lab.local")
    t = lab["targets"].add("default", "app.lab.local", resolve=False).target
    assert resolver.calls == [] and t.addresses == []


def test_same_ip_in_two_engagements_is_isolated(lab, layout):
    other = lab["engagements"].create("htb-other")
    lab["scope"].add(other, "10.10.10.0/24")
    a = lab["targets"].add("default", "10.10.10.5").target
    b = lab["targets"].add("htb-other", "10.10.10.5").target
    assert a.id != b.id
    assert layout.target_dir("default", "10.10.10.5") != layout.target_dir("htb-other", "10.10.10.5")
    assert len(lab["targets"].list(other)) == 1


def test_archive_and_reactivate(lab):
    lab["targets"].add("default", "10.10.10.5")
    t, changed = lab["targets"].archive(lab["default"], "10.10.10.5")
    assert changed and t.status == "archived"
    assert lab["targets"].list(lab["default"]) == []
    assert len(lab["targets"].list(lab["default"], include_archived=True)) == 1
    again = lab["targets"].add("default", "10.10.10.5")
    assert again.reactivated and again.target.status == "active"


def test_purge_removes_records_and_workspace_but_keeps_audit(lab, layout, db):
    lab["targets"].add("default", "10.10.10.5")
    ws = layout.target_dir("default", "10.10.10.5")
    (ws / "runs" / "note.txt").write_text("x")
    lab["targets"].purge(lab["default"], "10.10.10.5")
    assert not ws.exists()
    assert lab["targets"].find(lab["default"], "10.10.10.5") is None
    actions = [r["action"] for r in db.query("SELECT action FROM audit_events ORDER BY id")]
    assert "target.create" in actions and actions[-1] == "target.purge"
    assert not list((layout.trash_dir("default")).glob("*"))


def test_unknown_target_and_engagement(lab):
    with pytest.raises(NotFoundError):
        lab["targets"].get(lab["default"], "10.10.10.99")
    with pytest.raises(NotFoundError):
        lab["targets"].add("nope", "10.10.10.5")


def test_engagement_validity_bounds(services):
    eng = services["engagements"].create("past", valid_from="2020-01-01", valid_until="2020-12-31")
    assert eng.validity() == "expired"
    assert eng.valid_until == "2020-12-31T23:59:59Z"
    with pytest.raises(ValidationError):
        services["engagements"].create("bad", valid_from="2021-01-02", valid_until="2021-01-01")


def test_scope_change_refresh_flags(lab):
    lab["targets"].add("default", "10.10.10.5")
    lab["scope"].add(lab["default"], "10.10.10.5", EXCLUDE)
    results = lab["targets"].refresh_scope_flags(lab["default"])
    assert [(t.canonical, d.in_scope) for t, d in results] == [("10.10.10.5", False)]
    t = lab["targets"].get(lab["default"], "10.10.10.5")
    assert t.addresses[0].in_scope is False


def test_scope_import_validates_before_writing(services, tmp_path):
    bad = tmp_path / "scope.yaml"
    bad.write_text("include:\n  - 10.10.10.0/24\n  - not_a_host\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        services["scope"].import_file(services["default"], bad)
    assert services["scope"].rules(services["default"]) == []

    good = tmp_path / "good.yaml"
    good.write_text("include:\n  - 10.10.10.0/24\n  - value: '*.lab.local'\n    note: vhosts\nexclude:\n  - 10.10.10.1\n",
                    encoding="utf-8")
    result = services["scope"].import_file(services["default"], good)
    assert len(result.added) == 3
    services["scope"].write_mirror(services["default"])


def test_audit_records_scope_changes(services, db):
    services["scope"].add(services["default"], "10.10.10.0/24", note="lab")
    row = db.query_one("SELECT actor, action, detail_json FROM audit_events WHERE action = 'scope.add'")
    assert row["actor"] == "tester"
    assert json.loads(row["detail_json"])["rule"]["value"] == "10.10.10.0/24"
