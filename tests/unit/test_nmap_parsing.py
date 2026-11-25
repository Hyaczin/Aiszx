from pathlib import Path

import pytest

from aiszx.classify.classifier import Classifier
from aiszx.core.errors import ConfigError
from aiszx.modules.records import ServiceRecord
from aiszx.parsers.nmap_xml import parse_gnmap_ports, parse_nmap_xml, parse_nmap_xml_file
from aiszx.recon import nmap
from tests import nmap_samples as S

ADDR = "10.129.73.247"


def fmt(xml):
    return xml.format(addr=ADDR, args="nmap -test")


# --- XML parser ---------------------------------------------------------------------

def test_parse_complete_tcp_scan():
    run = parse_nmap_xml(fmt(S.TCP))
    assert run.complete and run.exit_status == "success" and run.version == "7.95" and run.elapsed == 60.0
    host = run.host(ADDR)
    assert [p.port for p in host.ports] == [22, 80, 443, 445, 5985]
    assert host.ports[0].state == "open" and host.ports[0].reason == "syn-ack"
    assert host.extraports == [("closed", 65530)]
    assert run.scaninfo[0]["type"] == "syn"


def test_parse_services_scripts_os_and_cpe():
    host = parse_nmap_xml(fmt(S.SERVICES)).host(ADDR)
    ssh = host.ports[0]
    assert (ssh.service.name, ssh.service.product, ssh.service.conf, ssh.service.method) == ("ssh", "OpenSSH", 10, "probed")
    assert ssh.service.cpes == ["cpe:/a:openbsd:openssh:8.9p1", "cpe:/o:linux:linux_kernel"]
    assert "256 aa:bb (ECDSA)" in ssh.scripts["ssh-hostkey"]
    assert host.ports[2].service.tunnel == "ssl"
    assert host.hostnames == ["box.htb"]
    assert host.os_matches[0] == {"name": "Linux 5.0 - 5.14", "accuracy": 95}


def test_truncated_xml_keeps_finished_hosts_and_is_incomplete():
    run = parse_nmap_xml(fmt(S.TRUNCATED))
    assert not run.complete and run.parse_error
    assert run.hosts == []  # the host element itself was cut; nothing half-parsed is invented


def test_truncated_after_first_host():
    two_hosts = fmt(S.RANGE).split('<host><status state="down"')[0]
    run = parse_nmap_xml(two_hosts)
    assert not run.complete and [h.address for h in run.hosts] == ["10.10.10.5", "10.10.10.7"]


def test_unreadable_and_empty_files(tmp_path):
    assert parse_nmap_xml_file(tmp_path / "missing.xml").parse_error.startswith("cannot read")
    (tmp_path / "e.xml").write_text("")
    assert parse_nmap_xml_file(tmp_path / "e.xml").parse_error.endswith("is empty")
    assert not parse_nmap_xml("not xml at all").complete


def test_failed_scan_is_not_complete():
    xml = fmt(S.TCP).replace('exit="success"', 'exit="error" errormsg="boom"')
    run = parse_nmap_xml(xml)
    assert not run.complete and run.error == "boom"


def test_gnmap_fallback():
    ports = parse_gnmap_ports(S.GNMAP_TCP.format(addr=ADDR, args="x"))[ADDR]
    assert [(p.port, p.state, p.service.name) for p in ports] == [(22, "open", "ssh"), (80, "open", "http"),
                                                                  (8080, "open", "http-proxy")]


# --- classification -----------------------------------------------------------------

@pytest.fixture(scope="module")
def classifier():
    return Classifier.load()


def svc(port, name=None, tunnel=None, product=None, method="probed", conf=10, proto="tcp"):
    return ServiceRecord(ADDR, proto, port, name=name, tunnel=tunnel, product=product, method=method, confidence=conf)


@pytest.mark.parametrize("record, categories, confidence", [
    (svc(80, "http"), ["http"], "high"),
    (svc(443, "http", tunnel="ssl"), ["https"], "high"),
    (svc(8443, "https"), ["https"], "high"),
    (svc(445, "microsoft-ds", method="table", conf=3), ["smb"], "medium"),
    (svc(5985, "http", product="Microsoft HTTPAPI httpd"), ["http", "winrm"], "high"),
    (svc(8080, "http", product="Microsoft HTTPAPI httpd"), ["http"], "high"),  # HTTPAPI off 5985/6 is not WinRM
    (svc(389, "ldap"), ["ldap"], "high"),
    (svc(88, "kerberos-sec"), ["kerberos"], "high"),
    (svc(53, "domain", proto="udp"), ["dns"], "high"),
    (svc(3389, "ms-wbt-server"), ["rdp"], "high"),
    (svc(1433, None, method="table", conf=0), ["mssql"], "low"),          # port hint only
    (svc(31337, "unknown"), ["other"], "low"),
    (svc(8000, "tcpwrapped"), ["http"], "low"),
])
def test_classification(classifier, record, categories, confidence):
    c = classifier.classify(record)
    assert (c.categories, c.confidence) == (categories, confidence)


def test_classifier_user_override(tmp_path):
    (tmp_path / "service_map.yaml").write_text("categories:\n  http:\n    ports: [80, 9999]\n", encoding="utf-8")
    c = Classifier.load(user_config_dir=tmp_path).classify(svc(9999, "unknown"))
    assert c.categories == ["http"]
    (tmp_path / "service_map.yaml").write_text("categories:\n  bad:\n    ports_required: true\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="ports_required"):
        Classifier.load(user_config_dir=tmp_path)


# --- command construction -------------------------------------------------------------

def test_privileges_from_inventory_detail():
    assert nmap.privileges({"nmap": {"privileges": {"mode": "capabilities"}}}) == (["--privileged"], True, "capabilities")
    assert nmap.privileges({"nmap": {"privileges": {"mode": "root"}}}) == ([], True, "root")
    assert nmap.privileges({}) == (["--unprivileged"], False, "unknown")


def test_port_and_rate_args():
    assert nmap.tcp_port_args("all") == ["-p-"]
    assert nmap.tcp_port_args("top:1000") == ["--top-ports", "1000"]
    assert nmap.tcp_port_args("22,80") == ["-p", "22,80"]
    p = nmap.params({"nmap": {"min_rate": 1500, "max_retries": 3}})
    assert nmap.rate_args(p) == ["--max-retries", "3", "--min-rate", "1500"]
    assert nmap.rate_args(nmap.params({})) == ["--max-retries", "2"]
    assert "-6" in nmap.common(nmap.params({}), [], "2001:db8::1")
    assert nmap.outputs(Path("/x"), "tcp") == ["-oA", str(Path("/x") / "raw" / "tcp")]
