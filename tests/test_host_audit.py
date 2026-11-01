from datetime import datetime, timezone
from pathlib import Path

import pytest

from watchtower.core import default_creds, snmp_audit, tls_audit
from watchtower.core.assessment import assess
from watchtower.core.nmap_runner import Host, Port, Script, parse_xml

FX = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 11, 1, 18, 0, tzinfo=timezone.utc)


def test_parse_testssl_real_output():
    issues = {i.id: i for i in tls_audit.parse_testssl((FX / "testssl.json").read_text())}
    assert issues["cipherlist_aNULL"].severity == "Critical"
    assert issues["TLS1"].category == "protocol" and issues["TLS1_1"].severity == "Low"
    assert issues["cert_chain_of_trust"].category == "certificate"
    assert "CVE-2011-3389" in issues["BEAST"].cve
    assert issues["cert_revocation"].severity == "Info"
    assert "cert_notAfter" not in issues and "DNS_CAArecord" not in issues
    assert not any(i.severity == "Info" and i.id not in ("cert_revocation",) for i in issues.values())


def test_parse_sslyze_real_output():
    issues = {i.id: i for i in tls_audit.parse_sslyze((FX / "sslyze.json").read_text(), now=NOW)}
    assert {"TLS 1.0", "TLS 1.1", "cipher_anon", "cert_expiring", "cert_no_san", "cert_untrusted"} <= set(issues)
    assert issues["cipher_anon"].severity == "Critical"
    assert issues["cert_untrusted"].detail == "self-signed"
    assert "SSLv3" not in issues and "heartbleed" not in issues
    expired = {i.id for i in tls_audit.parse_sslyze((FX / "sslyze.json").read_text(),
                                                    now=datetime(2027, 1, 1, tzinfo=timezone.utc))}
    assert "cert_expired" in expired


def test_tls_argv_and_ports():
    backends = tls_audit.backends()
    if "testssl.sh" in backends:
        a = tls_audit.build_argv("testssl.sh", "10.0.0.5", 8443, "/tmp/x.json")
        assert a[-1] == "10.0.0.5:8443" and "--jsonfile" in a
    if "sslyze" in backends:
        a = tls_audit.build_argv("sslyze", "fe80::1", 443, "/tmp/x.json")
        assert a[-1] == "[fe80::1]:443" and "--json_out" in a
    h = Host("10.0.0.5", "up", ports=[
        Port("tcp", 8443, "open", service="http", tunnel="ssl"),
        Port("tcp", 22, "open", service="ssh"), Port("tcp", 993, "open", service="imaps")])
    assert tls_audit.tls_ports(h) == [8443, 993]


def test_tls_findings_have_remediation():
    issues = tls_audit.parse_testssl((FX / "testssl.json").read_text())
    fs = tls_audit.findings("10.0.0.5", "10.0.0.5", 8443, issues, "testssl.sh")
    assert fs and all(f.remediation and f.port == "8443/tcp" and f.kind == "tls" for f in fs)
    assert any(f.severity == "Critical" for f in fs)


def test_snmp_parse_and_findings():
    vals = snmp_audit.parse_snmpget((FX / "snmp_public.txt").read_text())
    assert vals["sysName"] == "labbox" and vals["sysLocation"] == "Lab rack 1" and "Linux" in vals["sysDescr"]
    pub = snmp_audit.attempt_from_output("2c", "public", 0, (FX / "snmp_public.txt").read_text())
    priv = snmp_audit.attempt_from_output("2c", "private", 1, (FX / "snmp_timeout.txt").read_text())
    assert pub.responded and not priv.responded and "Timeout" in priv.error
    fs = snmp_audit.findings("10.0.0.5", "10.0.0.5", [pub, priv])
    assert len(fs) == 1 and fs[0].severity == "High" and "labbox" in fs[0].description and fs[0].weight == 15
    mine = snmp_audit.findings("10.0.0.5", "10.0.0.5", [snmp_audit.SnmpAttempt("2c", "s3cret-lab", True,
                                                                                {"sysName": "x"})])
    assert mine[0].severity == "Low"


def test_snmp_argv_is_get_only_and_validated(monkeypatch):
    monkeypatch.setattr(snmp_audit.deps, "find_binary", lambda *n: "/usr/bin/snmpget")
    a = snmp_audit.build_argv("10.0.0.5", "public", "2c")
    assert a[0].endswith("snmpget") and "udp:10.0.0.5:161" in a and set(snmp_audit.SYS_OIDS) <= set(a)
    assert snmp_audit.build_argv("fe80::1", "public", "1")[a.index("udp:10.0.0.5:161")] == "udp6:[fe80::1]:161"
    for bad in ("has space", "", "x" * 65):
        with pytest.raises(ValueError):
            snmp_audit.build_argv("10.0.0.5", bad)
    with pytest.raises(ValueError):
        snmp_audit.build_argv("10.0.0.5", "public", "3")


@pytest.mark.parametrize("port,expected", [
    (Port("tcp", 22, "open", service="ssh", product="OpenSSH", version="7.9p1 Raspbian 10+deb10u2"), "Raspberry Pi"),
    (Port("tcp", 80, "open", service="http", product="MikroTik router config httpd"), "MikroTik"),
    (Port("tcp", 443, "open", service="https", scripts=[Script("http-title", "pfSense - Login")]), "Netgate"),
    (Port("tcp", 443, "open", service="https", product="Dell iDRAC9 web interface"), "Dell"),
])
def test_default_creds_fingerprints(port, expected):
    h = Host("10.0.0.7", "up", ports=[port])
    fs = default_creds.findings(h)
    assert len(fs) == 1 and fs[0].title.startswith(expected) and fs[0].weight == 15
    assert "not attempted" in fs[0].confidence and fs[0].attck == ["T1078.001"]


def test_default_creds_no_false_positive_on_lab():
    h = parse_xml((FX / "nmap_localhost.xml").read_text()).hosts[0]
    assert default_creds.findings(h) == []


def test_assess_includes_audits_and_default_creds():
    xml = (FX / "nmap_lab.xml").read_text().replace("labbox.lan", "metasploitable")
    rows = [{"kind": "tls", "host": "192.168.56.101", "port": 443, "tool": "testssl.sh",
             "result_json": tls_audit.issues_to_json(tls_audit.parse_testssl((FX / "testssl.json").read_text()))},
            {"kind": "snmp", "host": "192.168.56.101", "port": 161, "tool": "snmpget",
             "result_json": snmp_audit.attempts_to_json([snmp_audit.attempt_from_output(
                 "2c", "public", 0, (FX / "snmp_public.txt").read_text())])}]
    a = assess([{"id": 1, "raw_output": xml}], [], host_audits=rows)
    kinds = {f.kind for f in a.findings}
    assert {"tls", "snmp", "default_creds", "service", "exposure"} <= kinds
    creds = next(f for f in a.findings if f.kind == "default_creds")
    assert "msfadmin" in creds.description
    tls = next(f for f in a.findings if f.kind == "tls")
    assert tls.device_label == "192.168.56.101 (metasploitable)"
