from pathlib import Path

import pytest

from watchtower.core import findings_engine as fe
from watchtower.core import risk_scoring, wifi_scan
from watchtower.core.assessment import assess
from watchtower.core.attck_mapping import TECHNIQUES, url
from watchtower.core.nmap_runner import parse_xml
from watchtower.core.wep_wpa_advisor import wifi_findings

FX = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize("a,b", [("8.9p1", "9.8p1"), ("8.9", "8.9p1"), ("2.4.9", "2.4.49"), ("1.3.5", "1.3.5a"),
                                  ("2016.73", "2016.74"), ("7.7", "7.8")])
def test_version_order(a, b):
    assert fe.version_key(a) < fe.version_key(b)


@pytest.mark.parametrize("raw,clean", [("8.9p1 Ubuntu 3ubuntu0.1", "8.9p1"), ("3.X - 4.X", None), ("", None),
                                       ("2.4.49", "2.4.49"), ("4.X", None)])
def test_clean_version(raw, clean):
    assert fe.clean_version(raw) == clean


def test_dataset_is_well_formed():
    for e in fe.dataset():
        assert e["cve"].startswith("CVE-") and 0 < e["cvss"] <= 10
        assert e["remediation"] and e["description"] and e["title"]
        assert e.get("exact") or e.get("ranges")


def test_dataset_matching():
    assert [e["cve"] for e in fe.match_dataset("vsftpd", "2.3.4")] == ["CVE-2011-2523"]
    assert fe.match_dataset("vsftpd", "3.0.5") == []
    assert {e["cve"] for e in fe.match_dataset("OpenSSH", "8.9p1 Ubuntu")} == {"CVE-2024-6387"}
    assert fe.match_dataset("OpenSSH", "9.8p1") == []
    assert {e["cve"] for e in fe.match_dataset("OpenSSH", "7.4")} == {"CVE-2018-15473"}
    assert {e["cve"] for e in fe.match_dataset("Apache httpd", "2.4.49")} == \
        {"CVE-2021-41773", "CVE-2021-42013", "CVE-2023-25690"}
    assert fe.match_dataset("Samba smbd", "3.X - 4.X") == []


def lab_host():
    return parse_xml((FX / "nmap_lab.xml").read_text()).hosts[0]


def test_host_findings_from_lab_scan():
    fs = fe.host_findings(lab_host())
    titles = {f.title for f in fs}
    assert "vsftpd 2.3.4 backdoor" in titles
    assert "Telnet enabled" in titles
    assert "Docker API exposed without TLS" in titles
    assert "Database port exposed" in titles
    assert any(f.source == "nmap NSE: smb-vuln-ms17-010" and f.cve_id == "CVE-2017-0143" and f.severity == "High"
               for f in fs)
    assert not any(f.port == "8000/tcp" for f in fs)            # filtered ports aren't findings
    assert all(f.remediation for f in fs)
    assert all(t in TECHNIQUES for f in fs for t in f.attck)
    ssh = next(f for f in fs if f.cve_id == "CVE-2024-6387")
    # banner revision 3ubuntu0.1 is older than Ubuntu's fix 3ubuntu0.10 (USN-6859-1)
    assert ssh.patch_check["verdict"] == "vulnerable" and ssh.severity == "High" and not ssh.patched
    assert "not installed" in ssh.confidence


def test_nse_not_vulnerable_ignored():
    from watchtower.core.nmap_runner import Script
    out = fe.nse_findings("h", "h", None, [Script("x", "NOT VULNERABLE: fine"), Script("y", "false")])
    assert out == []


def net(security, auth=None, wps=None, ssid="MyNet", cipher=None):
    return {"bssid": "AA:BB:CC:00:00:01", "ssid": ssid, "security": security, "auth": auth, "wps": wps,
            "cipher": cipher, "authorized": 1}


@pytest.mark.parametrize("n,expected", [
    (net("Open", "OPN"), {"Open network: no encryption"}),
    (net("WEP"), {"WEP encryption (broken)"}),
    (net("WPA/WPA2", "PSK", cipher="TKIP CCMP"),
     {"WPA1 / TKIP enabled", "WPA2-Personal: exposed to offline passphrase guessing"}),
    (net("WPA2", "PSK"), {"WPA2-Personal: exposed to offline passphrase guessing"}),
    (net("WPA2/WPA3", "SAE PSK"), {"WPA2/WPA3 transition mode: downgrade possible"}),
    (net("WPA3", "SAE"), set()),
    (net("WPA2-Enterprise", "MGT"), {"WPA-Enterprise (802.1X): check client certificate validation"}),
    (net("WPA2", "PSK", wps=1), {"WPA2-Personal: exposed to offline passphrase guessing",
                                 "WPS (Wi-Fi Protected Setup) enabled"}),
    (net("WPA3", "SAE", ssid="NETGEAR42"), {"Factory-default network name"}),
    (net("WPA3", "SAE", ssid=""), {"Hidden SSID (no real protection)"}),
])
def test_wifi_advisor(n, expected):
    fs = wifi_findings(n)
    assert {f.title for f in fs} == expected
    for f in fs:
        assert f.remediation and f.kind == "wifi"
        if f.severity in ("Critical", "High", "Medium"):
            assert f.technique


def test_wifi_advisor_on_parsed_scans():
    for ap in wifi_scan.parse_iw_scan((FX / "iw_scan.txt").read_text()):
        n = {**ap.__dict__}
        assert all(f.remediation for f in wifi_findings(n))


def test_risk_ranking():
    host = fe.host_findings(lab_host())
    wifi = wifi_findings(net("WEP"))
    risks = risk_scoring.rank(host + wifi, {"192.168.56.101": 7})
    assert risks[0].device == "192.168.56.101" and risks[0].score == 100
    wep = next(r for r in risks if r.kind == "wifi")
    assert 70 <= wep.score <= 100 and wep.worst == "Critical"
    assert risk_scoring.score([], 0) == 0


def test_assessment_dedups_and_filters_unauthorized():
    scans = [{"id": 1, "raw_output": (FX / "nmap_lab.xml").read_text()}]
    nets = [net("WEP"), {**net("Open", "OPN"), "bssid": "AA:BB:CC:00:00:02", "authorized": 0}]
    a = assess(scans, nets)
    assert a.hosts_assessed == 1 and a.networks_assessed == 1
    vsftpd = [f for f in a.findings if "CVE-2011-2523" in f.cve_id]
    assert len(vsftpd) == 1 and vsftpd[0].confidence == "confirmed by nmap script"
    assert "ftp-vsftpd-backdoor" in vsftpd[0].source
    keys = [f.key for f in a.findings]
    assert len(keys) == len(set(keys))
    assert a.findings[0].severity == "Critical"
    assert len(assess(scans, nets, include_unauthorized_wifi=True).risks) == 3


def test_attck_urls():
    assert url("T1557.004") == "https://attack.mitre.org/techniques/T1557/004/"



@pytest.mark.parametrize("version,verdict", [
    ("8.9p1 Ubuntu 3ubuntu0.10", "patched"),
    ("8.9p1 Ubuntu 3ubuntu0.13", "patched"),
    ("8.9p1 Ubuntu 3ubuntu0.6", "vulnerable"),
    ("9.6p1 Ubuntu 3ubuntu13.5", "patched"),
    ("9.2p1 Debian 2+deb12u3", "patched"),
    ("9.2p1 Debian 2+deb12u2", "vulnerable"),
    ("9.0p1 Ubuntu 1ubuntu7", "unknown"),        # no advisory recorded for 9.0p1
    ("8.9p1", "upstream"),
])
def test_distro_patch_status(version, verdict):
    entry = next(e for e in fe.dataset() if e["cve"] == "CVE-2024-6387")
    assert fe.distro_patch_status(entry, version)["verdict"] == verdict


def test_detect_distro():
    assert fe.detect_distro("8.9p1 Ubuntu 3ubuntu0.10") == ("Ubuntu", "3ubuntu0.10")
    assert fe.detect_distro("9.2p1 Debian 2+deb12u3") == ("Debian", "2+deb12u3")
    assert fe.detect_distro("2.4.52", "(Ubuntu)") == ("Ubuntu", "")
    assert fe.detect_distro("2.4.49", "(Unix)") is None


def _host_with(product, version, extrainfo=""):
    from watchtower.core.nmap_runner import Host, Port
    return Host(address="10.0.0.9", status="up", ports=[
        Port("tcp", 22, "open", service="ssh", product=product, version=version, extrainfo=extrainfo)])


def test_patched_finding_is_info_and_not_scored():
    fs = fe.host_findings(_host_with("OpenSSH", "8.9p1 Ubuntu 3ubuntu0.10"))
    f = next(x for x in fs if x.cve_id == "CVE-2024-6387")
    assert f.patched and f.severity == "Info" and "fixed by Ubuntu update" in f.title
    assert f.patch_check["advisory"] == "USN-6859-1"
    assert risk_scoring.score(fs, 1) == 1          # only the open port counts


def test_banner_without_revision_is_unknown():
    from watchtower.core.nmap_runner import Host, Port
    h = Host(address="10.0.0.9", status="up", ports=[
        Port("tcp", 80, "open", service="http", product="Apache httpd", version="2.4.49", extrainfo="(Ubuntu)")])
    f = next(x for x in fe.host_findings(h) if x.cve_id == "CVE-2021-41773")
    assert f.patch_check["verdict"] == "unknown" and not f.patched and "verify" in f.confidence


def test_nse_confirmation_overrides_patched_banner():
    from watchtower.core.nmap_runner import Host, Port, Script
    port = Port("tcp", 22, "open", service="ssh", product="OpenSSH", version="8.9p1 Ubuntu 3ubuntu0.10",
                scripts=[Script("ssh-regresshion", "VULNERABLE:\n  regreSSHion\n  IDs: CVE:CVE-2024-6387")])
    h = Host(address="10.0.0.9", status="up", ports=[port])
    from watchtower.core import assessment
    fs = fe.host_findings(h)
    merged = {}
    for f in fs:
        prev = merged.get(f.key)
        if prev is None:
            merged[f.key] = f
        elif f.kind == "nse":
            assessment.unmark_patched(prev)
    f = merged["10.0.0.9|22/tcp|CVE-2024-6387"]
    assert not f.patched and f.severity == "High"
