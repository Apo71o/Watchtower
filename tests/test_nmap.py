from pathlib import Path

import pytest

from watchtower.core import nmap_runner as nr
from watchtower.core.targets import in_scope, parse_target

FX = Path(__file__).parent / "fixtures"
Q = "Quick (top 1000 TCP ports + versions)"


@pytest.mark.parametrize("expr,size", [
    ("10.0.0.5", 1), ("10.0.0.0/24", 256), ("192.168.1.1-50", 50), ("10.0.0,1.1-9", 9 + 256 * 1 + 0),
    ("router.lan", 1), ("fe80::/120", 256),
])
def test_parse_target(expr, size):
    t = parse_target(expr)
    if not t.is_hostname and "," not in expr:
        assert t.size() == size


@pytest.mark.parametrize("bad", ["", "10.0.0.300", "a b", "1.2.3", "-sS", "http://x"])
def test_parse_target_rejects(bad):
    with pytest.raises(ValueError):
        parse_target(bad)


def test_scope():
    auth = ["192.168.1.0/24", "nas.lan"]
    assert in_scope("192.168.1.10", auth)
    assert in_scope("192.168.1.1-254", auth)
    assert in_scope("NAS.lan", auth)
    assert not in_scope("192.168.2.1", auth)
    assert not in_scope("192.168.0.0/16", auth)
    assert not in_scope("192.168.1.250-2.3".replace("-2.3", ""), ["192.168.1.0/30"])


def test_build_full_freedom_but_in_scope():
    cmd = nr.build("/usr/bin/nmap", "192.168.1.10", Q, vuln=True, os_detect=True,
                   extra="-p 22,80 --script-args http.useragent=x -T3 192.168.1.11", authorized=["192.168.1.0/24"])
    a = cmd.argv
    assert a[0] == "/usr/bin/nmap" and a[-2:] == ["192.168.1.10", "192.168.1.11"]
    assert ["--script", "vuln"] == a[a.index("--script"):a.index("--script") + 2]
    assert "-O" in a and "22,80" in a and "http.useragent=x" in a
    assert cmd.targets == ["192.168.1.10", "192.168.1.11"]


@pytest.mark.parametrize("extra,msg", [
    ("8.8.8.8", "not covered"),
    ("-iL hosts.txt", "-iL is not allowed"),
    ("-iR 100", "-iR is not allowed"),
    ("-b ftp.example.com", "-b is not allowed"),
    ("-sI 203.0.113.9", "not covered"),
    ("--proxies socks4://203.0.113.9:1080", "not covered"),
])
def test_build_refuses_out_of_scope(extra, msg):
    with pytest.raises(nr.ScopeError, match=msg):
        nr.build("nmap", "192.168.1.10", Q, extra=extra, authorized=["192.168.1.0/24"])


def test_build_main_target_must_be_in_scope():
    with pytest.raises(nr.ScopeError):
        nr.build("nmap", "10.9.9.9", Q, authorized=["192.168.1.0/24"])


def test_needs_root_detection(monkeypatch):
    monkeypatch.setattr(nr, "is_elevated", lambda: False)
    monkeypatch.setattr(nr.deps, "has_file_capabilities", lambda p: False)
    assert not nr.build("nmap", "10.0.0.1", Q, authorized=["10.0.0.1"]).needs_root
    assert nr.build("nmap", "10.0.0.1", Q, os_detect=True, authorized=["10.0.0.1"]).needs_root
    assert nr.build("nmap", "10.0.0.1", Q, extra="-sU", authorized=["10.0.0.1"]).needs_root


def test_privileged_flag_with_capabilities(monkeypatch):
    monkeypatch.setattr(nr, "is_elevated", lambda: False)
    monkeypatch.setattr(nr, "is_linux", lambda: True)
    monkeypatch.setattr(nr.deps, "has_file_capabilities", lambda p: True)
    cmd = nr.build("/usr/bin/nmap", "10.0.0.1", Q, os_detect=True, authorized=["10.0.0.1"])
    assert cmd.argv[1] == "--privileged" and not cmd.needs_root


def test_parse_real_xml():
    res = nr.parse_xml((FX / "nmap_localhost.xml").read_text())
    assert len(res.hosts) == 1
    h = res.hosts[0]
    assert h.address == "127.0.0.1" and h.status == "up"
    ports = {p.portid: p for p in h.ports}
    assert ports[8765].state == "open" and ports[8765].service == "http"
    assert ports[8765].product == "SimpleHTTPServer" and "0.6" in ports[8765].version_string
    assert ports[8766].state == "closed"


def test_parse_truncated_xml():
    text = (FX / "nmap_localhost.xml").read_text()
    cut = text[: text.index("</host>") + 7]
    assert nr.parse_xml(cut).hosts[0].address == "127.0.0.1"
    assert nr.parse_xml("").hosts == []


def test_target_store(db):
    from watchtower.storage.audit_log import AuditLog
    from watchtower.storage.scope import TargetStore
    ts = TargetStore(db, AuditLog(db))
    assert ts.add("192.168.1.0/24", note="home")
    assert not ts.add("192.168.1.0/24")
    assert ts.covers("192.168.1.77") and not ts.covers("10.0.0.1")
    with pytest.raises(ValueError):
        ts.add("not a target!")
    ts.remove("192.168.1.0/24")
    assert ts.values() == []
