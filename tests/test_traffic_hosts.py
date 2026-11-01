"""Per-device network rundown (core/traffic_hosts.py + the activity/endpoint/flow parsing in traffic_audit).

traffic_lan.pcapng is a REAL capture made on the bridge of a small virtual LAN (Linux network
namespaces + veth): router 10.9.0.1 (DNS, HTTP, FTP), "internet" server 203.0.113.10 (HTTP, HTTPS),
10.9.0.23 = Raspberry Pi MAC b8:27:eb:12:34:56, DHCP hostname "homeassistant" (talks to a vendor cloud,
offers Telnet), 10.9.0.42 = Apple MAC 3c:22:fb:ab:cd:ef, DHCP hostname "alice-macbook" (browses, logs in
to the router's FTP and the Pi's Telnet). The *_activity.tsv / *_stats.txt / *_fields.tsv files are
tshark 4.2.2's output for it. HTTP query strings in it carry fake secrets (K3Y-SECRET, S3SS-SECRET).
"""

import json
import shutil
from pathlib import Path

import pytest

from watchtower.core import report
from watchtower.core import traffic_audit as ta
from watchtower.core import traffic_hosts as th
from watchtower.core.assessment import assess
from watchtower.core.nmap_runner import Host, Port

FX = Path(__file__).parent / "fixtures"
NETS = ["10.9.0.0/24"]


def lan_stats(nets=NETS) -> ta.CaptureStats:
    st = ta.parse_stats((FX / "traffic_lan_stats.txt").read_text())
    st.local_nets = list(nets)
    st.activity = ta.parse_activity((FX / "traffic_lan_activity.tsv").read_text(), st.local_nets)
    st.start_epoch = 1793563287.0077
    return st


EVENTS = ta.parse_fields((FX / "traffic_lan_fields.tsv").read_text())


def test_activity_identity_and_requests():
    act = ta.parse_activity((FX / "traffic_lan_activity.tsv").read_text(), NETS)
    pi, mac = act["10.9.0.23"], act["10.9.0.42"]
    assert pi["names"] == ["homeassistant"] and pi["vendor"] == "Raspberry Pi Foundation"
    assert pi["macs"] == ["b8:27:eb:12:34:56"] and pi["dhcp_vendor"].startswith("dhcpcd")
    assert pi["dns"] == {"cloud.camvendor.example": 2, "time.example.net": 1}
    assert pi["sni"] == {"cloud.camvendor.example": 1}
    assert pi["http"] == {"POST cloud.camvendor.example/api/v2/upload": 1}          # query string dropped
    assert mac["names"] == ["alice-macbook"] and mac["vendor"] == "Apple, Inc."
    assert mac["sni"] == {"www.example.com": 1, "updates.example.org": 1}
    assert mac["http"] == {"GET router.lan/admin/status.cgi": 1}
    assert "203.0.113.10" not in act or not act["203.0.113.10"]["macs"]           # router MAC isn't the internet's
    raw = (FX / "traffic_lan_activity.tsv").read_text()
    assert "K3Y-SECRET" in raw and "S3SS-SECRET" in raw                             # tshark's output has them...
    assert "SECRET" not in json.dumps(act)                                          # ...the parsed result doesn't


def test_endpoints_flows_and_server_side():
    st = lan_stats()
    eps = {e.address: e for e in st.endpoints}
    assert (eps["10.9.0.42"].tx_bytes, eps["10.9.0.42"].rx_bytes) == (4698, 6484)
    assert len([f for f in st.flows if f.proto == "tcp"]) == 7
    telnet = next(f for f in st.flows if 23 in (f.a_port, f.b_port))
    assert th.server_side(telnet)[:2] == ("10.9.0.23", 23)
    dhcp = next(f for f in st.flows if 67 in (f.a_port, f.b_port))
    assert th.server_side(dhcp)[:2] == ("255.255.255.255", 67)
    assert ta.stats_from_json(ta.stats_to_json(st)) == st


def test_is_lan():
    assert ta.is_lan("192.168.1.5") and ta.is_lan("10.9.0.23") and ta.is_lan("fe80::1")
    assert not ta.is_lan("203.0.113.10") and not ta.is_lan("8.8.8.8") and not ta.is_lan("224.0.0.251")
    assert not ta.is_lan("255.255.255.255") and not ta.is_lan("127.0.0.1")
    assert ta.is_lan("10.9.0.23", NETS) and not ta.is_lan("10.8.0.1", NETS)


def test_rundown_devices():
    st = lan_stats()
    hosts = th.rundown(st, EVENTS)
    assert [h.ip for h in hosts] == ["10.9.0.42", "10.9.0.23", "10.9.0.1", "203.0.113.10"]   # local first, by volume
    by = {h.ip: h for h in hosts}
    assert not by["203.0.113.10"].local and all(by[i].local for i in ("10.9.0.1", "10.9.0.23", "10.9.0.42"))
    pi, mac, router = by["10.9.0.23"], by["10.9.0.42"], by["10.9.0.1"]
    assert pi.title == "10.9.0.23 (homeassistant)" and mac.vendor == "Apple, Inc."
    assert [(s.port, s.proto, s.peer) for s in pi.services_offered] == [(23, "tcp", "10.9.0.42")]
    assert {(s.peer, s.port) for s in mac.services_used} >= {("10.9.0.1", 21), ("10.9.0.23", 23),
                                                             ("203.0.113.10", 443), ("10.9.0.1", 53)}
    assert {s.port for s in router.services_offered} == {21, 53, 80}
    assert [f.title for f in pi.findings][0] == "Traffic: password sent unencrypted (Telnet)"
    assert any("FTP" in f.title for f in router.findings)
    assert {p.address for p in mac.unicast_peers} == {"203.0.113.10", "10.9.0.1", "10.9.0.23"}
    assert [p.address for p in mac.outside_peers] == ["203.0.113.10"]
    assert th.summary_line(mac).startswith("This device sent 4.6 KB and received 6.3 KB; talked to 3 address(es), "
                                           "1 on the internet; looked up 3 name(s)")
    assert pi.first is not None and pi.last >= pi.first


def test_rundown_with_nmap_and_quiet_devices():
    st = lan_stats()
    nm = Host(address="10.9.0.23", status="up", hostnames=["ha.lan"], mac="B8:27:EB:12:34:56",
              vendor="Raspberry Pi Foundation", ports=[Port("tcp", 8123, "open", service="http", product="aiohttp")])
    quiet = Host(address="10.9.0.77", status="up", mac="AA:BB:CC:00:11:22", vendor="Brother")
    hosts = th.rundown(st, EVENTS, {"10.9.0.23": "10.9.0.23 (ha.lan)"},
                       {"10.9.0.23": (nm, {}), "10.9.0.77": (quiet, {})}, ["10.9.0.77"])
    by = {h.ip: h for h in hosts}
    assert by["10.9.0.23"].title == "10.9.0.23 (ha.lan)" and "ha.lan" in by["10.9.0.23"].names
    assert by["10.9.0.23"].open_ports == ["8123/tcp http"]
    q = by["10.9.0.77"]
    assert not q.seen_in_traffic and q.vendor == "Brother" and "Answered the network scan" in th.summary_line(q)
    assert [h.ip for h in hosts].index("10.9.0.77") == 3          # after the devices that talked


def test_host_markdown_and_brief_show_no_secrets():
    st = lan_stats()
    hosts = th.rundown(st, EVENTS)
    text = "\n".join(th.host_markdown(h, st) for h in hosts)
    for needle in ("### Who it is", "Maker (from MAC) | Raspberry Pi Foundation", "### Services it offered to others",
                   "### Names it looked up (DNS)", "### Encrypted sites it connected to",
                   "`GET router.lan/admin/status.cgi`",
                   "Query strings are not shown", "| 224.0.0.251 | broadcast (your network) |", "UTC –"):
        assert needle in text, needle
    for secret in ("SECRET", "s3cret", "YWRtaW46"):
        assert secret not in text
    row = {"source": "interface:br0", "stats_json": ta.stats_to_json(st)}
    brief = "\n".join(th.host_brief([row], "10.9.0.23"))
    assert "### Traffic seen (br0)" in brief and "cloud.camvendor.example" in brief and "23/tcp" in brief
    assert th.host_brief([row], "10.1.1.1") == []


def test_assess_report_include_devices():
    st = lan_stats()
    cap = {"source": "interface:br0", "stats_json": ta.stats_to_json(st), "events_json": ta.events_to_json(EVENTS)}
    a = assess([], [], captures=[cap])
    html = report.render_html(report.ReportInput(a))
    assert "Devices seen in network traffic (br0)" in html and "10.9.0.23 (homeassistant)" in html
    assert "Raspberry Pi Foundation" in html and "SECRET" not in html and "203.0.113.10</td>" not in html


def test_ping_scan_scope_rules(db):
    ok, why = th.ping_scan_networks(["10.9.0.0/24"], [])
    assert not ok and "isn't in your authorized targets" in why
    ok, why = th.ping_scan_networks(["10.0.0.0/16"], ["10.0.0.0/8"])
    assert not ok and "too large" in why
    assert th.ping_scan_networks(["10.9.0.0/24", "fd00::/64"], ["10.9.0.0/16"]) == (["10.9.0.0/24"], "")
    assert th.ping_scan_networks([], ["0.0.0.0/0"])[0] == []


@pytest.mark.skipif(not shutil.which("nmap"), reason="nmap not installed")
def test_ping_scan_runs_and_is_stored(db):
    from watchtower.core.runner import CommandRunner
    from watchtower.storage.audit_log import AuditLog
    from watchtower.storage.scope import ScanStore
    audit = AuditLog(db)
    scans = ScanStore(db)
    sid, msg = th.ping_scan(CommandRunner(audit), scans, ["127.0.0.1"], "127.0.0.1")
    assert sid and "answered the ping scan" in msg
    assert scans.get(sid)["raw_output"].startswith("<?xml") and "-sn" in scans.get(sid)["command"]
    assert th.ping_scan(CommandRunner(audit), scans, ["127.0.0.1"], "127.0.0.2")[0] is None    # out of scope
    devs = th.devices_from_scans(scans.with_output(), ["127.0.0.0/8"])
    assert "127.0.0.1" not in devs                                          # loopback is never a LAN device


@pytest.mark.skipif(not shutil.which("tshark"), reason="tshark missing")
def test_analyze_pcap_lan_end_to_end(db):
    from watchtower.core.runner import CommandRunner
    from watchtower.storage.audit_log import AuditLog
    a = ta.analyze_pcap(CommandRunner(AuditLog(db)), str(FX / "traffic_lan.pcapng"), local_nets=NETS)
    assert not a.error and a.stats.packets == 131 and a.stats.local_nets == NETS
    assert a.stats.start_epoch == pytest.approx(1793563287.0077, abs=0.01)
    assert a.stats.activity["10.9.0.42"]["names"] == ["alice-macbook"]
    assert len(a.stats.flows) == 19 and len(a.stats.endpoints) == 8
