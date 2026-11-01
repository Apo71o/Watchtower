from pathlib import Path

from watchtower.core import interfaces, wifi_scan

FX = Path(__file__).parent / "fixtures"


def read(name):
    return (FX / name).read_text()


def test_parse_iw_dev():
    devs = interfaces.parse_iw_dev(read("iw_dev.txt"))
    assert [d["name"] for d in devs] == ["wlan1", "wlan0"]
    w1, w0 = devs
    assert w1 == {"name": "wlan1", "phy": "phy1", "mac": "00:C0:CA:AA:BB:CC", "mode": "monitor",
                  "channel": 6, "freq": 2437}
    assert w0["ssid"] == "Home Lab" and w0["mode"] == "managed" and w0["phy"] == "phy0"


def test_parse_iw_list_monitor_support():
    modes = interfaces.parse_iw_list(read("iw_list.txt"))
    assert "monitor" not in modes["phy0"] and "managed" in modes["phy0"]
    assert "monitor" in modes["phy1"] and "mesh" in modes["phy1"]


def test_ip_addr_and_network():
    addrs = interfaces.parse_ip_addr_json(read("ip_addr.json"))
    assert addrs["wlan0"] == ["192.168.1.23/24"]
    assert interfaces.network_of("192.168.1.23/24") == "192.168.1.0/24"


def test_mode_plan_validates_and_asks_root():
    plan = interfaces.set_mode_plan("wlan1", "monitor")
    assert plan.steps[0].elevated and "set type monitor" in plan.steps[0].script
    for bad in ("wlan0; rm -rf /", "x" * 20):
        try:
            interfaces.set_mode_plan(bad, "monitor")
        except ValueError:
            continue
        raise AssertionError(bad)


def test_parse_nmcli():
    aps = {a.bssid: a for a in wifi_scan.parse_nmcli(read("nmcli.txt"))}
    home = aps["AA:BB:CC:00:00:01"]
    assert home.in_use and home.ssid == "Home Lab" and home.channel == 36 and home.freq == 5180
    assert home.security == "WPA2/WPA3" and home.signal_pct == 92
    assert aps["AA:BB:CC:00:00:02"].ssid == "Cafe: Free" and aps["AA:BB:CC:00:00:02"].security == "Open"
    assert aps["AA:BB:CC:00:00:03"].security == "WEP"
    assert aps["AA:BB:CC:00:00:04"].security == "WPA2-Enterprise"
    assert aps["AA:BB:CC:00:00:05"].security == "WPA/WPA2" and aps["AA:BB:CC:00:00:05"].ssid == ""


def test_parse_iwlist_with_wps():
    aps = {a.bssid: a for a in wifi_scan.parse_iwlist(read("iwlist.txt"))}
    home = aps["AA:BB:CC:00:00:01"]
    assert home.security == "WPA2" and home.auth == "PSK" and home.wps == 1 and home.signal_dbm == -50
    assert aps["AA:BB:CC:00:00:03"].security == "WEP" and aps["AA:BB:CC:00:00:03"].wps == 0
    assert aps["AA:BB:CC:00:00:06"].security == "Open"
    modern = aps["AA:BB:CC:00:00:07"]
    assert modern.security == "WPA2/WPA3" and modern.freq == 5220 and modern.channel == 44


def test_parse_airodump_csv():
    aps, stations = wifi_scan.parse_airodump_csv(read("airodump.csv"))
    by = {a.bssid: a for a in aps}
    assert by["AA:BB:CC:00:00:01"].signal_dbm == -48 and by["AA:BB:CC:00:00:01"].security == "WPA2"
    assert by["AA:BB:CC:00:00:08"].ssid == "Lab, 2nd, AP"            # commas inside an ESSID
    assert by["AA:BB:CC:00:00:08"].security == "WPA2/WPA3"
    assert by["AA:BB:CC:00:00:09"].security == "Open" and by["AA:BB:CC:00:00:09"].signal_dbm is None
    s1, s2 = stations
    assert s1.bssid == "AA:BB:CC:00:00:01" and s1.probes == ["Home Lab"]
    assert s2.bssid is None and s2.probes == ["Neighbors", "Office WiFi"]


def test_airodump_argv_is_csv_only_and_validated(monkeypatch):
    monkeypatch.setattr(wifi_scan.deps, "find_binary", lambda *n: f"/usr/sbin/{n[0]}")
    run = wifi_scan.airodump_argv("wlan1", 30, band="abg")
    try:
        assert run.argv[-1] == "wlan1"
        assert run.argv[run.argv.index("--output-format") + 1] == "csv"
        assert "--signal=INT" in run.argv and "30" in run.argv
    finally:
        run.out_dir.rmdir()
    for bad in [("wlan1;x", "bg"), ("wlan1", "z")]:
        try:
            wifi_scan.airodump_argv(*bad[:1], 10, band=bad[1])
        except ValueError:
            continue
        raise AssertionError(bad)


def test_network_store_roundtrip(db):
    from watchtower.storage.audit_log import AuditLog
    from watchtower.storage.scope import NetworkStore
    log = AuditLog(db)
    store = NetworkStore(db, log)
    aps, stations = wifi_scan.parse_airodump_csv(read("airodump.csv"))
    store.record(aps, stations, source="airodump-ng")
    store.record(wifi_scan.parse_nmcli(read("nmcli.txt")), source="nmcli")
    rows = {r["bssid"]: r for r in store.all()}
    assert rows["AA:BB:CC:00:00:01"]["clients"] == 1
    assert rows["AA:BB:CC:00:00:01"]["source"] == "nmcli"
    store.set_authorized("AA:BB:CC:00:00:01", True)
    assert store.is_authorized("AA:BB:CC:00:00:01")
    assert log.entries()[0].event == "scope_change"
    assert store.forget_unauthorized() == len(rows) - 1
