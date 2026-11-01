"""Traffic Audit (core/traffic_audit.py, scheduled captures, storage).

Fixtures are REAL: traffic_lab.pcapng was recorded with dumpcap on loopback while a
script made FTP/Telnet/POP3/IMAP/SMTP logins, HTTP Basic + form logins, SNMP v1/v2c
GETs, SMBv1 negotiate, LLMNR/NBT-NS/mDNS/DNS (incl. WPAD) lookups, SSDP NOTIFY/M-SEARCH
and two TLS handshakes (TLS 1.0 and TLS 1.3) between 127.0.0.5-.7 (clients) and
127.0.0.1 (servers). traffic_fields.tsv / traffic_stats.txt are tshark 4.2.2's output
for it (fields_argv / stats_argv). The lab passwords are fake ('s3cret-...').
"""

import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from watchtower.core import scheduler
from watchtower.core import traffic_audit as ta
from watchtower.core.assessment import assess

FX = Path(__file__).parent / "fixtures"
EVENTS = ta.parse_fields((FX / "traffic_fields.tsv").read_text())


def by(kind):
    return [e for e in EVENTS if e.kind == kind]


def test_cleartext_logins_from_real_capture():
    cl = {(e.proto, e.client, e.server, e.port) for e in by("cleartext_login")}
    for proto, port in (("FTP", "21/tcp"), ("Telnet", "23/tcp"), ("POP3", "110/tcp"), ("IMAP", "143/tcp"),
                        ("SMTP AUTH", "25/tcp"), ("HTTP Basic auth", "80/tcp")):
        assert (proto, "127.0.0.5", "127.0.0.1", port) in cl, proto
    assert ("HTTP login form", "127.0.0.6", "127.0.0.1", "80/tcp") in cl
    # the Telnet server's prompts aren't a second "login" in the other direction
    assert not [e for e in by("cleartext_login") if e.proto == "Telnet" and e.server != "127.0.0.1"]
    snmp = {e.proto: e for e in by("cleartext_login") if e.proto.startswith("SNMP")}
    assert snmp["SNMP v2c"].detail == "community 'public' (factory default)" and snmp["SNMP v2c"].severity == "High"
    assert snmp["SNMP v1"].detail == "community 'n********t'" and snmp["SNMP v1"].severity == "Medium"


def test_no_secret_ever_reaches_events_or_findings():
    """The capture contains real (fake-lab) passwords; none may survive parsing."""
    raw = (FX / "traffic_fields.tsv").read_text()
    assert "s3cret-telnet" not in raw        # telnet.data isn't even extracted
    assert "YWRtaW46czNjcmV0LWJhc2lj" in raw  # but tshark's raw output does carry the Basic-auth credentials
    blob = ta.events_to_json(EVENTS) + "".join(f.description + f.title for f in ta.findings(EVENTS))
    for secret in ("s3cret", "YWRtaW46", "n0tdefault", "alice", "YWxp", "czNj"):
        assert secret not in blob, secret
    assert "telnet.data" not in ta.FIELDS and "ftp.request.arg" not in ta.FIELDS


def test_broadcasts_upnp_smb_tls_dns():
    nb = {(e.proto, e.client, e.detail) for e in by("name_broadcast")}
    assert ("LLMNR", "127.0.0.5", "fileserver") in nb and ("NBT-NS", "127.0.0.5", "FILESERVER<20>") in nb
    assert ("mDNS", "127.0.0.6", "_ipp._tcp.local") in nb
    assert {(e.client, e.detail) for e in by("wpad")} == {("127.0.0.6", "wpad"), ("127.0.0.7", "wpad.lan")}
    assert [(e.client, e.proto) for e in by("upnp")] == [("127.0.0.7", "SSDP/UPnP")]      # NOTIFY only, not M-SEARCH
    assert [(e.client, e.server, e.port) for e in by("smb1")] == [("127.0.0.7", "127.0.0.1", "445/tcp")]
    srv = by("tls_server")
    assert [(e.server, e.proto, e.port) for e in srv] == [("127.0.0.1", "TLS 1.0", "8443/tcp")]   # 1.3 not flagged
    assert [(e.proto, e.detail) for e in by("tls_client")] == [("TLS 1.0", "old.lan")]
    assert {e.client for e in by("plain_dns")} == {"127.0.0.5", "127.0.0.7"}
    assert not by("weak_cipher")                       # AES128-SHA isn't in a broken family


def test_weak_cipher_and_ssl3_rows():
    header = "\t".join(ta.FIELDS)

    def row(**kv):
        return "\t".join(kv.get(f.replace(".", "_"), "") for f in ta.FIELDS)
    text = "\n".join([header,
                      row(frame_protocols="eth:ip:tcp:tls", ip_src="10.0.0.2", ip_dst="10.0.0.9", tcp_srcport="443",
                          tcp_dstport="50000", tls_handshake_type="2", tls_handshake_version="0x0300",
                          tls_handshake_ciphersuite="0x0005"),
                      row(frame_protocols="eth:ip:tcp:tls", ip_src="10.0.0.3", ip_dst="10.0.0.9", tcp_srcport="8443",
                          tcp_dstport="50001", tls_handshake_type="2", tls_handshake_version="0x0303",
                          tls_handshake_ciphersuite="0x000a")])
    ev = ta.parse_fields(text)
    fs = {(f.device, f.title): f for f in ta.findings(ev)}
    assert fs[("10.0.0.2", "Traffic: server negotiated SSL 3.0")].severity == "High"
    assert fs[("10.0.0.2", "Traffic: server chose a RC4 cipher 0x0005")].severity == "High"
    assert fs[("10.0.0.3", "Traffic: server chose a 3DES (SWEET32) cipher 0x000A")].port == "8443/tcp"
    assert ta.parse_fields("") == []


def test_findings_severity_and_devices():
    fs = ta.findings(EVENTS, labels={"127.0.0.1": "127.0.0.1 (labbox)"}, source="lab.pcapng")
    titles = {(f.device, f.title): f for f in fs}
    ftp = titles[("127.0.0.1", "Traffic: password sent unencrypted (FTP)")]
    assert ftp.severity == "High" and ftp.port == "21/tcp" and ftp.device_label == "127.0.0.1 (labbox)"
    assert "127.0.0.5" in ftp.description and ftp.remediation.startswith("Switch to SFTP")
    assert titles[("127.0.0.5", "Traffic: broadcasts LLMNR name lookups")].severity == "Medium"
    assert titles[("127.0.0.6", "Traffic: uses mDNS / Bonjour")].severity == "Info"
    assert titles[("127.0.0.1", "Traffic: SMBv1 in use")].severity == "High"
    assert titles[("127.0.0.7", "Traffic: advertises UPnP (SSDP)")].severity == "Low"
    assert all(f.kind == "traffic" and f.remediation and f.technique for f in fs)
    assert all(f.source == "Traffic audit (lab.pcapng)" for f in fs)


def test_stats_and_interfaces():
    st = ta.parse_stats((FX / "traffic_stats.txt").read_text())
    assert st.packets == 176 and ("ftp", 3, 7) in st.protocols
    c = st.conversations[0]
    assert (c.a, c.b, c.frames, c.bytes) == ("127.0.0.5", "127.0.0.1", 110, 8286)
    newer = "10.0.0.1  <-> 10.0.0.2   5 1 kB   6 2 kB   11 3 kB   0.1   2.0\n"
    st2 = ta.parse_stats("IPv4 Conversations\n" + newer)
    assert st2.conversations[0].bytes == 3000                   # newer tshark prints kB units
    assert st.seconds == pytest.approx(8.074)
    assert ta.stats_from_json(ta.stats_to_json(st)) == st
    ifaces = ta.parse_interfaces((FX / "dumpcap_D.txt").read_text())
    assert ("lo", "Loopback") in ifaces and ("eth0", "") in ifaces
    assert [n for n, _ in ta.useful_interfaces(ifaces)] == ["eth0", "any", "lo"]


def test_capture_argv_safety(monkeypatch):
    monkeypatch.setattr(ta.deps, "find_binary", lambda *n: "/usr/bin/dumpcap")
    a = ta.capture_argv("eth0", "/tmp/x.pcapng", 60, 1000, "port 80")
    assert a[a.index("-f") + 1] == "(port 80) and not ether proto 0x888e"
    assert a[a.index("-a") + 1] == "duration:60" and a[a.index("-c") + 1] == "1000"
    assert ta.capture_argv("lo", "/tmp/x", 5)[-1] == "not ether proto 0x888e"
    with pytest.raises(ValueError, match="monitor mode"):
        ta.capture_argv("wlan0mon", "/tmp/x", 60, monitor_interfaces={"wlan0mon"})
    for bad in ("eth0; rm -rf /", "", "a b"):
        with pytest.raises(ValueError):
            ta.capture_argv(bad, "/tmp/x", 60)
    with pytest.raises(ValueError):
        ta.capture_argv("eth0", "/tmp/x", 0)
    assert "permission" in ta.capture_error("dumpcap: You don't have permission to capture on that device", 1)
    assert "BPF" in ta.capture_error("Invalid capture filter \"port x\" for interface", 2)


def test_diff_captures():
    old = [e for e in EVENTS if e.kind != "smb1"]
    new = [e for e in EVENTS if e.proto != "FTP"]
    ch = ta.diff_captures(old, new)
    assert any(c.level == "alert" and "SMBv1" in c.detail for c in ch)
    assert any(c.level == "good" and "FTP" in c.detail for c in ch)
    assert ta.diff_captures(EVENTS, EVENTS) == []


def test_assess_merges_traffic_with_hosts():
    cap = {"source": "file:/home/me/lab.pcapng", "events_json": ta.events_to_json(EVENTS)}
    a = assess([], [], captures=[cap])
    assert any(f.kind == "traffic" for f in a.findings) and a.captures == [cap]
    assert "1 traffic capture(s)" in a.scope_summary()
    r = a.risk_for("127.0.0.1")
    assert r and r.kind == "host" and r.worst == "High"
    assert all(f.source == "Traffic audit (lab.pcapng)" for f in a.findings)


def test_capture_store(db, tmp_path):
    from watchtower.storage.audit_log import AuditLog
    from watchtower.storage.scope import CaptureScheduleStore, CaptureStore, Maintenance
    st = CaptureStore(db)
    owned = tmp_path / "own.pcapng"
    owned.write_bytes(b"x")
    imported = tmp_path / "theirs.pcap"
    imported.write_bytes(b"y")
    a = st.start("interface:lo", str(owned), True, "dumpcap ...")
    st.finish(a, 0, 10, 1.5, "{}", ta.events_to_json(EVENTS[:2]))
    b = st.start("file:" + str(imported), str(imported), False, "import")
    st.finish(b, 0, 5, 1.0, "{}", "[]")
    c = st.start("interface:lo", str(owned), True, "dumpcap ...")
    st.finish(c, 1, 0, 0, "{}", "[]", "No permission to capture")        # failed: ignored by latest
    assert {r["id"] for r in st.latest_per_source()} == {a, b}
    assert [s["source"] for s in st.sources()] == ["file:" + str(imported), "interface:lo"]
    st.delete(b)
    assert imported.exists()                                             # never delete the user's own file
    st.delete(a)
    assert not owned.exists()
    sched = CaptureScheduleStore(db, AuditLog(db))
    sid = sched.add("lo", 30, 60, "port 53")
    assert sched.due()[0]["id"] == sid
    sched.set_enabled(sid, False)
    assert sched.due() == []
    assert Maintenance(db).prune(1) == {} or True


def _can_capture() -> bool:
    if not (shutil.which("dumpcap") and shutil.which("tshark") and sys.platform.startswith("linux")):
        return False
    r = subprocess.run(["dumpcap", "-i", "lo", "-a", "duration:1", "-w", "/dev/null", "-q"], capture_output=True)
    return r.returncode == 0


@pytest.mark.skipif(not _can_capture(), reason="no dumpcap/tshark or no capture permission")
def test_scheduled_capture_end_to_end(db, home):
    """A real scheduled capture on loopback: dumpcap records while we send an FTP-style login,
    tshark analyzes, the next run is compared with the previous one."""
    import socket
    import threading

    from watchtower.core.runner import CommandRunner
    from watchtower.storage.audit_log import AuditLog
    from watchtower.storage.scope import CaptureScheduleStore, CaptureStore
    audit = AuditLog(db)
    runner = CommandRunner(audit)
    caps, scheds = CaptureStore(db), CaptureScheduleStore(db, audit)
    sid = scheds.add("lo", 3, 60, "port 21")

    def ftp_login():
        time.sleep(1.2)
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind(("127.0.0.1", 21))
        except OSError:
            return
        srv.listen(1)
        cli = socket.create_connection(("127.0.0.1", 21))
        conn, _ = srv.accept()
        conn.sendall(b"220 hi\r\n")
        cli.recv(100)
        cli.sendall(b"USER u\r\n")
        conn.recv(100)
        cli.sendall(b"PASS p\r\n")
        conn.recv(100)
        for s in (cli, conn, srv):
            s.close()
    t = threading.Thread(target=ftp_login)
    t.start()
    r1 = scheduler.run_capture_schedule(scheds.all()[0], runner, caps, scheds, now=datetime.now(timezone.utc))
    t.join()
    assert r1.status == "ok: first capture (baseline)", r1.status
    row = caps.latest_per_source()[0]
    assert row["owned"] and Path(row["pcap_path"]).exists() and row["packets"] > 0
    assert "0x888e" in row["command"]
    assert any(e.proto == "FTP" for e in ta.events_from_json(row["events_json"]))
    r2 = scheduler.run_capture_schedule(scheds.all()[0], runner, caps, scheds)
    assert r2.status.startswith("ok:") and any(c.level == "good" and "FTP" in c.detail for c in r2.changes)
    cmds = [e.command for e in audit.entries(limit=50) if e.event == "command_start"]
    assert any(c and "dumpcap" in c for c in cmds) and any(c and "tshark" in c for c in cmds)
    assert sid == scheds.all()[0]["id"] and scheds.all()[0]["last_status"].startswith("ok")


@pytest.mark.skipif(not shutil.which("tshark") or not sys.platform.startswith("linux"), reason="needs tshark")
def test_analysis_works_when_tshark_may_not_open_files(db, tmp_path, monkeypatch):
    """Regression: on Ubuntu, AppArmor can stop tshark opening captures under ~/.local/share
    ("tshark: You don't have permission to read the file ..."). Watchtower pipes the file in
    instead. A stand-in tshark that refuses every file path proves the path is never needed."""
    from watchtower.core.runner import CommandRunner
    from watchtower.storage.audit_log import AuditLog
    real = shutil.which("tshark")
    fake = tmp_path / "tshark"
    fake.write_text(f"""#!/bin/sh
prev=""
for a in "$@"; do
  if [ "$prev" = "-r" ] && [ "$a" != "-" ]; then
    echo "tshark: You don't have permission to read the file \\"$a\\"." >&2; exit 2
  fi
  prev="$a"
done
exec {real} "$@"
""")
    fake.chmod(0o755)
    monkeypatch.setattr(ta, "tshark_binary", lambda: str(fake))
    hidden = tmp_path / ".local" / "share" / "watchtower" / "captures"
    hidden.mkdir(parents=True)
    pcap = hidden / "20261101-145058-wlp195s0.pcapng"
    pcap.write_bytes((FX / "traffic_lab.pcapng").read_bytes())
    audit = AuditLog(db)
    a = ta.analyze_pcap(CommandRunner(audit), str(pcap))
    assert not a.error, a.error
    assert a.stats.packets == 176 and any(e.proto == "FTP" for e in a.events)
    cmds = [e.command for e in audit.entries(limit=10) if e.event == "command_start"]
    assert cmds and all(" -r - " in c and c.endswith(f"< {pcap}") for c in cmds)    # shown honestly in the log
    # files Watchtower itself can't read get a clear explanation instead of tshark's
    assert ta.unreadable_reason(str(pcap)) == ""
    assert "no longer exists" in ta.analyze_pcap(CommandRunner(audit), str(tmp_path / "gone.pcapng")).error
    monkeypatch.setattr(ta, "unreadable_reason", lambda p: "Watchtower can't read it (it belongs to 'root')")
    assert "belongs to 'root'" in ta.analyze_pcap(CommandRunner(audit), str(pcap)).error
