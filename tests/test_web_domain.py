"""Web Audit (header_audit, web_scanner) and Domain Audit (domain_audit, subdomain_enum).

Fixtures:
  headers_good.txt / headers_weak.txt  real `curl -sD -` output from local test servers
  nikto_2.1.5.xml                      real nikto 2.1.5 XML against a local test server
  dns_records.json                     HAND-WRITTEN zone data (see its _about); real RSA keys
  subfinder.jsonl, amass_v4.txt,       HAND-WRITTEN from the tools' documented output formats
  crtsh.json                           (subfinder/amass weren't installable in the cloud container
                                        and crt.sh wasn't reachable): verify against real output locally
"""

import json
import shutil
import socket
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from watchtower.core import domain_audit, header_audit, remediation, report, subdomain_enum, web_scanner
from watchtower.core.assessment import assess
from watchtower.core.targets import domain_covered, normalize_domain, parse_url, url_in_scope

FX = Path(__file__).parent / "fixtures"
DNS = json.loads((FX / "dns_records.json").read_text())["records"]


def ids(issues):
    return {i.id: i for i in issues}


# ---- targets: URLs and domains ----

def test_parse_url_and_scope():
    u = parse_url("NAS.lan:5001/admin?x=1#frag")
    assert (u.url, u.scheme, u.host, u.port) == ("https://nas.lan:5001/admin?x=1", "https", "nas.lan", 5001)
    assert u.origin == "https://nas.lan:5001"
    assert parse_url("http://192.168.1.1:80").url == "http://192.168.1.1/"
    assert parse_url("https://[fe80::1]:8443/").host == "fe80::1"
    for bad in ("ftp://nas.lan/", "https://admin:pw@nas.lan/", "http://10.0.0.1-5/", "https://", "a b"):
        with pytest.raises(ValueError):
            parse_url(bad)
    assert url_in_scope("https://192.168.1.10:8443/", ["192.168.1.0/24"])
    assert not url_in_scope("https://192.168.2.10/", ["192.168.1.0/24"])
    assert not url_in_scope("https://nas.lan.evil.example/", ["nas.lan"])
    assert not url_in_scope("not a url", ["0.0.0.0/0"])


def test_domains():
    assert normalize_domain(" Example.COM. ") == "example.com"
    for bad in ("localhost", "10.0.0.1", "exa mple.com", ""):
        with pytest.raises(ValueError):
            normalize_domain(bad)
    assert domain_covered("mail.Example.com", ["example.com"])
    assert domain_covered("example.com", ["example.com"])
    assert not domain_covered("notexample.com", ["example.com"])
    assert not domain_covered("example.com", ["mail.example.com"])


# ---- header audit ----

def test_headers_weak_real_capture():
    snap = header_audit.parse_raw((FX / "headers_weak.txt").read_text(), "https://nas.lan/")
    assert snap.status == 200 and len(snap.get_all("Set-Cookie")) == 3
    got = ids(header_audit.analyze(snap))
    for k in ("hsts_short", "csp_unsafe_inline", "csp_unsafe_eval", "csp_wildcard", "framing_invalid",
              "nosniff_missing", "referrer_weak", "cookie_secure", "cookie_httponly", "cookie_samesite",
              "cookie_samesite_none", "disclosure_server", "disclosure_x-powered-by"):
        assert k in got, k
    assert "csp_missing" not in got and "hsts_missing" not in got and "no_https" not in got
    # PHPSESSID is a session cookie -> Medium; 'theme' alone would be Low
    assert got["cookie_secure"].severity == "Medium" and "PHPSESSID" in got["cookie_secure"].title
    assert "theme" not in got["cookie_httponly"].title and "tracking" in got["cookie_httponly"].title
    assert "tracking" in got["cookie_samesite_none"].title
    assert "theme" not in got["cookie_samesite"].title or "PHPSESSID" in got["cookie_samesite"].title
    assert got["disclosure_server"].severity == "Info"


def test_headers_good_real_capture():
    snap = header_audit.parse_raw((FX / "headers_good.txt").read_text(), "https://nas.lan/")
    assert header_audit.analyze(snap) == []
    # same headers over plain HTTP: only 'no HTTPS' (HSTS / Secure aren't meaningful there)
    plain = header_audit.parse_raw((FX / "headers_good.txt").read_text(), "http://nas.lan/")
    assert set(ids(header_audit.analyze(plain))) == {"no_https"}


def test_headers_missing_and_content_type():
    snap = header_audit.HttpSnapshot("https://r.lan/", "https://r.lan/", 200, [["Content-Type", "text/html"]])
    got = ids(header_audit.analyze(snap))
    assert {"hsts_missing", "csp_missing", "framing_missing", "nosniff_missing", "referrer_missing"} == set(got)
    assert got["csp_missing"].severity == "Medium" and got["framing_missing"].severity == "Medium"
    api = header_audit.HttpSnapshot("https://r.lan/", "https://r.lan/", 200, [["Content-Type", "application/json"]])
    assert ids(header_audit.analyze(api))["csp_missing"].severity == "Low"
    ro = header_audit.HttpSnapshot("https://r.lan/", "https://r.lan/", 200,
                                   [["Content-Security-Policy-Report-Only", "default-src 'self'"]])
    assert "csp_report_only" in ids(header_audit.analyze(ro))
    zero = header_audit.HttpSnapshot("https://r.lan/", "https://r.lan/", 200,
                                     [["Strict-Transport-Security", "max-age=0"]])
    assert ids(header_audit.analyze(zero))["hsts_zero"].severity == "Medium"
    nonce = header_audit.HttpSnapshot("https://r.lan/", "https://r.lan/", 200, [[
        "Content-Security-Policy", "script-src 'self' 'unsafe-inline' 'nonce-abc'; frame-ancestors 'self'"]])
    got = ids(header_audit.analyze(nonce))
    assert "csp_unsafe_inline" not in got and "framing_missing" not in got   # nonce wins; frame-ancestors set
    failed = header_audit.HttpSnapshot("https://r.lan/", error="ConnectionError: refused")
    assert header_audit.analyze(failed) == []


def test_header_findings_and_json():
    snap = header_audit.parse_raw((FX / "headers_weak.txt").read_text(), "https://nas.lan:5001/")
    issues = header_audit.analyze(snap)
    fs = header_audit.findings("https://nas.lan:5001/", issues)
    assert all(f.device == "https://nas.lan:5001/" and f.kind == "web" and f.port == "5001/tcp" for f in fs)
    assert all(f.remediation for f in fs if f.severity != "Info")
    snap2, issues2 = header_audit.result_from_json(header_audit.result_to_json(snap, issues))
    assert snap2.headers == snap.headers and issues2 == issues


class _Handler(BaseHTTPRequestHandler):
    server_version = "TestServer/1.0"
    sys_version = ""

    def do_GET(self):
        if self.path == "/":
            self.send_response(301)
            self.send_header("Location", "/home")
        elif self.path == "/out":
            self.send_response(302)
            self.send_header("Location", "http://elsewhere.example/")
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "sid=1; HttpOnly; Secure; SameSite=Lax")
            self.send_header("Set-Cookie", "pref=2; expires=Wed, 01 Jan 2031 00:00:00 GMT; Path=/")
        self.end_headers()
        self.wfile.write(b"<html></html>")

    def log_message(self, *a):
        pass


@pytest.fixture
def web_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()
    srv.server_close()


def _session():
    import requests
    s = requests.Session()
    s.trust_env = False      # talk to 127.0.0.1 directly, not through an environment proxy
    return s


def test_fetch_real_server_redirects_and_scope(web_server):
    port = web_server.server_address[1]
    log = []
    snap = header_audit.fetch(f"http://127.0.0.1:{port}/", _session(), lambda h: h == "127.0.0.1",
                              on_request=lambda m, u, n: log.append(u))
    assert snap.status == 200 and snap.final_url.endswith("/home") and snap.hops[0].status == 301
    assert len(snap.get_all("Set-Cookie")) == 2               # not folded into one header
    assert log == [f"http://127.0.0.1:{port}/", f"http://127.0.0.1:{port}/home"]
    got = ids(header_audit.analyze(snap))
    assert "no_https" in got and "pref" in got["cookie_httponly"].title and "sid" not in got["cookie_httponly"].title
    # a redirect off the authorized host is reported, not followed
    log.clear()
    snap = header_audit.fetch(f"http://127.0.0.1:{port}/out", _session(), lambda h: h == "127.0.0.1",
                              on_request=lambda m, u, n: log.append(u))
    assert snap.status == 302 and "elsewhere.example" in snap.stopped and len(log) == 1
    with pytest.raises(PermissionError):
        header_audit.fetch(f"http://127.0.0.1:{port}/", _session(), lambda h: False)
    closed = header_audit.fetch("http://127.0.0.1:1/", _session(), lambda h: True)
    assert closed.error and closed.status is None


@pytest.mark.skipif(not shutil.which("openssl"), reason="openssl missing")
def test_fetch_self_signed_https(tmp_path):
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(tmp_path / "k.pem"),
                    "-out", str(tmp_path / "c.pem"), "-days", "2", "-subj", "/CN=test.lan"], check=True,
                   capture_output=True)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        notes = []
        snap = header_audit.fetch(f"https://127.0.0.1:{srv.server_address[1]}/home", _session(), lambda h: True,
                                  on_request=lambda m, u, n: notes.append(n))
        assert snap.tls_verified is False and snap.status == 200 and "CERTIFICATE" in snap.tls_error.upper()
        assert notes[0] == "" and "not verified" in notes[1]       # the unverified retry is logged as such
        got = ids(header_audit.analyze(snap))
        assert "tls_untrusted" in got and "hsts_missing" in got and "no_https" not in got
    finally:
        srv.shutdown()
        srv.server_close()


# ---- nikto ----

def test_nikto_real_xml():
    items = web_scanner.parse_xml((FX / "nikto_2.1.5.xml").read_text())
    assert len(items) == 9
    by_uri = {i.uri: i for i in items}
    assert by_uri["/phpinfo.php"].severity == "Medium" and by_uri["/phpinfo.php"].osvdb == "3233"
    assert by_uri["/icons/"].category == "exposure"                        # directory indexing
    assert by_uri["/icons/README"].severity == "Low"
    rfi = next(i for i in items if "RFI" in i.description)
    assert rfi.severity == "High"
    hdr = [i for i in items if "X-Frame-Options" in i.description][0]
    assert hdr.severity == "Info"     # header audit covers it with exact settings; don't double count
    fs = web_scanner.findings("http://127.0.0.1:8093/", items)
    assert len(fs) == 9 and all(f.kind == "web" and f.device == "http://127.0.0.1:8093/" for f in fs)
    assert web_scanner.items_from_json(web_scanner.items_to_json(items)) == items


def test_nikto_truncated_and_25_format():
    text = (FX / "nikto_2.1.5.xml").read_text()
    cut = text[:text.index("/server-status")]           # killed mid-write (cancel / maxtime)
    items = web_scanner.parse_xml(cut)
    assert [i.uri for i in items] == ["/", "/", "/", "/phpinfo.php"]
    v25 = """<?xml version="1.0" ?><niktoscans><niktoscan><scandetails>
      <item id="000444" method="GET"><description><![CDATA[/cgi-bin/test.cgi: Site appears vulnerable to the
      'shellshock' vulnerability.]]></description><uri><![CDATA[/cgi-bin/test.cgi]]></uri>
      <references><![CDATA[https://nvd.nist.gov/vuln/detail/CVE-2014-6271]]></references></item>
      <item id="600575" method="GET"><description><![CDATA[Apache/2.4.41 appears to be outdated (current is at least
      2.4.62).]]></description><uri><![CDATA[/]]></uri></item>
    </scandetails></niktoscan></niktoscans>"""      # hand-written in nikto 2.5's layout
    a, b = web_scanner.parse_xml(v25)
    assert a.severity == "High" and a.cves == "CVE-2014-6271"
    assert b.category == "outdated" and b.severity == "Medium"


def test_nikto_argv_excludes_login_and_dos(monkeypatch):
    monkeypatch.setattr(web_scanner.deps, "find_binary", lambda *n: "/usr/bin/nikto")
    argv = web_scanner.build_argv("https://nas.lan:5001/", "/tmp/o.xml", 5)
    assert argv[argv.index("-Plugins") + 1] == "@@DEFAULT;-auth"
    assert argv[argv.index("-Tuning") + 1] == "x6"
    assert argv[argv.index("-h") + 1] == "https://nas.lan:5001/" and "-ssl" in argv
    assert argv[argv.index("-maxtime") + 1] == "300s" and "-id" not in argv
    monkeypatch.setattr(web_scanner.deps, "find_binary", lambda *n: None)
    with pytest.raises(RuntimeError):
        web_scanner.build_argv("https://nas.lan/", "/tmp/o.xml")


# ---- domain audit ----

def audit(domain, selectors=None):
    return domain_audit.audit(domain, domain_audit.dict_resolver(DNS), selectors)


def test_rsa_key_sizes_real_keys():
    for sel, dom, bits in (("selector1", "good.example", 2048), ("default", "weak.example", 768),
                           ("mail", "weak.example", 1024), ("k1", "open.example", 1024)):
        rec = DNS[f"{sel}._domainkey.{dom}"]["TXT"][0]
        assert domain_audit.analyze_dkim(rec)["bits"] == bits, sel
    assert domain_audit.rsa_key_bits("not base64!!") is None


def test_domain_good():
    rep = audit("Good.Example.")
    assert rep.domain == "good.example" and rep.sends_mail
    assert rep.issues == [] and rep.spf_lookups == 1 and list(rep.dkim) == ["selector1"]
    assert rep.dmarc_tags["p"] == "reject"


def test_domain_weak():
    rep = audit("weak.example", ["old"])
    got = ids(rep.issues)
    assert got["spf_multiple"].severity == "Medium"
    assert got["spf_neutral_all"].severity == "Medium" and "spf_ptr" in got
    assert "spf_too_many_lookups" in got and rep.spf_lookups > 10
    assert got["dmarc_none"].severity == "Low" and got["dmarc_no_rua"].severity == "Info"
    assert got["dkim_weak_default"].severity == "High" and "dkim_testing_default" in got
    assert got["dkim_1024_mail"].severity == "Low"           # bare PKCS#1 key parsed too
    assert rep.dkim_keys["old"]["revoked"] and not any("old" in k for k in got)
    fs = domain_audit.findings("weak.example", rep)
    assert all(f.kind == "email" and f.device == "weak.example" and f.remediation for f in fs)


def test_domain_bare_parked_open():
    got = ids(audit("bare.example").issues)
    assert set(got) == {"spf_missing", "dmarc_missing", "dkim_not_found"}
    assert "v=spf1 -all" in got["spf_missing"].detail and got["dkim_not_found"].severity == "Info"
    parked = audit("parked.example")
    assert not parked.sends_mail and {i.severity for i in parked.issues} == {"Info"}
    assert "null_mx" in ids(parked.issues)
    op = audit("open.example")
    got = ids(op.issues)
    assert got["spf_pass_all"].severity == "High" and "spf_syntax" in got
    assert "192.0.2.300" in got["spf_syntax"].detail and "include needs a domain" in got["spf_syntax"].detail
    assert {"dmarc_pct", "dmarc_sp_none", "dkim_1024_k1"} <= set(got)
    assert any("selector2._domainkey.open.example" in e for e in op.errors)   # SERVFAIL recorded, audit continues


def test_spf_include_without_record_and_softfail():
    recs = {"a.example": {"TXT": ["v=spf1 include:nospf.example ~all"]}, "nospf.example": {"TXT": ["hello"]},
            "_dmarc.a.example": {"TXT": ["v=DMARC1; p=reject; rua=mailto:x@a.example"]}}
    got = ids(domain_audit.audit("a.example", domain_audit.dict_resolver(recs)).issues)
    assert "spf_include_broken" in got and got["spf_softfail"].severity == "Info"   # DMARC enforces
    recs["_dmarc.a.example"]["TXT"] = ["v=DMARC1; p=none"]
    got = ids(domain_audit.audit("a.example", domain_audit.dict_resolver(recs)).issues)
    assert got["spf_softfail"].severity == "Low"


def test_spf_parse_and_selectors():
    terms, errs = domain_audit.parse_spf("v=spf1 ip4:10.0.0.0/8 ip6:2001:db8::/32 a:mail.x.example/24 -all exp=e.x")
    assert not errs and [t.name for t in terms] == ["ip4", "ip6", "a", "all", "exp"]
    assert domain_audit.parse_spf("v=spf2 -all")[1]
    assert domain_audit.parse_spf("v=spf1 ip4:2001:db8::1 bogus -all")[1] == [
        "invalid ip4 address: ip4:2001:db8::1", "unknown term: bogus"]
    rep = audit("good.example", ["custom", "bad selector!", "default"])
    assert rep.selectors_tried[0] == "custom" and "bad selector!" not in rep.selectors_tried
    assert rep.selectors_tried.count("default") == 1


def test_domain_report_json_roundtrip():
    rep = audit("weak.example")
    back = domain_audit.report_from_json(domain_audit.report_to_json(rep))
    assert back.issues == rep.issues and back.dkim_keys == rep.dkim_keys and back.spf == rep.spf


def test_dns_resolver_against_local_dns_server():
    """dnspython end to end: a tiny UDP DNS server built from dnspython's own message classes."""
    pytest.importorskip("dns")
    import dns.message
    import dns.rcode
    import dns.rrset

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(5)
    zone = {("example.test.", "TXT"): ['"v=spf1 ip4:192.0.2.1 " "-all"'],
            ("example.test.", "MX"): ["10 mx.example.test."]}
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                data, addr = sock.recvfrom(4096)
            except (TimeoutError, OSError):
                continue
            q = dns.message.from_wire(data)
            resp = dns.message.make_response(q)
            question = q.question[0]
            key = (question.name.to_text(), dns.rdatatype.to_text(question.rdtype))
            if key in zone:
                resp.answer.append(dns.rrset.from_text_list(question.name, 60, "IN", key[1], zone[key]))
            elif question.name.to_text() != "example.test.":
                resp.set_rcode(dns.rcode.NXDOMAIN)
            sock.sendto(resp.to_wire(), addr)

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        queries = []
        r = domain_audit.dns_resolver(lambda n, t: queries.append((n, t)), nameserver="127.0.0.1",
                                      port=sock.getsockname()[1], timeout=3)
        assert r("example.test", "TXT") == ["v=spf1 ip4:192.0.2.1 -all"]     # multi-string TXT joined
        assert r("example.test", "MX") == ["10 mx.example.test."]
        assert r("_dmarc.example.test", "TXT") == []                         # NXDOMAIN
        assert queries[0] == ("example.test", "TXT")
    finally:
        stop.set()
        t.join(2)
        sock.close()


# ---- subdomains ----

def test_parse_subfinder_amass_crtsh():
    subs = subdomain_enum.parse_subfinder((FX / "subfinder.jsonl").read_text(), "homelab.example")
    names = [s.name for s in subs]
    assert "evil-homelab.example" not in names and "homelab.example" in names
    www = next(s for s in subs if s.name == "www.homelab.example")
    assert www.sources == ["crtsh", "certspotter"]
    assert {s.name for s in subs if s.sensitive} == {"vpn.homelab.example", "jenkins.dev.homelab.example"}
    am = subdomain_enum.parse_amass((FX / "amass_v4.txt").read_text(), "homelab.example")
    assert [s.name for s in am] == ["homelab.example", "staging.homelab.example", "www.homelab.example"]
    assert subdomain_enum.parse_amass("a.homelab.example\nb.homelab.example\n", "homelab.example")[0].name == \
        "a.homelab.example"                                                 # amass v3: plain names
    crt = subdomain_enum.parse_crtsh((FX / "crtsh.json").read_text(), "homelab.example")
    assert [s.name for s in crt] == ["homelab.example", "grafana.homelab.example", "nas.homelab.example",
                                     "www.homelab.example"]                 # wildcard folded, case normalized
    assert subdomain_enum.subs_from_json(subdomain_enum.subs_to_json(crt)) == crt


def test_subdomain_findings_and_backends(monkeypatch):
    subs = subdomain_enum.parse_subfinder((FX / "subfinder.jsonl").read_text(), "homelab.example")
    fs = subdomain_enum.findings("homelab.example", subs, "subfinder")
    assert [f.severity for f in fs] == ["Info", "Low"]
    assert "4 name(s)" in fs[0].title and "vpn.homelab.example" in fs[1].description
    assert subdomain_enum.findings("homelab.example", [subdomain_enum.Subdomain("homelab.example")], "x") == []
    assert subdomain_enum.amass_supports_passive("Usage: amass enum [options]\n  -passive\tA purely passive mode")
    assert not subdomain_enum.amass_supports_passive("Usage: amass enum [options]\n  -active\tAttempt zone transfers")
    monkeypatch.setattr(subdomain_enum.deps, "find_binary", lambda *n: f"/usr/bin/{n[0]}")
    a = subdomain_enum.build_argv("subfinder", "homelab.example", "/tmp/o", 5)
    assert a[:3] == ["/usr/bin/subfinder", "-d", "homelab.example"] and "-json" in a and "-max-time" in a
    a = subdomain_enum.build_argv("amass", "homelab.example", "/tmp/o")
    assert a[1:3] == ["enum", "-passive"]
    av = subdomain_enum.available("Usage: amass enum\n -active")
    assert av["subfinder"] == "" and "passive" in av["amass"] and av["crt.sh"] == ""
    with pytest.raises(ValueError):
        subdomain_enum.build_argv("crt.sh", "homelab.example", "/tmp/o")
    assert subdomain_enum.crtsh_params("Homelab.Example") == {"q": "%.homelab.example", "output": "json"}


# ---- assessment / report / remediation ----

def _rows():
    weak = header_audit.parse_raw((FX / "headers_weak.txt").read_text(), "https://nas.lan/")
    nikto = web_scanner.parse_xml((FX / "nikto_2.1.5.xml").read_text())
    subs = subdomain_enum.parse_crtsh((FX / "crtsh.json").read_text(), "homelab.example")
    return [
        {"kind": "headers", "host": "https://nas.lan/", "port": 443, "tool": "HTTP GET", "finished": "2026-11-01",
         "result_json": header_audit.result_to_json(weak, header_audit.analyze(weak))},
        {"kind": "nikto", "host": "https://nas.lan/", "port": 443, "tool": "nikto", "finished": "2026-11-01",
         "result_json": web_scanner.items_to_json(nikto)},
        {"kind": "email", "host": "weak.example", "port": None, "tool": "dnspython", "finished": "2026-11-01",
         "result_json": domain_audit.report_to_json(audit("weak.example"))},
        {"kind": "subdomains", "host": "homelab.example", "port": None, "tool": "crt.sh", "finished": "2026-11-01",
         "result_json": subdomain_enum.subs_to_json(subs)},
    ]


def test_assess_includes_web_and_domain():
    a = assess([], [], host_audits=_rows())
    kinds = {f.kind for f in a.findings}
    assert {"web", "email", "subdomain"} <= kinds
    risk = {r.device: r for r in a.risks}
    assert risk["https://nas.lan/"].kind == "web" and risk["https://nas.lan/"].score > 0
    assert risk["weak.example"].kind == "domain" and risk["homelab.example"].kind == "domain"
    assert a.scope_summary() == "0 host(s), 0 Wi-Fi network(s), 1 web URL(s) and 2 domain(s)"
    assert set(a.web["https://nas.lan/"]) == {"headers", "nikto"}
    f = next(f for f in a.findings if f.kind == "web")
    assert remediation.fixes_for(f, local=False) == []
    html = report.render_html(report.ReportInput(a, domains=["weak.example", "homelab.example"]))
    assert "<td>Web</td>" in html and "<td>Domain</td>" in html and "Owned domains" in html
    assert "Email: DMARC policy is p=none" in html and "Web: Cookie without the Secure flag" in html


# ---- storage ----

def test_owned_domains_and_scope_storage(db):
    from watchtower.storage.audit_log import AuditLog
    from watchtower.storage.scope import HostAuditStore, OwnedDomainStore, TargetStore
    assert db.schema_version >= 6
    log = AuditLog(db)
    doms = OwnedDomainStore(db, log)
    assert doms.add("Example.COM.") and not doms.add("example.com")
    assert doms.values() == ["example.com"] and doms.covers("mail.example.com") and not doms.covers("example.org")
    with pytest.raises(ValueError):
        doms.add("10.0.0.1")
    doms.remove("example.com")
    assert not doms.covers("example.com")
    scope = [e for e in log.entries(limit=50) if e.event == "scope_change"]
    assert len(scope) == 2 and all(e.target == "example.com" for e in scope)
    targets = TargetStore(db, log)
    targets.add("nas.lan")
    assert targets.covers_url("https://nas.lan:5001/") and not targets.covers_url("https://router.lan/")
    audits = HostAuditStore(db)
    for kind, host in (("tls", "nas.lan"), ("headers", "https://nas.lan:5001/"), ("email", "example.com")):
        audits.finish(audits.start(kind, host, None, "t", "c"), 0, "", "{}")
    assert {r["kind"] for r in audits.latest(kinds=("tls", "snmp"))} == {"tls"}
    assert {r["kind"] for r in audits.latest()} == {"tls", "headers", "email"}


def test_new_findings_have_known_attck_ids():
    from watchtower.core import attck_mapping
    a = assess([], [], host_audits=_rows())
    for f in a.findings:
        for t in f.attck:
            assert attck_mapping.name(t) != "Unknown technique", (t, f.title)
