"""HTTP security-header audit of one authorized URL (no external tool).

Sends ordinary GET requests (the same a browser sends) to the URL and checks
the response for the browser security headers and cookie flags:

  Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options,
  X-Frame-Options (or CSP frame-ancestors), Referrer-Policy, and the Secure /
  HttpOnly / SameSite attributes of every Set-Cookie.

Redirects are followed by hand, and only while they stay on hosts the caller
says are in scope; a redirect that leaves scope stops the audit and is
reported. Every request goes through `on_request` so the GUI can log it.
"""

from __future__ import annotations

import json
import re
import warnings
from dataclasses import asdict, dataclass, field
from urllib.parse import urljoin

from watchtower.core.findings_engine import SEV_WEIGHT, Finding
from watchtower.core.targets import WebUrl, parse_url

USER_AGENT = "Watchtower-header-audit/1.0 (authorized self-audit)"
HSTS_MIN_AGE = 15_552_000          # 180 days: the common minimum (Mozilla Observatory, hstspreload wants 1 year)
SESSIONISH = re.compile(r"sess|sid\b|^sid|auth|token|jwt|login|remember|connect\.sid|identity", re.I)
CSRFISH = re.compile(r"csrf|xsrf", re.I)


@dataclass
class Hop:
    url: str
    status: int
    location: str = ""


@dataclass
class HttpSnapshot:
    url: str                                   # what was requested (normalized)
    final_url: str = ""
    status: int | None = None
    headers: list[list[str]] = field(default_factory=list)   # [name, value] pairs, duplicates kept
    hops: list[Hop] = field(default_factory=list)
    tls_verified: bool | None = None           # None: plain HTTP
    tls_error: str = ""
    stopped: str = ""                          # why redirects weren't followed further
    error: str = ""                            # request failed entirely

    def get(self, name: str) -> str | None:
        n = name.lower()
        vals = [v for k, v in self.headers if k.lower() == n]
        return ", ".join(vals) if vals else None

    def get_all(self, name: str) -> list[str]:
        n = name.lower()
        return [v for k, v in self.headers if k.lower() == n]


@dataclass
class HeaderIssue:
    id: str
    severity: str
    title: str
    detail: str = ""
    category: str = ""     # hsts / https / csp / framing / nosniff / referrer / cookie / disclosure / tls


# ---- fetching ----

def _header_pairs(resp) -> list[list[str]]:
    """All response headers in order, keeping repeated Set-Cookie headers apart
    (requests' resp.headers folds them into one comma-joined string)."""
    raw = getattr(getattr(resp, "raw", None), "headers", None)
    if raw is not None and hasattr(raw, "items"):
        try:   # urllib3 1.26: iteritems() yields repeats separately; 2.x: items() does
            it = raw.iteritems() if hasattr(raw, "iteritems") else raw.items()
            return [[k, v] for k, v in it]
        except Exception:  # noqa: BLE001 - fall back to the folded dict
            pass
    return [[k, v] for k, v in resp.headers.items()]


def fetch(url: str, session, in_scope, on_request=None, timeout: float = 15, max_redirects: int = 5) -> HttpSnapshot:
    """GET `url` with `session` (requests.Session-like). `in_scope(host) -> bool`
    is checked for the URL and every redirect target. `on_request(method, url, note)`
    is called before each request (for the audit log / Command Console)."""
    import requests

    u = parse_url(url)
    snap = HttpSnapshot(url=u.url)
    if not in_scope(u.host):
        raise PermissionError(f"{u.host} isn't covered by your authorized targets.")
    current: WebUrl = u
    verify = True
    for _ in range(max_redirects + 1):
        note = "" if verify else "certificate not verified (retry after TLS error)"
        if on_request:
            on_request("GET", current.url, note)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")      # InsecureRequestWarning on the unverified retry
                resp = session.get(current.url, allow_redirects=False, timeout=timeout, verify=verify, stream=True,
                                   headers={"User-Agent": USER_AGENT})
        except requests.exceptions.SSLError as exc:
            if verify and current.scheme == "https":
                snap.tls_verified = False
                snap.tls_error = _short(exc)
                verify = False
                continue
            snap.error = _short(exc)
            return snap
        except requests.exceptions.RequestException as exc:
            snap.error = _short(exc)
            return snap
        try:
            pairs = _header_pairs(resp)
            status = resp.status_code
        finally:
            resp.close()
        if current.scheme == "https" and snap.tls_verified is None:
            snap.tls_verified = True
        snap.final_url, snap.status, snap.headers = current.url, status, pairs
        loc = next((v for k, v in pairs if k.lower() == "location"), "")
        if status in (301, 302, 303, 307, 308) and loc:
            snap.hops.append(Hop(current.url, status, loc))
            try:
                nxt = parse_url(urljoin(current.url, loc))
            except ValueError:
                snap.stopped = f"redirect to an unsupported location: {loc}"
                return snap
            if not in_scope(nxt.host):
                snap.stopped = (f"redirect to {nxt.url} not followed: {nxt.host} isn't in your authorized targets. "
                                "Results are for the redirect response itself.")
                return snap
            current = nxt
            continue
        return snap
    snap.stopped = f"more than {max_redirects} redirects"
    return snap


def _short(exc: Exception) -> str:
    s = str(exc)
    m = re.search(r"\(Caused by (\w+)\((.*)\)\)$", s)
    return (f"{m.group(1)}: {m.group(2)}" if m else s)[:300]


def parse_raw(text: str, url: str) -> HttpSnapshot:
    """Build a snapshot from raw response headers (e.g. `curl -sI` / `curl -D -`
    output). The last response block wins (curl prints one per redirect)."""
    blocks = [b for b in re.split(r"\r?\n\r?\n", text.strip()) if b.lstrip().startswith("HTTP/")]
    snap = HttpSnapshot(url=parse_url(url).url, final_url=parse_url(url).url)
    if not blocks:
        snap.error = "no HTTP response found"
        return snap
    lines = blocks[-1].strip().splitlines()
    m = re.match(r"HTTP/[\d.]+\s+(\d{3})", lines[0])
    snap.status = int(m.group(1)) if m else None
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            snap.headers.append([k.strip(), v.strip()])
    if snap.final_url.startswith("https://"):
        snap.tls_verified = True
    return snap


# ---- analysis ----

def parse_csp(value: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in value.split(";"):
        toks = part.strip().split()
        if toks and toks[0].lower() not in out:      # first occurrence of a directive wins (CSP spec)
            out[toks[0].lower()] = toks[1:]
    return out


def parse_cookie(header: str) -> tuple[str, dict[str, str]]:
    parts = [p.strip() for p in header.split(";")]
    name = parts[0].split("=", 1)[0].strip() if parts and parts[0] else ""
    attrs: dict[str, str] = {}
    for p in parts[1:]:
        if p:
            k, _, v = p.partition("=")
            attrs[k.strip().lower()] = v.strip()
    return name, attrs


def _max_age(hsts: str) -> int | None:
    m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
    return int(m.group(1)) if m else None


def analyze(snap: HttpSnapshot) -> list[HeaderIssue]:
    """Security-header issues of the final response."""
    if snap.error or snap.status is None:
        return []
    issues: list[HeaderIssue] = []
    final = snap.final_url or snap.url
    https = final.startswith("https://")
    ctype = (snap.get("Content-Type") or "").lower()
    html = not ctype or "html" in ctype
    doc_sev = "Medium" if html else "Low"
    doc_note = "" if html else f" (the response is {ctype.split(';')[0]}, not a web page, so this matters less)"

    if snap.tls_verified is False:
        issues.append(HeaderIssue("tls_untrusted", "Medium", "HTTPS certificate not trusted",
                                  f"Certificate verification failed: {snap.tls_error}. Headers were read with "
                                  "verification turned off. The TLS audit in Host Audit has certificate details.",
                                  "tls"))
    if not https:
        redirected = snap.url.startswith("http://") and any(h.location for h in snap.hops)
        issues.append(HeaderIssue(
            "no_https", "Medium", "Site served over plain HTTP",
            ("The page is delivered over unencrypted HTTP" +
             (" even after following redirects." if redirected else ", with no redirect to HTTPS.") +
             " Anyone on the network path can read and change it, including passwords typed into it."), "https"))
    else:
        hsts = snap.get("Strict-Transport-Security")
        if not hsts:
            issues.append(HeaderIssue("hsts_missing", "Medium", "Strict-Transport-Security (HSTS) header missing",
                                      "Browsers will still try plain HTTP first when someone types the address, "
                                      "which an attacker on the network can intercept (SSL stripping).", "hsts"))
        else:
            age = _max_age(hsts)
            if age is None:
                issues.append(HeaderIssue("hsts_invalid", "Medium", "HSTS header has no valid max-age",
                                          f"Strict-Transport-Security: {hsts}", "hsts"))
            elif age == 0:
                issues.append(HeaderIssue("hsts_zero", "Medium", "HSTS disabled (max-age=0)",
                                          f"Strict-Transport-Security: {hsts}", "hsts"))
            elif age < HSTS_MIN_AGE:
                issues.append(HeaderIssue("hsts_short", "Low", "HSTS max-age is short",
                                          f"max-age={age} s ({age // 86400} days); at least 180 days "
                                          f"({HSTS_MIN_AGE} s) is recommended, 1 year for preloading.", "hsts"))

    csp_header = snap.get("Content-Security-Policy")
    csp = parse_csp(csp_header or "")
    if not csp_header:
        ro = snap.get("Content-Security-Policy-Report-Only")
        if ro:
            issues.append(HeaderIssue("csp_report_only", "Low", "CSP is in report-only mode",
                                      "Content-Security-Policy-Report-Only only reports violations; it blocks "
                                      "nothing." + doc_note, "csp"))
        else:
            issues.append(HeaderIssue("csp_missing", doc_sev, "Content-Security-Policy header missing",
                                      "Without a CSP, any script injected into the page (XSS) runs with full "
                                      "access to it." + doc_note, "csp"))
    else:
        directive = "script-src" if "script-src" in csp else "default-src" if "default-src" in csp else None
        if directive is None:
            issues.append(HeaderIssue("csp_no_script_policy", "Low", "CSP doesn't restrict scripts",
                                      "The policy has neither script-src nor default-src, so scripts from "
                                      f"anywhere are allowed. Policy: {csp_header[:200]}", "csp"))
        else:
            srcs = [s.lower() for s in csp[directive]]
            nonce_or_hash = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in srcs)
            if "'unsafe-inline'" in srcs and not nonce_or_hash and "'strict-dynamic'" not in srcs:
                issues.append(HeaderIssue("csp_unsafe_inline", "Low", "CSP allows inline scripts ('unsafe-inline')",
                                          f"{directive} {' '.join(csp[directive])}: injected inline scripts still "
                                          "run, which removes most of CSP's protection against XSS.", "csp"))
            if "'unsafe-eval'" in srcs:
                issues.append(HeaderIssue("csp_unsafe_eval", "Low", "CSP allows eval() ('unsafe-eval')",
                                          f"{directive} {' '.join(csp[directive])}", "csp"))
            wild = [s for s in srcs if s in ("*", "http:", "https:", "data:")]
            if wild:
                issues.append(HeaderIssue("csp_wildcard", "Low", "CSP allows scripts from any host",
                                          f"{directive} contains {', '.join(wild)}", "csp"))

    xfo = (snap.get("X-Frame-Options") or "").strip()
    if "frame-ancestors" not in csp:
        if not xfo:
            issues.append(HeaderIssue("framing_missing", doc_sev,
                                      "No clickjacking protection (X-Frame-Options / CSP frame-ancestors)",
                                      "Another site can load this page in an invisible frame and trick a "
                                      "logged-in user into clicking its buttons." + doc_note, "framing"))
        elif xfo.upper() not in ("DENY", "SAMEORIGIN"):
            issues.append(HeaderIssue("framing_invalid", "Low", "X-Frame-Options value not supported by browsers",
                                      f"X-Frame-Options: {xfo}. Only DENY and SAMEORIGIN are honoured "
                                      "(ALLOW-FROM is obsolete); use CSP frame-ancestors instead.", "framing"))

    xcto = (snap.get("X-Content-Type-Options") or "").strip().lower()
    if xcto != "nosniff":
        issues.append(HeaderIssue("nosniff_missing", "Low", "X-Content-Type-Options: nosniff missing",
                                  (f"Value is '{xcto}'. " if xcto else "") +
                                  "Browsers may guess ('sniff') a response's type and run an uploaded file as "
                                  "script or HTML.", "nosniff"))

    rp = (snap.get("Referrer-Policy") or "").strip().lower()
    last = rp.split(",")[-1].strip() if rp else ""
    if not rp:
        issues.append(HeaderIssue("referrer_missing", "Low", "Referrer-Policy header missing",
                                  "Modern browsers default to strict-origin-when-cross-origin, but older ones send "
                                  "the full URL (including paths and query strings) to other sites.", "referrer"))
    elif last in ("unsafe-url", "no-referrer-when-downgrade"):
        issues.append(HeaderIssue("referrer_weak", "Low", f"Referrer-Policy '{last}' leaks full URLs",
                                  "Full page URLs, including query strings, are sent to other sites.", "referrer"))

    issues += _cookie_issues(snap, https)

    for name in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"):
        v = snap.get(name)
        if v and re.search(r"\d", v):
            issues.append(HeaderIssue(f"disclosure_{name.lower()}", "Info", f"{name} header reveals a version",
                                      f"{name}: {v}. Not a weakness by itself, but it tells attackers exactly "
                                      "which known vulnerabilities to try.", "disclosure"))
    return issues


def _cookie_issues(snap: HttpSnapshot, https: bool) -> list[HeaderIssue]:
    cookies = [parse_cookie(c) for c in snap.get_all("Set-Cookie")]
    cookies = [(n, a) for n, a in cookies if n]
    out = []

    def add(iid, names_sev, title, detail):
        if names_sev:
            sev = "Medium" if any(s == "Medium" for _, s in names_sev) else "Low"
            names = ", ".join(sorted({n for n, _ in names_sev}))
            out.append(HeaderIssue(iid, sev, f"{title}: {names}", detail, "cookie"))

    def sev(name):
        return "Medium" if SESSIONISH.search(name) and not CSRFISH.search(name) else "Low"

    if https:
        add("cookie_secure", [(n, sev(n)) for n, a in cookies if "secure" not in a],
            "Cookie without the Secure flag",
            "The browser will also send these cookies over plain HTTP, where anyone on the network can read them. "
            "Session cookies (names like 'session', 'sid', 'token') are rated higher.")
    add("cookie_httponly", [(n, sev(n)) for n, a in cookies if "httponly" not in a and not CSRFISH.search(n)],
        "Cookie without the HttpOnly flag",
        "Page scripts, including injected ones (XSS), can read these cookies and steal the session.")
    add("cookie_samesite", [(n, "Low") for n, a in cookies if "samesite" not in a],
        "Cookie without a SameSite attribute",
        "Browsers differ in their default; set SameSite=Lax (or Strict) explicitly to limit cross-site request "
        "forgery (CSRF).")
    add("cookie_samesite_none", [(n, "Medium") for n, a in cookies
                                 if a.get("samesite", "").lower() == "none" and "secure" not in a],
        "Cookie with SameSite=None but no Secure flag",
        "Browsers reject SameSite=None cookies that aren't Secure, and they would be sent on cross-site requests.")
    return out


# ---- findings ----

REMEDIATION = {
    "https": ("Serve the site over HTTPS only: get a certificate (Let's Encrypt, or your internal CA for lab "
              "devices), then redirect all HTTP requests to HTTPS (nginx `return 301 https://$host$request_uri;`)."),
    "hsts": ("Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on every HTTPS response "
             "(nginx `add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;`, "
             "Apache `Header always set Strict-Transport-Security ...`). Only do this once HTTPS works everywhere."),
    "csp": ("Add a Content-Security-Policy. A safe start: `default-src 'self'; object-src 'none'; "
            "base-uri 'self'; frame-ancestors 'self'`, then allow the extra sources the site really needs. Replace "
            "inline scripts with files or nonces instead of 'unsafe-inline'. Test with "
            "Content-Security-Policy-Report-Only first if you're unsure."),
    "framing": ("Send `X-Frame-Options: DENY` (or SAMEORIGIN if the site frames itself), or the modern equivalent "
                "`Content-Security-Policy: frame-ancestors 'none'`."),
    "nosniff": "Send `X-Content-Type-Options: nosniff` on every response.",
    "referrer": "Send `Referrer-Policy: strict-origin-when-cross-origin` (or `no-referrer` for admin interfaces).",
    "cookie": ("Set cookies with `Secure; HttpOnly; SameSite=Lax` (Strict for admin interfaces). Most frameworks "
               "have a setting for this (e.g. PHP session.cookie_secure / cookie_httponly / cookie_samesite, "
               "Django SESSION_COOKIE_SECURE, Express cookie options). Leave HttpOnly off only for cookies page "
               "scripts must read, such as a CSRF token."),
    "disclosure": ("Hide version numbers: nginx `server_tokens off;`, Apache `ServerTokens Prod` + "
                   "`ServerSignature Off`, PHP `expose_php = Off`. More importantly, keep the software updated."),
    "tls": ("Install a certificate the browser trusts (Let's Encrypt, or an internal CA whose root you install on "
            "your devices). Run the TLS audit in Host Audit for the full picture."),
}
TECHNIQUE = {
    "https": "**Adversary-in-the-middle:** on shared Wi-Fi or a compromised router, plain HTTP can be read and "
             "modified in transit (credentials sniffed, scripts injected).",
    "hsts": "**SSL stripping:** an attacker in the middle answers the first plain-HTTP request and keeps the "
            "victim on HTTP while talking HTTPS to the real site. HSTS makes the browser refuse plain HTTP.",
    "csp": "**Cross-site scripting (XSS):** if any input is reflected into the page unescaped, attacker script runs "
           "as the site. CSP is the safety net that stops injected script from loading or running.",
    "framing": "**Clickjacking:** the page is shown transparently on top of a decoy, so the victim's clicks land on "
               "real buttons (change settings, confirm actions) without them realizing.",
    "nosniff": "**MIME sniffing:** a file served with the wrong type can be interpreted as HTML or script.",
    "cookie": "**Session hijacking:** a stolen session cookie logs the attacker in as the user. Missing Secure lets "
              "it leak over HTTP; missing HttpOnly lets XSS read it; missing SameSite helps CSRF.",
}
ATTCK = {"https": ["T1557", "T1040"], "hsts": ["T1557"], "tls": ["T1557"], "cookie": ["T1539", "T1185"],
         "csp": ["T1189", "T1185"], "framing": ["T1185"], "disclosure": ["T1592.002"]}


def findings(url: str, issues: list[HeaderIssue]) -> list[Finding]:
    u = parse_url(url)
    return [Finding(
        device=u.url, device_label=u.url, kind="web", title=f"Web: {i.title}", severity=i.severity,
        description=i.detail or i.title, remediation=REMEDIATION.get(i.category, ""),
        technique=TECHNIQUE.get(i.category, ""), service=f"{u.port}/tcp {u.scheme}", port=f"{u.port}/tcp",
        attck=ATTCK.get(i.category, []), confidence="confirmed (response headers)",
        weight=SEV_WEIGHT.get(i.severity, 0), source="Header audit (HTTP request)") for i in issues]


def result_to_json(snap: HttpSnapshot, issues: list[HeaderIssue]) -> str:
    return json.dumps({"snapshot": asdict(snap), "issues": [asdict(i) for i in issues]})


def result_from_json(text: str) -> tuple[HttpSnapshot | None, list[HeaderIssue]]:
    d = json.loads(text or "{}")
    s = d.get("snapshot")
    snap = None
    if s:
        snap = HttpSnapshot(**{**s, "hops": [Hop(**h) for h in s.get("hops", [])]})
    return snap, [HeaderIssue(**i) for i in d.get("issues", [])]
