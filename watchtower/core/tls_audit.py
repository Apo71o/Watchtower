"""TLS audit of one host:port with testssl.sh or SSLyze (subprocess, JSON output).

Both backends are normalized into TlsIssue records, which become findings with
remediation. The audit only performs TLS handshakes and the standard
vulnerability probes those tools run (Heartbleed, ROBOT, ...).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from watchtower.core import deps
from watchtower.core.findings_engine import SEV_WEIGHT, Finding

TLS_SERVICES = {"https", "ssl", "imaps", "pop3s", "smtps", "ldaps", "ftps", "https-alt", "ms-wbt-server"}


@dataclass
class TlsIssue:
    id: str
    severity: str        # Critical / High / Medium / Low / Info
    title: str
    detail: str = ""
    cve: str = ""
    category: str = ""   # protocol / cipher / certificate / vulnerability / config


def backends() -> dict[str, list[str]]:
    """Available backends -> argv prefix."""
    out = {}
    if importlib.util.find_spec("sslyze") is not None:
        out["sslyze"] = [sys.executable, "-m", "sslyze"]
    elif deps.find_binary("sslyze"):
        out["sslyze"] = [deps.find_binary("sslyze")]
    t = deps.find_binary("testssl", "testssl.sh")
    if t:
        out["testssl.sh"] = [t]
    return out


def build_argv(backend: str, host: str, port: int, out_json: str) -> list[str]:
    prefix = backends()[backend]
    target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    if backend == "testssl.sh":
        return [*prefix, "--quiet", "--warnings", "off", "--color", "0", "--jsonfile", out_json,
                "-p", "-s", "-S", "-U", "--ip", "one", target]
    return [*prefix, "--json_out", out_json, target]


def tls_ports(host) -> list[int]:
    """Ports of a parsed nmap Host that likely speak TLS."""
    return [p.portid for p in host.ports if p.state.startswith("open") and p.protocol == "tcp"
            and (p.tunnel == "ssl" or p.service in TLS_SERVICES or p.portid in (443, 8443, 993, 995, 465, 636))]


# ---- testssl.sh ----

_TESTSSL_SEV = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "WARN": "Low"}
_TESTSSL_SKIP = {"cert_notAfter", "cert_notBefore", "DNS_CAArecord", "scanTime", "overall_grade"}
_TESTSSL_INFO = {"cert_revocation": "No CRL/OCSP: normal for self-signed and private-CA certificates."}


def _category(tid: str) -> str:
    t = tid.lower()
    if t.startswith(("sslv", "tls1")):
        return "protocol"
    if t.startswith(("cipherlist", "cipher_", "pfs", "fs_")) or "rc4" in t or "sweet32" in t:
        return "cipher"
    if t.startswith("cert") or "chain_of_trust" in t:
        return "certificate"
    if t in ("secure_renego", "secure_client_renego", "crime_tls", "fallback_scsv", "breach"):
        return "config"
    return "vulnerability"


def parse_testssl(text: str) -> list[TlsIssue]:
    data = json.loads(text or "[]")
    if isinstance(data, dict):            # --jsonfile-pretty format
        data = [f for r in data.get("scanResult", []) for v in r.values() if isinstance(v, list) for f in v]
    issues = []
    for e in data:
        tid, sev = e.get("id", ""), e.get("severity", "")
        if tid in _TESTSSL_SKIP:
            continue
        if tid in _TESTSSL_INFO:
            issues.append(TlsIssue(tid, "Info", tid.replace("_", " "), _TESTSSL_INFO[tid], "", _category(tid)))
            continue
        if sev not in _TESTSSL_SEV:
            continue
        issues.append(TlsIssue(tid, _TESTSSL_SEV[sev], _testssl_title(tid, e.get("finding", "")),
                               e.get("finding", ""), e.get("cve", ""), _category(tid)))
    return issues


def _testssl_title(tid: str, finding: str) -> str:
    names = {"SSLv2": "SSLv2 offered", "SSLv3": "SSLv3 offered", "TLS1": "TLS 1.0 offered",
             "TLS1_1": "TLS 1.1 offered", "cipherlist_NULL": "NULL ciphers (no encryption) offered",
             "cipherlist_aNULL": "Anonymous ciphers (no authentication) offered",
             "cipherlist_EXPORT": "Export-grade ciphers offered", "cipherlist_LOW": "Low-strength ciphers offered",
             "cipherlist_3DES_IDEA": "3DES/IDEA ciphers offered",
             "cipherlist_OBSOLETED": "Obsolete CBC ciphers offered",
             "cert_chain_of_trust": "Certificate not trusted", "cert_trust": "Certificate doesn't match the host name",
             "cert_subjectAltName": "Certificate has no Subject Alternative Name",
             "cert_expirationStatus": "Certificate expired or expiring soon",
             "cert_signatureAlgorithm": "Weak certificate signature algorithm",
             "cert_keySize": "Weak certificate key size"}
    if tid in names:
        return names[tid]
    return f"{tid.replace('_', ' ')}: {finding[:60]}"


# ---- SSLyze ----

_PROTOCOLS = [("ssl_2_0_cipher_suites", "SSLv2", "Critical"), ("ssl_3_0_cipher_suites", "SSLv3", "High"),
              ("tls_1_0_cipher_suites", "TLS 1.0", "Low"), ("tls_1_1_cipher_suites", "TLS 1.1", "Low")]
_WEAK_CIPHERS = [("NULL", "NULL ciphers (no encryption) offered", "Critical"),
                 ("anon", "Anonymous ciphers (no authentication) offered", "Critical"),
                 ("EXPORT", "Export-grade ciphers offered", "Critical"), ("RC4", "RC4 ciphers offered", "High"),
                 ("3DES", "3DES ciphers offered (SWEET32)", "Medium"), ("DES_CBC", "DES ciphers offered", "High")]


def _accepted(scan: dict, key: str) -> list[str]:
    res = (scan.get(key) or {}).get("result") or {}
    return [c["cipher_suite"]["name"] for c in res.get("accepted_cipher_suites", [])]


def parse_sslyze(text: str, now: datetime | None = None) -> list[TlsIssue]:
    now = now or datetime.now(timezone.utc)
    data = json.loads(text or "{}")
    issues: list[TlsIssue] = []
    for server in data.get("server_scan_results", []):
        if server.get("scan_status") != "COMPLETED":
            issues.append(TlsIssue("connectivity", "Info", "SSLyze could not complete the scan",
                                   str(server.get("connectivity_error_trace") or server.get("connectivity_status"))))
            continue
        scan = server["scan_result"]
        all_ciphers: list[str] = []
        for key, name, sev in _PROTOCOLS:
            acc = _accepted(scan, key)
            all_ciphers += acc
            if acc:
                issues.append(TlsIssue(name, sev, f"{name} offered", f"{len(acc)} cipher suites accepted", "",
                                       "protocol"))
        for key in ("tls_1_2_cipher_suites", "tls_1_3_cipher_suites"):
            all_ciphers += _accepted(scan, key)
        if not _accepted(scan, "tls_1_2_cipher_suites") and not _accepted(scan, "tls_1_3_cipher_suites"):
            issues.append(TlsIssue("no_modern_tls", "High", "Neither TLS 1.2 nor TLS 1.3 offered", "", "", "protocol"))
        for token, title, sev in _WEAK_CIPHERS:
            hits = sorted({c for c in all_ciphers if token in c})
            if hits:
                issues.append(TlsIssue(f"cipher_{token}", sev, title, ", ".join(hits[:8]), "", "cipher"))
        checks = [("heartbleed", "is_vulnerable_to_heartbleed", "Heartbleed", "Critical", "CVE-2014-0160"),
                  ("openssl_ccs_injection", "is_vulnerable_to_ccs_injection", "OpenSSL CCS injection", "High",
                   "CVE-2014-0224")]
        for key, field_, title, sev, cve in checks:
            if ((scan.get(key) or {}).get("result") or {}).get(field_):
                issues.append(TlsIssue(key, sev, f"Vulnerable to {title}", "", cve, "vulnerability"))
        robot = ((scan.get("robot") or {}).get("result") or {}).get("robot_result", "")
        if robot.startswith("VULNERABLE"):
            issues.append(TlsIssue("robot", "High", "Vulnerable to ROBOT (RSA padding oracle)", robot,
                                   "CVE-2017-13099", "vulnerability"))
        if ((scan.get("tls_compression") or {}).get("result") or {}).get("supports_compression"):
            issues.append(TlsIssue("compression", "Medium", "TLS compression enabled (CRIME)", "", "CVE-2012-4929",
                                   "config"))
        reneg = (scan.get("session_renegotiation") or {}).get("result") or {}
        if reneg and not reneg.get("supports_secure_renegotiation", True):
            issues.append(TlsIssue("insecure_renegotiation", "Medium", "Insecure renegotiation supported", "",
                                   "CVE-2009-3555", "config"))
        if reneg.get("is_vulnerable_to_client_renegotiation_dos"):
            issues.append(TlsIssue("client_renegotiation_dos", "Low", "Client-initiated renegotiation (DoS risk)",
                                   "", "", "config"))
        issues += _sslyze_cert(scan, now)
    return issues


def _sslyze_cert(scan: dict, now: datetime) -> list[TlsIssue]:
    out = []
    res = (scan.get("certificate_info") or {}).get("result") or {}
    for dep in res.get("certificate_deployments", [])[:1]:
        chain = dep.get("received_certificate_chain") or []
        if chain:
            leaf = chain[0]
            subject = (leaf.get("subject") or {}).get("rfc4514_string", "")
            issuer = (leaf.get("issuer") or {}).get("rfc4514_string", "")
            try:
                not_after = datetime.fromisoformat(leaf["not_valid_after"].replace("Z", "+00:00"))
                days = (not_after - now).days
                if days < 0:
                    out.append(TlsIssue("cert_expired", "High", "Certificate expired",
                                        f"expired {-days} days ago ({not_after:%Y-%m-%d})", "", "certificate"))
                elif days < 30:
                    out.append(TlsIssue("cert_expiring", "Medium", "Certificate expiring soon",
                                        f"expires in {days} days ({not_after:%Y-%m-%d})", "", "certificate"))
            except (KeyError, ValueError):
                pass
            san = leaf.get("subject_alternative_name") or {}
            if not (san.get("dns_names") or san.get("ip_addresses")):
                out.append(TlsIssue("cert_no_san", "Low", "Certificate has no Subject Alternative Name",
                                    subject, "", "certificate"))
            key_size = (leaf.get("public_key") or {}).get("key_size")
            if (leaf.get("public_key") or {}).get("algorithm") == "RSAPublicKey" and key_size and key_size < 2048:
                out.append(TlsIssue("cert_weak_key", "High", "Weak certificate key size", f"RSA {key_size} bits",
                                    "", "certificate"))
            self_signed = subject and subject == issuer
        else:
            self_signed = False
        results = dep.get("path_validation_results") or []
        moz = next((r for r in results if (r.get("trust_store") or {}).get("name") == "Mozilla"), None)
        if moz and not moz.get("was_validation_successful"):
            detail = "self-signed" if self_signed else (moz.get("validation_error") or "")
            out.append(TlsIssue("cert_untrusted", "Medium", "Certificate not trusted by browsers", detail[:200], "",
                                "certificate"))
        if dep.get("verified_chain_has_sha1_signature"):
            out.append(TlsIssue("cert_sha1", "Medium", "SHA-1 signature in certificate chain", "", "", "certificate"))
    return out


# ---- findings ----

REMEDIATION = {
    "protocol": ("Disable SSLv2, SSLv3, TLS 1.0 and TLS 1.1 in the server's TLS settings and offer TLS 1.2 and 1.3 "
                 "only (e.g. nginx `ssl_protocols TLSv1.2 TLSv1.3;`, Apache `SSLProtocol -all +TLSv1.2 +TLSv1.3`). "
                 "On appliances, update the firmware or look for a 'minimum TLS version' setting."),
    "cipher": ("Restrict the cipher list to modern AEAD suites with forward secrecy (ECDHE with AES-GCM or "
               "ChaCha20-Poly1305). Mozilla's SSL Configuration Generator gives ready-made settings per server."),
    "certificate": ("Use a certificate from a trusted CA (Let's Encrypt is free; for internal-only devices, an "
                    "internal CA whose root you install on your clients). It must list the host name in its "
                    "Subject Alternative Name, use RSA 2048+ or ECDSA, and be renewed before it expires."),
    "vulnerability": ("Update the TLS library (OpenSSL etc.) and the server or firmware to a version that fixes "
                      "this vulnerability, then restart the service."),
    "config": "Update the server/TLS library and disable the insecure feature in the TLS configuration.",
}
TECHNIQUE = {
    "protocol": ("Old protocol versions have known design flaws (POODLE against SSLv3, BEAST against TLS 1.0 CBC). "
                 "An attacker in the middle can try to force a downgrade to the weakest version both sides support."),
    "cipher": ("Weak cipher suites can be broken or bypassed by an attacker who can see or modify the traffic: "
               "NULL/anonymous suites provide no confidentiality or no authentication at all, export and RC4/3DES "
               "suites are cryptographically broken."),
    "certificate": ("If clients learn to click through certificate warnings for this host, they can't tell it apart "
                    "from an impostor presenting its own certificate: the warning they've learned to ignore is the "
                    "only sign of an adversary-in-the-middle."),
}


def findings(host: str, label: str, port: int, issues: list[TlsIssue], backend: str) -> list[Finding]:
    out = []
    for i in issues:
        if i.severity == "Info" and i.id == "connectivity":
            continue
        out.append(Finding(
            device=host, device_label=label, kind="tls", title=f"TLS: {i.title}", severity=i.severity,
            description=(i.detail or i.title) + f"\n\nReported by {backend} on port {port}.",
            technique=TECHNIQUE.get(i.category, ""), remediation=REMEDIATION.get(i.category, REMEDIATION["config"]),
            service=f"{port}/tcp TLS", port=f"{port}/tcp", cve_id=i.cve.replace(" ", ", ") if i.cve else "",
            attck=["T1557", "T1040"] if i.category in ("protocol", "cipher", "certificate") else ["T1210"],
            confidence=f"confirmed by {backend}", weight=SEV_WEIGHT.get(i.severity, 0),
            source=f"TLS audit ({backend})"))
    return out


def issues_to_json(issues: list[TlsIssue]) -> str:
    return json.dumps([asdict(i) for i in issues])


def issues_from_json(text: str) -> list[TlsIssue]:
    return [TlsIssue(**d) for d in json.loads(text or "[]")]
