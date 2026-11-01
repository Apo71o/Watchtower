from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_packaged_install_md_matches_top_level():
    """Help -> Setup shows the packaged copy; it must match INSTALL.md.
    Fix with:  cp INSTALL.md watchtower/help/INSTALL.md"""
    assert (ROOT / "INSTALL.md").read_text() == (ROOT / "watchtower/help/INSTALL.md").read_text()


def test_every_tab_has_help():
    from watchtower.help.content import GLOSSARY, TAB_HELP
    for key in ["interfaces", "nearby", "scan", "findings", "host_audit", "web_audit", "domain_audit", "traffic",
                "changes",
                "audit_log", "settings", "deps"]:
        assert TAB_HELP.get(key, "").strip(), key
    required = {"WPA / WPA2 / WPA3", "PMKID", "4-way handshake", "WPS (Wi-Fi Protected Setup)",
                "PSK (Pre-Shared Key)", "CVSS", "CVE", "SNMP community string", "TLS cipher suite",
                "MITRE ATT&CK", "Risk score", "SPF / DKIM / DMARC", "Certificate Transparency (CT)",
                "Security headers (HSTS, CSP, X-Frame-Options)", "Cookie flags (Secure, HttpOnly, SameSite)",
                "Packet capture (pcap)", "Capture filter (BPF)", "LLMNR / NBT-NS", "SMBv1", "UPnP / SSDP"}
    assert required <= {t for t, _ in GLOSSARY}
