from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import QListWidget, QSplitter, QTabWidget, QTextBrowser, QVBoxLayout, QWidget

from watchtower import __version__
from watchtower.core.platform_utils import WIFI_UNSUPPORTED_REASON
from watchtower.gui.context import AppContext
from watchtower.help.content import GLOSSARY, TAB_HELP

WHERE_TO_START = [
    ('See which devices are on my network and what they expose',
     '**Scan a Target**: add your network (e.g. *Add one of my subnets…*), click **Run scan**'),
    ('Know what to fix first',
     '**Findings**: everything found, worst first, with a risk score per device and how to fix each item'),
    ("Check my Wi-Fi's security (and spot look-alike networks)",
     '**Nearby Networks**: scan, then tick **Authorized** for your own networks'),
    ('Find passwords sent unencrypted, risky Windows lookups, old protocols',
     '**Traffic Audit**: capture for a minute while you use your devices, or open a .pcap'),
    ('Check a router/NAS admin page or my website',
     '**Web Audit** (security headers, nikto) and **Host Audit** (TLS, SNMP)'),
    ('Stop others sending email as my domain',
     '**Domain Audit**: SPF / DKIM / DMARC check and public subdomains'),
    ('Check how strong a password is, or whether it leaked',
     '**Password Tools**'),
    ('Be told when something changes',
     '**What Changed**: compare scans and schedule repeats'),
    ('Hand someone a report',
     '**Findings → Export report…**'),
]
START_TABLE = "| I want to... | Go to |\n|---|---|\n" + "\n".join(f"| {a} | {b} |" for a, b in WHERE_TO_START)

OVERVIEW = f"""
# Watchtower {__version__}

A security check-up tool for **your own** network, devices, websites and
domains. It runs well-known tools for you (nmap, tshark, testssl.sh, nikto,
net-snmp, ...), shows every command before it runs, and turns the results into
a prioritized list of problems, each explained in plain language with how to
fix it.

## Where to start

{START_TABLE}

Every tab has a **(?) What is this?** button (top right) explaining it, and
hovering over any button or field says what it does. Words you may not know are
in the **Glossary** tab above.

## Ground rules Watchtower follows

- **It only touches what you authorize.** Scans and checks run only against
  targets on your authorized list or domains you've confirmed you own, and only
  when you click. Every change to that list is logged.
- **It reports; it never attacks.** No Wi-Fi deauthentication, handshake
  capture, password cracking, WPS attacks, rogue access points or login
  attempts (not even default passwords). Weaknesses are explained in text.
- **Everything is recorded.** Every command and network request appears in the
  Command Console at the bottom and in the **Audit Log** tab.
- **Your data stays here.** Everything is stored in one local database. No
  telemetry. Watchtower only contacts outside services when you ask it to:
  NVD CVE lookups (off by default, Settings), the Pwned Passwords breach check
  (sends only 5 characters of a hash), and Domain Audit's public DNS and
  Certificate Transparency lookups.

**Platform support:** full feature set on Debian-family Linux. On Windows,
everything except the Wi-Fi radio features works. {WIFI_UNSUPPORTED_REASON}
"""


def _find_install_md() -> str:
    # Packaged copy of the top-level INSTALL.md (kept identical by tests/test_docs.py).
    p = Path(__file__).resolve().parents[2] / "help" / "INSTALL.md"
    if p.is_file():
        return p.read_text(encoding="utf-8")
    return "INSTALL.md is missing from this installation. See the project repository."


class HelpTab(QWidget):
    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        tabs = QTabWidget()
        overview = QTextBrowser(openExternalLinks=True)
        overview.setMarkdown(OVERVIEW)
        tabs.addTab(overview, "Overview")
        tabs.addTab(self._glossary(), "Glossary")
        guides = QTextBrowser()
        guides.setMarkdown("\n\n---\n\n".join(TAB_HELP.values()))
        tabs.addTab(guides, "Tab guides")
        setup = QTextBrowser(openExternalLinks=True)
        setup.setMarkdown(_find_install_md())
        tabs.addTab(setup, "Setup")
        lay = QVBoxLayout(self)
        lay.addWidget(tabs)
        self.tabs = tabs

    def _glossary(self) -> QWidget:
        terms = QListWidget()
        body = QTextBrowser()
        for term, _ in GLOSSARY:
            terms.addItem(term)
        terms.currentRowChanged.connect(
            lambda i: body.setMarkdown(f"## {GLOSSARY[i][0]}\n\n{GLOSSARY[i][1]}") if i >= 0 else None)
        terms.setCurrentRow(0)
        split = QSplitter()
        split.addWidget(terms)
        split.addWidget(body)
        split.setStretchFactor(1, 3)
        return split
