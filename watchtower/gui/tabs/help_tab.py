from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import QListWidget, QSplitter, QTabWidget, QTextBrowser, QVBoxLayout, QWidget

from watchtower import __version__
from watchtower.core.platform_utils import WIFI_UNSUPPORTED_REASON
from watchtower.gui.context import AppContext
from watchtower.help.content import GLOSSARY, TAB_HELP

OVERVIEW = f"""
# Watchtower {__version__}

A local, reporting-only security audit tool for networks and Wi-Fi you own or
are authorized to test. It wraps existing tools (nmap, airodump-ng, sslyze,
net-snmp…), shows you every command it runs, and turns their output into
findings with remediation advice.

**What it never does:** deauthentication, handshake/PMKID capture, password
cracking, WPS attacks, rogue access points, or login attempts. When it finds a
weakness, it explains the technique in text. Testing it hands-on is something
you do yourself, outside this app.

**Platform support:** full feature set on Debian-family Linux. On Windows,
everything except the Wi-Fi radio features works. {WIFI_UNSUPPORTED_REASON}

**Data:** everything is stored locally in one SQLite file in your user data
directory. No telemetry. The only optional outbound connection is NVD CVE
lookups, off by default.
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
