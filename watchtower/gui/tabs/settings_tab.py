from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from watchtower.core.platform_utils import data_dir
from watchtower.gui.context import AppContext
from watchtower.gui.theme import apply_theme
from watchtower.storage.audit_log import Event
from watchtower.storage.settings import NVD_API_KEY, NVD_ENABLED, THEME


class SettingsTab(QWidget):
    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx

        # NVD
        nvd_box = QGroupBox("Vulnerability data (NVD)")
        self.nvd_enabled = QCheckBox("Enable live NVD CVE lookups (off = no outbound network calls)")
        self.nvd_enabled.setChecked(bool(ctx.settings.get(NVD_ENABLED, False)))
        self.nvd_key = QLineEdit(ctx.settings.get(NVD_API_KEY, "") or "")
        self.nvd_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.nvd_key.setPlaceholderText("optional, raises rate limit")
        self.nvd_enabled.toggled.connect(self._toggle_nvd)
        self.nvd_key.editingFinished.connect(lambda: ctx.settings.set(NVD_API_KEY, self.nvd_key.text().strip()))
        nf = QFormLayout(nvd_box)
        nf.addRow(self.nvd_enabled)
        nf.addRow("NVD API key:", self.nvd_key)
        note = QLabel("When on, Findings can query services.nvd.nist.gov for CVEs matching the service versions "
                      "nmap found (automatically after each scan, and via “Look up CVEs on NVD”). Results are "
                      "cached for 7 days. Every request appears in the Command Console and the audit log. "
                      "A free API key (nvd.nist.gov/developers/request-an-api-key) raises the rate limit from "
                      "5 to 50 requests per 30 seconds.")
        note.setWordWrap(True)
        nf.addRow(note)
        clear = QPushButton("Clear NVD cache")
        clear.clicked.connect(lambda: (ctx.nvd.clear(), ctx.bus.audit_finished.emit()))
        nf.addRow(clear)

        # Appearance
        look_box = QGroupBox("Appearance")
        self.theme = QComboBox()
        self.theme.addItems(["system", "light", "dark"])
        self.theme.setCurrentText(ctx.settings.get(THEME, "system"))
        self.theme.currentTextChanged.connect(self._theme)
        lf = QFormLayout(look_box)
        lf.addRow("Theme:", self.theme)

        sched_box = QGroupBox("Scheduler")
        QVBoxLayout(sched_box).addWidget(QLabel("Recurring scans arrive in build step 8."))

        info = QLabel(f"Data directory: {data_dir()}\nDatabase: {ctx.db.path}")
        info.setWordWrap(True)

        row = QHBoxLayout()
        row.addWidget(nvd_box)
        row.addWidget(look_box)
        lay = QVBoxLayout(self)
        lay.addLayout(row)
        lay.addWidget(sched_box)
        lay.addWidget(info)
        lay.addStretch()

    def _toggle_nvd(self, on: bool):
        self.ctx.settings.set(NVD_ENABLED, on)
        self.ctx.audit.append(Event.CONFIRMATION, detail={"action": "NVD lookups " + ("enabled" if on else "disabled")})
        self.ctx.bus.audit_finished.emit()   # refresh Findings (shows/hides NVD results and button)

    def _theme(self, name: str):
        self.ctx.settings.set(THEME, name)
        apply_theme(name)
