from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from watchtower.core.platform_utils import data_dir
from watchtower.gui.context import AppContext
from watchtower.gui.theme import apply_theme
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
        self.nvd_enabled.toggled.connect(lambda v: ctx.settings.set(NVD_ENABLED, v))
        self.nvd_key.editingFinished.connect(lambda: ctx.settings.set(NVD_API_KEY, self.nvd_key.text().strip()))
        nf = QFormLayout(nvd_box)
        nf.addRow(self.nvd_enabled)
        nf.addRow("NVD API key:", self.nvd_key)
        nf.addRow(QLabel("Live lookups are wired up in build step 11; until then a bundled "
                         "local dataset is used."))

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

    def _theme(self, name: str):
        self.ctx.settings.set(THEME, name)
        apply_theme(name)
