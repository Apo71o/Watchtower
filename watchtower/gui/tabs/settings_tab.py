from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from watchtower.core.platform_utils import data_dir
from watchtower.gui.context import AppContext
from watchtower.gui.theme import apply_theme
from watchtower.gui.ui import tip
from watchtower.storage.audit_log import Event
from watchtower.storage.settings import NVD_API_KEY, NVD_ENABLED, RETENTION_DAYS, THEME


def _human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


class SettingsTab(QWidget):
    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx

        # NVD
        nvd_box = QGroupBox("Vulnerability data (NVD)")
        self.nvd_enabled = QCheckBox("Enable live NVD CVE lookups (sends software names/versions to nvd.nist.gov)")
        tip(self.nvd_enabled, ("When on, Findings can look up CVEs for discovered software versions on the NIST NVD "
                               "website. Off by default; every request is logged."))
        self.nvd_enabled.setChecked(bool(ctx.settings.get(NVD_ENABLED, False)))
        self.nvd_key = QLineEdit(ctx.settings.get(NVD_API_KEY, "") or "")
        tip(self.nvd_key, ("Optional free NVD API key: lookups go about 10x faster. Get one at "
                           "nvd.nist.gov/developers/request-an-api-key."))
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
        tip(clear, 'Forget cached NVD results so the next lookup fetches fresh data.')
        clear.clicked.connect(lambda: (ctx.nvd.clear(), ctx.bus.audit_finished.emit()))
        nf.addRow(clear)

        # Appearance
        look_box = QGroupBox("Appearance")
        self.theme = QComboBox()
        tip(self.theme, "Light, dark, or follow your system's setting.")
        self.theme.addItems(["system", "light", "dark"])
        self.theme.setCurrentText(ctx.settings.get(THEME, "system"))
        self.theme.currentTextChanged.connect(self._theme)
        lf = QFormLayout(look_box)
        lf.addRow("Theme:", self.theme)

        # Data & history
        data_box = QGroupBox("Data && history")
        self.retention = QSpinBox(minimum=0, maximum=3650, value=int(ctx.settings.get(RETENTION_DAYS, 0) or 0))
        tip(self.retention, ("Automatically delete scans, captures and history older than this many days (0 = keep "
                             "everything). The audit log and your authorized targets are never deleted."))
        self.retention.setSpecialValueText("keep everything")
        self.retention.setSuffix(" days")
        self.retention.valueChanged.connect(lambda v: ctx.settings.set(RETENTION_DAYS, v))
        self.cleanup_btn = QPushButton("Clean up now")
        tip(self.cleanup_btn, 'Delete old data now using the setting above, then compact the database.')
        self.cleanup_btn.clicked.connect(self._cleanup)
        self.data_info = QLabel()
        self.data_info.setWordWrap(True)
        df = QFormLayout(data_box)
        df.addRow("Delete scans/history older than:", self.retention)
        df.addRow(QLabel("Applied on startup. The audit log and your authorized targets/networks are never pruned."))
        df.addRow(self.cleanup_btn)
        df.addRow(self.data_info)

        info = QLabel(f"Data directory: {data_dir()}\nDatabase: {ctx.db.path}")
        info.setWordWrap(True)

        row = QHBoxLayout()
        row.addWidget(nvd_box)
        row.addWidget(look_box)
        lay = QVBoxLayout(self)
        lay.addLayout(row)
        lay.addWidget(data_box)
        lay.addWidget(info)
        lay.addStretch()
        self._refresh_data_info()

    def _refresh_data_info(self):
        n = self.ctx.scans.targets()
        total_scans = sum(t["n"] for t in n)
        self.data_info.setText(f"Database size: {_human_size(self.ctx.maintenance.db_size_bytes())} · "
                               f"{total_scans} stored scan(s) across {len(n)} target(s), "
                               f"{len(self.ctx.networks.snapshots())} Wi-Fi snapshot(s), "
                               f"{len(self.ctx.captures.all(limit=100_000))} traffic capture(s).")

    def _cleanup(self):
        days = self.retention.value()
        if days <= 0:
            if QMessageBox.question(self, "Clean up", "Retention is set to keep everything, so nothing would be "
                                    "deleted. Set a number of days first.") or True:
                return
        pruned = self.ctx.maintenance.prune(days)
        self.ctx.maintenance.vacuum()
        if pruned:
            self.ctx.audit.append(Event.CONFIRMATION, detail={"action": "retention cleanup (manual)", **pruned})
        summary = ", ".join(f"{v} {k}" for k, v in pruned.items()) if pruned else "nothing older than the cutoff"
        QMessageBox.information(self, "Clean up", f"Deleted: {summary}.")
        self._refresh_data_info()
        self.ctx.bus.scan_finished.emit()
        self.ctx.bus.networks_changed.emit()

    def _toggle_nvd(self, on: bool):
        self.ctx.settings.set(NVD_ENABLED, on)
        self.ctx.audit.append(Event.CONFIRMATION, detail={"action": "NVD lookups " + ("enabled" if on else "disabled")})
        self.ctx.bus.audit_finished.emit()   # refresh Findings (shows/hides NVD results and button)

    def _theme(self, name: str):
        self.ctx.settings.set(THEME, name)
        apply_theme(name)
