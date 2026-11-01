"""Stand-in for tabs whose build step hasn't landed yet. Shows which tools
the feature will need (grayed with a tooltip if missing) so the degraded-mode
behavior is visible from day one."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QPushButton, QVBoxLayout, QWidget

from watchtower.gui.context import AppContext


class PlaceholderTab(QWidget):
    def __init__(self, ctx: AppContext, title: str, step: str, requires: list[str],
                 action_label: str, disabled_reason: str | None = None, parent=None):
        super().__init__(parent)
        self.ctx, self.requires, self.disabled_reason = ctx, requires, disabled_reason
        head = QLabel(f"<h2>{title}</h2><p>Arrives in <b>{step}</b> of the build order "
                      f"(see CLAUDE.md).</p>")
        head.setWordWrap(True)
        self.action = QPushButton(action_label)
        self.action.setEnabled(False)
        self.req_lbl = QLabel()
        self.req_lbl.setWordWrap(True)
        lay = QVBoxLayout(self)
        lay.addWidget(head)
        lay.addWidget(self.action, alignment=Qt.AlignmentFlag.AlignLeft)
        lay.addWidget(self.req_lbl)
        lay.addStretch()
        ctx.bus.dependencies_changed.connect(self.refresh)
        self.refresh()

    def refresh(self):
        if self.disabled_reason:
            reason = self.disabled_reason
        else:
            missing = [self.ctx.deps.reason(k) for k in self.requires if not self.ctx.deps.available(k)]
            reason = "; ".join(missing) if missing else "Not built yet."
        self.action.setToolTip(reason)
        req = ", ".join(self.requires) or "nothing external"
        self.req_lbl.setText(f"Needs: {req}\nStatus: {reason}")
