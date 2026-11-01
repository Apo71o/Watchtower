"""First-run authorization acknowledgment.

The scope limit (own or written-authorization networks only) is a legal
boundary, so scanning stays locked until this is accepted. Shown once; the
acceptance is stored locally and written to the audit log.
"""

from __future__ import annotations

from datetime import datetime, timezone

from PySide6.QtWidgets import QCheckBox, QDialog, QDialogButtonBox, QLabel, QTextBrowser, QVBoxLayout

from watchtower.gui.context import AppContext
from watchtower.storage.audit_log import Event
from watchtower.storage.settings import AUTH_ACK

ACK_TEXT = ("I confirm I own the networks and devices I will scan with Watchtower, or have "
            "explicit written authorization from their owner to test them.")

BODY = """
## Before you start

Watchtower discovers and fingerprints networks and devices, then explains the
risks it finds. Scanning or probing networks and devices you do not own or
have permission to test is illegal in most countries (for example the U.S.
CFAA, the U.K. Computer Misuse Act and equivalents elsewhere), even if you
intend no harm.

**How Watchtower keeps you in scope**
- Passive listening (seeing which Wi-Fi networks are nearby) is always allowed.
- Anything that sends traffic to a host (nmap, TLS, SNMP) only runs against
  networks and hosts you individually mark **Authorized**.
- Watchtower never runs attacks: no deauthentication, handshake capture,
  password cracking, WPS attacks, rogue access points or login attempts.
  Findings explain techniques in text only.
- Every command it runs is shown on screen and recorded in an append-only audit log.
"""


class AuthGateDialog(QDialog):
    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self.setWindowTitle("Watchtower: authorization")
        self.setMinimumSize(560, 480)
        body = QTextBrowser()
        body.setMarkdown(BODY)
        statement = QLabel(ACK_TEXT)
        statement.setWordWrap(True)
        statement.setStyleSheet("font-weight: bold; padding: 6px;")
        self.check = QCheckBox("I confirm the statement above")
        lbl = QLabel("You will only see this once. You can revoke it later in Settings.")
        lbl.setWordWrap(True)
        self.buttons = QDialogButtonBox()
        self.accept_btn = self.buttons.addButton("Accept and unlock scanning",
                                                 QDialogButtonBox.ButtonRole.AcceptRole)
        self.buttons.addButton("Not now (stay locked)", QDialogButtonBox.ButtonRole.RejectRole)
        self.accept_btn.setEnabled(False)
        self.check.toggled.connect(self.accept_btn.setEnabled)
        self.buttons.accepted.connect(self._accept)
        self.buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addWidget(body)
        lay.addWidget(statement)
        lay.addWidget(self.check)
        lay.addWidget(lbl)
        lay.addWidget(self.buttons)

    def _accept(self):
        record_acknowledgment(self.ctx)
        self.accept()


def record_acknowledgment(ctx: AppContext) -> None:
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    ctx.settings.set(AUTH_ACK, {"ts": ts, "text": ACK_TEXT})
    ctx.audit.append(Event.AUTHORIZATION_ACK, detail={"accepted": True, "text": ACK_TEXT})
    ctx.bus.authorization_changed.emit(True)


def revoke_acknowledgment(ctx: AppContext) -> None:
    ctx.settings.delete(AUTH_ACK)
    ctx.audit.append(Event.AUTHORIZATION_ACK, detail={"accepted": False, "revoked": True})
    ctx.bus.authorization_changed.emit(False)
