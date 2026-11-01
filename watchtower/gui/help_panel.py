"""The collapsible "What is this?" panel every tab carries.

The panel's open/closed state is a checkable QAction (`HelpPanel.toggle`). In the main window
one "(?) What is this?" button in the tab bar's corner drives the current tab's action, so a
closed panel takes no space at all. A standalone TabPage (e.g. in the Dependency Check dialog)
shows its own button in a slim row above the content instead.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QHBoxLayout, QSplitter, QTextBrowser, QToolButton, QVBoxLayout, QWidget

from watchtower.help.content import TAB_HELP

TOGGLE_TEXT = "(?) What is this?"
TOGGLE_TIP = ("Show or hide the explanation of this tab: what it does, why it matters and how to read the results. "
              "Settings → Appearance decides whether it starts open.")


class HelpPanel(QWidget):
    def __init__(self, help_key: str, parent=None):
        super().__init__(parent)
        self.toggle = QAction(TOGGLE_TEXT, self, checkable=True, checked=True)
        self.toggle.setToolTip(TOGGLE_TIP)
        self.browser = QTextBrowser(openExternalLinks=True)
        self.browser.setMarkdown(TAB_HELP.get(help_key, "_No help written for this tab yet._"))
        self.setMinimumWidth(260)
        self.setMaximumWidth(460)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.browser)
        # Closed: hide the whole panel, so the splitter gives the tab content all the width.
        self.toggle.toggled.connect(self.setVisible)


def toggle_button(action: QAction | None = None) -> QToolButton:
    b = QToolButton()
    b.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)
    if action is not None:
        b.setDefaultAction(action)
    return b


class TabPage(QWidget):
    """Tab content on the left, help panel on the right."""

    def __init__(self, content: QWidget, help_key: str, parent=None, own_button: bool = True):
        super().__init__(parent)
        self.content = content
        self.help = HelpPanel(help_key)
        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(content)
        split.addWidget(self.help)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 1)
        split.setChildrenCollapsible(False)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(6, 6, 6, 6)
        if own_button:
            row = QHBoxLayout()
            row.addStretch()
            row.addWidget(toggle_button(self.help.toggle))
            lay.addLayout(row)
        lay.addWidget(split)
