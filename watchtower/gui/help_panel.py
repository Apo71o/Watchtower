"""The collapsible "What is this?" panel every tab carries."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QSplitter, QTextBrowser, QToolButton, QVBoxLayout, QWidget

from watchtower.help.content import TAB_HELP


class HelpPanel(QWidget):
    def __init__(self, help_key: str, parent=None):
        super().__init__(parent)
        self.toggle = QToolButton(text="(?) What is this?", checkable=True, checked=True)
        self.toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)
        self.toggle.setToolTip("Show or hide the explanation of this tab: what it does, why it matters and how to "
                               "read the results.")
        self.browser = QTextBrowser(openExternalLinks=True)
        self.browser.setMarkdown(TAB_HELP.get(help_key, "_No help written for this tab yet._"))
        self.browser.setMinimumWidth(260)
        self.browser.setMaximumWidth(460)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.toggle, alignment=Qt.AlignmentFlag.AlignRight)
        lay.addWidget(self.browser, 1)
        lay.addStretch(0)
        self.toggle.toggled.connect(self._set_expanded)

    def _set_expanded(self, expanded: bool):
        self.browser.setVisible(expanded)
        # Collapsed: shrink to just the button so the tab content gets the space.
        self.setMaximumWidth(16777215 if expanded else self.toggle.sizeHint().width())


class TabPage(QWidget):
    """Tab content on the left, help panel on the right."""

    def __init__(self, content: QWidget, help_key: str, parent=None):
        super().__init__(parent)
        self.content = content
        self.help = HelpPanel(help_key)
        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(content)
        split.addWidget(self.help)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 1)
        split.setChildrenCollapsible(False)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(6, 6, 6, 6)
        lay.addWidget(split)
