from __future__ import annotations

from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication

_default_palette: QPalette | None = None


def apply_theme(name: str) -> None:
    global _default_palette
    app = QApplication.instance()
    if app is None:
        return
    app.setStyle("Fusion")
    if _default_palette is None:
        _default_palette = QPalette(app.palette())
    if name == "dark":
        p = QPalette()
        base, alt, text = QColor(30, 30, 30), QColor(45, 45, 45), QColor(225, 225, 225)
        for role, col in [(QPalette.ColorRole.Window, alt), (QPalette.ColorRole.WindowText, text),
                          (QPalette.ColorRole.Base, base), (QPalette.ColorRole.AlternateBase, alt),
                          (QPalette.ColorRole.Text, text), (QPalette.ColorRole.Button, alt),
                          (QPalette.ColorRole.ButtonText, text), (QPalette.ColorRole.ToolTipBase, alt),
                          (QPalette.ColorRole.ToolTipText, text),
                          (QPalette.ColorRole.Highlight, QColor(42, 130, 218)),
                          (QPalette.ColorRole.HighlightedText, QColor(0, 0, 0)),
                          (QPalette.ColorRole.Link, QColor(90, 160, 240))]:
            p.setColor(role, col)
        p.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, QColor(120, 120, 120))
        p.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, QColor(120, 120, 120))
        app.setPalette(p)
    elif name == "light":
        app.setPalette(app.style().standardPalette())
    else:
        app.setPalette(_default_palette)
