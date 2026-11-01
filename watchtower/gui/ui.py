"""Small UI helpers shared by the tabs.

Every interactive control has a tooltip saying what it does (tests/test_gui.py
enforces this). When a control is disabled, its tooltip says why; `restore_tip`
puts the normal explanation back once it's enabled again.
"""

from __future__ import annotations

_PROP = "watchtower_default_tip"


def tip(widget, text: str):
    """Set a control's explanation and remember it as its default tooltip."""
    widget.setToolTip(text)
    widget.setProperty(_PROP, text)
    return widget


def restore_tip(widget, reason: str = "") -> None:
    """Show `reason` (why it's disabled) if given, else the control's default explanation."""
    widget.setToolTip(reason or widget.property(_PROP) or "")
