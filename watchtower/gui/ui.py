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


def follow(ctx, key: str, apply) -> None:
    """Apply preference `key` now and whenever it changes in Settings (or after a reset)."""
    from watchtower.storage import preferences

    def update(changed: str):
        if changed in (key, "*"):
            apply(preferences.get(ctx.settings, key))
    apply(preferences.get(ctx.settings, key))
    ctx.bus.settings_changed.connect(update)


def set_combo(combo, text: str) -> None:
    idx = combo.findText(text)
    if idx >= 0:
        combo.setCurrentIndex(idx)
