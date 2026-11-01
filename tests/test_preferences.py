"""User preferences registry (storage/preferences.py)."""

import pytest

from watchtower.storage import preferences as prefs
from watchtower.storage.settings import CONSOLE_VISIBLE, Settings


def test_registry_is_consistent():
    keys = [p.key for p in prefs.PREFS]
    assert len(keys) == len(set(keys))
    for p in prefs.PREFS:
        assert p.label and p.tip and p.section in prefs.SECTIONS, p.key
        assert prefs.valid(p, p.default), p.key                 # every default is allowed
        if p.kind == "choice":
            assert prefs.choices_for(p), p.key
    assert prefs.BY_KEY[prefs.SCAN_PROFILE].default in prefs.choices_for(prefs.BY_KEY[prefs.SCAN_PROFILE])


def test_get_set_fallback_and_reset(db):
    s = Settings(db)
    assert prefs.get(s, prefs.NIKTO_MINUTES) == 30 and prefs.is_default(s, prefs.NIKTO_MINUTES)
    prefs.set(s, prefs.NIKTO_MINUTES, 45)
    prefs.set(s, prefs.FONT_SIZE, "Large")
    prefs.set(s, CONSOLE_VISIBLE, False)
    assert prefs.get(s, prefs.NIKTO_MINUTES) == 45 and not prefs.is_default(s, prefs.FONT_SIZE)
    for key, bad in ((prefs.NIKTO_MINUTES, 999), (prefs.FONT_SIZE, "Huge"), (prefs.HELP_PANELS, "yes"),
                     (prefs.REPORT_TITLE, 5)):
        with pytest.raises(ValueError):
            prefs.set(s, key, bad)
    s.set(prefs.SCAN_PROFILE, "A profile that no longer exists")     # e.g. stored by an older version
    assert prefs.get(s, prefs.SCAN_PROFILE) == "Intense scan"
    s.set("nvd_api_key", "keep-me")
    prefs.reset_all(s)
    assert prefs.get(s, prefs.NIKTO_MINUTES) == 30 and prefs.get(s, CONSOLE_VISIBLE) is True
    assert s.get("nvd_api_key") == "keep-me"                          # reset only touches the listed options
