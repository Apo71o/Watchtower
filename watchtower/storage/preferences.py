"""User preferences: one registry of every customizable option.

Each Pref says where it appears in Settings, what it's called, its default, the tooltip that
explains it, and which values are allowed. The Settings tab builds its controls from this list,
`get()` always returns a valid value (falling back to the default if a stored value is
missing or no longer allowed), and `reset_all()` restores the defaults.

Adding a preference: append a Pref here, read it with `preferences.get(settings, KEY)` where it
applies, and (if it should take effect immediately) react to `ctx.bus.settings_changed`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from watchtower.storage.settings import CONSOLE_VISIBLE, Settings

# keys
FONT_SIZE = "ui.font_size"
HELP_PANELS = "ui.help_panels_open"
START_TAB = "ui.start_tab"
LAST_TAB = "ui.last_tab"                     # internal: remembered by the window, not shown in Settings
NOTIFY_DESKTOP = "notify.desktop"
SCAN_PROFILE = "scan.default_profile"
SCAN_OS_DETECT = "scan.default_os_detect"
SCHEDULE_INTERVAL = "schedule.default_interval"
TRAFFIC_DURATION = "traffic.default_duration"
TRAFFIC_INTERFACE = "traffic.default_interface"
TRAFFIC_DISCOVER = "traffic.default_discover"
NIKTO_MINUTES = "web.nikto_minutes"
DKIM_SELECTORS = "domain.dkim_selectors"
SUBDOMAIN_MINUTES = "domain.subdomain_minutes"
FINDINGS_MIN_SEVERITY = "findings.min_severity"
REPORT_TITLE = "report.title"
REPORT_AUTHOR = "report.author"
REPORT_INCLUDE_INFO = "report.include_info"

FONT_SIZES = {"Small": -1, "Normal": 0, "Large": 2, "Extra large": 4}
START_TABS = ["Last tab used", "Help (Where to start)", "Findings", "Scan a Target", "Nearby Networks",
              "Traffic Audit"]
SEVERITY_FILTERS = ["All severities", "Low and above", "Medium and above", "High and above", "Critical only"]


@dataclass
class Pref:
    key: str
    section: str
    label: str
    kind: str                     # "bool" | "int" | "choice" | "text"
    default: Any
    tip: str
    choices: list[str] = field(default_factory=list)   # for "choice" (filled lazily for some, see choices_for)
    minimum: int = 0
    maximum: int = 0
    suffix: str = ""
    placeholder: str = ""


def _profiles() -> list[str]:
    from watchtower.core.nmap_runner import PROFILES
    return [p for p in PROFILES if not p.startswith("Custom")]


def _durations() -> list[str]:
    from watchtower.core.traffic_audit import DURATIONS
    return list(DURATIONS)


def _intervals() -> list[str]:
    from watchtower.core.scheduler import INTERVALS
    return list(INTERVALS)


_LAZY_CHOICES = {SCAN_PROFILE: _profiles, TRAFFIC_DURATION: _durations, SCHEDULE_INTERVAL: _intervals}

PREFS: list[Pref] = [
    # Appearance
    Pref(FONT_SIZE, "Appearance", "Text size", "choice", "Normal",
         "Make all text in Watchtower smaller or larger.", list(FONT_SIZES)),
    Pref(HELP_PANELS, "Appearance", "Show the “What is this?” explanation on each tab", "bool", True,
         "When on, each tab opens with its explanation panel on the right. You can always open or close it with "
         "the (?) button."),
    Pref(CONSOLE_VISIBLE, "Appearance", "Show the Command Console", "bool", True,
         "The panel at the bottom that shows every command as it starts (also View → Command Console, "
         "Ctrl+`). Hidden or not, every command is kept in the Audit Log."),
    Pref(START_TAB, "Appearance", "Open Watchtower on", "choice", "Last tab used",
         "Which tab to show when Watchtower starts. (The very first launch always opens Help.)", START_TABS),
    # Notifications
    Pref(NOTIFY_DESKTOP, "Notifications", "Desktop notifications for alerts from scheduled scans and captures",
         "bool", True,
         "Pop up a system notification when a scheduled scan or capture finds something that needs attention. "
         "Alerts are always shown in the status bar and What Changed."),
    # Defaults for the tools
    Pref(SCAN_PROFILE, "Scan a Target", "Default scan profile", "choice", "Intense scan",
         "The nmap profile selected when Scan a Target opens. Quick scan is faster; Intense scan finds more."),
    Pref(SCAN_OS_DETECT, "Scan a Target", "Tick “OS detection” by default", "bool", False,
         "Start with OS detection (-O) switched on. It needs capture permission or your password."),
    Pref(SCHEDULE_INTERVAL, "Scan a Target", "Default repeat interval for schedules", "choice", "Daily",
         "The interval pre-selected when you add a scheduled scan or a repeating capture."),
    Pref(TRAFFIC_DURATION, "Traffic Audit", "Default capture length", "choice", "1 minute",
         "How long a live capture listens unless you pick something else."),
    Pref(TRAFFIC_INTERFACE, "Traffic Audit", "Preferred interface", "text", "",
         "Interface selected first in Traffic Audit, e.g. eth0 or wlp195s0. Leave empty to pick automatically.",
         placeholder="automatic"),
    Pref(TRAFFIC_DISCOVER, "Traffic Audit", "Tick “Also find quiet devices” by default", "bool", False,
         "Start with the after-capture ping scan switched on (it still only runs on authorized networks)."),
    Pref(NIKTO_MINUTES, "Web & Domain Audit", "Nikto time limit", "int", 30,
         "How long a nikto scan may run before it stops.", minimum=1, maximum=240, suffix=" min"),
    Pref(DKIM_SELECTORS, "Web & Domain Audit", "Your DKIM selectors", "text", "",
         "Selectors your mail provider uses (comma-separated), filled in automatically in Domain Audit. Find yours "
         "in the s= value of the DKIM-Signature header of an email you sent.", placeholder="e.g. selector1, google"),
    Pref(SUBDOMAIN_MINUTES, "Web & Domain Audit", "Subdomain search time limit", "int", 10,
         "How long subfinder/amass may search.", minimum=1, maximum=60, suffix=" min"),
    # Findings & reports
    Pref(FINDINGS_MIN_SEVERITY, "Findings & reports", "Show findings from", "choice", "All severities",
         "The severity filter selected when the Findings tab opens.", SEVERITY_FILTERS),
    Pref(REPORT_TITLE, "Findings & reports", "Report title", "text", "Home lab security assessment",
         "Pre-filled title for exported reports."),
    Pref(REPORT_AUTHOR, "Findings & reports", "Report author", "text", "",
         "Pre-filled author for exported reports. Leave empty to use your login name.", placeholder="your login name"),
    Pref(REPORT_INCLUDE_INFO, "Findings & reports", "Include Info-level findings in reports", "bool", False,
         "Pre-tick “Include Info-level findings” in the export dialog."),
]
BY_KEY = {p.key: p for p in PREFS}
SECTIONS = list(dict.fromkeys(p.section for p in PREFS))


def choices_for(p: Pref) -> list[str]:
    return _LAZY_CHOICES[p.key]() if p.key in _LAZY_CHOICES else p.choices


def valid(p: Pref, value: Any) -> bool:
    if p.kind == "bool":
        return isinstance(value, bool)
    if p.kind == "int":
        return isinstance(value, int) and not isinstance(value, bool) and p.minimum <= value <= p.maximum
    if p.kind == "choice":
        return value in choices_for(p)
    return isinstance(value, str)


def get(settings: Settings, key: str) -> Any:
    """The stored value if it's still valid, else the default."""
    p = BY_KEY[key]
    value = settings.get(key, p.default)
    return value if valid(p, value) else p.default


def set(settings: Settings, key: str, value: Any) -> None:  # noqa: A001 - mirrors Settings.set
    p = BY_KEY[key]
    if not valid(p, value):
        raise ValueError(f"invalid value for {p.label}: {value!r}")
    settings.set(key, value)


def reset_all(settings: Settings) -> list[str]:
    """Back to defaults (only the options listed here; scope lists, data and API keys are untouched)."""
    for p in PREFS:
        settings.delete(p.key)
    settings.delete(LAST_TAB)
    return [p.key for p in PREFS]


def is_default(settings: Settings, key: str) -> bool:
    return get(settings, key) == BY_KEY[key].default
