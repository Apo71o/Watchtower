"""Password strength analysis (local, no network).

Wraps the `zxcvbn` library for pattern/entropy scoring and adds a plain-language
NIST SP 800-63B checklist. Everything runs in-process; passwords never leave the
machine. Degrades to a basic character/entropy estimate if zxcvbn isn't installed.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

SCORE_LABELS = {0: "Very weak", 1: "Weak", 2: "Fair", 3: "Strong", 4: "Very strong"}
# NIST SP 800-63B minimum is 8; it recommends supporting at least 64 and encourages long passphrases.
NIST_MIN = 8
RECOMMENDED = 15


@dataclass
class CheckItem:
    name: str
    passed: bool | None      # True pass, False fail, None = not evaluated (e.g. breach check not run)
    detail: str


@dataclass
class StrengthResult:
    score: int                       # 0-4
    label: str
    guesses: float
    crack_times: dict                # scenario -> human string
    warning: str = ""
    suggestions: list[str] = field(default_factory=list)
    checklist: list[CheckItem] = field(default_factory=list)
    backend: str = "zxcvbn"


def _entropy_bits(password: str) -> float:
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(r"[^A-Za-z0-9]", password):
        pool += 33
    return len(password) * math.log2(pool) if pool else 0.0


def _human_time(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    for amount, unit in ((60, "second"), (60, "minute"), (24, "hour"), (365, "day"), (100, "year")):
        if seconds < amount:
            n = round(seconds)
            return f"{n} {unit}{'s' if n != 1 else ''}"
        seconds /= amount
    return "centuries"


def nist_checklist(password: str, zxcvbn_result: dict | None, breached: int | None) -> list[CheckItem]:
    items = []
    n = len(password)
    items.append(CheckItem("At least 8 characters (NIST minimum)", n >= NIST_MIN,
                           f"{n} characters." + ("" if n >= NIST_MIN else " Too short.")))
    items.append(CheckItem("At least 15 characters (recommended)", n >= RECOMMENDED,
                           "Longer passphrases beat complexity rules." if n < RECOMMENDED else f"{n} characters."))
    if breached is None:
        items.append(CheckItem("Not found in a known breach", None,
                               "Run the breach check (HaveIBeenPwned) to evaluate this."))
    else:
        items.append(CheckItem("Not found in a known breach", breached == 0,
                               "Not in the Pwned Passwords set." if breached == 0 else
                               f"Seen {breached:,} times in breaches — do not use it."))
    # Predictability (from zxcvbn when available)
    if zxcvbn_result is not None:
        score = zxcvbn_result.get("score", 0)
        items.append(CheckItem("Not an easily guessed pattern", score >= 3,
                               "No obvious dictionary word, keyboard walk, date or repetition."
                               if score >= 3 else "zxcvbn found guessable patterns (see suggestions)."))
    else:
        items.append(CheckItem("Reasonable entropy estimate", _entropy_bits(password) >= 60,
                               f"~{_entropy_bits(password):.0f} bits (zxcvbn not installed for a better estimate)."))
    # NIST discourages forced composition and periodic rotation; those are verifier policies, noted for awareness.
    items.append(CheckItem("No forced complexity / rotation needed", True,
                           "NIST 800-63B advises against mandatory character-mix rules and periodic expiry; "
                           "rely on length + a breach check instead."))
    return items


def analyze(password: str, user_inputs: list[str] | None = None, breached: int | None = None) -> StrengthResult:
    if not password:
        return StrengthResult(0, SCORE_LABELS[0], 0, {}, "Empty password.", [], [], "none")
    try:
        from zxcvbn import zxcvbn
        z = zxcvbn(password, user_inputs=user_inputs or [])
        ct = z.get("crack_times_display", {})
        crack_times = {
            "Online, throttled (100/hr)": ct.get("online_throttling_100_per_hour", ""),
            "Online, no throttle (10/s)": ct.get("online_no_throttling_10_per_second", ""),
            "Offline, slow hash (1e4/s)": ct.get("offline_slow_hashing_1e4_per_second", ""),
            "Offline, fast hash (1e10/s)": ct.get("offline_fast_hashing_1e10_per_second", ""),
        }
        feedback = z.get("feedback", {})
        return StrengthResult(
            int(z.get("score", 0)), SCORE_LABELS[int(z.get("score", 0))], float(z.get("guesses", 0)),
            crack_times, feedback.get("warning", "") or "", list(feedback.get("suggestions", [])),
            nist_checklist(password, z, breached), "zxcvbn")
    except ImportError:
        bits = _entropy_bits(password)
        guesses = 2 ** bits
        score = 0 if bits < 28 else 1 if bits < 40 else 2 if bits < 60 else 3 if bits < 80 else 4
        crack_times = {"Offline, fast hash (1e10/s)": _human_time(guesses / 1e10 / 2),
                       "Online, no throttle (10/s)": _human_time(guesses / 10 / 2)}
        return StrengthResult(score, SCORE_LABELS[score], guesses, crack_times,
                              "Install zxcvbn for pattern-based analysis." if score >= 2 else
                              "Short or low-variety password.", [], nist_checklist(password, None, breached), "basic")
