"""Check passwords against HaveIBeenPwned "Pwned Passwords" using k-anonymity.

Only the first 5 hex characters of the password's SHA-1 hash are ever sent to
the API; the API returns all hash suffixes with that prefix and the match is
made locally, so the password and its full hash never leave the machine.

Offline mode needs no network at all: it binary-searches a downloaded
HIBP "ordered-by-hash" file (lines "SHA1HASH:COUNT", sorted). Get it with the
official downloader (https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader).
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

API_RANGE = "https://api.pwnedpasswords.com/range/"


def sha1_hex(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def split_hash(password: str) -> tuple[str, str]:
    h = sha1_hex(password)
    return h[:5], h[5:]


@dataclass
class BreachResult:
    password_label: str      # never the password itself in logs: a masked form
    count: int               # times seen in breaches (0 = not found)
    source: str              # "api" | "offline"

    @property
    def breached(self) -> bool:
        return self.count > 0


def mask(password: str) -> str:
    if len(password) <= 2:
        return "*" * len(password)
    return password[0] + "*" * (len(password) - 2) + password[-1]


def parse_range(text: str, suffix: str) -> int:
    for line in text.splitlines():
        s, _, count = line.strip().partition(":")
        if s.upper() == suffix:
            return int(count or 0)
    return 0


def check_api(password: str, session, on_request=None, timeout: int = 15) -> BreachResult:
    """session: a requests.Session-like object. on_request(url) logs the (prefix-only) request."""
    prefix, suffix = split_hash(password)
    url = API_RANGE + prefix
    if on_request:
        on_request(url)
    resp = session.get(url, headers={"Add-Padding": "true"}, timeout=timeout)
    if resp.status_code != 200:
        raise RuntimeError(f"Pwned Passwords API returned HTTP {resp.status_code}")
    return BreachResult(mask(password), parse_range(resp.text, suffix), "api")


def check_offline(password: str, path: str) -> BreachResult:
    full = sha1_hex(password)
    count = _bsearch_hash_file(path, full)
    return BreachResult(mask(password), count, "offline")


def _bsearch_hash_file(path: str, full_hash: str) -> int:
    """Binary search a file of 'SHA1HASH:COUNT' lines sorted by hash. Invariant:
    lo and hi are always line-start byte offsets, and the match (if any) lies in
    [lo, hi). Converges to the first line whose hash >= target, then compares."""
    target = full_hash.upper().encode("ascii")
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        lo, hi = 0, size
        while lo < hi:
            mid = (lo + hi) // 2
            if mid:
                f.seek(mid - 1)
                if f.read(1) != b"\n":        # mid is mid-line: consume the rest of the straddled line
                    f.readline()               # (if the byte before mid is a newline, mid is already a line start)
            else:
                f.seek(0)
            line_start = f.tell()
            if line_start >= hi:               # no full line began in [mid, hi)
                hi = mid
                continue
            line = f.readline()
            if not line:
                hi = mid
                continue
            key = line.split(b":", 1)[0].strip().upper()
            if key < target:
                lo = line_start + len(line)
            else:
                hi = line_start
        f.seek(lo)
        line = f.readline()
        if line:
            parts = line.split(b":", 1)
            if parts[0].strip().upper() == target:
                return int(parts[1].strip() or b"0")
    return 0


def check_batch(passwords, checker) -> list[BreachResult]:
    """checker: a callable(password) -> BreachResult (api or offline). De-duplicates."""
    seen: dict[str, BreachResult] = {}
    out = []
    for pw in passwords:
        if pw not in seen:
            seen[pw] = checker(pw)
        out.append(seen[pw])
    return out
