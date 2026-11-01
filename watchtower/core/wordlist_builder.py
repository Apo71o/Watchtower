"""Build and manage wordlists locally — for auditing passwords you own.

Everything here is local: generating a targeted wordlist (from base words you
supply, with common mutations), merging/cleaning lists you already have, and
reading the small starter lists bundled with Watchtower. The one action that
reaches the network is installing the standard public wordlists, and that is
done through a visible, logged command (apt / git) via RunPlanDialog, exactly
like every other external tool — never silently.

No cracking happens here; a wordlist is just a text file of candidate
passwords. You feed it to the Hash Recovery command, which you run yourself.
"""

from __future__ import annotations

import os
import shlex
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from watchtower.core import deps, hash_cracker
from watchtower.storage.settings import WORDLISTS, Settings

# Letter -> leet replacement used when the "leet-speak" option is on. One
# substitution per letter keeps the output bounded (no combinatorial blow-up).
LEET = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7", "l": "1", "g": "9", "b": "8"}

DEFAULT_DIGITS = ["1", "2", "3", "12", "123", "1234", "0", "01", "007", "69", "99", "111", "000", "321"]
DEFAULT_SYMBOLS = ["!", "@", "#", "$", "!!", "1!", "!@#", "123!", "."]


def _this_year() -> int:
    return datetime.now().year


@dataclass
class BuildOptions:
    case_variants: bool = True      # word, word.lower(), Word, WORD
    leet: bool = False              # also add a leet-substituted form of each
    append_digits: bool = False
    append_years: bool = False
    append_symbols: bool = False
    combine_words: bool = False     # also try each ordered pair concatenated
    year_start: int = 1980
    year_end: int = field(default_factory=lambda: _this_year() + 1)
    digits: list[str] = field(default_factory=lambda: list(DEFAULT_DIGITS))
    symbols: list[str] = field(default_factory=lambda: list(DEFAULT_SYMBOLS))
    min_length: int = 0
    max_entries: int = 100_000      # hard cap so the list can't explode


def _dedupe(items) -> list[str]:
    return list(dict.fromkeys(items))


def _case_variants(word: str, enabled: bool) -> list[str]:
    if not enabled:
        return [word]
    return _dedupe([word, word.lower(), word.capitalize(), word.upper()])


def leet(word: str) -> str:
    """Replace mapped letters with their leet substitution (case-insensitive)."""
    return "".join(LEET.get(ch.lower(), ch) for ch in word)


def _suffixes(opts: BuildOptions) -> list[str]:
    sfx = [""]
    if opts.append_digits:
        sfx += opts.digits
    if opts.append_years:
        sfx += [str(y) for y in range(opts.year_start, opts.year_end + 1)]
    if opts.append_symbols:
        sfx += opts.symbols
    return _dedupe(sfx)


def generate(base_words, opts: BuildOptions) -> tuple[list[str], bool]:
    """Return (words, truncated). Deterministic; stops once max_entries is hit."""
    words = _dedupe(w.strip() for w in base_words if w and w.strip())
    pool = list(words)
    if opts.combine_words:
        pool += [a + b for a in words for b in words if a != b]
    pool = _dedupe(pool)

    suffixes = _suffixes(opts)
    out: dict[str, None] = {}
    for w in pool:
        variants = _case_variants(w, opts.case_variants)
        if opts.leet:
            variants = _dedupe(variants + [leet(v) for v in variants])
        for v in variants:
            for sfx in suffixes:
                cand = v + sfx
                if len(cand) < opts.min_length:
                    continue
                if cand not in out:
                    out[cand] = None
                    if len(out) >= opts.max_entries:
                        return list(out), True
    return list(out), False


def write_list(path: str, words) -> int:
    """Write one word per line (UTF-8). Returns the number of lines written."""
    words = list(words)
    Path(path).write_text("\n".join(words) + ("\n" if words else ""), encoding="utf-8")
    return len(words)


def merge_files(paths, dedupe: bool = True, sort: bool = False) -> tuple[list[str], int]:
    """Read several wordlists into one. Blank lines are dropped. Returns
    (lines, total_read_before_dedupe)."""
    lines: list[str] = []
    for p in paths:
        try:
            with open(p, encoding="utf-8", errors="replace") as fh:
                lines += [ln.rstrip("\r\n") for ln in fh if ln.strip()]
        except OSError as exc:
            raise ValueError(f"Couldn't read {p}: {exc}") from exc
    total = len(lines)
    if dedupe:
        lines = _dedupe(lines)
    if sort:
        lines = sorted(lines)
    return lines, total


# --------------------------------------------------------------------------- #
# Bundled starter lists (small, shipped with the app)                         #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class BundledList:
    name: str
    path: Path
    count: int
    description: str


_BUNDLED = [
    ("common-passwords.txt", "Common passwords",
     "A few hundred of the most frequently used and leaked passwords — a quick "
     "\"is my password an obvious one?\" check."),
    ("keyboard-patterns.txt", "Keyboard patterns",
     "Keyboard walks and runs such as qwerty, 1qaz2wsx and asdfgh."),
]


def bundled_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "data" / "wordlists"


def count_lines(path) -> int:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return sum(1 for ln in fh if ln.strip())
    except OSError:
        return 0


def bundled_wordlists() -> list[BundledList]:
    out = []
    for fname, name, desc in _BUNDLED:
        p = bundled_dir() / fname
        if p.is_file():
            out.append(BundledList(name, p, count_lines(p), desc))
    return out


# --------------------------------------------------------------------------- #
# Installing the big standard lists (shown + logged, never silent)            #
# --------------------------------------------------------------------------- #

SECLISTS_URL = "https://github.com/danielmiessler/SecLists"
ROCKYOU_URL = SECLISTS_URL + "/raw/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz"


def rockyou_plan(dest_dir: str) -> deps.Plan:
    """Download rockyou.txt from SecLists into `dest_dir`. No root and no distro
    package needed (Ubuntu doesn't ship the Kali 'wordlists' package); just curl
    or wget plus disk space. The resulting path is dest_dir/rockyou.txt."""
    d = shlex.quote(dest_dir)
    script = (
        f"set -e; mkdir -p {d}; cd {d}; "
        f'if command -v curl >/dev/null 2>&1; then curl -fL -o rockyou.txt.tar.gz "{ROCKYOU_URL}"; '
        f'elif command -v wget >/dev/null 2>&1; then wget -O rockyou.txt.tar.gz "{ROCKYOU_URL}"; '
        'else echo "Need curl or wget to download rockyou."; exit 1; fi; '
        "tar -xzf rockyou.txt.tar.gz; rm -f rockyou.txt.tar.gz; ls -l rockyou.txt"
    )
    return deps.Plan([deps.Step("Download rockyou.txt from SecLists", ["sh", "-c", script], script=script)], [])


def seclists_plan(dest: str) -> deps.Plan:
    """Clone SecLists (a large collection of security wordlists) to a local folder.
    No root needed; just git and disk space."""
    return deps.Plan([deps.Step(f"Clone SecLists into {dest}",
                                ["git", "clone", "--depth", "1", SECLISTS_URL, dest])], [])


# --------------------------------------------------------------------------- #
# Saved-wordlists registry (so paths don't have to be retyped)                #
# --------------------------------------------------------------------------- #

def registered_paths(settings: Settings) -> list[str]:
    return [str(p) for p in (settings.get(WORDLISTS, []) or [])]


def add_wordlist(settings: Settings, path: str) -> None:
    """Remember a wordlist path so it can be picked later (no duplicates)."""
    path = str(Path(path).expanduser())
    cur = registered_paths(settings)
    if path not in cur:
        settings.set(WORDLISTS, cur + [path])


def remove_wordlist(settings: Settings, path: str) -> None:
    settings.set(WORDLISTS, [p for p in registered_paths(settings) if p != str(Path(path).expanduser())])


def _human_size(path: str) -> str:
    try:
        n: float = os.path.getsize(path)
    except OSError:
        return "?"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.0f} TB"


def known_wordlists(settings: Settings) -> list[tuple[str, str]]:
    """(label, path) for every selectable wordlist: bundled starter lists, the
    standard auto-detected ones, and whatever the user saved — existing files
    only, de-duplicated. Prunes saved paths whose file has gone. Skips .gz
    (the recovery tools need an uncompressed list)."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(path, tag: str = ""):
        p = str(path)
        if p.endswith(".gz") or not Path(p).is_file():
            return
        try:
            key = str(Path(p).resolve())
        except OSError:
            key = p
        if key in seen:
            return
        seen.add(key)
        label = f"{Path(p).name} ({_human_size(p)})" + (f" — {tag}" if tag else "")
        out.append((label, p))

    for b in bundled_wordlists():
        add(b.path, "included")
    for w in hash_cracker.default_wordlists():
        add(w)
    existing = [p for p in registered_paths(settings) if Path(p).is_file()]
    if existing != registered_paths(settings):
        settings.set(WORDLISTS, existing)   # prune vanished ones
    for p in existing:
        add(p)
    return out
