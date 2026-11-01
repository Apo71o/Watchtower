"""Password recovery for hashes/files you own, wrapping hashcat or John the Ripper.

This is a recovery and self-audit tool: it runs a dictionary attack (your own
wordlist) against a hash file you provide and confirm you own — a forgotten
ZIP/PDF/Office password, an /etc/shadow backup from your own machine, etc. It
is gated like the rest of the app: the GUI requires you to confirm ownership,
shows the exact command, and only runs on an explicit click. It does not
orchestrate attacks on live systems and (consistent with Phase 1) does not do
Wi-Fi handshake cracking.
"""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from watchtower.core import deps


@dataclass(frozen=True)
class HashType:
    label: str
    hashcat_mode: int | None
    john_format: str | None
    note: str = ""


# Common recovery scenarios. Ordered roughly by how often they come up.
HASH_TYPES: list[HashType] = [
    HashType("MD5", 0, "Raw-MD5"),
    HashType("SHA-1", 100, "Raw-SHA1"),
    HashType("SHA-256", 1400, "Raw-SHA256"),
    HashType("SHA-512", 1700, "Raw-SHA512"),
    HashType("NTLM (Windows)", 1000, "NT", "Windows account hashes."),
    HashType("bcrypt ($2*$)", 3200, "bcrypt", "Slow by design; use a targeted wordlist."),
    HashType("sha512crypt ($6$) — Linux /etc/shadow", 1800, "sha512crypt", "Modern Linux shadow hashes."),
    HashType("md5crypt ($1$)", 500, "md5crypt"),
    HashType("ZIP (PKZIP/WinZip)", None, "zip", "Produce the hash with zip2john first."),
    HashType("RAR", None, "rar", "Produce the hash with rar2john first."),
    HashType("7-Zip", None, "7z", "Produce the hash with 7z2john first."),
    HashType("Office (Word/Excel/PowerPoint)", 9600, "office", "Produce the hash with office2john first."),
    HashType("PDF", 10500, "pdf", "Produce the hash with pdf2john first."),
]

# john's *2john document extractors (script names vary by install).
EXTRACTORS = {
    "zip": ["zip2john"],
    "rar": ["rar2john"],
    "7z": ["7z2john", "7z2john.pl"],
    "office": ["office2john", "office2john.py"],
    "pdf": ["pdf2john", "pdf2john.pl", "pdf2john.py"],
}


class CrackError(RuntimeError):
    pass


def available_tools() -> list[str]:
    return [t for t in ("hashcat", "john") if deps.find_binary(t)]


def find_extractor(kind: str) -> str | None:
    for name in EXTRACTORS.get(kind, []):
        p = deps.find_binary(name)
        if p:
            return p
    # john ships some under /usr/share/john or /usr/sbin
    for base in ("/usr/share/john", "/usr/sbin", "/usr/bin"):
        for name in EXTRACTORS.get(kind, []):
            cand = Path(base) / name
            if cand.exists():
                return str(cand)
    return None


def extractor_argv(kind: str, document: str) -> list[str]:
    tool = find_extractor(kind)
    if not tool:
        raise CrackError(f"No {kind}2john extractor found (part of the John the Ripper 'jumbo' package).")
    argv = [tool, document]
    if tool.endswith((".pl",)):
        perl = deps.find_binary("perl")
        if perl:
            argv = [perl, *argv]
    elif tool.endswith(".py"):
        import sys
        argv = [sys.executable, *argv]
    return argv


@dataclass
class CrackJob:
    tool: str
    argv: list[str]
    hash_file: str
    hash_type: HashType
    out_file: str = ""
    pot_file: str = ""
    workdir: str = ""


def build_hashcat(hash_file: str, htype: HashType, wordlist: str, workdir: str,
                  rules: str | None = None) -> CrackJob:
    if htype.hashcat_mode is None:
        raise CrackError(f"hashcat has no mode configured for {htype.label}; use John instead.")
    hashcat = deps.find_binary("hashcat")
    if not hashcat:
        raise CrackError("hashcat is not installed.")
    out_file = str(Path(workdir) / "cracked.txt")
    pot_file = str(Path(workdir) / "watchtower.potfile")
    argv = [hashcat, "-m", str(htype.hashcat_mode), "-a", "0", "--potfile-path", pot_file,
            "-o", out_file, "--outfile-format", "1,2", "--status", "--status-json", "--status-timer", "2",
            "--force", hash_file, wordlist]
    if rules:
        argv += ["-r", rules]
    return CrackJob("hashcat", argv, hash_file, htype, out_file, pot_file, workdir)


def build_john(hash_file: str, htype: HashType, wordlist: str, workdir: str,
               rules: str | None = None) -> CrackJob:
    if not htype.john_format:
        raise CrackError(f"No John format configured for {htype.label}.")
    john = deps.find_binary("john")
    if not john:
        raise CrackError("John the Ripper is not installed.")
    pot_file = str(Path(workdir) / "watchtower.pot")
    argv = [john, f"--format={htype.john_format}", f"--wordlist={wordlist}", f"--pot={pot_file}", hash_file]
    if rules:
        argv.append("--rules" if rules in ("", "default") else f"--rules={rules}")
    return CrackJob("john", argv, hash_file, htype, "", pot_file, workdir)


def build(tool: str, hash_file: str, htype: HashType, wordlist: str, workdir: str,
          rules: str | None = None) -> CrackJob:
    if not Path(hash_file).is_file():
        raise CrackError(f"Hash file not found: {hash_file}")
    if not Path(wordlist).is_file():
        raise CrackError(f"Wordlist not found: {wordlist}")
    return (build_hashcat if tool == "hashcat" else build_john)(hash_file, htype, wordlist, workdir, rules)


def show_argv(job: CrackJob) -> list[str]:
    """Command to list recovered passwords after a run."""
    if job.tool == "hashcat":
        return [deps.find_binary("hashcat"), "-m", str(job.hash_type.hashcat_mode), "--potfile-path", job.pot_file,
                "--show", "--outfile-format", "1,2", job.hash_file]
    return [deps.find_binary("john"), f"--format={job.hash_type.john_format}", f"--pot={job.pot_file}", "--show",
            job.hash_file]


def read_cracked(job: CrackJob) -> list[tuple[str, str]]:
    """Recovered (hash, plaintext) pairs from the job's potfile ('hash:plain',
    same for hashcat and John), robust across tool versions."""
    try:
        text = Path(job.pot_file).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return [(line.rpartition(":")[0], line.rpartition(":")[2]) for line in text.splitlines() if ":" in line]


def parse_hashcat_status(line: str) -> dict | None:
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        d = json.loads(line)
    except ValueError:
        return None
    if "progress" not in d:
        return None
    prog = d.get("progress", [0, 0])
    pct = (100 * prog[0] / prog[1]) if len(prog) == 2 and prog[1] else 0
    return {"status": _HASHCAT_STATUS.get(d.get("status"), str(d.get("status", ""))),
            "percent": round(pct, 1), "recovered": d.get("recovered_hashes", [0, 0]),
            "speed": sum(d.get("devices", [{}])[i].get("speed", 0) for i in range(len(d.get("devices", [])))),
            "eta": d.get("estimated_stop", "")}


_HASHCAT_STATUS = {3: "Running", 5: "Exhausted", 6: "Cracked", 7: "Aborted", 8: "Quit"}


def parse_cracked(tool: str, show_output: str) -> list[tuple[str, str]]:
    """Parse the --show output into (hash, plaintext) pairs."""
    out = []
    for line in show_output.splitlines():
        line = line.rstrip("\n")
        if not line or line.startswith(("Loaded ", "No password", "Use the ", "Proceeding", "Session", "0 password")):
            continue
        if ":" in line:
            h, _, pw = line.partition(":")
            if tool == "john" and re.match(r"^\d+ password", line):
                continue
            out.append((h, pw))
    return out


def john_show_count(output: str) -> int:
    m = re.search(r"(\d+)\s+password hash(?:es)? cracked", output)
    return int(m.group(1)) if m else 0


def default_wordlists() -> list[str]:
    """Common wordlist locations, if present."""
    candidates = [
        "/usr/share/wordlists/rockyou.txt", "/usr/share/wordlists/rockyou.txt.gz",
        "/usr/share/john/password.lst", "/usr/share/dict/words", "/usr/share/wordlists/fasttrack.txt",
    ]
    return [c for c in candidates if Path(c).is_file() and (shutil.which("gzip") or not c.endswith(".gz"))]
