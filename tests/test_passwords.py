import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from watchtower.core import hash_cracker as hc
from watchtower.core import password_strength as ps
from watchtower.core import pwned_check as pw

# ---- password strength ----

def test_strength_weak_vs_strong():
    weak = ps.analyze("password")
    strong = ps.analyze("correct-horse-battery-staple-9471")
    assert weak.score <= 1 and strong.score >= 3
    assert weak.label in ps.SCORE_LABELS.values()
    assert strong.crack_times and (weak.warning or weak.suggestions or True)


def test_strength_nist_checklist_and_breach():
    r = ps.analyze("abc", breached=42)
    names = {c.name: c for c in r.checklist}
    assert names["At least 8 characters (NIST minimum)"].passed is False
    assert names["Not found in a known breach"].passed is False and "42" in names["Not found in a known breach"].detail
    r2 = ps.analyze("a-very-long-and-unique-passphrase-xyz", breached=0)
    assert next(c for c in r2.checklist if c.name.startswith("Not found")).passed is True
    r3 = ps.analyze("whatever-passphrase")
    assert next(c for c in r3.checklist if c.name.startswith("Not found")).passed is None  # not checked


def test_strength_uses_context_inputs():
    plain = ps.analyze("Smith2020")
    with_ctx = ps.analyze("Smith2020", user_inputs=["Smith", "2020"])
    assert with_ctx.score <= plain.score


def test_strength_basic_fallback(monkeypatch):
    import builtins
    real = builtins.__import__

    def fake(name, *a, **k):
        if name == "zxcvbn":
            raise ImportError
        return real(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", fake)
    r = ps.analyze("Tr0ub4dour&3xtra-long-9")
    assert r.backend == "basic" and 0 <= r.score <= 4 and r.checklist


# ---- pwned (HaveIBeenPwned) ----

def test_hash_split_and_mask():
    assert pw.sha1_hex("password") == hashlib.sha1(b"password").hexdigest().upper()
    prefix, suffix = pw.split_hash("password")
    assert len(prefix) == 5 and len(suffix) == 35 and prefix + suffix == pw.sha1_hex("password")
    assert pw.mask("password") == "p******d" and pw.mask("ab") == "**"


class FakeResp:
    def __init__(self, status, text=""):
        self.status_code, self.text = status, text


class FakeSession:
    def __init__(self, resp):
        self.resp, self.calls = resp, []

    def get(self, url, headers=None, timeout=None):
        self.calls.append(url)
        return self.resp


def test_check_api_k_anonymity():
    prefix, suffix = pw.split_hash("password")
    body = f"0000000000000000000000000000000000A:3\r\n{suffix}:99999\r\nFFFF:1"
    sess = FakeSession(FakeResp(200, body))
    logged = []
    res = pw.check_api("password", sess, on_request=logged.append)
    assert res.count == 99999 and res.breached and res.source == "api"
    assert sess.calls == [pw.API_RANGE + prefix] and logged == [pw.API_RANGE + prefix]
    # only the 5-char prefix is sent: the full hash and the suffix never leave the machine
    assert suffix not in sess.calls[0] and pw.sha1_hex("password") not in sess.calls[0]
    assert sess.calls[0].rsplit("/", 1)[1] == prefix
    miss = pw.check_api("password", FakeSession(FakeResp(200, "ABC:1")))
    assert miss.count == 0 and not miss.breached
    with pytest.raises(RuntimeError, match="HTTP 503"):
        pw.check_api("x", FakeSession(FakeResp(503)))


def test_check_offline_binary_search(tmp_path):
    words = ["password", "secret", "hunter2", "letmein", "dragon", "qwerty", "zzzzz"]
    rows = sorted((pw.sha1_hex(w), w) for w in words)
    counts = {"password": 1000, "secret": 50, "dragon": 7}
    f = tmp_path / "pwned.txt"
    f.write_text("\n".join(f"{h}:{counts.get(w, 1)}" for h, w in rows) + "\n")
    assert pw.check_offline("password", str(f)).count == 1000
    assert pw.check_offline("dragon", str(f)).count == 7
    assert pw.check_offline("qwerty", str(f)).count == 1          # present, default count
    assert pw.check_offline("not-in-the-file-xyz", str(f)).count == 0


def test_check_batch_dedups():
    seen = []
    res = pw.check_batch(["a", "b", "a"], lambda p: (seen.append(p), pw.BreachResult(pw.mask(p), 1, "x"))[1])
    assert seen == ["a", "b"] and len(res) == 3


# ---- hash cracker ----

def test_build_validates_files(tmp_path):
    md5 = next(t for t in hc.HASH_TYPES if t.label == "MD5")
    with pytest.raises(hc.CrackError, match="Hash file not found"):
        hc.build("hashcat", str(tmp_path / "nope"), md5, str(tmp_path / "wl"), str(tmp_path))
    (tmp_path / "h").write_text("5ebe2294ecd0e0f08eab7690d2a6ee69\n")
    with pytest.raises(hc.CrackError, match="Wordlist not found"):
        hc.build("hashcat", str(tmp_path / "h"), md5, str(tmp_path / "wl"), str(tmp_path))


def test_hashcat_argv_shape(tmp_path, monkeypatch):
    monkeypatch.setattr(hc.deps, "find_binary", lambda *n: "/usr/bin/hashcat")
    (tmp_path / "h").write_text("x")
    (tmp_path / "wl").write_text("y")
    md5 = next(t for t in hc.HASH_TYPES if t.label == "MD5")
    job = hc.build("hashcat", str(tmp_path / "h"), md5, str(tmp_path / "wl"), str(tmp_path), rules="best64.rule")
    assert job.argv[:5] == ["/usr/bin/hashcat", "-m", "0", "-a", "0"]
    assert "--force" in job.argv and job.argv[-2:] == ["-r", "best64.rule"]
    assert str(tmp_path / "wl") in job.argv and str(tmp_path / "h") in job.argv


def test_parse_hashcat_status():
    line = ('{"session":"s","status":3,"progress":[5,10],"recovered_hashes":[1,2],'
            '"devices":[{"speed":1000},{"speed":500}],"estimated_stop":"soon"}')
    st = hc.parse_hashcat_status(line)
    assert st["status"] == "Running" and st["percent"] == 50.0 and st["speed"] == 1500
    assert hc.parse_hashcat_status("not json") is None
    assert hc.parse_hashcat_status('{"no":"progress"}') is None


def test_read_cracked_from_potfile(tmp_path):
    md5 = next(t for t in hc.HASH_TYPES if t.label == "MD5")
    job = hc.CrackJob("hashcat", [], "h", md5, pot_file=str(tmp_path / "p.pot"))
    (tmp_path / "p.pot").write_text("5ebe2294ecd0e0f08eab7690d2a6ee69:secret\nAAAA:pass:with:colons\n")
    out = hc.read_cracked(job)
    assert out[0] == ("5ebe2294ecd0e0f08eab7690d2a6ee69", "secret")
    assert out[1] == ("AAAA:pass:with", "colons")           # rpartition keeps plaintext as the last field


@pytest.mark.skipif(not shutil.which("hashcat"), reason="hashcat not installed")
def test_hashcat_end_to_end_recovers_own_password():
    work = tempfile.mkdtemp()
    hashf = Path(work) / "hashes.txt"
    hashf.write_text(hashlib.md5(b"secret").hexdigest() + "\n")
    wl = Path(work) / "wl.txt"
    wl.write_text("wrong\nsecret\nother\n")
    md5 = next(t for t in hc.HASH_TYPES if t.label == "MD5")
    job = hc.build("hashcat", str(hashf), md5, str(wl), work)
    r = subprocess.run(job.argv, capture_output=True, text=True, timeout=180)
    assert r.returncode in (0, 1), r.stderr[-500:]
    assert hc.read_cracked(job) == [(hashlib.md5(b"secret").hexdigest(), "secret")]


def test_offline_search_matches_bruteforce(tmp_path):
    import random
    random.seed(13)
    words = [f"w{random.randint(0, 9_999_999)}q{i}" for i in range(1500)]
    rows = sorted((pw.sha1_hex(w), w, random.randint(1, 9999)) for w in words)
    truth = {w: c for _, w, c in rows}
    body = "\n".join(f"{h}:{c}" for h, w, c in rows)
    for text in (body + "\n", body):                 # with and without a trailing newline
        f = tmp_path / "p.txt"
        f.write_text(text)
        mismatches = [w for w in words + ["absent-x", "absent-y"]
                      if pw.check_offline(w, str(f)).count != truth.get(w, 0)]
        assert not mismatches, f"{len(mismatches)} wrong (first: {mismatches[:3]})"
    # first and last line specifically
    assert pw.check_offline(rows[0][1], str(f)).count == truth[rows[0][1]]
    assert pw.check_offline(rows[-1][1], str(f)).count == truth[rows[-1][1]]


# ---- wordlist builder ----

def test_wordlist_generate_mutations_and_cap():
    from watchtower.core import wordlist_builder as wl
    opts = wl.BuildOptions(case_variants=True, leet=True, append_digits=True,
                           append_years=True, year_start=2019, year_end=2021, append_symbols=True)
    words, truncated = wl.generate(["Spot", "smith"], opts)
    assert not truncated
    # base + case variants
    for w in ("Spot", "spot", "SPOT"):
        assert w in words
    # leet, suffixes
    assert wl.leet("spot") == "$p07" and "$p07" in words
    assert "spot2020" in words and "smith!" in words
    # deterministic + unique
    assert len(words) == len(set(words))
    assert wl.generate(["Spot", "smith"], opts)[0] == words
    # combine pairs
    combo, _ = wl.generate(["red", "fox"], wl.BuildOptions(case_variants=False, combine_words=True))
    assert "redfox" in combo and "foxred" in combo
    # hard cap
    capped, trunc = wl.generate(["a", "b", "c"], wl.BuildOptions(append_years=True, max_entries=7))
    assert trunc and len(capped) == 7


def test_wordlist_merge_and_write(tmp_path):
    from watchtower.core import wordlist_builder as wl
    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    a.write_text("beta\nalpha\n\nbeta\n")
    b.write_text("alpha\ngamma\n")
    lines, total = wl.merge_files([str(a), str(b)], dedupe=True, sort=True)
    assert lines == ["alpha", "beta", "gamma"] and total == 5
    # no dedupe / no sort keeps order and count
    lines2, total2 = wl.merge_files([str(a), str(b)], dedupe=False, sort=False)
    assert lines2 == ["beta", "alpha", "beta", "alpha", "gamma"] and total2 == 5
    out = tmp_path / "out.txt"
    n = wl.write_list(str(out), lines)
    assert n == 3 and out.read_text().splitlines() == ["alpha", "beta", "gamma"]
    with pytest.raises(ValueError):
        wl.merge_files([str(tmp_path / "nope.txt")])


def test_wordlist_bundled_and_plans():
    from watchtower.core import wordlist_builder as wl
    bundled = wl.bundled_wordlists()
    names = {b.name for b in bundled}
    assert {"Common passwords", "Keyboard patterns"} <= names
    for b in bundled:
        assert b.count > 0 and b.path.is_file()
    # install plans build the documented, visible commands (never run here)
    assert "wordlists" in wl.rockyou_plan().describe()
    assert "git clone" in wl.seclists_plan("/tmp/SecLists").describe()
