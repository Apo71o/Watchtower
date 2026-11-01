"""Email-authentication audit of a domain you own: SPF, DKIM and DMARC.

Only DNS lookups (TXT / MX) are made, through the system resolver via
dnspython, and only when the user starts the audit. Nothing is sent to the
domain's mail servers. The analysis functions are pure and take a `resolve`
callable, so they're tested against recorded DNS data in tests/fixtures.

  resolve(name, rdtype) -> list[str]
      TXT: each record's strings joined; MX: "PREF HOST"; [] if the name or
      record type doesn't exist. Raise DnsError for timeouts / SERVFAIL.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass, field

from watchtower.core.findings_engine import SEV_WEIGHT, Finding
from watchtower.core.targets import normalize_domain

Resolver = Callable[[str, str], list[str]]

# Common DKIM selectors. DNS can't list selectors, so the audit can only try
# names; add your provider's selector (it's in the DKIM-Signature "s=" tag of
# any mail you send) in the Domain Audit tab.
DEFAULT_SELECTORS = ["default", "dkim", "mail", "selector1", "selector2", "google", "k1", "k2", "k3", "s1", "s2",
                     "smtp", "email", "key1", "fm1", "fm2", "fm3", "protonmail", "protonmail2", "protonmail3",
                     "zoho", "mxvault", "sig1", "mandrill"]
SPF_LOOKUP_LIMIT = 10
_SELECTOR_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62})$")


class DnsError(RuntimeError):
    pass


@dataclass
class MailIssue:
    id: str
    severity: str
    title: str
    detail: str = ""
    category: str = ""      # spf / dmarc / dkim / mx


@dataclass
class DomainReport:
    domain: str
    mx: list[str] = field(default_factory=list)
    spf: list[str] = field(default_factory=list)          # v=spf1 records at the domain
    spf_lookups: int | None = None
    spf_tree: list[str] = field(default_factory=list)     # "include:x -> v=spf1 ..." lines
    dmarc: list[str] = field(default_factory=list)
    dmarc_tags: dict = field(default_factory=dict)
    dkim: dict = field(default_factory=dict)              # selector -> record
    dkim_keys: dict = field(default_factory=dict)         # selector -> {"type", "bits", "revoked", "testing"}
    selectors_tried: list[str] = field(default_factory=list)
    issues: list[MailIssue] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)       # DNS failures (results may be incomplete)

    @property
    def sends_mail(self) -> bool:
        return bool(self.mx) and self.mx != ["0 ."]


def valid_selector(s: str) -> bool:
    return bool(_SELECTOR_RE.match(s))


def dns_resolver(on_query=None, nameserver: str | None = None, timeout: float = 5.0, port: int = 53) -> Resolver:
    """A Resolver backed by dnspython. on_query(name, rdtype) is called before
    each lookup so it can be logged."""
    import dns.exception
    import dns.resolver

    res = dns.resolver.Resolver()
    if nameserver:
        res.nameservers = [nameserver]
        res.port = port
    res.lifetime = timeout

    def resolve(name: str, rdtype: str) -> list[str]:
        if on_query:
            on_query(name, rdtype)
        try:
            ans = res.resolve(name, rdtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.resolver.NoNameservers as exc:
            raise DnsError(f"{name} {rdtype}: no name server answered (SERVFAIL?)") from exc
        except dns.exception.Timeout as exc:
            raise DnsError(f"{name} {rdtype}: timed out") from exc
        except dns.exception.DNSException as exc:
            raise DnsError(f"{name} {rdtype}: {exc}") from exc
        if rdtype == "TXT":
            return [b"".join(r.strings).decode("utf-8", "replace") for r in ans]
        if rdtype == "MX":
            return [f"{r.preference} {r.exchange.to_text()}" for r in ans]
        return [r.to_text() for r in ans]
    return resolve


def dict_resolver(records: dict) -> Resolver:
    """Resolver over recorded data {"name": {"TXT": [...], "MX": [...]}}; a value
    of "SERVFAIL" raises DnsError. Used by tests and for replaying results."""
    def resolve(name: str, rdtype: str) -> list[str]:
        v = records.get(name.lower().rstrip("."), {}).get(rdtype, [])
        if v == "SERVFAIL":
            raise DnsError(f"{name} {rdtype}: SERVFAIL")
        return list(v)
    return resolve


# ---- SPF ----

_MECH_RE = re.compile(r"^([+\-~?]?)(all|include|a|mx|ptr|ip4|ip6|exists)(?:([:/])(.*))?$", re.I)
_MOD_RE = re.compile(r"^([a-z][a-z0-9_.-]*)=(.*)$", re.I)
_LOOKUP_MECHS = {"include", "a", "mx", "ptr", "exists"}


@dataclass
class SpfTerm:
    qualifier: str      # + - ~ ?
    name: str           # mechanism or modifier name, lower-case
    value: str = ""
    modifier: bool = False


def parse_spf(record: str) -> tuple[list[SpfTerm], list[str]]:
    """-> (terms, syntax errors)."""
    toks = record.split()
    errors: list[str] = []
    if not toks or toks[0].lower() != "v=spf1":
        return [], ["record doesn't start with v=spf1"]
    terms = []
    for t in toks[1:]:
        m = _MECH_RE.match(t)
        if m:
            q, name, sep, val = m.group(1) or "+", m.group(2).lower(), m.group(3), m.group(4) or ""
            if name in ("ip4", "ip6"):
                try:
                    net = ipaddress.ip_network(val, strict=False)
                    if net.version != int(name[-1]):
                        raise ValueError
                except ValueError:
                    errors.append(f"invalid {name} address: {t}")
            if name in ("include", "exists") and (sep != ":" or not val):
                errors.append(f"{name} needs a domain: {t}")
            if name == "all" and sep:
                errors.append(f"'all' takes no argument: {t}")
            terms.append(SpfTerm(q, name, (sep + val) if sep == "/" else val))
            continue
        m = _MOD_RE.match(t)
        if m:
            terms.append(SpfTerm("", m.group(1).lower(), m.group(2), modifier=True))
            continue
        errors.append(f"unknown term: {t}")
    return terms, errors


def _spf_records(txts: list[str]) -> list[str]:
    return [t for t in txts if t.lower() == "v=spf1" or t.lower().startswith("v=spf1 ")]


def count_spf_lookups(domain: str, resolve: Resolver, tree: list[str] | None = None, depth: int = 0,
                      seen: set | None = None) -> tuple[int, list[str]]:
    """Count DNS-querying terms (include, a, mx, ptr, exists, redirect) across
    the whole include/redirect tree, as receivers must (RFC 7208 4.6.4).
    Returns (count, problems). Stops early once the limit is exceeded."""
    tree = tree if tree is not None else []
    seen = seen if seen is not None else set()
    problems: list[str] = []
    if depth > SPF_LOOKUP_LIMIT or domain in seen:
        return 0, ([f"include loop at {domain}"] if domain in seen else [])
    seen.add(domain)
    recs = _spf_records(resolve(domain, "TXT"))
    if depth:
        tree.append(f"{'  ' * depth}{domain}: {recs[0] if recs else '(no SPF record)'}")
    if not recs:
        return 0, ([f"{domain} (included) has no SPF record: that's a permanent error"] if depth else [])
    if len(recs) > 1 and depth:
        problems.append(f"{domain} (included) has {len(recs)} SPF records")
    terms, _errs = parse_spf(recs[0])
    count = 0
    has_all = any(t.name == "all" and not t.modifier for t in terms)
    for t in terms:
        if t.modifier and t.name != "redirect":
            continue
        if t.name in _LOOKUP_MECHS or t.name == "redirect":
            if t.name == "redirect" and has_all:
                continue                      # redirect is ignored when 'all' is present
            count += 1
            if count > SPF_LOOKUP_LIMIT:
                break
            if t.name in ("include", "redirect") and t.value and "%" not in t.value:
                sub, p = count_spf_lookups(t.value.lower().rstrip("."), resolve, tree, depth + 1, seen)
                count += sub
                problems += p
        if count > SPF_LOOKUP_LIMIT:
            break
    return count, problems


def spf_issues(report: DomainReport, resolve: Resolver) -> list[MailIssue]:
    out = []
    recs = report.spf
    if not recs:
        sev = "Medium"
        why = ("Without SPF, receiving mail servers have no list of servers allowed to send as "
               f"@{report.domain}." + ("" if report.sends_mail else
                                     " This domain has no MX record; if it never sends mail, publish "
                                     "`v=spf1 -all` so nobody can send as it."))
        return [MailIssue("spf_missing", sev, "No SPF record", why, "spf")]
    if len(recs) > 1:
        out.append(MailIssue("spf_multiple", "Medium", f"{len(recs)} SPF records (SPF fails: permerror)",
                             "Only one v=spf1 TXT record is allowed. With two, receivers treat SPF as broken. "
                             "Merge them into one record.\n\n" + "\n".join(f"`{r}`" for r in recs), "spf"))
    rec = recs[0]
    terms, errors = parse_spf(rec)
    if errors:
        out.append(MailIssue("spf_syntax", "Medium", "SPF record has syntax errors (permerror)",
                             "; ".join(errors) + f"\n\n`{rec}`", "spf"))
    alls = [t for t in terms if t.name == "all" and not t.modifier]
    redirect = next((t for t in terms if t.modifier and t.name == "redirect"), None)
    if alls:
        q = alls[-1].qualifier
        if q == "+":
            out.append(MailIssue("spf_pass_all", "High", "SPF allows every server on the internet (+all)",
                                 f"`{rec}` ends in +all, which authorizes any sender: SPF gives no protection.",
                                 "spf"))
        elif q == "?":
            out.append(MailIssue("spf_neutral_all", "Medium", "SPF ends in ?all (neutral)",
                                 "?all says 'no opinion' about other senders, so spoofed mail isn't penalized.",
                                 "spf"))
        elif q == "~":
            enforcing = (report.dmarc_tags.get("p") or "").lower() in ("quarantine", "reject")
            out.append(MailIssue("spf_softfail", "Info" if enforcing else "Low", "SPF ends in ~all (soft fail)",
                                 "~all marks other senders as suspicious but doesn't fail them. " +
                                 ("That's fine here because DMARC enforces the policy." if enforcing else
                                  "Without an enforcing DMARC policy, spoofed mail is often still delivered. Use "
                                  "-all once you're sure the record lists every server that sends your mail."),
                                 "spf"))
    elif not redirect:
        out.append(MailIssue("spf_no_all", "Low", "SPF record has no 'all' at the end",
                             f"`{rec}`: without -all / ~all the result for unlisted senders is neutral.", "spf"))
    if any(t.name == "ptr" for t in terms):
        out.append(MailIssue("spf_ptr", "Low", "SPF uses the deprecated 'ptr' mechanism",
                             "RFC 7208 says not to use ptr: it's slow, unreliable, and some receivers ignore it.",
                             "spf"))
    tree: list[str] = []
    try:
        count, problems = count_spf_lookups(report.domain, resolve, tree)
        report.spf_lookups, report.spf_tree = count, tree
        if count > SPF_LOOKUP_LIMIT:
            out.append(MailIssue("spf_too_many_lookups", "Medium",
                                 f"SPF needs more than {SPF_LOOKUP_LIMIT} DNS lookups (permerror)",
                                 f"Counting includes of includes, evaluating this record takes {count}+ DNS "
                                 "lookups; receivers stop at 10 and treat SPF as broken. Remove unused includes "
                                 "or replace them with ip4:/ip6: ranges.", "spf"))
        for p in problems:
            out.append(MailIssue("spf_include_broken", "Medium", "SPF include is broken (permerror)", p, "spf"))
    except DnsError as exc:
        report.errors.append(f"SPF include check: {exc}")
    return out


def lookups_text(n: int | None) -> str:
    if n is None:
        return ""
    if n > SPF_LOOKUP_LIMIT:
        return f"more than {SPF_LOOKUP_LIMIT} (counting stopped at {n}): too many"
    return f"{n} (limit {SPF_LOOKUP_LIMIT})"


# ---- DMARC ----

def parse_tags(record: str) -> dict[str, str]:
    tags = {}
    for part in record.split(";"):
        k, sep, v = part.strip().partition("=")
        if sep and k.strip():
            tags.setdefault(k.strip().lower(), v.strip())
    return tags


def dmarc_issues(report: DomainReport) -> list[MailIssue]:
    recs = report.dmarc
    if not recs:
        return [MailIssue("dmarc_missing", "Medium", "No DMARC record",
                          f"No TXT record at _dmarc.{report.domain}. Receivers decide on their own what to do "
                          "with mail that fails SPF/DKIM, and you get no reports about who sends as your domain.",
                          "dmarc")]
    out = []
    if len(recs) > 1:
        out.append(MailIssue("dmarc_multiple", "Medium", f"{len(recs)} DMARC records (DMARC is ignored)",
                             "Receivers ignore DMARC when there's more than one record. Keep one.", "dmarc"))
    tags = report.dmarc_tags
    p = tags.get("p", "").lower()
    if p not in ("none", "quarantine", "reject"):
        out.append(MailIssue("dmarc_invalid", "Medium", "DMARC record has no valid p= policy",
                             f"`{recs[0]}`: p= must be none, quarantine or reject; without it the record is "
                             "ignored.", "dmarc"))
        return out
    if p == "none":
        out.append(MailIssue("dmarc_none", "Low", "DMARC policy is p=none (monitoring only)",
                             "Mail that fails authentication is still delivered normally; p=none only produces "
                             "reports. Move to quarantine, then reject, once reports show your legitimate mail "
                             "passes.", "dmarc"))
    try:
        pct = int(tags.get("pct", "100"))
    except ValueError:
        pct = 100
    if p != "none" and pct < 100:
        out.append(MailIssue("dmarc_pct", "Low", f"DMARC policy applies to only {pct}% of failing mail",
                             f"pct={pct}: the rest is treated as p=none.", "dmarc"))
    sp = tags.get("sp", "").lower()
    if p != "none" and sp == "none":
        out.append(MailIssue("dmarc_sp_none", "Low", "DMARC subdomain policy is sp=none",
                             "Spoofed mail from made-up subdomains (e.g. billing." + report.domain + ") isn't "
                             "blocked.", "dmarc"))
    if not tags.get("rua"):
        out.append(MailIssue("dmarc_no_rua", "Info", "DMARC has no rua= report address",
                             "You won't receive aggregate reports showing who sends mail as your domain.", "dmarc"))
    return out


# ---- DKIM ----

def _der_read(buf: bytes, i: int) -> tuple[int, bytes, int]:
    """One DER TLV at i -> (tag, value, next index)."""
    tag = buf[i]
    ln = buf[i + 1]
    i += 2
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(buf[i:i + n], "big")
        i += n
    return tag, buf[i:i + ln], i + ln


def rsa_key_bits(p_b64: str) -> int | None:
    """Modulus size of a DKIM RSA key (SubjectPublicKeyInfo, or bare PKCS#1)."""
    try:
        der = base64.b64decode(re.sub(r"\s+", "", p_b64), validate=False)
        tag, seq, _ = _der_read(der, 0)
        if tag != 0x30:
            return None
        tag, first, nxt = _der_read(seq, 0)
        if tag == 0x02:                       # PKCS#1 RSAPublicKey: SEQUENCE { n, e }
            modulus = first
        else:                                 # SPKI: SEQUENCE { AlgorithmIdentifier, BIT STRING }
            tag, bits, _ = _der_read(seq, nxt)
            if tag != 0x03:
                return None
            _t, rsa, _ = _der_read(bits[1:], 0)   # skip the unused-bits byte
            _t, modulus, _ = _der_read(rsa, 0)
        modulus = modulus.lstrip(b"\x00")
        return len(modulus) * 8 - (8 - modulus[0].bit_length()) if modulus else None
    except (IndexError, ValueError):
        return None


def analyze_dkim(record: str) -> dict:
    tags = parse_tags(record)
    k = (tags.get("k") or "rsa").lower()
    p = tags.get("p", "")
    info = {"type": k, "bits": None, "revoked": not p.strip(), "testing": "y" in (tags.get("t") or "").split(":")}
    if k == "rsa" and p.strip():
        info["bits"] = rsa_key_bits(p)
    return info


def dkim_issues(report: DomainReport) -> list[MailIssue]:
    out = []
    live = {s: i for s, i in report.dkim_keys.items() if not i["revoked"]}
    if not live:
        sel = ", ".join(report.selectors_tried[:8]) + ("…" if len(report.selectors_tried) > 8 else "")
        out.append(MailIssue("dkim_not_found", "Low" if report.sends_mail else "Info",
                             "No DKIM key found for the selectors tried",
                             f"Tried {len(report.selectors_tried)} common selectors ({sel}). DNS can't list "
                             "selectors, so a key may exist under another name: find yours in the "
                             "DKIM-Signature header (s=...) of a message you sent, and add it to the selector "
                             "list." + ("" if report.sends_mail else " This domain has no MX record, so it may "
                                        "not send mail at all."), "dkim"))
    for s, i in sorted(report.dkim_keys.items()):
        bits = i.get("bits")
        if i["revoked"]:
            continue
        if i["type"] == "rsa" and bits is None:
            out.append(MailIssue(f"dkim_unparsable_{s}", "Medium", f"DKIM key '{s}' can't be parsed",
                                 "The p= value isn't a valid RSA public key, so signatures with this selector "
                                 "fail.", "dkim"))
        elif i["type"] == "rsa" and bits < 1024:
            out.append(MailIssue(f"dkim_weak_{s}", "High", f"DKIM key '{s}' is only {bits} bits",
                                 "RSA keys under 1024 bits can be factored; an attacker could sign mail as you. "
                                 "Many receivers also ignore such signatures.", "dkim"))
        elif i["type"] == "rsa" and bits < 2048:
            out.append(MailIssue(f"dkim_1024_{s}", "Low", f"DKIM key '{s}' is {bits} bits",
                                 "1024-bit RSA is the minimum; 2048 bits is recommended (RFC 8301).", "dkim"))
        if i["testing"]:
            out.append(MailIssue(f"dkim_testing_{s}", "Low", f"DKIM key '{s}' is in test mode (t=y)",
                                 "Receivers may treat failures as if the message weren't signed.", "dkim"))
    return out


# ---- running the audit ----

def audit(domain: str, resolve: Resolver, selectors: list[str] | None = None) -> DomainReport:
    domain = normalize_domain(domain)
    rep = DomainReport(domain)

    def q(name, rdtype):
        try:
            return resolve(name, rdtype)
        except DnsError as exc:
            rep.errors.append(str(exc))
            return None

    rep.mx = q(domain, "MX") or []
    txt = q(domain, "TXT")
    rep.spf = _spf_records(txt or [])
    dm = q(f"_dmarc.{domain}", "TXT")
    rep.dmarc = [t for t in (dm or []) if t.replace(" ", "").lower().startswith("v=dmarc1")]
    rep.dmarc_tags = parse_tags(rep.dmarc[0]) if rep.dmarc else {}
    sels = []
    for s in [*(selectors or []), *DEFAULT_SELECTORS]:
        if valid_selector(s) and s not in sels:
            sels.append(s)
    rep.selectors_tried = sels
    for s in sels:
        recs = q(f"{s}._domainkey.{domain}", "TXT") or []
        recs = [r for r in recs if "p=" in r.replace(" ", "")]
        if recs:
            rep.dkim[s] = recs[0]
            rep.dkim_keys[s] = analyze_dkim(recs[0])
    if txt is not None:
        rep.issues += spf_issues(rep, resolve)
    if dm is not None:
        rep.issues += dmarc_issues(rep)
    rep.issues += dkim_issues(rep)
    if rep.mx == ["0 ."]:
        rep.issues.append(MailIssue("null_mx", "Info", "Null MX: domain declares it receives no mail",
                                    "MX 0 . (RFC 7505). Make sure SPF is `v=spf1 -all` and DMARC p=reject too.",
                                    "mx"))
    return rep


# ---- findings ----

REMEDIATION = {
    "spf": ("Publish exactly one TXT record at the domain listing every service that sends your mail, ending in "
            "-all, e.g. `v=spf1 include:_spf.google.com include:servers.mcsv.net -all` (your mail provider "
            "documents its include). For a domain that never sends mail: `v=spf1 -all`. Keep it under 10 DNS "
            "lookups."),
    "dmarc": ("Publish a TXT record at _dmarc.<domain>. Start with `v=DMARC1; p=none; rua=mailto:dmarc@<domain>` "
              "to collect reports, then move to `p=quarantine` and finally `p=reject` (with `sp=reject` for "
              "subdomains). A domain that never sends mail can go straight to `v=DMARC1; p=reject;`."),
    "dkim": ("Turn on DKIM signing in your mail provider (Google Workspace, Microsoft 365, Fastmail, Proton, ...) "
             "and publish the TXT/CNAME record it gives you. Use 2048-bit RSA keys and rotate them periodically; "
             "remove the t=y test flag once signing works."),
    "mx": "No change needed if the domain truly never receives mail.",
}
TECHNIQUE = ("**Email spoofing / impersonation:** anyone can put your domain in a message's From: line. SPF "
             "(which servers may send), DKIM (a cryptographic signature) and DMARC (what receivers should do when "
             "both fail, and who to report to) are what let receiving mail servers reject those forgeries, "
             "which are the raw material of phishing and invoice fraud.")


def findings(domain: str, report: DomainReport) -> list[Finding]:
    return [Finding(
        device=domain, device_label=domain, kind="email", title=f"Email: {i.title}", severity=i.severity,
        description=i.detail or i.title, remediation=REMEDIATION.get(i.category, ""), technique=TECHNIQUE,
        service="DNS (email authentication)", port="dns", attck=["T1566", "T1656"],
        confidence="confirmed (DNS records)", weight=SEV_WEIGHT.get(i.severity, 0),
        source="Domain audit (SPF/DKIM/DMARC via DNS)") for i in report.issues]


def report_to_json(rep: DomainReport) -> str:
    return json.dumps(asdict(rep))


def report_from_json(text: str) -> DomainReport | None:
    d = json.loads(text or "{}")
    if not d:
        return None
    d["issues"] = [MailIssue(**i) for i in d.get("issues", [])]
    return DomainReport(**d)
