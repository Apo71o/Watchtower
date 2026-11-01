"""Target expressions and scope checks (no Qt, no I/O).

A target is anything nmap accepts as a target: a single IP, a CIDR
(10.0.0.0/24), an nmap octet range (192.168.1.1-50, 10.0.0,1.1-9) or a
hostname. Scope is the user's list of authorized targets; a target is in
scope when every address it can expand to lies inside one authorized entry.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                      r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$")
_OCTET_PART = re.compile(r"^(\d{1,3})(?:-(\d{1,3}))?$")


@dataclass(frozen=True)
class Target:
    text: str
    lo: int | None = None        # numeric address bounds (IPv4/IPv6), None for hostnames
    hi: int | None = None
    version: int | None = None
    hostname: str | None = None

    @property
    def is_hostname(self) -> bool:
        return self.hostname is not None

    def size(self) -> int:
        return 1 if self.is_hostname else (self.hi - self.lo + 1)

    def within(self, other: Target) -> bool:
        if self.is_hostname or other.is_hostname:
            return bool(self.hostname and other.hostname and self.hostname == other.hostname)
        return self.version == other.version and other.lo <= self.lo and self.hi <= other.hi


def _octet_range(text: str) -> tuple[int, int] | None:
    """nmap IPv4 octet syntax: each of 4 octets is N, N-M, '-' or a comma list."""
    octets = text.split(".")
    if len(octets) != 4:
        return None
    lows, highs = [], []
    for o in octets:
        if o == "-":
            lows.append(0)
            highs.append(255)
            continue
        vals: list[int] = []
        for part in o.split(","):
            m = _OCTET_PART.match(part)
            if not m:
                return None
            a = int(m.group(1))
            b = int(m.group(2)) if m.group(2) is not None else a
            if a > 255 or b > 255 or a > b:
                return None
            vals += [a, b]
        lows.append(min(vals))
        highs.append(max(vals))
    lo = int(ipaddress.IPv4Address(".".join(map(str, lows))))
    hi = int(ipaddress.IPv4Address(".".join(map(str, highs))))
    return lo, hi


def parse_target(text: str) -> Target:
    """Raise ValueError if `text` isn't a valid single target expression."""
    t = text.strip()
    if not t or any(c.isspace() for c in t):
        raise ValueError(f"not a single target: {text!r}")
    try:
        net = ipaddress.ip_network(t, strict=False)
        return Target(t, int(net.network_address), int(net.broadcast_address), net.version)
    except ValueError:
        pass
    rng = _octet_range(t)
    if rng:
        return Target(t, rng[0], rng[1], 4)
    if _HOST_RE.match(t) and not re.fullmatch(r"[\d.]+", t):
        return Target(t, hostname=t.lower().rstrip("."))
    raise ValueError(f"not a valid IP, CIDR, nmap range or hostname: {text!r}")


def in_scope(target: str | Target, authorized: list[str]) -> bool:
    tgt = target if isinstance(target, Target) else parse_target(target)
    for entry in authorized:
        try:
            if tgt.within(parse_target(entry)):
                return True
        except ValueError:
            continue
    return False


def looks_like_target(token: str) -> bool:
    try:
        parse_target(token)
        return True
    except ValueError:
        return False


# ---- web URLs and owned domains (Web Audit / Domain Audit) ----

@dataclass(frozen=True)
class WebUrl:
    url: str          # normalized: scheme://host[:port]/path (default port dropped, no fragment)
    scheme: str       # "http" | "https"
    host: str         # lower-case host name or IP (no brackets)
    port: int

    @property
    def origin(self) -> str:
        return self.url.split("/", 3)[0] + "//" + self.url.split("/", 3)[2]


def parse_url(text: str) -> WebUrl:
    """Validate an http(s) URL for a single host. A bare host gets https://.
    Raise ValueError for anything else (other schemes, credentials in the URL,
    ranges/CIDRs as host)."""
    from urllib.parse import urlsplit, urlunsplit

    t = text.strip()
    if not t or any(c.isspace() for c in t):
        raise ValueError(f"not a URL: {text!r}")
    if "://" not in t:
        t = "https://" + t
    parts = urlsplit(t)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"only http:// and https:// URLs are supported: {text!r}")
    if parts.username or parts.password:
        raise ValueError("remove the user name / password from the URL")
    host = (parts.hostname or "").lower().rstrip(".")
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError(f"invalid port in {text!r}") from exc
    tgt = parse_target(host) if host else None
    if tgt is None or tgt.size() != 1:
        raise ValueError(f"the URL must name one host: {text!r}")
    netloc = f"[{host}]" if ":" in host else host
    if port != (443 if scheme == "https" else 80):
        netloc += f":{port}"
    return WebUrl(urlunsplit((scheme, netloc, parts.path or "/", parts.query, "")), scheme, host, port)


def url_in_scope(url: str | WebUrl, authorized: list[str]) -> bool:
    """A URL is in scope when its host is covered by the authorized-target list."""
    try:
        u = url if isinstance(url, WebUrl) else parse_url(url)
        return in_scope(u.host, authorized)
    except ValueError:
        return False


def normalize_domain(text: str) -> str:
    """'Example.COM.' -> 'example.com'. Must be a registrable-looking DNS name
    with at least one dot (not an IP, not a single label)."""
    d = text.strip().lower().rstrip(".")
    if d.startswith("*."):
        d = d[2:]
    if not _HOST_RE.match(d) or "." not in d or re.fullmatch(r"[\d.]+", d) or ":" in d:
        raise ValueError(f"not a domain name: {text!r}")
    return d


def domain_covered(name: str, owned: list[str]) -> bool:
    """True if `name` equals an owned domain or is a subdomain of one."""
    try:
        n = normalize_domain(name)
    except ValueError:
        return False
    for o in owned:
        try:
            o = normalize_domain(o)
        except ValueError:
            continue
        if n == o or n.endswith("." + o):
            return True
    return False
