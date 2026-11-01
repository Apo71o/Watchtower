"""Wi-Fi findings from what an access point advertises (advisory text only).

Input is a network row as stored by storage.scope.NetworkStore (security,
auth, cipher, wps, ssid, bssid). Each finding explains the relevant attack
technique in plain language and how to defend against it.
"""

from __future__ import annotations

import re

from watchtower.core.findings_engine import Finding

DEFAULT_SSID_RE = re.compile(
    r"^(NETGEAR\d*|TP-?Link_[0-9A-F]{4,6}(_5G)?|Linksys\d*|dlink[-_]?\w*|D-Link\w*|ASUS(_\w+)?|"
    r"HUAWEI-\w+|Vodafone-?\w*|BTHub\d?-\w+|BT-\w+|SKY\w{5}|VM\d{6,}|ATT\w{3,}|xfinitywifi|"
    r"HOME-\w{4}|MySpectrumWiFi\w*|Fios-\w+|TELUS\w*|Belkin\.\w+|default|linksys|Tenda_\w+|"
    r"Xiaomi_\w+|ZTE-\w+|FRITZ!Box \d+.*|Livebox-\w+|Bbox-\w+|WLAN-\w+|o2-WLAN\d+|EE-\w+|"
    r"TALKTALK\w+|PLUSNET-\w+|Optus_\w+|Telstra\w+|SpectrumSetup-\w+)$", re.IGNORECASE)


def _label(n: dict) -> str:
    return f"{n.get('ssid') or '(hidden)'} ({n['bssid']})"


def _f(n, title, severity, weight, description, technique, remediation, attck) -> Finding:
    return Finding(device=n["bssid"], device_label=_label(n), kind="wifi", title=title, severity=severity,
                   description=description, technique=technique, remediation=remediation, attck=attck,
                   service=f"{n.get('security') or '?'} {n.get('auth') or ''} {n.get('cipher') or ''}".strip(),
                   weight=weight, source="wifi advisor")


def wifi_findings(n: dict) -> list[Finding]:
    sec = (n.get("security") or "").strip()
    auth = (n.get("auth") or "").upper()
    cipher = (n.get("cipher") or "").upper()
    out: list[Finding] = []

    if sec == "Open":
        out.append(_f(n, "Open network: no encryption", "High", 70,
            "The network has no Wi-Fi encryption. Everything not protected by HTTPS/TLS can be read by anyone "
            "within radio range, and anyone can join the network and reach its devices.",
            "**Passive sniffing:** with an open network, every frame is readable as-is. A listener needs no key, "
            "just a monitor-mode adapter in range. **Evil twin:** because there's no key to prove the real access "
            "point's identity, anyone can broadcast the same network name. Devices that remember the network "
            "join whichever is stronger, putting the attacker in the middle of their traffic.",
            "Enable WPA3-Personal (or WPA2-AES with a long random passphrase). For a guest network that must stay "
            "open, use Wi-Fi Enhanced Open (OWE) and isolate it from your LAN (client isolation, separate VLAN).",
            ["T1040", "T1557.004"]))
    elif sec == "OWE":
        out.append(_f(n, "Enhanced Open (OWE): encrypted but unauthenticated", "Info", 10,
            "OWE encrypts each client's traffic individually, so passive sniffing doesn't work, but anyone can still "
            "join, and clients can't tell the real access point from an impostor.",
            "OWE defeats passive listening, but not an active evil twin, since there's no shared secret to "
            "authenticate the access point.", "Fine for guest networks; keep it isolated from the LAN.",
            ["T1557.004"]))
    elif sec == "WEP":
        out.append(_f(n, "WEP encryption (broken)", "Critical", 80,
            "WEP has been broken since 2001 and deprecated since 2004. Its key can be recovered from captured "
            "traffic in minutes regardless of how long or random it is.",
            "**Why WEP fails:** WEP uses the RC4 cipher with a 24-bit initialization vector (IV) sent in the clear "
            "and prepended to the key. With only ~16 million IVs they repeat quickly, and RC4's key-scheduling "
            "weakness (Fluhrer-Mantin-Shamir, later the PTW attack) means each packet leaks statistical information "
            "about the key. Collecting tens of thousands of packets, which an attacker can speed up by replaying "
            "packets to make the network generate more, is enough to compute the key outright. No password "
            "guessing is involved, so key strength doesn't matter.",
            "Switch the access point to WPA3 or WPA2-AES. If a device only supports WEP, replace it, or move it to "
            "an isolated network with no access to anything sensitive.",
            ["T1040", "T1557"]))
    else:
        has_wpa1 = re.search(r"(^|/)WPA($|/)", sec) is not None
        has_wpa2 = "WPA2" in sec
        has_wpa3 = "WPA3" in sec
        enterprise = "Enterprise" in sec or "MGT" in auth
        if has_wpa1 or "TKIP" in cipher:
            out.append(_f(n, "WPA1 / TKIP enabled", "High", 55,
                "The network still allows WPA (version 1) and/or the TKIP cipher, which were stopgaps for WEP-era "
                "hardware and are deprecated. Mixed WPA/WPA2 mode also forces TKIP for broadcast traffic and blocks "
                "fast Wi-Fi speeds (802.11n/ac require AES).",
                "**TKIP weaknesses:** TKIP wraps RC4 with per-packet keys and a weak integrity check called Michael. "
                "Published attacks (Beck-Tews, Ohigashi-Morii) can decrypt short packets and inject a limited number "
                "of forged ones without knowing the key. On top of that, WPA-PSK has the same offline-guessing "
                "exposure as WPA2-PSK (see that finding).",
                "Set the access point to WPA2-AES (CCMP) only, or WPA3. Disable 'WPA/WPA2 mixed' and 'TKIP'.",
                ["T1040", "T1557"]))
        if enterprise:
            out.append(_f(n, "WPA-Enterprise (802.1X): check client certificate validation", "Info", 10,
                "Enterprise Wi-Fi authenticates each user with a RADIUS server instead of a shared passphrase, which "
                "is strong, provided clients verify the server's certificate.",
                "**Rogue RADIUS / evil twin:** if a client doesn't validate the authentication server's certificate, "
                "an impostor access point with its own RADIUS server can complete PEAP/EAP-TTLS with the client and "
                "capture its MSCHAPv2 challenge-response, which can then be cracked offline to recover the user's "
                "password.",
                "Configure every client to validate the server certificate (pin the CA and the server name). Prefer "
                "EAP-TLS (client certificates) over password-based PEAP-MSCHAPv2.",
                ["T1557.004", "T1110.002"]))
        elif has_wpa2 and not has_wpa3 and ("PSK" in auth or not auth):
            out.append(_f(n, "WPA2-Personal: exposed to offline passphrase guessing", "Medium", 25,
                "WPA2-Personal's security rests entirely on the passphrase. Anyone in range can record the material "
                "needed to test passphrase guesses offline, at billions of guesses per second on GPUs, without "
                "further contact with the network.",
                "**Handshake capture:** when a device joins, it and the access point run the 4-way handshake. It never "
                "sends the passphrase, but it contains a message integrity code (MIC) computed from a key derived "
                "from the passphrase and SSID (PBKDF2, 4096 rounds). Someone who records one handshake can test "
                "candidate passphrases offline until the MIC matches. **PMKID:** many access points include a PMKID "
                "(an HMAC of that same key) in the first handshake message, so the attacker doesn't even need a real "
                "client to connect; asking the AP to start association is enough. Dictionary words, phone numbers, "
                "8-digit defaults and anything under ~12 random characters fall quickly. Long random passphrases do "
                "not.",
                "Best: switch to WPA3-Personal (SAE), which removes offline guessing. If older devices need WPA2: use "
                "a random passphrase of 14+ characters (password-manager generated), change any default SSID, enable "
                "Protected Management Frames (802.11w) if available, and rotate the passphrase if it was ever shared.",
                ["T1110.002", "T1040"]))
        elif has_wpa2 and has_wpa3:
            out.append(_f(n, "WPA2/WPA3 transition mode: downgrade possible", "Low", 15,
                "WPA3 is enabled, but WPA2 is still accepted so older devices can join. Devices that use WPA2 keep "
                "WPA2's offline-guessing exposure.",
                "**Downgrade (Dragonblood):** an impostor access point advertising the same network as WPA2-only can "
                "get WPA3-capable clients to start a WPA2 handshake, giving the attacker material for offline "
                "passphrase guessing even though the real network supports WPA3. Clients that remember the network "
                "as WPA3-only (\"transition disable\") resist this.",
                "Move to WPA3-only once every device supports it. Until then use a long random passphrase, and "
                "enable 'WPA3 transition disable' / PMF required if your access point offers it.",
                ["T1557.004", "T1110.002"]))

    if n.get("wps") == 1:
        out.append(_f(n, "WPS (Wi-Fi Protected Setup) enabled", "High", 25,
            "WPS lets devices join with an 8-digit PIN or button press. The PIN method is weak enough that it "
            "reveals the WPA passphrase, however strong that passphrase is.",
            "**PIN brute force:** the access point checks the PIN's two halves separately and the last digit is a "
            "checksum, so only 10,000 + 1,000 = 11,000 combinations need trying instead of 100 million. Many APs "
            "lock out after failures, slowing but not stopping this. **Pixie Dust:** some chipsets generate the "
            "secret nonces in the WPS exchange from weak or predictable random numbers, letting the PIN be computed "
            "offline from a single exchange in seconds. Either way, the AP then hands over the network passphrase.",
            "Disable WPS in the router settings (both PIN and push-button if you don't use it). Some routers keep "
            "advertising WPS after you 'disable' it, so rescan to confirm it's gone, and update the firmware.",
            ["T1110"]))

    ssid = n.get("ssid") or ""
    if ssid and DEFAULT_SSID_RE.match(ssid):
        out.append(_f(n, "Factory-default network name", "Low", 5,
            "The SSID looks like a manufacturer or ISP default. It reveals the router model, and default networks "
            "often still use the default passphrase printed on the device.",
            "**Why the name matters:** the SSID is the salt in WPA2's passphrase hashing, so common default names "
            "have precomputed tables for common passphrases. For some older ISP routers the default passphrase can "
            "even be derived from the SSID or MAC address, because the generation algorithms have been reverse-"
            "engineered.",
            "Rename the network to something non-identifying and change the passphrase to a long random one.",
            ["T1110.002"]))
    if not ssid:
        out.append(_f(n, "Hidden SSID (no real protection)", "Info", 0,
            "Hiding the network name doesn't secure it: the name still appears in clear text whenever a device "
            "connects, and devices that remember a hidden network broadcast its name while searching for it, even "
            "away from home.",
            "Hidden networks are revealed by watching association or probe traffic, so hiding adds no security and "
            "makes your devices leak the name elsewhere.",
            "Don't rely on hiding; use strong encryption. Unhiding is usually better for client privacy.", []))
    return out
