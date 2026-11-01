"""In-app help text (Markdown, rendered by QTextBrowser.setMarkdown).

TAB_HELP feeds the collapsible "What is this?" panel on each tab.
GLOSSARY feeds Help -> Glossary. Keep entries plain-language; this content is
meant to be a learning resource, not an afterthought.
"""

TAB_HELP: dict[str, str] = {
"interfaces": """
### Interfaces
**What it does:** lists the network interfaces on this machine, especially
wireless ones, and checks whether each Wi-Fi adapter supports **monitor mode**.
It wraps `iw dev` and `iw phy` (read-only queries; nothing is reconfigured).

**Why it matters:** normal ("managed") Wi-Fi mode only hands your OS frames
addressed to you. Monitor mode passes up every frame the radio hears, which is
what passive recon tools like airodump-ng need. Many built-in laptop adapters
do not support it; many USB adapters do.

**Reading the result:** "monitor: yes" means the driver advertises the mode.
Watchtower asks before switching any interface into monitor mode, because
doing so drops your normal Wi-Fi connection on that adapter. Switching back
hands the adapter back to NetworkManager so it reconnects.
""",
"nearby": """
### Nearby Networks
**What it does:** lists every access point in range: SSID, BSSID, channel,
encryption, WPS and signal strength. Two methods:
- **Managed scan** (`nmcli`, else `iwlist`): the same scan your OS runs to fill
  its Wi-Fi menu. Works with any adapter and keeps you connected. `iwlist` also
  reveals whether an AP advertises **WPS**.
- **Monitor-mode listen** (`airodump-ng`): purely passive listening on every
  channel for the time you choose. It also sees **client devices** and which
  network each one is talking to or probing for. Needs a monitor-capable adapter
  (see Interfaces). Watchtower offers to switch the adapter for you.

Only CSV summaries are written; no packets are captured or saved.

**Why it matters:** this is how an attacker first sees your network. Weak
encryption (open, WEP, WPA1) or WPS being enabled is visible from the street.

**The Authorized checkbox:** tick it for your own networks. Only authorized
networks can be **Investigated**: Watchtower adds your subnet on that network to
the authorized targets and opens Scan a Target. Every change is written to the
audit log. Colors: red = open/WEP, orange = WPA1 or WPS enabled.
""",
"scan": """
### Scan a Target
**What it does:** runs `nmap` with any options you like, against targets on your
**authorized targets** list (left). The exact command is previewed live, shown in
the Command Console and recorded in the audit log. Results (hosts, open ports,
services, versions, OS guesses, script output) are parsed from nmap's XML output
and every scan is kept in Scan history.

**Targets:** single IPs, CIDRs (`192.168.1.0/24`), nmap ranges
(`192.168.1.1-50`) or hostnames. Add entries manually, pick one of your local
subnets, or use Investigate on an authorized Wi-Fi network. Any extra targets
typed in Extra arguments must also be on the list. `-iL`, `-iR`, `-b` and
`--resume` are refused because their targets can't be checked.

**Privileges:** options such as `-O`, `-sU` or `-A` need raw sockets. If nmap has
been granted capabilities (Tools → Dependency Check) Watchtower adds
`--privileged` automatically. Otherwise it offers to run that scan through the
password prompt.

**Why it matters:** each open port is a service someone can talk to. Old
versions of those services are where most known vulnerabilities (CVEs) live.

**Options:** `--script vuln` runs nmap's own vulnerability-detection scripts.
It is opt-in because some scripts are intrusive (they send real probes for
specific bugs), so only use it on hosts you are allowed to stress.

""",
"findings": """
### Findings
**What it does:** turns raw scan data into a prioritized list of problems.
Each finding has a severity, a CVSS score where one applies, a MITRE ATT&CK
technique tag, a per-device risk score (0-100) and, always, **remediation text**:
what to change to fix it.

For Wi-Fi findings, the expanded row explains the attack technique in plain
language so you understand the exposure. Watchtower never performs the attack.
If you want to test one, do it by hand with the underlying tools, outside this app.

*Status: implemented in build steps 4, 5 and 7.*
""",
"host_audit": """
### Host Audit
**What it does:** deeper, read-only checks on one authorized host:
- **TLS audit** (`sslyze` or `testssl.sh`): protocol versions, weak ciphers,
  expired or self-signed certificates.
- **SNMP audit** (`snmpget`, GET only): does a common community string such as
  `public` grant read access?
- **Default-credentials fingerprint:** does the device's banner match a model
  known to ship with a default password? Reported only; no login is attempted.

*Status: implemented in build step 6.*
""",
"changes": """
### What Changed
**What it does:** compares each scan of an authorized network or host with the
previous one: new devices, ports that opened, service versions that changed,
access points that disappeared. The scheduler can repeat scans on a timer so
this becomes continuous monitoring of your own network.

**Why it matters:** an unexpected new port or device is often the first sign
of a misconfiguration or compromise.

*Status: implemented in build step 8.*
""",
"audit_log": """
### Audit Log
**What it does:** a read-only record of everything Watchtower has done: every
external command (exact command line, start time, exit code), every
confirmation you gave, every network you marked authorized or unauthorized,
and any outbound network request (only NVD lookups, and only if you enable them).

The log is **append-only**: the database refuses edits and deletions to it.
Export it to CSV or JSON for your write-ups.
""",
"settings": """
### Settings
- **NVD lookups:** off by default. When off, Watchtower makes no network
  requests of its own at all. When on, it queries the NIST National
  Vulnerability Database for CVEs matching discovered service versions.
  An API key raises NVD's rate limit.
- **Theme** and **scheduler** options.
""",
"help": """
### Help
Overview, a glossary of every term used in the UI, the per-tab guides collected
in one place, and the setup guide (same text as INSTALL.md).
""",
"deps": """
### Dependency Check
Watchtower is a front end for existing, well-known tools; it does not bundle
them. This screen shows which are installed and their versions. Features whose
tool is missing are grayed out with a tooltip rather than failing.

Nothing is installed automatically. The install button shows you the full
command list first and only runs it after you confirm; on Linux it asks for
your password through `pkexec`, the graphical sudo prompt.

**Raw-socket capabilities (Linux):** nmap SYN scans and airodump-ng need raw
network access. Instead of running the whole GUI as root, Watchtower can grant
just those binaries the `cap_net_raw,cap_net_admin` capabilities with
`setcap`. Trade-off: any local user can then use those binaries with raw
sockets. On a single-user lab machine that is normally fine.
""",
}


GLOSSARY: list[tuple[str, str]] = [
("SSID / BSSID",
 "The **SSID** is a network's human-readable name (\"HomeWiFi\"). The **BSSID** is "
 "the MAC address of a specific access point radio broadcasting it. One SSID can have "
 "many BSSIDs (mesh systems, 2.4 GHz plus 5 GHz radios)."),
("Monitor mode",
 "A Wi-Fi adapter mode in which the radio passes every frame it hears to the OS, not "
 "just frames addressed to it. Required for passive recon of networks you are not "
 "connected to. Support depends on the chipset and driver, and in practice on Linux."),
("WEP",
 "Wired Equivalent Privacy, the original 1999 Wi-Fi encryption. Its RC4 key-scheduling "
 "and short IVs are fundamentally broken: a key can be recovered from captured traffic "
 "in minutes regardless of key strength. Any WEP network should be treated as open."),
("WPA / WPA2 / WPA3",
 "**WPA** (2003) was a stopgap on WEP-era hardware using TKIP, now deprecated. **WPA2** "
 "(2004) uses AES-CCMP and is still the most common. In **WPA2-Personal** everyone shares "
 "one passphrase, and anyone who records a client joining can test password guesses "
 "offline, so security comes down to passphrase strength. **WPA3-Personal** replaces the "
 "4-way-handshake key exchange with SAE (Dragonfly), which resists offline guessing: each "
 "guess needs a live exchange with the AP. **Transition mode** (WPA2+WPA3 together) keeps "
 "WPA2's weakness for any client that uses it."),
("PSK (Pre-Shared Key)",
 "The shared passphrase in WPA/WPA2/WPA3-Personal. In WPA2 it is stretched with "
 "PBKDF2 (4096 rounds, with the SSID as salt) into the Pairwise Master Key. Because the "
 "SSID is the salt, common SSIDs with common passwords are covered by precomputed tables. "
 "Defense: a long random passphrase (14+ characters from a password manager) and a "
 "non-default SSID."),
("4-way handshake",
 "The exchange in which a WPA2 client and AP prove they both know the PMK and derive "
 "fresh session keys. It never sends the passphrase, but it contains enough (nonces, MAC "
 "addresses and a MIC computed from the key) that anyone who records it can test candidate "
 "passphrases offline at GPU speed, with no further contact with the network. Recording it "
 "only requires being in radio range while a client connects. This is why WPA2-PSK "
 "strength is purely a function of passphrase entropy."),
("PMKID",
 "An identifier some APs include in the first message of the handshake: an HMAC of the "
 "PMK, the AP MAC and the client MAC. Discovered in 2018 to be enough on its own for "
 "offline guessing, so an attacker does not even need a real client to connect; asking "
 "the AP to begin association is enough. Same defense as the handshake: a strong "
 "passphrase, or WPA3-SAE."),
("WPS (Wi-Fi Protected Setup)",
 "A convenience feature that lets devices join with an 8-digit PIN or button press. "
 "The PIN is validated in two halves and the last digit is a checksum, so it has only "
 "about 11,000 possibilities rather than 100 million. Some chipsets also generate their "
 "internal nonces predictably (\"Pixie Dust\"), letting the PIN be computed offline from "
 "a single exchange. Recovering the PIN reveals the WPA passphrase no matter how strong "
 "it is. Defense: disable WPS entirely (some routers only pretend to; check that the "
 "beacon no longer advertises it)."),
("Evil twin / rogue AP",
 "An attacker-controlled access point imitating a legitimate SSID so clients connect to "
 "it. Watchtower does not create one; the term is here because \"What Changed\" can flag "
 "an unexpected new BSSID advertising your SSID, which is how you would spot one."),
("CVE",
 "Common Vulnerabilities and Exposures: a public identifier (e.g. CVE-2011-2523) for a "
 "specific known flaw in a specific product and version range. Findings link service "
 "versions seen by nmap to CVEs."),
("CVSS",
 "Common Vulnerability Scoring System: a 0.0-10.0 severity score for a CVE based on how "
 "it is exploited (network vs local, complexity, privileges, user interaction) and its "
 "impact on confidentiality, integrity and availability. 0.1-3.9 Low, 4.0-6.9 Medium, "
 "7.0-8.9 High, 9.0-10.0 Critical. It measures technical severity, not risk to *you*; "
 "that is what Watchtower's risk score adds."),
("NVD",
 "The U.S. National Vulnerability Database, run by NIST, which publishes CVE records "
 "with CVSS scores and affected-product data (CPEs). Watchtower can query it, but only "
 "if you turn that on in Settings."),
("SNMP community string",
 "SNMP v1/v2c \"authenticates\" with a plaintext password called a community string, sent "
 "unencrypted. Devices often ship with `public` (read) and `private` (read-write). Read "
 "access can leak interface lists, routing tables, ARP caches, usernames and sometimes "
 "configuration. Write access can let someone reconfigure the device. Defense: disable "
 "SNMP if unused, else use SNMPv3 with authPriv, and restrict which hosts may query it."),
("TLS cipher suite",
 "The set of algorithms a TLS connection uses for key exchange, authentication, bulk "
 "encryption and integrity, e.g. `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`. Weak suites "
 "include RC4, 3DES, export-grade and NULL ciphers, and non-forward-secret RSA key "
 "exchange. Old protocol versions (SSLv3, TLS 1.0/1.1) are also flagged, as are expired "
 "or self-signed certificates."),
("Nmap SYN scan",
 "Nmap's default privileged scan (`-sS`): it sends a TCP SYN, notes the reply (SYN/ACK "
 "means open, RST means closed) and never completes the connection. It needs raw sockets, "
 "hence root, Linux capabilities, or Npcap plus Administrator on Windows. Without them "
 "nmap falls back to a full-connect scan (`-sT`)."),
("Linux capabilities (setcap)",
 "Linux splits root's powers into separate capabilities. `cap_net_raw` and "
 "`cap_net_admin` are what packet tools need. Granting them to one binary with `setcap` "
 "is far narrower than running a whole GUI as root."),
("MITRE ATT&CK",
 "A public knowledge base of real-world adversary tactics and techniques, each with an "
 "ID (e.g. T1110 Brute Force, T1078.001 Default Accounts). Watchtower tags each finding "
 "with the technique an attacker would use against it, which helps you look up detection "
 "and mitigation guidance."),
("Default credentials",
 "Factory usernames and passwords (admin/admin, root/12345 and so on) that ship with "
 "routers, cameras, printers and IoT devices and are published in manuals. Watchtower "
 "only matches a device's banner against a list of models known to ship with them and "
 "tells you to change them. It never tries to log in."),
("Risk score",
 "Watchtower's 0-100 per-device priority number. It combines the worst CVSS score, "
 "whether a default-credential fingerprint matched, Wi-Fi encryption weakness and how "
 "many ports are exposed. It is a triage aid for deciding what to fix first, not a "
 "formal metric."),
]
