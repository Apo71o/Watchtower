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
- **Managed scan**: the same scan your OS runs to fill its Wi-Fi menu. Works
  with any adapter and keeps you connected. Pick the tool: `nmcli` (no password)
  or `iw` (asks for your password, and also reveals whether an AP advertises
  **WPS**). Legacy `iwlist` is used if installed.
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
**What it does:** turns stored scan results and your authorized Wi-Fi networks
into a prioritized list of problems. Each finding has a severity, a CVSS score
where one applies, MITRE ATT&CK technique tags and, always, **remediation text**:
what to change to fix it. Select a finding to read the details; Wi-Fi findings
also explain how the attack technique works.

**Where findings come from (all offline):**
- **Version matches** against a small bundled set of well-known CVEs. Linux
  distributions often fix ("backport") security bugs without changing the
  version number nmap sees, so Watchtower reads the package revision from the
  banner (e.g. `OpenSSH 8.9p1 Ubuntu 3ubuntu0.10`) and compares it with
  Ubuntu/Debian security advisories. Each such finding has an **Is it fixed on
  this system?** section: *fixed by distro update* (shown as Info, not counted
  in the risk score), *update not installed*, or *can't tell* (with the commands
  to check on the host). If nmap's own vuln script confirms the CVE, that
  overrides the version check.
- **Exposure rules:** risky services being reachable at all (telnet, Docker API,
  Redis, RDP, SNMP, plain FTP/HTTP, ...).
- **nmap vuln scripts:** anything a `--script vuln` run reported as VULNERABLE.
- **Wi-Fi advisor:** encryption type, WPS, default or hidden SSID.
- **NVD (optional, off by default):** turn on *live NVD CVE lookups* in Settings
  and Watchtower asks the National Vulnerability Database which CVEs affect each
  exact service version nmap identified (its CPE). This is the only feature that
  makes network requests of its own; each one is shown in the Command Console
  and audit log, and results are cached for a week. NVD matches on Ubuntu/Debian
  packages are marked *unverified* and don't count toward the risk score, since
  the distribution may already have backported the fix.

**One-click fixes:** select a finding and use the **Fix** buttons above its details:
- *This machine* (where Watchtower runs): install the security update for the
  affected package, or stop and disable the service on a risky port. The exact
  commands are shown first, run as root after your password, and the output
  includes how to undo it.
- *Another Linux host you administer*: **Run fix on host via SSH** opens a
  terminal running the same commands over your SSH login, or **Copy fix
  commands** to paste yourself.
- *Routers, cameras, printers*: **Open admin page**, then follow "How to fix it".
- **Re-scan to verify** reruns the scan for that host.
Every fix is recorded in the audit log.

**Public exploit** marks CVEs with a ready-made Metasploit module (module names
only, from a built-in list plus your local Metasploit install if present; read
from its files, never run). Those findings get +5 risk, because a public exploit
means low effort for an attacker.

**Export report** (button above, or Tools → Export report…) writes a single
self-contained HTML file: executive summary with what to fix first, scope,
top risks, every finding with remediation and technique explanations,
recent changes, and a methodology appendix listing the commands that were
run. Optionally also a PDF, via WeasyPrint (`sudo apt install weasyprint`).

**Top risks** ranks each device 0-100: 6 × its worst CVSS score, plus
weights for its findings (severity, or the Wi-Fi weakness), plus 1 per open
port. Click a device to filter the list and see everything known about it.
Every finding's details include the CVE data (CWE, dates, affected and fixed
versions, NVD/Ubuntu/Debian links) and the device it was found on. Live NVD lookups (build step 11) will
extend the CVE coverage.
""",
"host_audit": """
### Host Audit
**What it does:** deeper checks on one host from your authorized targets. Hosts
you've scanned appear on the left; you can add another in-scope host by hand.

- **Default credentials** (automatic, nothing sent): matches what nmap learned
  (banners, page titles, hostnames, MAC vendor) against device types known to
  ship with a published default login, such as Raspberry Pi OS pi/raspberry,
  Ubiquiti ubnt/ubnt or Dell iDRAC root/calvin. It shows what matched and why.
  It never tries to log in.
- **TLS audit** (`testssl.sh` or `sslyze`): pick a port; Watchtower suggests the
  ones nmap saw speaking TLS. It checks protocol versions (SSLv2/3, TLS 1.0/1.1),
  weak cipher suites (NULL, anonymous, export, RC4, 3DES), the certificate
  (trust, expiry, host name, key size) and known TLS bugs (Heartbleed, ROBOT,
  CCS injection, ...). testssl.sh is more thorough; SSLyze is faster.
- **SNMP check** (`snmpget`, GET requests only): asks for a few system values
  (description, name, contact, location, uptime) using each community string
  you list (by default the factory `public` and `private`). An answer means that
  string grants read access. Watchtower never sends SET (write) requests.

Results also appear in **Findings** with remediation and count toward the
host's risk score. Every command is shown in the Command Console and audit log.
""",
"changes": """
### What Changed
**What it does:** compares each scan of an authorized network or host with the
previous one: new devices, ports that opened, service versions that changed,
access points that disappeared. The scheduler can repeat scans on a timer so
this becomes continuous monitoring of your own network.

**Why it matters:** an unexpected new port or device is often the first sign
of a misconfiguration or compromise.

**Reading it:** pick a target (or *Wi-Fi nearby*) on the left and two scans to
compare; the newest two are preselected. Levels:
- **alert**: likely needs action. A port opened, a new finding appeared, a
  different device now answers at an address, your network got weaker
  security or WPS was turned back on, or a **new access point is using your
  network's name** (a possible evil twin, unless you just added a mesh node).
- **notice**: worth a look (new host, service or version changed, your
  network not seen).
- **good**: something was fixed: port closed, finding resolved, software updated.
- **info**: background changes (new neighbours' networks, OS guess changed).

**Scheduled scans** re-run a profile against an authorized target hourly to
weekly while Watchtower is open. Tick *Keep running scheduled scans when
Watchtower is closed* to install a systemd **user** timer (no root) that runs
due scans every 15 minutes and sends a desktop notification on alerts.
Schedules skip targets you've removed from the authorized list, and
profiles that need root (e.g. Intense scan) unless nmap has been granted
capabilities.
""",
"web_audit": """
### Web Audit
**What it does:** checks the web interfaces you run (router, NAS, home server,
self-hosted apps) for missing browser protections and known problems. Add a URL
such as `https://nas.lan:5001/`; its host must be in your authorized targets (if
it isn't, Watchtower asks before adding it, and logs that scope change).

- **Check headers** (no external tool): one ordinary GET request, like a
  browser's. It reports whether the site uses HTTPS and the security headers
  browsers rely on: **HSTS** (always use HTTPS), **Content-Security-Policy**
  (limits what scripts can run: the safety net against XSS),
  **X-Frame-Options** / CSP `frame-ancestors` (clickjacking),
  **X-Content-Type-Options: nosniff**, **Referrer-Policy**, and the **Secure**,
  **HttpOnly** and **SameSite** flags of every cookie it sets. Redirects are
  followed only while they stay on authorized hosts. A self-signed certificate
  is reported, then the headers are read anyway.
- **Run nikto**: nikto requests thousands of known paths (default files,
  exposed `.git` / backups / phpinfo, admin pages, outdated server versions).
  Watchtower runs it **without nikto's `auth` plugin**, which would try default
  user names and passwords on login prompts, and **without its denial-of-service
  tests** (`-Plugins "@@DEFAULT;-auth" -Tuning x6`). Nikto doesn't rate its
  results, so Watchtower rates them from the description. It takes a few
  minutes and is noisy in the server's logs; that's expected.

Results go to **Findings** (device = the URL) with exact server settings to fix
each one, count toward the risk score, and appear in the report. Every request
and command is shown in the Command Console and written to the audit log.
""",
"domain_audit": """
### Domain Audit
**What it does:** checks a domain you own the way the rest of the internet sees
it. Add the domain first (Watchtower asks you to confirm you own it, and logs
it). Nothing here is sent to your own servers.

- **Check DNS records** (SPF / DKIM / DMARC, via dnspython): looks up the public
  DNS records that let receiving mail servers reject mail **forged** to look like
  it came from you.
  - **SPF**: which servers may send as your domain. Checked for a single valid
    record, a strict ending (`-all`), and the 10-DNS-lookup limit (includes of
    includes count too).
  - **DKIM**: the public key that verifies your mail's signatures. DNS can't list
    keys, so common selector names are tried; add yours (the `s=` value in the
    DKIM-Signature header of a message you sent). Keys under 2048 bits are flagged.
  - **DMARC**: what receivers should do when SPF and DKIM both fail
    (`p=none` only monitors, `quarantine`/`reject` protect) and where to send reports.
- **Find subdomains** (passive): lists names under your domain that are already
  public in **Certificate Transparency** logs and passive-DNS data sets, using
  **subfinder**, **amass** (only builds that still support `enum -passive`) or
  Watchtower's built-in **crt.sh** query. The names aren't resolved or probed.
  Names that look like admin, dev or backup systems are highlighted: anyone can
  see them, so make sure they aren't reachable unless they should be.

The DNS lookups and third-party queries are network requests you start with a
click; each one is shown in the Command Console and written to the audit log.
""",
"traffic": """
### Traffic Audit
**What it does:** listens to the traffic on one of your network connections
(like Wireshark) or opens a capture file, then explains the security problems
it shows, in plain language, with how to fix each one.

**How to use it**
1. **Capture live traffic:** pick the interface connected to your network and
   how long to listen, then click **Start capture**. While it listens, use your
   devices normally (log in to the router or NAS, check mail, open a file share):
   that's the traffic Watchtower can check. Click **Stop** to finish early.
   The first time, click **Allow capturing…** once so capturing works without
   running Watchtower as root.
2. **…or open a capture file** made with Wireshark, tcpdump or your router.
3. *(Optional)* **Repeat automatically:** saves the capture settings and runs
   them on a schedule. Each run is compared with the previous one in
   **What Changed**, so a device that starts sending passwords unencrypted shows
   up as an alert.
4. Read the results under **What was found**. **Traffic overview** shows who
   talked to whom and which protocols were used. **Open in Wireshark** shows
   every packet.

**What it looks for**
- **Passwords sent without encryption:** FTP, Telnet, POP3, IMAP, SMTP AUTH,
  HTTP Basic logins and HTTP login forms, and SNMP community strings. Watchtower
  sees that a login happened; it never shows or saves the password itself.
- **Risky Windows name lookups:** LLMNR and NetBIOS (NBT-NS) broadcasts, and
  WPAD proxy lookups. Attack tools answer these to steal Windows logins.
- **SMBv1** (the protocol WannaCry used), **old TLS** (SSL 3.0, TLS 1.0/1.1) and
  broken ciphers (RC4, 3DES, export, NULL).
- **UPnP announcements** (SSDP), **mDNS/Bonjour**, and unencrypted DNS.

**Good to know**
- Listening sends nothing to the network. On a switched network or Wi-Fi you
  mostly see this computer's own traffic plus broadcasts from other devices; to
  see everything, capture on the router or a switch mirror port.
- Wi-Fi handshakes are never recorded (the filter `not ether proto 0x888e` is
  always added) and capturing on an interface in monitor mode is refused.
- Capture files can contain anything that crossed the network, including
  unencrypted passwords. Watchtower stores the ones it records in its own data
  folder, readable only by you; **Delete** removes them.
""",
"passwords": """
### Password Tools
Check your own passwords for strength and exposure. Everything here is
local-first; nothing is stored and passwords are never written to the audit log.

**Strength Analyzer** (`zxcvbn`, entirely offline): scores a password 0-4 by
looking for dictionary words, keyboard walks, dates, repeats and reuse of any
context words you supply (your name, email, the site). It shows estimated
time-to-guess under several attack speeds, and a plain-language **NIST SP
800-63B** checklist (length over complexity rules, breach-checked, not an
obvious pattern).

**Breach Check** (HaveIBeenPwned "Pwned Passwords"): tells you how many times a
password has appeared in known breaches — if it has, stop using it.
- **Online** uses *k-anonymity*: only the first 5 hex characters of the
  password's SHA-1 are sent; the service returns a batch of matching suffixes
  and the comparison happens on your machine. The password and its full hash
  never leave the computer. Each request is shown in the Command Console and
  audit log.
- **Offline** needs no network: point it at a sorted Pwned Passwords hash file
  (from the official HIBP downloader) and it binary-searches that.
- **Batch** checks a whole list at once — for example an export from your own
  password manager — and flags every entry seen in a breach.
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
("TKIP vs CCMP (AES)",
 "The ciphers WPA uses to encrypt data. **TKIP** was a 2003 patch that kept WEP's RC4 cipher so old hardware "
 "could be upgraded by firmware. It has known weaknesses and is deprecated. **CCMP** uses AES and is what WPA2 "
 "and WPA3 should use. A router in \"WPA/WPA2 mixed\" or \"TKIP+AES\" mode still offers TKIP."),
("SAE (WPA3-Personal)",
 "Simultaneous Authentication of Equals, also called Dragonfly: WPA3-Personal's password exchange. Each password "
 "guess needs a live exchange with the access point, so recorded traffic can't be cracked offline, and it gives "
 "forward secrecy (learning the password later doesn't decrypt old sessions)."),
("OWE (Enhanced Open)",
 "Opportunistic Wireless Encryption: encryption for networks without a password (cafés, guest Wi-Fi). Each "
 "client gets its own key, which stops passive eavesdropping. It doesn't stop an impostor access point."),
("802.1X / WPA-Enterprise",
 "Instead of one shared passphrase, each user or device authenticates to a RADIUS server (with a password or "
 "a certificate) and gets its own keys. Secure when clients verify the server's certificate."),
("PMF (802.11w)",
 "Protected Management Frames: cryptographically protects Wi-Fi management frames such as disconnect "
 "messages, so they can't be forged to knock devices off the network. Mandatory in WPA3, optional in WPA2."),
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
("k-anonymity (Pwned Passwords)",
 "A way to check a secret against a database without revealing it. Watchtower hashes the password "
 "(SHA-1) locally and sends only the first 5 hex characters of that hash. The API returns every "
 "breached-hash suffix sharing those 5 characters (hundreds of them), and Watchtower finds the match "
 "locally. The server never learns which one you asked about, and never sees the password or its full hash."),
("NIST SP 800-63B",
 "The US digital-identity guideline for passwords. Its modern advice: require length (8+ minimum, longer "
 "is better), screen new passwords against breach lists, and do NOT force arbitrary complexity rules "
 "(mixed case/symbols) or periodic expiry — those push people toward predictable patterns. The Strength "
 "Analyzer turns this into a pass/fail checklist."),
("Security headers (HSTS, CSP, X-Frame-Options)",
 "HTTP response headers that tell the browser to protect a site's users. **HSTS** makes the browser use HTTPS "
 "only, defeating SSL stripping. **Content-Security-Policy** lists where scripts may come from, so injected "
 "script (XSS) doesn't run. **X-Frame-Options** / CSP frame-ancestors stop other sites from framing the page "
 "(clickjacking). **X-Content-Type-Options: nosniff** stops browsers guessing file types. **Referrer-Policy** "
 "limits what URL is sent to other sites."),
("Cookie flags (Secure, HttpOnly, SameSite)",
 "Attributes on a Set-Cookie header. **Secure**: only sent over HTTPS. **HttpOnly**: page scripts can't read "
 "it, so XSS can't steal the session. **SameSite=Lax/Strict**: not sent on requests started by other sites, "
 "which blocks most cross-site request forgery (CSRF)."),
("SPF / DKIM / DMARC",
 "Three DNS records that stop others sending email as your domain. **SPF** lists the servers allowed to send "
 "it. **DKIM** publishes a public key; your mail server signs each message and receivers verify the signature. "
 "**DMARC** tells receivers what to do when a message passes neither (none / quarantine / reject) and where to "
 "send reports. All three are needed for real protection against spoofing."),
("DKIM selector",
 "The name under which a DKIM key is published: selector._domainkey.example.com. A domain can have several "
 "(one per mail service). DNS can't list them, so you find yours in the s= tag of the DKIM-Signature header of "
 "an email you sent."),
("Certificate Transparency (CT)",
 "Public, append-only logs of every certificate trusted CAs issue. They let anyone spot a mis-issued "
 "certificate for their domain, and also reveal every host name you've ever got a certificate for. Passive "
 "subdomain discovery reads them; using a wildcard certificate or an internal CA keeps internal names out."),
("Passive reconnaissance",
 "Collecting information from public third-party sources (CT logs, passive DNS, search engines) without "
 "sending anything to the target's own systems. Domain Audit's subdomain discovery is passive only."),
("Nikto",
 "An open-source web server scanner that requests thousands of known paths and checks for dangerous files, "
 "outdated software and misconfiguration. Watchtower runs it without its default-login plugin and DoS tests."),
("Packet capture (pcap)",
 "A recording of the network packets that crossed an interface, saved as a .pcap or .pcapng file. Wireshark, "
 "tcpdump and Watchtower's Traffic Audit all read and write this format. A capture can contain anything that was "
 "sent unencrypted, so treat the file like a password list."),
("Capture filter (BPF)",
 "A small expression that decides which packets are recorded, e.g. `host 192.168.1.20` or `port 21`. It uses "
 "the Berkeley Packet Filter syntax shared by tcpdump and Wireshark's capture filters."),
("Cleartext protocol",
 "A protocol that sends data, including passwords, without encryption: FTP, Telnet, HTTP, POP3, IMAP, SNMP v1/v2c. "
 "Anyone who can see the traffic can read it. Each has an encrypted replacement (SFTP, SSH, HTTPS, POP3S/IMAPS, "
 "SNMPv3)."),
("LLMNR / NBT-NS",
 "Fallback name lookups Windows broadcasts to the whole local network when DNS has no answer. Any device can "
 "reply, and the asking computer then sends it a login hash. Turning both off is a standard hardening step."),
("SMBv1",
 "The original Windows file-sharing protocol from the 1980s. It has no protection against tampering and was the "
 "way in for WannaCry and NotPetya. Modern systems use SMB 2/3; SMBv1 should be off everywhere."),
("UPnP / SSDP",
 "Universal Plug and Play lets devices find each other (SSDP) and change each other's settings without a "
 "password, for example asking the router to open a port to the internet. Convenient for consoles, risky "
 "because malware can do the same."),
("Backported security fix",
 "Ubuntu and Debian freeze a package's upstream version for the life of a release and apply security fixes as "
 "patches, bumping only the package revision: OpenSSH 8.9p1 on Ubuntu 22.04 went from 3ubuntu0.1 to 3ubuntu0.10 "
 "and beyond. A scanner that only looks at '8.9p1' would call it vulnerable forever. The advisories (USN for "
 "Ubuntu, DSA for Debian) list the first fixed revision, which is what Watchtower compares against."),
("Self-signed certificate",
 "A TLS certificate signed by its own key instead of a trusted certificate authority. The connection is still "
 "encrypted, but the client can't verify who it's talking to, so an impostor's certificate looks the same. "
 "Common on routers, NAS boxes and lab VMs. Fix with Let's Encrypt or your own internal CA."),
("Probable vs confirmed",
 "A **probable** finding is a version match: nmap reported a version known to be vulnerable. Linux distributions "
 "often backport security fixes without changing the version number (Ubuntu's OpenSSH 8.9p1 can be fully "
 "patched), so check the package version. **Confirmed** means an nmap vuln script actively verified the issue."),
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
