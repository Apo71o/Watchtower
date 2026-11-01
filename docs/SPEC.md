# Build Prompt: Local Wi-Fi/Network Security Audit GUI ("Watchtower")

Paste everything below into Claude Code running locally on your own machine.

---

## Context & Ground Rules

I want you to build a local, GUI-based network/Wi-Fi security auditing tool
for my own authorized home lab / CTF practice use, strictly educational. It
wraps already-existing, widely-used security tools (nmap, passive Wi-Fi
recon via `iwlist`/`nmcli`/`airodump-ng`, sslyze/testssl.sh, read-only SNMP
queries) rather than reimplementing attack primitives. This is a **reporting
and advisory tool**: it discovers, fingerprints, and explains risk; it does
not launch attacks, capture credentials, or execute exploits itself.

Hard requirements on behavior:
- The tool only scans networks/interfaces I explicitly select in the GUI.
  No scanning of arbitrary ranges, no auto-discovery that runs without my
  initiating it.
- No attack execution of any kind — no deauth, no handshake/PMKID capture,
  no password cracking orchestration, no WPS/Pixie-Dust attack execution, no
  rogue-AP/evil-twin/captive-portal functionality, no automated login
  attempts against discovered devices. Where a Wi-Fi or host weakness is
  found (weak encryption, WPS enabled, a device fingerprint matching a
  known-default-credential pattern, a vulnerable service version), the tool
  reports the finding and explains the technique and remediation in text —
  it never runs the attack. Actually testing an exploit or cracking a
  password is something I do myself, by hand, with the underlying tools
  directly — that stays outside this app, by design, not as a stretch goal
  to add later.
- Every scan action must display (and log to a local audit log) the exact
  underlying command being run, so nothing happens opaquely.
- Include an "authorization banner" on first launch: a simple acknowledgment
  screen ("I confirm I own this network or have explicit written
  authorization to test it") that must be dismissed before the tool unlocks
  scanning features. Store the acknowledgment locally; don't make it
  annoying on every launch, just first run. This is single-user, local-only
  software with no sharing/distribution — the gate exists because the scope
  boundary (own/authorized networks only) is a legal one, not a UX
  formality, so keep it even though nobody else will ever see this install.
- No telemetry, no network calls except: (a) optional CVE/NVD lookups I
  explicitly enable, (b) nothing else. Fully local-first.

---

## Scope note

This should feel like a serious, broad tool (in the territory of Nessus/
OpenVAS/Kismet on the recon-and-reporting side) — depth comes from
integrating more existing, well-known tools and presenting unified,
well-explained results, not from adding attack capability. Passive recon is
unrestricted (same as Kismet/airodump-ng). Anything that queries a live host
(nmap scan, TLS audit, SNMP read) runs only against hosts/networks flagged
"authorized" in the per-network settings. Nothing in this tool crosses from
reporting into execution.

## What to Build

### 1. Stack
Python 3.11+, PyQt6 for the GUI (or PySide6 — your call), SQLite for local
storage. Package it so it can run via `pipx` on Debian or an installer/
`run.bat` on Windows.

**Cross-platform reality check — read this before building anything:**
Monitor mode (passive AP/client scanning) depends on Linux Wi-Fi driver
capabilities that Windows does not expose to userspace in a reliable,
general way. This is a driver/OS limitation, not something solvable with
better packaging. So:

- **Debian**: full feature set, as designed throughout this doc — this is
  the primary target.
- **Windows**: everything NOT dependent on raw Wi-Fi radio access works
  fine and should be fully supported — nmap scanning, the findings engine,
  TLS audit, SNMP audit, Metasploit module cross-reference, default-creds
  fingerprint detection, risk scoring, history diff, scheduler, reporting.
  The GUI should detect it's running on Windows and gray out the Nearby
  Networks passive-scan tab with a tooltip/help text explaining why, rather
  than attempting a broken or fake implementation. Mention in the Help tab
  that a Debian machine, VM, or a Debian install on spare hardware is
  needed for the Wi-Fi-radio feature.
- Build platform detection (`sys.platform` / `platform.system()`) as a core
  utility early on (part of step 1 in the build order) so every module that
  shells out to a Linux-only tool can check it and fail gracefully with a
  clear message instead of a raw subprocess error.

### 2. Architecture
- `core/nmap_runner.py` — wraps `nmap` via subprocess, parses `-oX` XML
  output into structured Python objects (hosts, ports, services, versions,
  `--script vuln` output if the user opts in).
- `core/wifi_scan.py` — wraps `iwlist`/`nmcli`/`airodump-ng` for nearby AP
  and client enumeration via monitor mode, so it can passively discover APs,
  connected clients (MACs), channels, encryption types, and signal strength
  for networks the machine is NOT associated with/connected to — this is
  standard passive 802.11 recon (what airodump-ng already does) and doesn't
  require joining a network. Needs to detect if the selected interface
  supports monitor mode and tell the user clearly if it doesn't, rather than
  failing silently. This module is read-only: it listens, it never
  transmits (no deauth frames, no probe/association attempts).
- `core/findings_engine.py` — takes nmap results (service name + version) and
  matches them against a local vulnerability dataset. Two options, pick
  whichever is simpler to ship:
  (a) bundle a periodically-refreshed local cache of NVD CVE data (via the
      NVD REST API, rate-limited, cached to SQLite), or
  (b) integrate `nuclei` as a subprocess if installed, parsing its JSON
      output.
  Each finding should normalize to: `{service, version, cve_id, cvss_score,
  severity, description, remediation}`. Remediation text is the point of
  this module — always populate it, e.g. "upgrade to X", "disable legacy
  protocol Y", "WPA2-only AP found → recommend WPA3 or 14+ char
  high-entropy PSK".
- `core/wep_wpa_advisor.py` — for Wi-Fi-specific findings (open network, WEP,
  WPA1, WPA2 with weak-looking PSK heuristics, WPS enabled), produce findings
  with remediation guidance. This is advisory only: for a WPA2 PSK network,
  for example, the finding explains in text that handshake-capture +
  offline dictionary attack is the relevant technique and why the network is
  exposed to it, but the app does not run or orchestrate that attack in any
  way — no capture, no cracking, no stage-gated "attack helper." If I want
  to actually test that, I run `aircrack-ng`/`hcxdumptool`/`hashcat` myself,
  outside this app.
- `gui/` — PyQt6 main window with tabs: "Interfaces", "Nearby Networks",
  "Scan a Target", "Findings", "Audit Log", "Settings".
- `storage/audit_log.py` — append-only local SQLite log of every command run,
  timestamp, and user confirmation.

### Additional modules (build these after the core pipeline works end to end)

- `core/exploit_xref.py` — cross-reference nmap service/version fingerprints
  against the Metasploit Framework's local module database (just reads
  `msfdb`/the modules folder structure, or shells out to
  `msfconsole -q -x "search ...". -x exit` and parses output) to surface
  "known module: exploit/unix/ftp/vsftpd_234_backdoor" as a finding field.
  This only ever reports a module name/description — it does not launch
  Metasploit or fire anything.
- `core/default_creds.py` — local table (bundle a small curated JSON) of
  known default credentials per device fingerprint (router/camera/printer/
  IoT vendor strings from nmap banner/service detection). This module only
  ever *detects and reports* — "this device's banner matches model X, which
  ships with default credentials admin/admin; change them." It never
  attempts a login itself.
- `core/tls_audit.py` — wraps `testssl.sh` or the `sslyze` Python library
  against any HTTPS/TLS service nmap found: weak ciphers, expired/self-
  signed certs, protocol downgrade issues (SSLv3/TLS1.0 still enabled).
- `core/snmp_audit.py` — read-only SNMP query (`snmpwalk`/`snmpget` with
  GET operations only) against authorized hosts to check whether common
  community strings (public/private/etc.) grant read access, flagging it
  as a finding if so. Read-only; no SET operations, no attempt to pivot.
- `core/history_diff.py` — stores each scan's results keyed by
  BSSID/host+timestamp, computes a diff against the previous scan of the
  same authorized network (new device, changed service version, newly
  opened port, AP that disappeared) for the "What Changed" view.
- `core/risk_scoring.py` — combines CVSS score + default-creds fingerprint
  hit + encryption weakness + open-port count into one per-device risk score
  (0-100) for a prioritized "Top Risks" view instead of a flat findings list.
- `core/attck_mapping.py` — small bundled lookup table mapping common
  finding types (weak Wi-Fi encryption, default creds, outdated service,
  open SNMP, etc.) to MITRE ATT&CK technique IDs, shown as a tag on each
  finding.
- `core/scheduler.py` — cron-style recurring re-scan of authorized networks/
  hosts, feeding `history_diff` automatically; surfaces a "continuous
  monitoring" view of your own network over time.

### 3. GUI Flow
1. Launch → authorization acknowledgment screen (first run only).
2. "Interfaces" tab: list wireless interfaces, show monitor-mode capability.
3. "Nearby Networks" tab: scan button → table of SSID/BSSID/channel/
   encryption/signal for every AP in range (passive, no association needed).
   Each row has an "Authorized (mine / written permission)" checkbox the
   user sets per-network — persisted in local SQLite. Only networks flagged
   authorized unlock the "Investigate" button (nmap against hosts on that
   AP). Unauthorized rows stay visible (that's legitimate passive recon) but
   inert beyond the basic fields already shown.
4. "Scan a Target" tab: run nmap against a selected host/IP on an authorized
   network only (not the whole subnet by default — require explicit target
   entry or a "scan all hosts I discovered via ARP on this AP" opt-in).
5. "Findings" tab: table of normalized findings with severity color-coding
   and a risk score column, expandable rows showing CVE detail + Metasploit
   module name (if any) + default-creds fingerprint result (if any) + MITRE
   ATT&CK tag + remediation text + (for Wi-Fi findings) plain-text
   explanation of the relevant attack technique and how to defend against
   it — explanation only, no "run it" button anywhere in this tool.
6. "Host Audit" tab: per authorized host, TLS audit results, SNMP audit
   results, default-creds fingerprint results.
7. "What Changed" tab: history diff view across scans of the same
   authorized network/host, plus the scheduler config for recurring scans.
8. "Audit Log" tab: read-only view of everything executed, exportable to
   CSV/JSON.
9. "Help" tab: see "In-App Help & Explanations" below — this is not an
   afterthought, build it as a first-class tab.
10. "Settings": NVD API key (optional), theme, scheduler config.

## In-App Help & Explanations

Every tab needs a persistent "What is this?" panel (collapsible sidebar or
a `(?)` icon opening a short explainer), written in plain language, for:
- what the feature does and which underlying tool it wraps
- why it matters (what weakness it's checking for)
- how to interpret the result
- for Wi-Fi/exploit-technique findings: explain the attack technique in
  enough detail that reading it is a learning exercise, in plain text —
  this is explanatory content, not a command runner.

Also build a "Glossary" page inside the Help tab covering terms used
throughout the UI (WPA2/WPA3, PMKID, handshake, WPS, PSK, CVSS, CVE, SNMP
community string, TLS cipher suite, MITRE ATT&CK, risk score) in a few
sentences each. This is meant to double as a learning tool, so don't
skimp on this — treat the explanatory text as a core deliverable, same
priority as the scanning code.

### 4. Reporting
Add a "Export Report" button that renders findings + remediations into a
clean HTML (and optionally PDF via `weasyprint`) report — like a mini pentest
report, useful for write-ups in home-lab/CTF documentation.

### Installation & Packaging

This tool is a GUI orchestrator around a stack of external security tools —
it can't (and shouldn't try to) reimplement nmap, sslyze, etc. itself.
"Clean install" here means: one install step for the Python app, and a
dependency-checker that handles the system tools, not a single binary that
bundles compiled copies of nmap/etc. inside it.

Design it like this:

1. **Packaging the app itself.**
   - Debian: ship as a pipx-installable package (`pipx install watchtower`
     from a local wheel, or a `./install.sh` that creates a venv, installs
     the Python deps, and drops a desktop launcher `.desktop` file).
   - Windows: ship as a PyInstaller-built `.exe` (or a `./install.ps1` that
     creates a venv + desktop shortcut, if you'd rather avoid PyInstaller's
     build complexity) — either way, one installer, no manual Python setup
     required on the Windows side.
   Both are a normal clean install — one step, isolated environment, no
   system Python pollution.

2. **External tool dependencies — do NOT auto-install silently.** On first
   launch, run a "Dependency Check" screen that:
   - On Debian: detects which of nmap, airodump-ng (passive recon only),
     testssl.sh or sslyze, net-snmp (snmpwalk/snmpget), and (optionally)
     Metasploit are present, with version numbers. For each missing tool,
     shows the exact `apt install ...` command and a short note on what
     it's used for.
   - On Windows: detects nmap (has an official Windows installer) and
     optionally Nmap's `Npcap` driver dependency. Points to the official
     download page for anything that doesn't have a clean package-manager
     story on Windows (`winget`/Chocolatey where available, e.g.
     `winget install Insecure.Nmap`).
   - Has a "Run these install commands for me" button that, when clicked,
     shows the full command list and asks for explicit confirmation before
     shelling out with sudo — never silently escalates privileges.
   - Lets the app run in a degraded mode where features whose backing tool
     is missing are visibly disabled (grayed out with a tooltip: "requires
     sslyze, not installed") rather than crashing.

3. **Elevated-privilege handling.**
   - Debian: nmap SYN scans and airodump-ng need elevated privileges or
     specific capabilities. Prefer setting Linux capabilities
     (`setcap cap_net_raw,cap_net_admin+eip`) on the specific binaries over
     running the whole GUI as root — offer this as a one-time confirmed
     setup step from the dependency-check screen.
   - Windows: nmap needs Npcap installed (its own installer handles the
     driver) and some scan types need the app run elevated. Detect this and
     prompt to relaunch as administrator only when a specific action needs
     it, rather than requiring elevation for the whole app up front.

4. **requirements.txt** for the Python side should stay small: PyQt6 (or
   PySide6), requests (for NVD lookups), optionally sslyze — everything else
   is a subprocess call to a system binary, not a Python dependency.

5. Document all of this in a top-level `INSTALL.md` and surface the same
   content in the in-app "Help → Setup" page.

### Build Order (do this incrementally, show me working output at each step)
1. Project skeleton, platform-detection utility, dependency-check screen,
   authorization gate screen, SQLite storage, audit log.
2. Interface detection + nearby network scan (read-only, passive),
   per-network authorized checkbox + persistence.
3. Nmap integration against a manually-entered target IP (authorized only),
   XML parsing, results table (incl. `--script vuln` opt-in).
4. Findings engine with a small bundled sample vuln dataset first (don't
   wire up live NVD calls until the UI around it works), remediation text,
   risk scoring, MITRE ATT&CK tagging.
5. Wi-Fi-specific advisor findings (encryption type, WPS, open network
   checks) — advisory text only.
6. Host Audit tab: default-creds fingerprint detection (reporting only),
   TLS audit, SNMP read-only audit — all authorized-host-only.
7. Metasploit module cross-reference in findings (reports module name only).
8. History diff ("What Changed") + scheduler for recurring scans.
9. Audit log viewer + HTML/PDF report export.
10. In-App Help/Glossary content for every tab (can be written incrementally
    alongside each feature rather than all at the end).
11. Wire up live NVD lookups behind a settings toggle.

---

## Deliverable format
Normal Claude Code project: create the repo structure, write the code,
install deps into a venv, and show me how to run it. Ask me before touching
any system Wi-Fi interface settings or installing anything that needs sudo.
