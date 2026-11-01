# Watchtower: notes for Claude Code

Local PySide6 GUI that wraps existing security tools for **authorized**
home-lab auditing and **reports** findings with remediation. The full,
authoritative requirements are in `docs/SPEC.md`; read the relevant section
before starting a build step. Where the user has since changed a requirement,
the "User decisions" section below wins over the spec.

## User decisions (override docs/SPEC.md)

- 2026-11-01: **No startup authorization/legal warning.** The user is the sole user
  and asked for it to be removed. Don't re-add a first-run acknowledgment screen.
  (Per-network "Authorized" flags and the authorized-target list remain; they are
  the user's own scope list, not a warning.)
- 2026-11-01: **Wrapped tools keep their full functionality.** Watchtower never
  modifies or restricts the installed tools (users can run aircrack-ng, nmap etc.
  directly at full capability), and the Scan tab accepts any nmap option via Extra
  arguments. The only checks are scope checks on targets.

- 2026-11-01: **One-click remediation** is wanted (core/remediation.py + Fix bar in Findings):
  fixes (security updates, disabling a risky service) for this machine via RunPlanDialog, for
  remote Linux hosts via the user's own SSH in a terminal, otherwise open the admin page. This is
  defensive remediation, not attack execution; it never logs in with discovered/default creds.

## Non-negotiables (check every change against these)

1. **No attack execution, ever.** No deauth, handshake/PMKID capture, cracking
   orchestration, WPS/Pixie-Dust, rogue AP/evil twin/captive portal, or login
   attempts (including default-credential *tries*). Weaknesses are reported and
   explained in text. There is no "run it" button anywhere. Do not add one as a
   stretch goal. If a request would cross this line, say so and stop.
2. **Scope:** passive listening is unrestricted. Anything that sends packets to a
   host (nmap, TLS, SNMP) only runs against networks/hosts flagged authorized in
   SQLite, and only when the user starts it. Never scan a whole subnet unless the
   user explicitly opts in.
3. **Transparency:** every external process goes through
   `watchtower.core.runner.CommandRunner.run()` (argv list, never `shell=True`).
   It shows the exact command in the Command Console and writes it to the audit log.
4. **No network calls** except: NVD lookups behind the Settings toggle (off by default); and the
   HaveIBeenPwned "Pwned Passwords" range API, which is user-initiated (clicking Check) and sends
   only the first 5 hex chars of a password's SHA-1 (k-anonymity) — the password and full hash never
   leave the machine. Breach checking also has a fully offline mode (local HIBP hash file). Password
   strength analysis (zxcvbn) is entirely local. Domain Audit (user-initiated, owned domains only):
   public DNS TXT/MX lookups via the system resolver, and passive subdomain sources (subfinder/amass
   query third-party data sets; crt.sh is one HTTPS GET). Web Audit's header check is an HTTP GET to
   an authorized URL (same scope rule as nmap). All of these are logged as `Event.NETWORK_REQUEST`
   (via `AppContext.log_network`) or go through CommandRunner. Traffic Audit makes no network calls
   (dumpcap listens passively; tshark analyzes locally).
5. **Ask the user** before touching system Wi-Fi interface settings (monitor
   mode) or running anything with sudo/pkexec. Show the command, then confirm.
6. **Read-only SNMP:** GET/WALK only, never SET.

## Layout

```
watchtower/
  app.py                 entry point (GUI, or --check-deps for a terminal report)
  core/platform_utils.py OS detection, require_linux(), data_dir(), WIFI_UNSUPPORTED_REASON
  core/runner.py         CommandRunner: the only way to run subprocesses
  core/deps.py           TOOLS table, find_binary() (also searches /usr/sbin etc.), check_all(),
                         DependencyState (feature gating), install_plan()/setcap_plan() -> Plan of Steps,
                         elevate() (pkexec), terminal_argv() (sudo-in-a-terminal fallback)
  core/targets.py        parse_target() / in_scope(): IPs, CIDRs, nmap ranges, hostnames
  core/interfaces.py     iw dev / iw list / ip -j addr parsing, set_mode_plan() (monitor <-> managed)
  core/wifi_scan.py      nmcli / iw scan / iwlist / airodump-ng CSV parsers, managed_scan(), airodump_argv()
  core/nmap_runner.py    PROFILES, build() (scope-checks every target incl. extra args), parse_xml()
  core/targets.py        also parse_url()/url_in_scope() (Web Audit) and normalize_domain()/domain_covered()
  core/header_audit.py   fetch() (manual in-scope redirects, unverified retry on TLS error), analyze() -> HeaderIssue
  core/web_scanner.py    nikto argv (-Plugins "@@DEFAULT;-auth" -Tuning x6), XML parser, description-based rating
  core/domain_audit.py   SPF/DKIM/DMARC: pure analysis over a resolve(name, rdtype) callable; dns_resolver() (dnspython)
  core/subdomain_enum.py passive only: subfinder / amass enum -passive (refused if absent) / crt.sh; parsers
  core/traffic_audit.py  dumpcap capture argv (EAPOL always excluded, monitor-mode refused), tshark FIELDS ->
                         parse_fields() -> Event (names only, never secrets) -> findings(); stats; diff_captures()
  core/traffic_hosts.py  per-device rundown (rundown(), host_markdown(), host_brief()), opt-in ping_scan() of an
                         authorized <= /22 local network (nmap -sn, stored as a normal scan)
  storage/preferences.py PREFS registry of user options (section, label, kind, default, tooltip, choices);
                         get() falls back to the default for missing/invalid values; reset_all()
  gui/ui.py              follow(ctx, KEY, apply): apply a preference now + on bus.settings_changed; set_combo()
  gui/ui.py              tip()/restore_tip(): every control's tooltip (enforced by test_every_control_explains_itself)
  storage/db.py          SQLite + MIGRATIONS list (append new entries, never edit old ones)
  storage/audit_log.py   append-only log (DB triggers block UPDATE/DELETE); Event enum
  storage/settings.py    JSON key/value settings + well-known keys
  storage/scope.py       NetworkStore (seen APs/stations + authorized flag), TargetStore, ScanStore
  help/content.py        TAB_HELP (per-tab "What is this?") + GLOSSARY
  help/INSTALL.md        packaged copy of /INSTALL.md (test enforces they match)
  gui/context.py         AppContext (db, settings, audit, runner, deps, platform, bus)
  gui/main_window.py     tabs + Command Console dock + first-run flow
  gui/help_panel.py      TabPage = content + collapsible help panel
  gui/worker.py          run_in_background(): keep subprocesses off the GUI thread
  gui/run_dialog.py      RunPlanDialog: confirm -> run a Plan with live output; pkexec, else terminal
  gui/dependency_check.py, gui/tabs/*.py (all tabs implemented; placeholder.py was removed)
tests/                   pytest; GUI tests run with QT_QPA_PLATFORM=offscreen; tool output in tests/fixtures/
docs/SPEC.md             original build prompt (authoritative requirements)
```

## Conventions

- `core/` and `storage/` must not import Qt; they are unit-tested headless.
- Look up binaries with `deps.find_binary()` / `ctx.deps.path(key)` and put the absolute path in
  argv. Never rely on PATH: Debian's non-root PATH has no /usr/sbin, where iw/airodump-ng live.
- Anything needing root: build a `deps.Plan` and show it in `RunPlanDialog`, or wrap with
  `deps.elevate()` after a confirmation. Never call sudo directly.
- Linux-only modules call `require_linux("Feature name")` and the GUI shows the
  `PlatformUnsupported` message. Missing tools: gate with
  `ctx.deps.available(key)` and use `ctx.deps.reason(key)` as the tooltip.
- New tool → add a `Tool(...)` entry in `core/deps.py` (apt package, winget id, purpose).
- Scope changes (marking a network/host authorized) → `Event.SCOPE_CHANGE` audit entry.
- Write the tab's `TAB_HELP` text and any new glossary terms in the same change
  as the feature. Explanatory text is a core deliverable.
- When replacing a `PlaceholderTab`, keep the help key and tab order (the GUI test checks the labels).
- After editing `INSTALL.md`: `cp INSTALL.md watchtower/help/INSTALL.md`.
- **GUI clarity (user requirement, 2026-11-01):** the GUI must be clear and easy to use for every feature.
  Every button/checkbox/choice/input gets `gui.ui.tip(widget, "what it does")`; gates that disable a control
  call `restore_tip(widget, "" if ok else "why it's disabled")` instead of blanking the tooltip. Tests
  `test_every_control_explains_itself` / `test_dialogs_explain_their_controls` fail on any control without
  one. Also: empty states say what to do next, results say what was found + why it matters + how to fix,
  plain words over jargon (add a glossary entry when a term is unavoidable), and Help -> Overview's
  "Where to start" table must list every tab's main use (WHERE_TO_START in gui/tabs/help_tab.py).
- Before committing: `.venv/bin/ruff check watchtower tests && .venv/bin/pytest -q`.

## Known gaps / notes for later steps

- WPS status comes from `iw dev <if> scan` (root; "WPS:" section) or legacy `iwlist` (vendor IE
  00:50:F2:04). nmcli and airodump-ng CSV don't report it (shown as "?").
- The user's machine runs Ubuntu 26.04: wireless-tools (iwlist) is no longer packaged there.
  `deps.check_all()` asks `apt-cache policy` which packages exist and the installer skips the rest.
  Prefer iw/nmcli over iwlist in new code.
- Scans are stored as raw nmap XML in `scans.raw_output`; findings are computed on demand from the
  newest result per host (`findings_engine.latest_hosts`). Step 8 (history diff) can compare
  consecutive scans of the same host the same way.
- Findings aren't persisted; `assessment.assess()` recomputes them. Step 6 (default creds, TLS, SNMP)
  should add its results as Finding objects into `assess()` and set Finding.weight (default-creds
  hit: +15 per the spec) so risk scoring picks them up.
- Dataset version matches: `findings_engine.distro_patch_status()` reads the distro + package revision
  from the banner and compares it with `distro_fixes` (USN/DSA fixed revisions) in data/vulns.json:
  patched -> severity Info, Finding.patched=True, excluded from risk score; vulnerable; unknown
  (distro marker but no revision/advisory); upstream. An NSE confirmation of the same
  device|port|CVE merges into one "confirmed" finding and un-patches it. Only add distro_fixes
  entries you can cite from the advisory.
- Findings tab details = finding_markdown() (+ "Is it fixed on this system?", CVE details) +
  device_markdown() (network/host data, open ports, risk-score breakdown, other findings). Selecting
  a device in Top Risks shows device_markdown even when it has no findings.
- Shutdown order matters (app.py): runner.terminate_all() -> worker.shutdown() (sets a closing flag
  so finished jobs don't emit into dead Qt objects) -> delete window -> close DB; os._exit only if a
  job is stuck. GUI tests' ctx fixture mirrors this and deletes top-level widgets; widgets left
  alive past QApplication segfault the interpreter at exit. Don't monkeypatch attributes on PySide
  classes in tests; patch the name in the module under test instead.
- TLS/SNMP fixtures in tests/fixtures are real tool output (testssl.sh 3.2rc3, SSLyze 6, net-snmp)
  captured against local test servers; tests/test_gui.py also runs both audits end-to-end against
  openssl s_server / snmpd when those binaries exist.
- Remediation: the "stop the service on port X" script was run for real against a non-systemd
  listener (it refuses, correctly); disabling an actual systemd unit is untested here (no systemd
  in the cloud container), so verify on the user's machine. The local apt upgrade path was run
  for real (snmpd).
- Scheduler: GUI ticks every 60 s unless settings SCHED_BACKGROUND is on (then the systemd timer owns
  runs, to avoid double scans). Scheduled scans never prompt for root: they're skipped with a
  status instead. The systemd timer install path is untested here (no systemd in the container).
- NVD: the cloud container's network policy blocked services.nvd.nist.gov, so the client was built
  from the documented API 2.0 schema and tested against tests/fixtures/nvd_api2_sample.json, which is
  HAND-WRITTEN (see its _about). First thing to verify locally: enable the toggle, scan a host with
  -sV, click "Look up CVEs on NVD"; then replace the sample with a captured response.
- Monitor-mode and airodump-ng paths are unit-tested against fixtures only; the cloud container
  has no Wi-Fi hardware. Verify on real hardware locally.

## Build progress (update this when a step lands)

- [x] 1. Skeleton, platform detection, dependency check screen, authorization gate,
        SQLite storage, audit log (+ viewer/export, command console, help panels, glossary)
- [x] 2. Interface detection + monitor/managed switching, nearby network scan (nmcli/iw/iwlist,
        airodump-ng listen with client stations), per-network Authorized checkbox, Investigate
- [x] 3. nmap with profiles/options/free-form args, authorized-target list with scope checks,
        live output, cancel, XML parsing, results tree, scan history, --privileged / pkexec /
        Windows relaunch-as-admin. Profiles use nmap's own names (Zenmap's standard profiles) plus
        a Scan type picker with nmap's technique names (-sS, -sT, -sU, -sX, ...), each explained
- [x] 4. Findings engine (core/findings_engine.py: data/vulns.json version matches, exposure RULES,
        NSE "VULNERABLE" parsing), core/risk_scoring.py, core/attck_mapping.py, core/assessment.py
        (shared by the Findings tab and the future report), Findings tab with Top Risks + details
- [x] 5. Wi-Fi advisor (core/wep_wpa_advisor.py): open/OWE/WEP/WPA1-TKIP/WPA2-PSK/transition/
        Enterprise/WPS/default SSID/hidden SSID, each with technique explanation + remediation
- [x] 6. Host Audit tab: core/default_creds.py + data/default_creds.json (fingerprint match only),
        core/tls_audit.py (testssl.sh --jsonfile / sslyze --json_out -> TlsIssue), core/snmp_audit.py
        (snmpget GET of system-group OIDs), host_audits table (migration 3), results feed assess()
- [x] 6b. One-click remediation (core/remediation.py): local apt --only-upgrade / stop the systemd
        unit on a port (protected units refused), SSH-in-terminal or copy for remote hosts,
        open admin page (gateway for Wi-Fi), re-scan to verify; Event.REMEDIATION in audit log
- [x] 7. core/exploit_xref.py: bundled CVE->module list + index of local Metasploit module files
        (reads 'References'/'Name'/Rank from .rb, cached in data_dir/msf_index.json; never runs msf);
        Finding.exploits, +5 weight (assessment.EXPLOIT_WEIGHT), "Public exploit" column + details
- [x] 8. core/history_diff.py (host/scan/Wi-Fi diffs incl. new/resolved findings, evil-twin alert),
        core/scheduler.py + schedules table (migration 4), wifi_snapshots/observations recorded by
        NetworkStore.record(), What Changed tab (compare any two scans; schedules; tray notify),
        headless `watchtower --run-scheduled` + optional systemd --user timer (no root)
- [x] 9. core/report.py (self-contained HTML; all untrusted text html-escaped, incl. SSIDs and NSE output;
        tiny **bold**/`code` markdown), gui/report_export.py (Findings "Export report…" + Tools menu),
        PDF via `python -m weasyprint` or the weasyprint CLI (tested for real with WeasyPrint 61)
- [x] 10. Help/glossary content: written alongside each step (keep doing so for new features)
- [x] 11. core/nvd.py (NVD CVE API 2.0 via virtualMatchString=<CPE 2.3 from nmap>, paging, 6.5 s/0.7 s
        throttle without/with apiKey, 403/429 handling), NvdCache table (migration 5, 7-day TTL),
        AppContext.nvd_lookup() logs every request as Event.NETWORK_REQUEST + Command Console;
        Findings "Look up CVEs on NVD" (+ automatic after scans) only when Settings toggle is on

## Housekeeping done (2026-11-01, post step 11)

- LICENSE (MIT), .github/workflows/tests.yml (ruff + pytest on 3.11/3.12/3.13).
- Data retention: settings RETENTION_DAYS, storage.scope.Maintenance.prune()/vacuum()/db_size_bytes();
  pruned on startup (app.py) and from Settings "Clean up now". Never prunes audit_log or scope.
- App icon watchtower/data/watchtower.svg (shield + signal arcs), set as window icon and shipped by
  install.sh to ~/.local/share/icons + referenced from the .desktop (Icon=@ICON@).

## Phase 2 (password / web / email-domain modules) — docs/SPEC-phase2 in chat

Same rules: authorized/own targets only, ownership gate for new target types, every command shown
+ logged, no network calls except opt-in (NVD, HIBP k-anonymity). Build order: 1 hash cracker,
2 pwned+strength, 3 header audit, 4 nikto/zap, 5 SPF/DKIM/DMARC, 6 subdomain enum (passive),
7 wire into findings/risk/report.

- [x] P2-cores: core/password_strength.py (zxcvbn + NIST 800-63B checklist; local; basic-entropy
      fallback), core/pwned_check.py (HIBP range API k-anonymity — sends only the 5-char SHA-1
      prefix; offline binary-search over a sorted HASH:COUNT file — the search was subtle, see the
      preceding-byte alignment fix + property test), core/hash_cracker.py (hashcat/john dictionary
      recovery of OWN hashes/files; *2john extractors; parse results from the potfile, robust across
      versions). deps.py: hashcat/john/zxcvbn/nikto entries. 14 tests in tests/test_passwords.py,
      incl. a real hashcat MD5 crack and a brute-force property test of the offline search.
- [x] P2-1 GUI (partial): "Password Tools" tab (gui/tabs/password_tab.py) with TWO sub-panels:
      Strength Analyzer (zxcvbn + NIST checklist, live, local) and Breach Check (HIBP k-anonymity via
      AppContext.pwned_online, logged as NETWORK_REQUEST; offline file mode; single + batch).
      Tab sits before Audit Log. Help + glossary (k-anonymity, NIST 800-63B) added. 3 GUI tests.
- [ ] P2-1 DEFERRED: the hash-recovery panel. The safety classifier repeatedly flags any
      hash-cracking UI (even a "show the command, don't run it" generator), which forces a model
      downgrade mid-response. Per the user: SKIP for now, finish the rest, and add this panel later
      on Opus 4.8. hash_cracker.py core is built + tested; a panel would just call build()/show_argv()
      and display/copy the command (no in-app execution).
- [x] P2-3/4 Web Audit tab (gui/tabs/web_audit_tab.py, after Host Audit): URL list; a URL is in scope when
      its host is an authorized target (adding an out-of-scope URL asks, then TargetStore.add -> SCOPE_CHANGE).
      core/header_audit.py (requests GET, allow_redirects=False, follows redirects only to in-scope hosts,
      keeps repeated Set-Cookie apart via resp.raw.headers; HSTS/CSP/framing/nosniff/Referrer-Policy/cookie
      flags/version disclosure). core/web_scanner.py wraps nikto with `-Plugins "@@DEFAULT;-auth"` (nikto's
      auth plugin TRIES DEFAULT LOGINS: non-negotiable #1) and `-Tuning x6` (no DoS tests); XML output (2.1.5
      has no JSON). ZAP was not added.
- [x] P2-5/6 Domain Audit tab (gui/tabs/domain_audit_tab.py): owned_domains table (migration 6) +
      OwnedDomainStore (covers subdomains; SCOPE_CHANGE on add/remove, confirm dialog). core/domain_audit.py:
      SPF (single record, syntax, +all/?all/~all, ptr, recursive 10-lookup count, broken includes), DMARC
      (p, pct, sp, rua), DKIM (common selectors + user's; RSA size from SPKI/PKCS#1 DER, revoked, t=y), null
      MX. core/subdomain_enum.py: subfinder -json / amass enum -passive (checks `amass enum -h` first) /
      built-in crt.sh; names are never resolved or probed; "sensitive-looking" names -> Low finding.
- [x] P2-7 wiring: results stored in host_audits (kind headers/nikto with host = normalized URL; kind
      email/subdomains with host = domain); assessment.audit_findings() turns them into Findings
      (kind web/email/subdomain), DeviceRisk.kind web/domain (KIND_LABEL), Assessment.web/.domains +
      scope_summary(), Findings device pane, report (Type column, "Owned domains" in Scope, network requests
      in Methodology). remediation.fixes_for() returns no one-click action for these kinds (config/DNS
      changes; the finding's "How to fix it" has exact settings). HostAuditTab filters to HOST_KINDS.
      Help + glossary added; tests in tests/test_web_domain.py (+2 GUI tests).
- Web/Domain verification notes: tests/fixtures/headers_*.txt and nikto_2.1.5.xml are REAL captures
  (curl / nikto 2.1.5 against local test servers). dns_records.json, subfinder.jsonl, amass_v4.txt and
  crtsh.json are HAND-WRITTEN (container DNS answers everything empty, subfinder install was blocked,
  the container proxy returns 403 for crt.sh); dns_resolver() itself is tested against a local dnspython-built UDP server. First
  things to verify locally: Domain Audit on a real domain you own; crt.sh and subfinder output; whether your
  amass build still has `enum -passive`; a nikto 2.5 run (its XML layout was hand-written in the test).
  Ubuntu's nikto 2.1.5 prints a bogus "ERROR: Host maximum execution time ... reached" at start with any
  -maxtime but scans normally. The cloud container strips /usr/share/doc, so nikto's DTD was missing there.
- [x] Traffic Audit tab (gui/tabs/traffic_tab.py, after Domain Audit; user-requested 2026-11-01): live capture
      (dumpcap; filter always ANDed with `not ether proto 0x888e`; refused on monitor-mode interfaces; files in
      data_dir/captures, 0600, "owned") or open a pcap (never copied/deleted). tshark fields pass keeps only command/
      scheme NAMES (FTP USER/PASS, HTTP Basic, form field names, IMAP LOGIN, SMTP AUTH), masks SNMP communities;
      telnet.data/ftp args/smtp params are deliberately not extracted; CommandRunner logs commands, not output.
      Findings (kind "traffic", device = IP so they merge with nmap hosts): cleartext logins (High), SNMP (High if
      default community), SMBv1, LLMNR/NBT-NS + WPAD (Medium), mDNS/plain DNS (Info), UPnP NOTIFY (Low), server-chosen
      old TLS / broken cipher, client max TLS < 1.2. captures + capture_schedules (migration 7); assess(captures=
      CaptureStore.latest_per_source()); scheduler.run_capture_schedule() (run_due with the capture stores, GUI tick
      + headless); What Changed lists "Traffic on <iface>" sources and diffs them. "Allow capturing…" = setcap plan
      on dumpcap (Tool needs_raw_sockets). Fixture traffic_lab.pcapng is a REAL loopback capture of generated lab
      traffic (fake 's3cret-*' passwords); traffic_fields.tsv/traffic_stats.txt are tshark 4.2.2 output.
      tshark NEVER opens the capture path itself: analyze_pcap() pipes the file in (`tshark -r -`, via
      CommandRunner.run(stdin_file=...), logged as `... -r - < path`). Reason: on the user's Ubuntu 26.04 tshark
      failed with "You don't have permission to read the file ~/.local/share/watchtower/captures/..." although
      dumpcap had just written it (AppArmor confines Wireshark's tools to certain paths; passing an open fd
      wouldn't help, AppArmor revalidates inherited fds). Capture length comes from `-z io,stat,0` (capinfos
      can't read stdin). Tab has "Analyze again" for captures whose analysis failed. This
      OpenSSL had no 3DES, so weak-cipher detection is unit-tested with synthetic rows. Verify locally: capture on
      your real LAN/Wi-Fi interface without root after "Allow capturing…", and Open in Wireshark.
- [x] Network rundown (user request 2026-11-01: "a rundown of each ip address on the network, overview of all its
      requests and traffic"): analyze_pcap() now also runs tshark endpoints/conv,tcp/conv,udp (CaptureStats.endpoints,
      .flows), an activity pass (ACTIVITY_FIELDS with `-N m` for offline MAC-maker names: DHCP hostname/vendor class,
      ARP/IP MAC<->IP pairs (only for LAN addresses: a router's MAC carries the internet), mDNS names, DNS queries,
      TLS SNI, HTTP method+host+path with query strings DROPPED) and the first-packet time; stats.local_nets = the
      interface's networks for live captures (private ranges otherwise; note Python's is_private counts TEST-NETs, so
      ta.is_lan uses an explicit RFC1918/CGNAT/ULA list). Traffic Audit "Devices" results tab (DevicesView: filter
      local/outside/all, sortable table, host_markdown detail, "Scan this device…" -> request_scan if authorized),
      Findings device pane "Traffic seen", report "Devices seen in network traffic". Opt-in "Also find quiet
      devices" = nmap ping scan after the capture, only if the interface network is authorized and <= /22.
      Fixture traffic_lan.pcapng: REAL capture on a bridge between Linux network namespaces (router, Raspberry
      Pi MAC, Apple MAC, TEST-NET "internet" server) with DHCP/ARP/DNS/TLS/HTTP/FTP/Telnet/SSDP/mDNS/LLMNR.
- [x] Settings & customization (user request 2026-11-01): storage/preferences.py registry; Settings tab builds its
      controls from it (scrollable, grouped by section, "Reset these options to defaults"), saves immediately and
      emits bus.settings_changed(key) ("*" after reset). Applied live via gui.ui.follow(): text size
      (theme.apply_font_size), help panels open, Command Console (kept in sync with View menu, Ctrl+`), start tab
      (incl. last used, remembered in ui.last_tab), desktop notifications, scan profile/OS detection, schedule
      interval, Traffic Audit length/interface/quiet-device default, nikto/subdomain limits, DKIM selectors, Findings
      severity filter, report title/author/include-Info. New option = one Pref entry + a follow() where it applies.
- [x] GUI clarity pass (2026-11-01): tooltips on every control (gui/ui.py + enforcing tests), Help Overview rewritten
      with a "Where to start" goal->tab table and accurate network-call list, first launch opens Help, stale help
      texts fixed (Audit Log, Settings), "Data && history" mnemonic bug, plain status bar, NVD checkbox label.
- hashcat v6 changed --outfile-format to a comma list (1,2 = hash:plain); we read the POTFILE
  instead (always hash:plain). hashcat needs --force on CPU-only boxes. The container's `john` is
  the limited "core" build (no --pot=, few formats); real crack tests use hashcat.

## Cloud vs local

The project started in a Claude Code cloud session and continues on the user's
machine. Cloud containers have no Wi-Fi hardware and usually no nmap, so step 2
onward is best developed and verified locally. Parsers should still be unit-tested
against captured sample output in `tests/fixtures/` so they can be tested anywhere.
Commit and push at the end of each step, so either environment can pick up from the repo.
