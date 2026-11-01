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
4. **No network calls** except NVD lookups behind the Settings toggle (off by
   default), each logged as `Event.NETWORK_REQUEST`.
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
- [ ] 9. Report export (HTML, optional PDF via weasyprint). Audit log viewer is already done.
- [ ] 10. Help/glossary content: ongoing alongside each step
- [ ] 11. Live NVD lookups behind the Settings toggle

## Cloud vs local

The project started in a Claude Code cloud session and continues on the user's
machine. Cloud containers have no Wi-Fi hardware and usually no nmap, so step 2
onward is best developed and verified locally. Parsers should still be unit-tested
against captured sample output in `tests/fixtures/` so they can be tested anywhere.
Commit and push at the end of each step, so either environment can pick up from the repo.
