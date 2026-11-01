# Watchtower: notes for Claude Code

Local PySide6 GUI that wraps existing security tools for **authorized**
home-lab auditing and **reports** findings with remediation. The full,
authoritative requirements are in `docs/SPEC.md`; read the relevant section
before starting a build step.

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
4. **Authorization gate:** scanning features stay disabled while
   `ctx.authorized` is False (first-run acknowledgment, revocable in Settings).
5. **No network calls** except NVD lookups behind the Settings toggle (off by
   default), each logged as `Event.NETWORK_REQUEST`.
6. **Ask the user** before touching system Wi-Fi interface settings (monitor
   mode) or running anything with sudo/pkexec. Show the command, then confirm.
7. **Read-only SNMP:** GET/WALK only, never SET.

## Layout

```
watchtower/
  app.py                 entry point (GUI, or --check-deps for a terminal report)
  core/platform_utils.py OS detection, require_linux(), data_dir(), WIFI_UNSUPPORTED_REASON
  core/runner.py         CommandRunner: the only way to run subprocesses
  core/deps.py           TOOLS table, check_all(), DependencyState (feature gating), install/setcap plans
  storage/db.py          SQLite + MIGRATIONS list (append new entries, never edit old ones)
  storage/audit_log.py   append-only log (DB triggers block UPDATE/DELETE); Event enum
  storage/settings.py    JSON key/value settings + well-known keys
  help/content.py        TAB_HELP (per-tab "What is this?") + GLOSSARY
  help/INSTALL.md        packaged copy of /INSTALL.md (test enforces they match)
  gui/context.py         AppContext (db, settings, audit, runner, deps, platform, bus)
  gui/main_window.py     tabs + Command Console dock + first-run flow
  gui/help_panel.py      TabPage = content + collapsible help panel
  gui/worker.py          run_in_background(): keep subprocesses off the GUI thread
  gui/auth_gate.py, gui/dependency_check.py, gui/tabs/*.py
tests/                   pytest; GUI tests run with QT_QPA_PLATFORM=offscreen
docs/SPEC.md             original build prompt (authoritative requirements)
```

## Conventions

- `core/` and `storage/` must not import Qt; they are unit-tested headless.
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

## Commitments already promised in UI/docs (must be honored by later steps)

- Step 2: switching an interface to monitor mode asks first (it drops the Wi-Fi connection).
- Step 3: pass `--privileged` to nmap when the binary has capabilities set (Linux), since
  the setcap button in the Dependency Check tells the user this happens. On Windows, prompt to
  relaunch elevated only when a scan type needs it, not at startup.
- Step 3: `--script vuln` is opt-in, with the intrusiveness warning from TAB_HELP["scan"].

## Build progress (update this when a step lands)

- [x] 1. Skeleton, platform detection, dependency check screen, authorization gate,
        SQLite storage, audit log (+ viewer/export, command console, help panels, glossary)
- [ ] 2. Interface detection (`iw dev`/`iw phy` → monitor-mode capability) + nearby network
        scan (nmcli/iwlist managed; airodump-ng monitor, listen-only, parse its CSV),
        per-network Authorized checkbox persisted in SQLite (new migration)
- [ ] 3. nmap against a manually entered, authorized target; `-oX` XML parsing; results table
- [ ] 4. Findings engine with a small bundled dataset in `watchtower/data/`, remediation,
        risk scoring, MITRE ATT&CK tags
- [ ] 5. Wi-Fi advisor findings (open/WEP/WPA1/WPA2-PSK/WPS), advisory text only
- [ ] 6. Host Audit tab: default-creds fingerprint (report only), TLS audit, SNMP read-only
- [ ] 7. Metasploit module cross-reference (module names only)
- [ ] 8. History diff ("What Changed") + scheduler
- [ ] 9. Report export (HTML, optional PDF via weasyprint). Audit log viewer is already done.
- [ ] 10. Help/glossary content: ongoing alongside each step
- [ ] 11. Live NVD lookups behind the Settings toggle

## Cloud vs local

The project started in a Claude Code cloud session and continues on the user's
machine. Cloud containers have no Wi-Fi hardware and usually no nmap, so step 2
onward is best developed and verified locally. Parsers should still be unit-tested
against captured sample output in `tests/fixtures/` so they can be tested anywhere.
Commit and push at the end of each step, so either environment can pick up from the repo.
