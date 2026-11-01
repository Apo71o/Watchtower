# Watchtower

A local, GUI-based network and Wi-Fi security **auditing and reporting** tool
for your own home lab and CTF practice. It wraps well-known tools (nmap,
airodump-ng, sslyze/testssl.sh, net-snmp) and turns their output into
prioritized findings with plain-language explanations and remediation advice.

**Reporting only, by design.** Watchtower never deauths, captures handshakes or
PMKIDs, cracks passwords, attacks WPS, runs rogue APs or tries logins. It only
scans networks and hosts you mark as authorized, shows every command before it
runs, and records everything in an append-only audit log. No telemetry; the
only optional network call is NVD CVE lookups, off by default.

- **Install:** see [INSTALL.md](INSTALL.md) (`./install.sh` on Debian, `install.ps1` on Windows)
- **Full spec:** [docs/SPEC.md](docs/SPEC.md)
- **Build progress and conventions:** [CLAUDE.md](CLAUDE.md)

## Status

Build step 1 of 11 is done: project skeleton, platform detection, dependency
check screen, first-run authorization gate, SQLite storage, append-only audit
log with viewer and CSV/JSON export, command console, help panels and glossary.
The other tabs are placeholders that already gray out correctly when a tool is
missing or scanning is locked.

## Continuing development on your own machine

This project was started in a Claude Code cloud session and is meant to be
continued locally, where the real Wi-Fi hardware is.

```bash
git clone https://github.com/Apo71o/watchtower.git
cd watchtower
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
.venv/bin/python -m watchtower
```

Then start Claude Code in the folder (`claude`) and say e.g. *"continue with
build step 2"*. It reads `CLAUDE.md` automatically, which holds the rules,
architecture, conventions and the progress checklist. Keep that checklist
updated as steps land, so the next session (cloud or local) knows where things stand.
