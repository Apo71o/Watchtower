# Watchtower

A local, GUI-based network and Wi-Fi security **auditing and reporting** tool
for your own home lab and CTF practice. It wraps well-known tools (nmap,
airodump-ng, sslyze/testssl.sh, net-snmp) and turns their output into
prioritized findings with plain-language explanations and remediation advice.

Watchtower only scans networks and hosts on your own authorized list, shows
every command before it runs, and records everything in an append-only audit
log. The tools it wraps are installed normally and keep their full functionality
if you use them directly. No telemetry; the only optional network call is NVD
CVE lookups, off by default.

- **Install:** see [INSTALL.md](INSTALL.md) (`./install.sh` on Debian, `install.ps1` on Windows)
- **Full spec:** [docs/SPEC.md](docs/SPEC.md)
- **Build progress and conventions:** [CLAUDE.md](CLAUDE.md)

## Status

Build steps 1-3 of 11 are done:

- Dependency check with a working one-click installer (live output, password prompt or terminal)
- **Interfaces:** wireless adapters, monitor-mode support, switch monitor/managed mode
- **Nearby Networks:** managed scan (nmcli/iwlist) or passive monitor-mode listening
  (airodump-ng, incl. client devices), Authorized checkbox, Investigate
- **Scan a Target:** nmap with profiles, OS detection, vuln scripts and any extra
  options; authorized-target list; live output; results tree; scan history
- Audit log viewer/export, command console, help panels, glossary

Findings, Host Audit and What Changed are still placeholders (steps 4-8).

## Continuing development on your own machine

This project was started in a Claude Code cloud session and is meant to be
continued locally, where the real Wi-Fi hardware is.

```bash
git clone https://github.com/Apo71o/Watchtower.git watchtower
cd watchtower
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
.venv/bin/python -m watchtower
```

Then start Claude Code in the folder (`claude`) and say e.g. *"continue with
build step 2"*. It reads `CLAUDE.md` automatically, which holds the rules,
architecture, conventions and the progress checklist. Keep that checklist
updated as steps land, so the next session (cloud or local) knows where things stand.
