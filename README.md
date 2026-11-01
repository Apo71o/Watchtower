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

Build steps 1-7 of 11 are done, plus one-click fixes:

- Dependency check with a working one-click installer (live output, password prompt or terminal)
- **Interfaces:** wireless adapters, monitor-mode support, switch monitor/managed mode
- **Nearby Networks:** managed scan (nmcli or iw) or passive monitor-mode listening
  (airodump-ng, incl. client devices), Authorized checkbox, Investigate
- **Scan a Target:** nmap's standard profiles (Intense scan, Quick scan plus, ...) and scan
  types (SYN, connect, UDP, Xmas, ...) with explanations, OS detection, vuln scripts and any extra
  options; authorized-target list; live output; results tree; scan history
- **Findings:** CVE version matches, risky-service rules, nmap vuln-script results and Wi-Fi
  advisor findings, each with remediation, MITRE ATT&CK tags and a plain explanation; per-device
  0-100 risk score in a Top Risks view
- **Host Audit:** TLS audit (testssl.sh or SSLyze), read-only SNMP community check, and
  default-credential fingerprinting (report only, never tries a login)
- **One-click fixes** from Findings: security updates or disabling a risky service on this machine,
  the same over SSH for your other Linux hosts, or open the device's admin page; then re-scan
- **Public exploit** flag: CVEs with ready-made Metasploit modules (names only) rank higher
- Audit log viewer/export, command console, help panels, glossary

What Changed (history diff + scheduler) is next (step 8), then reports and NVD lookups.

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
