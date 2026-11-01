# Installing Watchtower

Watchtower is a GUI that runs existing security tools (nmap, airodump-ng,
sslyze, net-snmp…) and explains what they find. Installing it is two parts:

1. **The app itself:** one step, isolated environment, no system Python changes.
2. **The external tools it wraps:** checked by the in-app **Dependency Check**
   (Tools → Dependency Check…, also shown on first launch). Missing tools gray
   out the features that need them; nothing is installed without your confirmation.

## Debian / Ubuntu / Kali (full feature set)

```bash
git clone https://github.com/Apo71o/Watchtower.git watchtower
cd watchtower
./install.sh
```

`install.sh` uses `pipx` if you have it (`sudo apt install pipx`), otherwise a
private venv in `~/.local/share/watchtower-app/venv`, and adds a desktop launcher.
If Qt's system libraries are missing it prints the `sudo apt install …` line and
asks before running it.

Then install the security tools you want (or let the Dependency Check screen do it
after showing you the command):

```bash
sudo apt install nmap iw aircrack-ng network-manager snmp testssl.sh nikto
```

Passive subdomain discovery also works with no tool at all (built-in crt.sh
search); subfinder or amass add more data sources.

| Tool | Package | Used for |
|---|---|---|
| nmap | `nmap` | Host/port/service/version scanning |
| iw | `iw` | Listing Wi-Fi interfaces and monitor-mode support |
| airodump-ng | `aircrack-ng` | Passive, listen-only AP/client listing (the only tool from that package Watchtower runs) |
| nmcli | `network-manager` | Nearby-network scan without a password (usually preinstalled) |
| iwlist | `wireless-tools` | Obsolete and not needed (`iw` replaces it); missing from newer Ubuntu/Debian, and the installer skips it there |
| sslyze *or* testssl.sh | `testssl.sh` (apt) / sslyze: the installer button runs `pip install sslyze` inside Watchtower's environment | TLS audit in Host Audit (optional; either one is enough) |
| snmpget/snmpwalk | `snmp` | Read-only SNMP community-string check (optional) |
| Metasploit | [Rapid7 installer](https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html) | Module-name cross-reference only (optional) |
| nikto | `nikto` | Web server scan in Web Audit (optional; run without its default-login plugin and DoS tests) |
| dnspython | Python package (installed with Watchtower; `pip install dnspython` otherwise) | SPF / DKIM / DMARC lookups in Domain Audit |
| subfinder | [release binary](https://github.com/projectdiscovery/subfinder/releases) (not packaged by Ubuntu) | Passive subdomain discovery in Domain Audit (optional) |
| amass | `amass` where packaged, or [release binary](https://github.com/owasp-amass/amass/releases) | Alternative passive subdomain source (optional; only builds with `enum -passive` are used) |
| weasyprint | `weasyprint` | PDF report export (optional) |

### Privileges

nmap SYN scans and airodump-ng need raw-socket access. Rather than running the
GUI as root, the Dependency Check screen offers a one-time, confirmed step:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f "$(command -v nmap)")"
sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f "$(command -v airodump-ng)")"
```

Trade-off: any local user can then use those two binaries with raw sockets.
Watchtower passes `--privileged` to nmap so it uses the capabilities. Without
this step nmap falls back to slower connect scans.

Putting an interface into monitor mode disconnects it from Wi-Fi. Watchtower
always asks first.

## Windows (everything except Wi-Fi radio features)

Windows does not give userspace programs reliable monitor-mode access to Wi-Fi
adapters, so the **Nearby Networks** passive scan is disabled there (the tab
explains why). Everything else works: nmap scanning, findings, TLS/SNMP audits,
default-credential fingerprints, risk scoring, history diff, scheduler, reports.
For Wi-Fi recon, use a Debian machine, a Debian VM with a USB Wi-Fi adapter
passed through, or spare hardware.

```powershell
git clone https://github.com/Apo71o/Watchtower.git watchtower
cd watchtower
powershell -ExecutionPolicy Bypass -File install.ps1
winget install Insecure.Nmap     # includes the Npcap driver; tick "Npcap" in its installer
```

`install.ps1` needs Python 3.11+ (`winget install Python.Python.3.12`), creates a venv in
`%LOCALAPPDATA%\Watchtower\venv` and a desktop shortcut. It does not need Administrator.
Some nmap scan types need an elevated process. Watchtower asks to relaunch elevated
only when you start one of those, not up front. `run.bat` launches the app.

## Running from source (development)

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m watchtower            # GUI
.venv/bin/python -m watchtower --check-deps   # terminal dependency report
.venv/bin/pytest
```

On Windows use `.venv\Scripts\python` instead of `.venv/bin/python`.

## Where data lives

One SQLite file holds settings, scan history and the append-only audit log:

- Linux: `~/.local/share/watchtower/watchtower.db`
- Windows: `%APPDATA%\Watchtower\watchtower.db`

Set `WATCHTOWER_HOME=/some/dir` to use a different location (handy for testing).

## Uninstall

- pipx: `pipx uninstall watchtower`
- venv install: `rm -rf ~/.local/share/watchtower-app ~/.local/bin/watchtower ~/.local/share/applications/watchtower.desktop`
- Windows: delete `%LOCALAPPDATA%\Watchtower` and the desktop shortcut.
- Your data (audit log, history) is kept unless you also delete the data folder above.
