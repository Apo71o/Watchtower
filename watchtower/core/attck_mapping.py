"""Small bundled lookup of MITRE ATT&CK techniques used to tag findings."""

from __future__ import annotations

TECHNIQUES: dict[str, tuple[str, str]] = {
    # id: (name, tactic)
    "T1040": ("Network Sniffing", "Credential Access / Discovery"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1078": ("Valid Accounts", "Initial Access / Persistence"),
    "T1078.001": ("Valid Accounts: Default Accounts", "Initial Access / Persistence"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1110.001": ("Brute Force: Password Guessing", "Credential Access"),
    "T1110.002": ("Brute Force: Password Cracking", "Credential Access"),
    "T1133": ("External Remote Services", "Initial Access / Persistence"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1210": ("Exploitation of Remote Services", "Lateral Movement"),
    "T1021": ("Remote Services", "Lateral Movement"),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", "Lateral Movement"),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
    "T1021.004": ("Remote Services: SSH", "Lateral Movement"),
    "T1021.005": ("Remote Services: VNC", "Lateral Movement"),
    "T1557": ("Adversary-in-the-Middle", "Credential Access / Collection"),
    "T1557.004": ("Adversary-in-the-Middle: Evil Twin", "Credential Access / Collection"),
    "T1602.001": ("Data from Configuration Repository: SNMP (MIB Dump)", "Collection"),
    "T1610": ("Deploy Container", "Execution"),
    "T1595.002": ("Active Scanning: Vulnerability Scanning", "Reconnaissance"),
    "T1595.003": ("Active Scanning: Wordlist Scanning", "Reconnaissance"),
    "T1592": ("Gather Victim Host Information", "Reconnaissance"),
    "T1592.002": ("Gather Victim Host Information: Software", "Reconnaissance"),
    "T1590.002": ("Gather Victim Network Information: DNS", "Reconnaissance"),
    "T1596.003": ("Search Open Technical Databases: Digital Certificates", "Reconnaissance"),
    "T1566": ("Phishing", "Initial Access"),
    "T1656": ("Impersonation", "Defense Evasion"),
    "T1539": ("Steal Web Session Cookie", "Credential Access"),
    "T1185": ("Browser Session Hijacking", "Collection"),
    "T1189": ("Drive-by Compromise", "Initial Access"),
}


def name(tid: str) -> str:
    return TECHNIQUES.get(tid, ("Unknown technique", ""))[0]


def url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def label(tid: str) -> str:
    return f"{tid} {name(tid)}"
