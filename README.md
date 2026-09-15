# Windows-Forensics-Toolkit

## This is a Python-based Windows forensic tool that collects and analyses Windows Security Event Logs and Registry artefacts to identify potentially suspicious authentication activity and persistence mechanisms.

## What this tool does

* Collects selected Windows Security Event Logs
* Parses Windows Event Log XML into structured data
* Monitors security events including:

  * 4624 - Successful logon
  * 4625 - Failed logon
  * 4634 - Logoff
  * 4648 - Logon using explicit credentials
  * 4688 - Process creation
  * 1102 - Security audit log cleared
* Detects repeated failed login attempts
* Groups failed logins by source IP address and target username
* Collects startup entries from the Windows Registry Run key
* Flags potentially suspicious Registry persistence
* Detects startup commands using interpreters such as PowerShell and CMD
* Exports collected evidence and alerts into JSON files

---

## Why this Matters

Windows Event Logs and Registry artefacts are important sources of evidence during security monitoring and digital forensic investigations.

Repeated authentication failures can potentially indicate:

* brute-force password attacks
* password guessing
* credential-based attacks
* suspicious authentication activity

Registry Run keys can also be abused by attackers to maintain persistence by automatically executing programs when a user logs into Windows.

This tool demonstrates the fundamentals of defensive security monitoring:

* collecting forensic evidence from Windows systems
* parsing and structuring security logs
* identifying abnormal authentication patterns
* analysing Registry persistence
* creating detection rules
* generating alerts for further investigation

---

## Skills Demo'd

* Windows Event Log analysis
* Windows Registry analysis
* Digital forensics fundamentals
* Threat detection
* Python scripting and automation
* PowerShell
* XML parsing
* JSON evidence handling
* Authentication analysis
* Persistence detection
* Basic SOC investigation workflow

---

## How to run

Run the toolkit from the project directory:

```
python main.py
```

The toolkit will collect Windows Security events and Registry startup entries before applying the detection rules.

Generated evidence is stored inside the `output` directory:

```
output/
├── security_events.json
├── security_alerts.json
├── registry_entries.json
└── registry_alerts.json
```

Some Windows Security Event Logs may require the terminal to be run with Administrator privileges.

---

## Current Detection Rules

### Failed Login Detection

The toolkit analyses Windows Event ID `4625` and groups failed authentication attempts using the source IP address and target username.

When the configured threshold is reached, the toolkit generates a:

```
Possible Brute Force
```

alert for further investigation.

### Registry Persistence Detection

The toolkit examines:

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

for programs configured to execute when the current user logs into Windows.

Startup entries containing potentially suspicious interpreters or locations are flagged for further investigation.

The presence of an alert does not automatically mean that malicious activity has occurred. Alerts are intended to identify activity that may require additional investigation.

---

## Future Development

Version 2 of the toolkit may include:

* Browser history analysis
* USB device history
* Windows Prefetch analysis
* Scheduled task analysis
* Windows service analysis
* Sysmon integration
* Additional detection rules
* Forensic timeline generation
* MITRE ATT&CK mapping
* Automated reporting
