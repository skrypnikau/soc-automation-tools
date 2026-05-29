# SOC Automation Tools: Cross-Platform Security Log Analyzer

A lightweight, high-performance command-line tool written in Python for Digital Forensics and Incident Response (DFIR) and Security Operations (SOC) triage. 

This tool automates threat hunting and session auditing across **Windows Event Logs (`.evtx` and flat structures)** and **Linux Authentication logs (`auth.log`/`secure`)**, mapping security incidents directly to the **MITRE ATT&CK®** framework.

---

## 🚀 Key Features

* **Dual-Engine Architecture:** Detects attacks across both Windows and Linux hosts.
* **Threat Detection Core:**
  * **Brute-Force Detection (MITRE T1110):** Analyzes failed SSH/RDP connection attempts using a configurable sliding time window and attempt threshold.
  * **Persistence Hunting (MITRE T1136.001):** Detects local user account creation events.
  * **Defense Evasion Detection (MITRE T1070):** Identifies unauthorized event audit log clearing events.
  * **Privilege Escalation Hunting (MITRE T1548.003):** Flags unauthorized `sudo` executions and privilege escalation attempts on Linux systems.
* **Heuristic Session Auditing (MITRE T1078):** Logs all successful logins and flags anomalous activity (e.g., out-of-hours logons between 10 PM and 6 AM).
* **Zero Dependencies:** Formatted using native ANSI codes for clean colored terminal outputs without installing external UI frameworks.

---

## 📊 Supported Log Sources & Event IDs

### 🐧 Linux OS (`/var/log/auth.log` or `/var/log/secure`)
* **SSH Failed Password:** Attempts to login using SSH with non-valid passwords or users.
* **SSH Accepted Connection:** Successful login events.
* **Sudoers Violations:** Non-sudo users trying to execute commands with administrator privileges.
* **Sudo Executions:** Full commands executed via `sudo` for administrative audit trails.

### 🪟 Windows OS (Binary `.evtx` or CSV representation)
* **Event ID 4625 (Failed Logon):** Captured to identify brute-force or credential stuffing patterns.
* **Event ID 4624 (Successful Logon):** Analyzed to map RDP and interactive sessions.
* **Event ID 4720 (User Created):** Flags critical account creation events that could indicate backdoor creation.
* **Event ID 1102 (Log Cleared):** Flags critical administrative audit log wipes used to conceal host intrusion.

---

## 🛠️ Quick Start & CLI Usage

### Requirements
* Python 3.6+
* `pip install evtx` *(Optional: only needed to parse binary `.evtx` logs directly)*

### Commands

To view help and arguments:
```bash
python security_log_analyzer.py --help
```

#### 1. Analyze Linux Authentication Logs
Run the analyzer against the provided mock log using a sliding window of **10 minutes** and a threshold of **5 failed attempts**:
```bash
python security_log_analyzer.py --file test_logs/test_auth.log --os linux --threshold 5 --window 10
```

#### 2. Analyze Windows Security Logs (CSV Flat-File)
Run the analyzer against the provided flat-file CSV representation:
```bash
python security_log_analyzer.py --file test_logs/test_windows_security.csv --os windows --threshold 5 --window 10
```

#### 3. Analyze Windows Security Logs (Binary `.evtx` - Requires `evtx` package)
```bash
python security_log_analyzer.py --file C:\Windows\System32\Winevt\Logs\Security.evtx --os windows
```

---

## 📈 Sample Outputs

### Linux Analysis Output
```text
+----------------------------------------------------------------------+
|                   CROSS-PLATFORM SECURITY LOG ANALYZER               |
|             DFIR & Threat Detection - Windows EVTX & Linux           |
+----------------------------------------------------------------------+
    
[*] Analyzing Linux Syslog/Auth log: test_auth.log

=== DETECTION REPORT: LINUX AUTH ANALYSES ===

[1] Threat Hunting - SSH Brute Force (MITRE T1110.001)
---------------------------------------------------------------------------
[!] ALERT: SSH Brute Force from 203.0.113.5
    - IP Address:      203.0.113.5
    - Failed Attempts: 5 within 10 min window
    - Target Users:    root, admin, backup, user
    - First Attempt:   2026-05-19 09:22:11
    - Severity:         HIGH 

[2] Threat Hunting - Unauthorized Privilege Escalation (MITRE T1548.003)
---------------------------------------------------------------------------
[!] ALERT: Unauthorized Sudo Attempt!
    - Timestamp:   2026-05-19 14:02:10
    - User:        attacker (NOT in sudoers)
    - Target User: root
    - Command:     /usr/bin/cat /etc/shadow
    - Severity:     MEDIUM-HIGH 

[3] Auditing - Successful SSH Sessions (MITRE T1078)
---------------------------------------------------------------------------
    [+] 2026-05-19 08:12:05 - Login by yauheni from 192.168.1.50
    [+] 2026-05-19 23:45:12 - Login by yauheni from 198.51.100.12 [ANOMALOUS TIMING]
```
