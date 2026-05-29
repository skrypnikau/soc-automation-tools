#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SOC & DFIR Security Log Analyzer
Author: Yauheni Skrypnikau
Description: Cross-platform command-line security log analysis tool for Windows EVTX and Linux Auth logs.
             Detects SSH/RDP Brute-Force attacks, Privilege Escalations, Account Creation, 
             and Audit Log Clearing attempts. Maps events to MITRE ATT&CK framework.
"""

import os
import re
import sys
import argparse
from datetime import datetime, timedelta
from collections import defaultdict

# Professional Terminal Styling (Pure ANSI - Zero Dependencies)
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BG_RED = '\033[41m'
    BG_YELLOW = '\033[43m'

def print_banner():
    banner = f"""
{Colors.BLUE}{Colors.BOLD}+----------------------------------------------------------------------+
|                   CROSS-PLATFORM SECURITY LOG ANALYZER               |
|             DFIR & Threat Detection - Windows EVTX & Linux           |
+----------------------------------------------------------------------+{Colors.ENDC}
    """
    print(banner)

# ----------------------------------------------------------------------
# LINUX AUTH LOG PARSING ENGINE
# ----------------------------------------------------------------------
class LinuxAuthAnalyzer:
    def __init__(self, filepath, threshold=5, window_mins=10):
        self.filepath = filepath
        self.threshold = threshold
        self.window_mins = window_mins
        
        # Regex patterns for SSH activity
        self.ssh_fail_pattern = re.compile(
            r'Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port (?P<port>\d+)'
        )
        self.ssh_success_pattern = re.compile(
            r'Accepted (password|publickey) for (?P<user>\S+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        )
        self.sudo_pattern = re.compile(
            r'(?P<user>\S+) : TTY=.* ; USER=(?P<target_user>\S+) ; COMMAND=(?P<command>.*)'
        )
        self.sudo_fail_pattern = re.compile(
            r'(?P<user>\S+) : user NOT in sudoers ; TTY=.* ; USER=(?P<target_user>\S+) ; COMMAND=(?P<command>.*)'
        )

    def parse_time(self, log_line):
        """Parses standard syslog timestamps (e.g. 'May 19 14:32:01' or '2026-05-19T14:32:01.123+02:00')"""
        parts = log_line.split()
        if len(parts) < 3:
            return None
        
        # Format 1: ISO 8601 (newer systems)
        try:
            iso_match = re.match(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', parts[0])
            if iso_match:
                return datetime.strptime(iso_match.group(1), "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            pass

        # Format 2: Standard Syslog (e.g., "May 19 14:32:10")
        try:
            current_year = datetime.now().year
            time_str = f"{parts[0]} {parts[1]} {parts[2]} {current_year}"
            return datetime.strptime(time_str, "%b %d %H:%M:%S %Y")
        except ValueError:
            return None

    def analyze(self):
        print(f"[*] Analyzing Linux Syslog/Auth log: {Colors.BOLD}{os.path.basename(self.filepath)}{Colors.ENDC}")
        if not os.path.exists(self.filepath):
            print(f"{Colors.FAIL}[-] File not found: {self.filepath}{Colors.ENDC}")
            return

        failed_logins = defaultdict(list)  # IP -> list of timestamps
        successful_logins = []
        sudo_activities = []
        unauthorized_sudos = []
        
        with open(self.filepath, 'r', errors='ignore') as f:
            for line in f:
                timestamp = self.parse_time(line)
                if not timestamp:
                    continue

                # 1. Check SSH Failed Logins
                fail_match = self.ssh_fail_pattern.search(line)
                if fail_match:
                    ip = fail_match.group('ip')
                    user = fail_match.group('user')
                    failed_logins[ip].append((timestamp, user))
                    continue

                # 2. Check SSH Successful Logins
                success_match = self.ssh_success_pattern.search(line)
                if success_match:
                    ip = success_match.group('ip')
                    user = success_match.group('user')
                    successful_logins.append({
                        'time': timestamp,
                        'ip': ip,
                        'user': user
                    })
                    continue

                # 3. Check Sudo Unauthorized Access
                sudo_fail_match = self.sudo_fail_pattern.search(line)
                if sudo_fail_match:
                    unauthorized_sudos.append({
                        'time': timestamp,
                        'user': sudo_fail_match.group('user'),
                        'target': sudo_fail_match.group('target_user'),
                        'cmd': sudo_fail_match.group('command')
                    })
                    continue

                # 4. Check Sudo General Activities
                sudo_match = self.sudo_pattern.search(line)
                if sudo_match:
                    sudo_activities.append({
                        'time': timestamp,
                        'user': sudo_match.group('user'),
                        'target': sudo_match.group('target_user'),
                        'cmd': sudo_match.group('command')
                    })

        self.report_results(failed_logins, successful_logins, sudo_activities, unauthorized_sudos)

    def report_results(self, failed_logins, successful_logins, sudo_activities, unauthorized_sudos):
        print(f"\n{Colors.HEADER}=== DETECTION REPORT: LINUX AUTH ANALYSES ==={Colors.ENDC}")

        # 1. SSH Brute Force Detection
        brute_force_detected = False
        print(f"\n{Colors.BOLD}[1] Threat Hunting - SSH Brute Force (MITRE T1110.001){Colors.ENDC}")
        print("-" * 75)
        
        for ip, attempts in failed_logins.items():
            # Sort attempts by timestamp
            attempts.sort(key=lambda x: x[0])
            
            # Analyze sliding windows
            for i in range(len(attempts)):
                start_time = attempts[i][0]
                window_attempts = 1
                users_targeted = {attempts[i][1]}
                
                for j in range(i + 1, len(attempts)):
                    delta = attempts[j][0] - start_time
                    if delta <= timedelta(minutes=self.window_mins):
                        window_attempts += 1
                        users_targeted.add(attempts[j][1])
                    else:
                        break
                
                if window_attempts >= self.threshold:
                    print(f"{Colors.FAIL}{Colors.BOLD}[!] ALERT: SSH Brute Force from {ip}{Colors.ENDC}")
                    print(f"    - IP Address:      {ip}")
                    print(f"    - Failed Attempts: {window_attempts} within {self.window_mins} min window")
                    print(f"    - Target Users:    {', '.join(users_targeted)}")
                    print(f"    - First Attempt:   {start_time}")
                    print(f"    - Severity:        {Colors.BG_RED} HIGH {Colors.ENDC}")
                    brute_force_detected = True
                    break  # Alert once per IP to keep screen clean

        if not brute_force_detected:
            print(f"{Colors.GREEN}[+] No SSH Brute Force patterns detected.{Colors.ENDC}")

        # 2. Critical Privilege Escalation Alerts (Unauthorized Sudo)
        print(f"\n{Colors.BOLD}[2] Threat Hunting - Unauthorized Privilege Escalation (MITRE T1548.003){Colors.ENDC}")
        print("-" * 75)
        if unauthorized_sudos:
            for s in unauthorized_sudos:
                print(f"{Colors.WARNING}{Colors.BOLD}[!] ALERT: Unauthorized Sudo Attempt!{Colors.ENDC}")
                print(f"    - Timestamp:   {s['time']}")
                print(f"    - User:        {s['user']} (NOT in sudoers)")
                print(f"    - Target User: {s['target']}")
                print(f"    - Command:     {s['cmd']}")
                print(f"    - Severity:    {Colors.BG_YELLOW} MEDIUM-HIGH {Colors.ENDC}")
        else:
            print(f"{Colors.GREEN}[+] No unauthorized sudo attempts found.{Colors.ENDC}")

        # 3. Session Auditing (Successful Logins)
        print(f"\n{Colors.BOLD}[3] Auditing - Successful SSH Sessions (MITRE T1078){Colors.ENDC}")
        print("-" * 75)
        if successful_logins:
            for s in successful_logins[:15]:  # limit to top 15
                # Simple heuristic for anomalous timing (night logon: 10 PM - 6 AM)
                hour = s['time'].hour
                timing_alert = ""
                if hour >= 22 or hour <= 6:
                    timing_alert = f" {Colors.WARNING}[ANOMALOUS TIMING]{Colors.ENDC}"
                print(f"    [+] {s['time']} - Login by {Colors.GREEN}{s['user']}{Colors.ENDC} from {s['ip']}{timing_alert}")
            if len(successful_logins) > 15:
                print(f"    ... {len(successful_logins) - 15} more logins omitted from summary.")
        else:
            print("    [-] No successful SSH logins logged.")


# ----------------------------------------------------------------------
# WINDOWS EVTX/XML LOG PARSING ENGINE
# ----------------------------------------------------------------------
class WindowsEvtxAnalyzer:
    def __init__(self, filepath, threshold=10, window_mins=10):
        self.filepath = filepath
        self.threshold = threshold
        self.window_mins = window_mins

    def analyze(self):
        print(f"[*] Analyzing Windows EVTX/Security Logs: {Colors.BOLD}{os.path.basename(self.filepath)}{Colors.ENDC}")
        
        # Test if it's a binary .evtx or an exported XML/CSV
        if not os.path.exists(self.filepath):
            print(f"{Colors.FAIL}[-] File not found: {self.filepath}{Colors.ENDC}")
            return
            
        is_binary = self.filepath.lower().endswith('.evtx')
        
        if is_binary:
            self.analyze_binary_evtx()
        else:
            self.analyze_flat_file()

    def analyze_binary_evtx(self):
        try:
            import Evtx.Evtx as evtx
            import Evtx.Views as e_views
            import xml.etree.ElementTree as ET
        except ImportError:
            print(f"\n{Colors.FAIL}[-] Python-evtx package is missing.{Colors.ENDC}")
            print(f"    To parse binary files directly, run: {Colors.BOLD}pip install evtx{Colors.ENDC}")
            print("    Falling back to standard text/CSV/XML parsing engines if available...")
            return

        failed_logins = defaultdict(list)
        successful_logins = []
        accounts_created = []
        log_clears = []

        # Namespaces for Event XML elements
        ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}

        try:
            with evtx.Evtx(self.filepath) as log:
                for record in log.records():
                    xml_data = record.xml()
                    try:
                        root = ET.fromstring(xml_data)
                    except ET.ParseError:
                        continue
                    
                    # Extract System Data
                    system = root.find('ns:System', ns)
                    if system is None:
                        continue
                    
                    event_id_elem = system.find('ns:EventID', ns)
                    time_elem = system.find('ns:TimeCreated', ns)
                    
                    if event_id_elem is None or time_elem is None:
                        continue
                        
                    event_id = int(event_id_elem.text)
                    time_str = time_elem.attrib.get('SystemTime', '')
                    
                    # Standard system timestamps: 2026-05-19 14:32:01.123456
                    try:
                        timestamp = datetime.strptime(time_str[:19], "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        try:
                            timestamp = datetime.strptime(time_str[:19], "%Y-%m-%dT%H:%M:%S")
                        except ValueError:
                            continue

                    # Extract Event Data details
                    event_data = root.find('ns:EventData', ns)
                    data_dict = {}
                    if event_data is not None:
                        for data in event_data.findall('ns:Data', ns):
                            name = data.attrib.get('Name')
                            if name:
                                data_dict[name] = data.text

                    # 1. Event ID 4625 - Failed Logon (Brute Force Hunting)
                    if event_id == 4625:
                        ip = data_dict.get('IpAddress', '-')
                        user = data_dict.get('TargetUserName', '-')
                        if ip != '-' and ip != '127.0.0.1' and ip != '::1':
                            failed_logins[ip].append((timestamp, user))

                    # 2. Event ID 4624 - Successful Logon
                    elif event_id == 4624:
                        ip = data_dict.get('IpAddress', '-')
                        user = data_dict.get('TargetUserName', '-')
                        logon_type = data_dict.get('LogonType', '-')
                        if ip != '-' and ip != '127.0.0.1' and ip != '::1':
                            successful_logins.append({
                                'time': timestamp,
                                'ip': ip,
                                'user': user,
                                'type': logon_type
                            })

                    # 3. Event ID 4720 - Local User Creation (Persistence Hunting)
                    elif event_id == 4720:
                        target_user = data_dict.get('TargetUserName', '-')
                        subject_user = data_dict.get('SubjectUserName', '-')
                        accounts_created.append({
                            'time': timestamp,
                            'created_user': target_user,
                            'created_by': subject_user
                        })

                    # 4. Event ID 1102 - Audit Log Cleared (Defense Evasion)
                    elif event_id == 1102:
                        subject_user = data_dict.get('SubjectUserName', '-')
                        log_clears.append({
                            'time': timestamp,
                            'user': subject_user
                        })

            self.report_results(failed_logins, successful_logins, accounts_created, log_clears)

        except Exception as e:
            print(f"{Colors.FAIL}[-] Error reading EVTX binary: {e}{Colors.ENDC}")

    def analyze_flat_file(self):
        """Fallback for custom CSV or JSON representations of Windows Event Logs"""
        print("[*] Analyzing file as CSV/Text representation...")
        # Simulating standard flat file analysis to enable checking of mock security artifacts
        failed_logins = defaultdict(list)
        successful_logins = []
        accounts_created = []
        log_clears = []

        try:
            with open(self.filepath, 'r', errors='ignore') as f:
                for line in f:
                    # Generic parser for standard text/CSV dumps of Windows Event logs
                    # Expected CSV Format: Timestamp, EventID, User, IP, Details...
                    parts = line.strip().split(',')
                    if len(parts) < 4:
                        continue
                    
                    try:
                        timestamp = datetime.strptime(parts[0][:19], "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        try:
                            timestamp = datetime.strptime(parts[0][:19], "%Y-%m-%dT%H:%M:%S")
                        except ValueError:
                            continue
                            
                    try:
                        event_id = int(parts[1])
                    except ValueError:
                        continue

                    user = parts[2]
                    ip = parts[3]

                    if event_id == 4625:
                        if ip != '-' and ip != '127.0.0.1' and ip != '::1':
                            failed_logins[ip].append((timestamp, user))
                    elif event_id == 4624:
                        successful_logins.append({'time': timestamp, 'ip': ip, 'user': user, 'type': '10 (RDP)'})
                    elif event_id == 4720:
                        accounts_created.append({'time': timestamp, 'created_user': user, 'created_by': 'Administrator'})
                    elif event_id == 1102:
                        log_clears.append({'time': timestamp, 'user': user})

            self.report_results(failed_logins, successful_logins, accounts_created, log_clears)
        except Exception as e:
            print(f"{Colors.FAIL}[-] Error parsing flat file: {e}{Colors.ENDC}")

    def report_results(self, failed_logins, successful_logins, accounts_created, log_clears):
        print(f"\n{Colors.HEADER}=== DETECTION REPORT: WINDOWS SECURITY EVENTS ==={Colors.ENDC}")

        # 1. Audit Log Cleared Alert (MITRE T1070)
        print(f"\n{Colors.BOLD}[1] Threat Hunting - Defensive Evasion (MITRE T1070){Colors.ENDC}")
        print("-" * 75)
        if log_clears:
            for c in log_clears:
                print(f"{Colors.FAIL}{Colors.BOLD}[CRITICAL] ALERT: Windows Security Log Cleared!{Colors.ENDC}")
                print(f"    - Timestamp: {c['time']}")
                print(f"    - User:      {c['user']}")
                print(f"    - Severity:  {Colors.BG_RED} SEVERE / TACTICAL THREAT {Colors.ENDC}")
        else:
            print(f"{Colors.GREEN}[+] Security Log Cleared check passed (No incidents).{Colors.ENDC}")

        # 2. Local User Account Creation Alert (MITRE T1136.001)
        print(f"\n{Colors.BOLD}[2] Threat Hunting - Persistence / Account Creation (MITRE T1136.001){Colors.ENDC}")
        print("-" * 75)
        if accounts_created:
            for a in accounts_created:
                print(f"{Colors.WARNING}{Colors.BOLD}[!] ALERT: New Local User Created!{Colors.ENDC}")
                print(f"    - Timestamp:    {a['time']}")
                print(f"    - Created User: {Colors.WARNING}{a['created_user']}{Colors.ENDC}")
                print(f"    - Created By:   {a['created_by']}")
                print(f"    - Severity:     {Colors.BG_YELLOW} HIGH {Colors.ENDC}")
        else:
            print(f"{Colors.GREEN}[+] No local user account creation events detected.{Colors.ENDC}")

        # 3. RDP / Network Brute Force Detection
        brute_force_detected = False
        print(f"\n{Colors.BOLD}[3] Threat Hunting - RDP/Network Brute Force (MITRE T1110.001){Colors.ENDC}")
        print("-" * 75)
        
        for ip, attempts in failed_logins.items():
            attempts.sort(key=lambda x: x[0])
            for i in range(len(attempts)):
                start_time = attempts[i][0]
                window_attempts = 1
                users_targeted = {attempts[i][1]}
                
                for j in range(i + 1, len(attempts)):
                    delta = attempts[j][0] - start_time
                    if delta <= timedelta(minutes=self.window_mins):
                        window_attempts += 1
                        users_targeted.add(attempts[j][1])
                    else:
                        break
                
                if window_attempts >= self.threshold:
                    print(f"{Colors.FAIL}{Colors.BOLD}[!] ALERT: Windows Brute Force / Credential Stuffing from {ip}{Colors.ENDC}")
                    print(f"    - IP Address:      {ip}")
                    print(f"    - Failed Logins:   {window_attempts} within {self.window_mins} min window")
                    print(f"    - Targeted Users:  {', '.join(users_targeted)}")
                    print(f"    - First Timestamp: {start_time}")
                    print(f"    - Severity:        {Colors.BG_RED} HIGH {Colors.ENDC}")
                    brute_force_detected = True
                    break

        if not brute_force_detected:
            print(f"{Colors.GREEN}[+] No RDP or credential brute force patterns identified.{Colors.ENDC}")

        # 4. Successful Remote Sessions Audit
        print(f"\n{Colors.BOLD}[4] Auditing - Successful Sessions (MITRE T1078){Colors.ENDC}")
        print("-" * 75)
        if successful_logins:
            for s in successful_logins[:15]:
                hour = s['time'].hour
                timing_alert = ""
                if hour >= 22 or hour <= 6:
                    timing_alert = f" {Colors.WARNING}[ANOMALOUS TIMING]{Colors.ENDC}"
                print(f"    [+] {s['time']} - Login by {Colors.GREEN}{s['user']}{Colors.ENDC} from {s['ip']} (LogonType: {s['type']}){timing_alert}")
        else:
            print("    [-] No remote network/RDP sessions captured.")


# ----------------------------------------------------------------------
# CLI CONTROL POINT
# ----------------------------------------------------------------------
def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="SOC Toolkit: Windows & Linux Cross-Platform Security Log Analyzer."
    )
    parser.add_argument(
        '-f', '--file', 
        required=True, 
        help="Path to the security log file (e.g. auth.log, Security.evtx, or CSV file)"
    )
    parser.add_argument(
        '-o', '--os', 
        required=True, 
        choices=['windows', 'linux'], 
        help="Operating system source for parsing strategies"
    )
    parser.add_argument(
        '-t', '--threshold', 
        type=int, 
        default=5, 
        help="Minimum failed attempts threshold to trigger Brute-Force alert (default: 5)"
    )
    parser.add_argument(
        '-w', '--window', 
        type=int, 
        default=10, 
        help="Sliding time window size in minutes (default: 10)"
    )

    args = parser.parse_args()

    if args.os == 'linux':
        analyzer = LinuxAuthAnalyzer(args.file, threshold=args.threshold, window_mins=args.window)
    else:
        analyzer = WindowsEvtxAnalyzer(args.file, threshold=args.threshold, window_mins=args.window)

    analyzer.analyze()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] Analysis aborted by analyst.")
        sys.exit(0)
