#!/usr/bin/env python3
"""
Linux Remote Security Auditor (LRSA) - v1.0
A multi-sector remote Windows security audit tool for Linux.

Usage:
    python3 remote_audit.py -t TARGET -u USERNAME -p PASSWORD [OPTIONS]

Requirements:
    pip install impacket python-ldap pywinrm dnspython

Author: Charles Ndirangu
"""

import argparse
import subprocess
import json
import sys
import re
import socket
import ipaddress
from datetime import datetime, timedelta
import xml.etree.ElementTree as ET

# Try importing optional modules
try:
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport, samr, lsad, scmr
    from impacket.dcerpc.v5.ndr import NDRCALL
    from impacket.dcerpc.v5.dtypes import NULL
except ImportError:
    print("[!] impacket not installed. Run: pip install impacket")
    sys.exit(1)

try:
    import winrm
except ImportError:
    print("[!] pywinrm not installed. Run: pip install pywinrm")
    sys.exit(1)

try:
    import ldap3
except ImportError:
    print("[!] python-ldap3 not installed. Run: pip install ldap3")
    sys.exit(1)

# Color codes for terminal output
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
WHITE = '\033[97m'
BOLD = '\033[1m'
RESET = '\033[0m'

class RemoteAuditor:
    def __init__(self, target, username, password, domain=None, port=445, use_winrm=True):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain or ""
        self.port = port
        self.use_winrm = use_winrm
        self.results = []
        self.findings = []
        self.critical_issues = []
        self.high_issues = []

    def add_result(self, category, check, status, details, risk="Info", recommendation=""):
        """Add a result to the audit log."""
        result = {
            "category": category,
            "check": check,
            "status": status,
            "details": details,
            "risk": risk,
            "recommendation": recommendation,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        self.results.append(result)

        if status in ["FAIL", "WARNING"]:
            self.findings.append(result)
            if risk in ["Critical", "High"]:
                self.critical_issues.append(result)
        elif status == "WARNING":
            self.high_issues.append(result)

    def print_banner(self):
        """Print tool banner."""
        print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════════════╗
║  Linux Remote Security Auditor (LRSA) - v1.0               ║
║  Remote Windows Security Audit Tool                         ║
║  Author: Charles Ndirangu                                   ║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")

    # ============================================================
    # CONNECTION METHODS
    # ============================================================

    def test_connection(self):
        """Test if the target is reachable."""
        try:
            socket.gethostbyname(self.target)
            return True
        except:
            return False

    def test_port(self, port):
        """Test if a port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((self.target, port))
            sock.close()
            return result == 0
        except:
            return False

    def get_smb_connection(self):
        """Establish SMB connection."""
        try:
            conn = SMBConnection(self.target, self.target, timeout=10)
            conn.login(self.username, self.password, domain=self.domain)
            return conn
        except Exception as e:
            return None

    def run_powershell_remote(self, command):
        """Execute PowerShell command via WinRM."""
        if not self.use_winrm:
            return None
        try:
            session = winrm.Session(self.target, auth=(self.username, self.password), 
                                   transport='ntlm', server_cert_validation='ignore')
            result = session.run_ps(command)
            if result.status_code == 0:
                return result.std_out.decode('utf-8').strip()
            return None
        except Exception as e:
            return None

    # ============================================================
    # SECTION 1: SYSTEM INFORMATION
    # ============================================================

    def audit_system_info(self):
        """Gather basic system information."""
        print(f"\n{BLUE}[*] Gathering System Information...{RESET}")

        # Try WinRM first
        if self.use_winrm:
            cmd = """
            $os = Get-CimInstance Win32_OperatingSystem
            $comp = Get-CimInstance Win32_ComputerSystem
            Write-Output "Hostname: $($comp.Name)"
            Write-Output "Domain: $($comp.Domain)"
            Write-Output "OS: $($os.Caption) $($os.Version)"
            Write-Output "Uptime: $((Get-Date) - $os.LastBootUpTime)"
            Write-Output "LastBoot: $($os.LastBootUpTime)"
            Write-Output "Manufacturer: $($comp.Manufacturer)"
            Write-Output "Model: $($comp.Model)"
            """
            output = self.run_powershell_remote(cmd)
            if output:
                for line in output.split('\n'):
                    if ':' in line:
                        key, val = line.split(':', 1)
                        self.add_result("System Info", key.strip(), "PASS", val.strip(), "Info")
                return

        # Fallback to SMB/RPC
        conn = self.get_smb_connection()
        if conn:
            try:
                # Try to get server info via RPC
                self.add_result("System Info", "Hostname", "PASS", self.target, "Info")
                self.add_result("System Info", "Domain", "PASS", self.domain or "Unknown", "Info")
            except:
                pass

    # ============================================================
    # SECTION 2: PATCH MANAGEMENT
    # ============================================================

    def audit_patches(self):
        """Check for missing patches and installed hotfixes."""
        print(f"\n{BLUE}[*] Checking Patch Status...{RESET}")

        if not self.use_winrm:
            self.add_result("Patch Management", "Hotfixes", "WARNING", 
                          "WinRM not available - hotfix enumeration skipped", "Info")
            return

        cmd = """
        $hotfixes = Get-HotFix | Select-Object HotFixID, InstalledOn, Description
        $hotfixes | ForEach-Object { 
            Write-Output "$($_.HotFixID)|$($_.InstalledOn)|$($_.Description)" 
        }
        """
        output = self.run_powershell_remote(cmd)
        if output:
            hotfix_count = len(output.split('\n'))
            if hotfix_count > 0:
                self.add_result("Patch Management", "Installed Hotfixes", "PASS", 
                              f"{hotfix_count} hotfixes installed", "Info")
            else:
                self.add_result("Patch Management", "Installed Hotfixes", "WARNING", 
                              "No hotfixes detected - possible missing patches", "High",
                              "Install all critical security updates")

    # ============================================================
    # SECTION 3: SECURITY HARDENING
    # ============================================================

    def audit_security_hardening(self):
        """Check security hardening settings."""
        print(f"\n{BLUE}[*] Checking Security Hardening...{RESET}")

        if not self.use_winrm:
            self.add_result("Security Hardening", "Hardening Checks", "WARNING", 
                          "WinRM not available - skipping", "Info")
            return

        # 3.1 Windows Defender
        cmd = """
        $def = Get-MpComputerStatus
        Write-Output "Defender: $($def.AntivirusEnabled)"
        Write-Output "RealTime: $($def.RealTimeProtectionEnabled)"
        Write-Output "SignatureVersion: $($def.AntivirusSignatureVersion)"
        """
        output = self.run_powershell_remote(cmd)
        if output:
            if "Defender: True" in output:
                self.add_result("Security Hardening", "Windows Defender", "PASS", 
                              "Antivirus is enabled", "Info")
            else:
                self.add_result("Security Hardening", "Windows Defender", "FAIL", 
                              "Antivirus is disabled", "Critical",
                              "Enable Windows Defender or install alternative AV")

            if "RealTime: True" in output:
                self.add_result("Security Hardening", "Real-Time Protection", "PASS", 
                              "Real-time protection is enabled", "Info")
            else:
                self.add_result("Security Hardening", "Real-Time Protection", "FAIL", 
                              "Real-time protection is disabled", "Critical",
                              "Enable real-time protection immediately")

        # 3.2 Windows Firewall
        cmd = """
        $profiles = Get-NetFirewallProfile
        $profiles | ForEach-Object { Write-Output "$($_.Name): $($_.Enabled)" }
        """
        output = self.run_powershell_remote(cmd)
        if output:
            disabled = []
            for line in output.split('\n'):
                if ':' in line:
                    name, status = line.split(':', 1)
                    if status.strip() == 'False':
                        disabled.append(name.strip())
            if disabled:
                self.add_result("Security Hardening", "Windows Firewall", "FAIL", 
                              f"Firewall disabled for: {', '.join(disabled)}", "Critical",
                              "Enable Windows Firewall for all profiles")
            else:
                self.add_result("Security Hardening", "Windows Firewall", "PASS", 
                              "Firewall is enabled for all profiles", "Info")

        # 3.3 UAC
        cmd = """
        $uac = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
        Write-Output "UAC: $($uac.EnableLUA)"
        """
        output = self.run_powershell_remote(cmd)
        if output and "UAC: 1" in output:
            self.add_result("Security Hardening", "UAC Enabled", "PASS", 
                          "UAC is enabled", "Info")
        else:
            self.add_result("Security Hardening", "UAC Enabled", "FAIL", 
                          "UAC is disabled", "High",
                          "Enable UAC via Group Policy")

        # 3.4 BitLocker
        cmd = """
        $bit = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
        if ($bit) {
            Write-Output "BitLocker: $($bit.ProtectionStatus)"
        } else {
            Write-Output "BitLocker: NotEnabled"
        }
        """
        output = self.run_powershell_remote(cmd)
        if output and "BitLocker: On" in output:
            self.add_result("Security Hardening", "BitLocker", "PASS", 
                          "BitLocker is enabled on C:", "Info")
        elif output and "BitLocker: Off" in output:
            self.add_result("Security Hardening", "BitLocker", "WARNING", 
                          "BitLocker is disabled on C:", "Medium",
                          "Enable BitLocker for data-at-rest protection")

        # 3.5 LSASS Protection
        cmd = """
        $lsass = Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
        if ($lsass.RunAsPPL -eq 1) {
            Write-Output "LSASS: PPL"
        } else {
            Write-Output "LSASS: NotProtected"
        }
        """
        output = self.run_powershell_remote(cmd)
        if output and "LSASS: PPL" in output:
            self.add_result("Security Hardening", "LSASS Protection", "PASS", 
                          "LSASS is running as Protected Process Light", "Info")
        else:
            self.add_result("Security Hardening", "LSASS Protection", "WARNING", 
                          "LSASS not running as PPL", "High",
                          "Enable LSASS PPL to protect against credential dumping")

        # 3.6 AMSI
        cmd = """
        $amsi = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Features" -Name "AMSIEnable" -ErrorAction SilentlyContinue
        if ($amsi.AMSIEnable -eq 0) {
            Write-Output "AMSI: Disabled"
        } else {
            Write-Output "AMSI: Enabled"
        }
        """
        output = self.run_powershell_remote(cmd)
        if output and "AMSI: Disabled" in output:
            self.add_result("Security Hardening", "AMSI", "FAIL", 
                          "AMSI is disabled", "Critical",
                          "Enable AMSI to prevent script-based attacks")
        else:
            self.add_result("Security Hardening", "AMSI", "PASS", 
                          "AMSI is enabled", "Info")

        # 3.7 LAPS
        cmd = """
        $laps = Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%LAPS%'" -ErrorAction SilentlyContinue
        if ($laps) {
            Write-Output "LAPS: Installed"
        } else {
            Write-Output "LAPS: NotInstalled"
        }
        """
        output = self.run_powershell_remote(cmd)
        if output and "LAPS: Installed" in output:
            self.add_result("Security Hardening", "LAPS", "PASS", 
                          "LAPS is installed", "Info")
        else:
            self.add_result("Security Hardening", "LAPS", "WARNING", 
                          "LAPS not installed", "Medium",
                          "Consider deploying LAPS for local admin password management")

        # 3.8 PowerShell Logging
        cmd = """
        $pslog = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
        if ($pslog.EnableScriptBlockLogging -eq 1) {
            Write-Output "PSLogging: Enabled"
        } else {
            Write-Output "PSLogging: Disabled"
        }
        """
        output = self.run_powershell_remote(cmd)
        if output and "PSLogging: Enabled" in output:
            self.add_result("Security Hardening", "PowerShell Script Block Logging", "PASS", 
                          "Script block logging is enabled", "Info")
        else:
            self.add_result("Security Hardening", "PowerShell Script Block Logging", "WARNING", 
                          "Script block logging is not enabled", "High",
                          "Enable PowerShell script block logging via Group Policy")

        # 3.9 Sysmon
        cmd = """
        $sysmon = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
        if ($sysmon.Status -eq "Running") {
            Write-Output "Sysmon: Running"
        } else {
            Write-Output "Sysmon: NotRunning"
        }
        """
        output = self.run_powershell_remote(cmd)
        if output and "Sysmon: Running" in output:
            self.add_result("Security Hardening", "Sysmon", "PASS", 
                          "Sysmon is running", "Info")
        else:
            self.add_result("Security Hardening", "Sysmon", "WARNING", 
                          "Sysmon is not installed or not running", "High",
                          "Deploy Sysmon with a production-tuned configuration")

    # ============================================================
    # SECTION 4: NETWORK SECURITY
    # ============================================================

    def audit_network_security(self):
        """Check network security settings."""
        print(f"\n{BLUE}[*] Checking Network Security...{RESET}")

        # 4.1 Port scan
        print(f"{BLUE}[*] Scanning common ports...{RESET}")
        common_ports = [445, 3389, 22, 5985, 5986, 135, 139, 1433, 3306, 8080, 8443, 88, 389, 636, 3268, 3269]
        open_ports = []
        for port in common_ports:
            if self.test_port(port):
                open_ports.append(str(port))

        if open_ports:
            self.add_result("Network Security", "Open Ports", "WARNING", 
                          f"Open ports: {', '.join(open_ports)}", "Medium",
                          "Review firewall rules; close unnecessary ports")
        else:
            self.add_result("Network Security", "Open Ports", "PASS", 
                          "No common attack ports open", "Info")

        # 4.2 LLMNR/mDNS
        if self.use_winrm:
            cmd = """
            $llmnr = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
            if ($llmnr.EnableMulticast -eq 0) {
                Write-Output "LLMNR: Disabled"
            } else {
                Write-Output "LLMNR: Enabled"
            }
            """
            output = self.run_powershell_remote(cmd)
            if output and "LLMNR: Disabled" in output:
                self.add_result("Network Security", "LLMNR/mDNS", "PASS", 
                              "LLMNR/mDNS is disabled", "Info")
            else:
                self.add_result("Network Security", "LLMNR/mDNS", "WARNING", 
                              "LLMNR/mDNS is enabled", "High",
                              "Disable LLMNR/mDNS to prevent responder attacks")

        # 4.3 NetBIOS
        if self.use_winrm:
            cmd = """
            $netbios = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.NetBIOSEnabled -eq $true }
            if ($netbios) {
                Write-Output "NetBIOS: Enabled"
            } else {
                Write-Output "NetBIOS: Disabled"
            }
            """
            output = self.run_powershell_remote(cmd)
            if output and "NetBIOS: Disabled" in output:
                self.add_result("Network Security", "NetBIOS", "PASS", 
                              "NetBIOS is disabled", "Info")
            else:
                self.add_result("Network Security", "NetBIOS", "WARNING", 
                              "NetBIOS is enabled", "High",
                              "Disable NetBIOS to reduce attack surface")

        # 4.4 SMB Signing
        if self.use_winrm:
            cmd = """
            $smb = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
            if ($smb.EnableSecuritySignature -eq $true) {
                Write-Output "SMB: Signed"
            } else {
                Write-Output "SMB: Unsigned"
            }
            """
            output = self.run_powershell_remote(cmd)
            if output and "SMB: Signed" in output:
                self.add_result("Network Security", "SMB Signing", "PASS", 
                              "SMB signing is enabled", "Info")
            else:
                self.add_result("Network Security", "SMB Signing", "FAIL", 
                              "SMB signing is disabled", "High",
                              "Enable SMB signing to prevent man-in-the-middle attacks")

    # ============================================================
    # SECTION 5: LOG ANALYSIS
    # ============================================================

    def audit_logs(self):
        """Analyze security logs."""
        print(f"\n{BLUE}[*] Analyzing Security Logs...{RESET}")

        if not self.use_winrm:
            self.add_result("Log Analysis", "Security Logs", "WARNING", 
                          "WinRM not available - log analysis skipped", "Info")
            return

        # 5.1 Failed Logins (last 30 days)
        cmd = """
        $start = (Get-Date).AddDays(-30)
        $events = Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4625]]" -MaxEvents 10000 -ErrorAction SilentlyContinue
        $count = ($events | Where-Object { $_.TimeCreated -gt $start }).Count
        Write-Output "FailedLogins: $count"
        """
        output = self.run_powershell_remote(cmd)
        if output:
            match = re.search(r'FailedLogins:\s*(\d+)', output)
            if match:
                count = int(match.group(1))
                if count > 100:
                    self.add_result("Log Analysis", "Failed Logins (30 days)", "WARNING", 
                                  f"{count} failed logins detected", "High",
                                  "Investigate source IPs; consider brute-force protection")
                elif count > 0:
                    self.add_result("Log Analysis", "Failed Logins (30 days)", "INFO", 
                                  f"{count} failed logins detected", "Info",
                                  "Monitor for unusual patterns")
                else:
                    self.add_result("Log Analysis", "Failed Logins (30 days)", "PASS", 
                                  "No failed logins detected in last 30 days", "Info")

        # 5.2 Account Lockouts
        cmd = """
        $start = (Get-Date).AddDays(-30)
        $events = Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4740]]" -MaxEvents 10000 -ErrorAction SilentlyContinue
        $count = ($events | Where-Object { $_.TimeCreated -gt $start }).Count
        Write-Output "Lockouts: $count"
        """
        output = self.run_powershell_remote(cmd)
        if output:
            match = re.search(r'Lockouts:\s*(\d+)', output)
            if match:
                count = int(match.group(1))
                if count > 5:
                    self.add_result("Log Analysis", "Account Lockouts", "WARNING", 
                                  f"{count} lockout events", "Medium",
                                  "Investigate potential brute-force or service account issues")
                else:
                    self.add_result("Log Analysis", "Account Lockouts", "PASS", 
                                  f"{count} lockout events", "Info")

        # 5.3 Privilege Escalation Events
        cmd = """
        $start = (Get-Date).AddDays(-30)
        $events = Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4673]]" -MaxEvents 10000 -ErrorAction SilentlyContinue
        $count = ($events | Where-Object { $_.TimeCreated -gt $start }).Count
        Write-Output "PrivEsc: $count"
        """
        output = self.run_powershell_remote(cmd)
        if output:
            match = re.search(r'PrivEsc:\s*(\d+)', output)
            if match:
                count = int(match.group(1))
                if count > 10:
                    self.add_result("Log Analysis", "Privilege Escalation Events", "WARNING", 
                                  f"{count} events detected", "High",
                                  "Review privileged service usage; investigate anomalies")
                else:
                    self.add_result("Log Analysis", "Privilege Escalation Events", "PASS", 
                                  f"{count} events detected", "Info")

    # ============================================================
    # SECTION 6: ACTIVE DIRECTORY AUDITING
    # ============================================================

    def audit_ad(self):
        """Audit Active Directory via LDAP."""
        print(f"\n{BLUE}[*] Auditing Active Directory...{RESET}")

        if not self.domain:
            self.add_result("Active Directory", "Domain", "WARNING", 
                          "No domain specified - AD checks skipped", "Info")
            return

        try:
            # Connect to LDAP
            server = ldap3.Server(f"{self.domain}", get_info=ldap3.ALL)
            conn = ldap3.Connection(server, user=f"{self.domain}\\{self.username}", 
                                   password=self.password, auto_bind=True)

            if not conn.bind():
                self.add_result("Active Directory", "LDAP Connection", "WARNING", 
                              "Unable to bind to LDAP", "Medium")
                return

            # 6.1 Domain Admins
            search_filter = "(&(objectCategory=group)(cn=Domain Admins))"
            conn.search(search_base=f"DC={self.domain.replace('.', ',DC=')}", 
                       search_filter=search_filter, attributes=['member'])
            if conn.entries:
                members = conn.entries[0]['member'].values
                self.add_result("Active Directory", "Domain Admins", "PASS", 
                              f"{len(members)} Domain Admins found", "Info",
                              "Review members regularly; follow least privilege")

            # 6.2 Kerberoastable Accounts
            search_filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))"
            conn.search(search_base=f"DC={self.domain.replace('.', ',DC=')}", 
                       search_filter=search_filter, attributes=['sAMAccountName', 'servicePrincipalName'])
            kerberoastable = conn.entries
            if len(kerberoastable) > 0:
                accounts = [e['sAMAccountName'].value for e in kerberoastable if 'sAMAccountName' in e]
                self.add_result("Active Directory", "Kerberoastable Accounts", "WARNING", 
                              f"{len(kerberoastable)} accounts with SPNs set: {', '.join(accounts[:5])}{'...' if len(accounts) > 5 else ''}", 
                              "High", "Review SPNs; consider using gMSA accounts")
            else:
                self.add_result("Active Directory", "Kerberoastable Accounts", "PASS", 
                              "No Kerberoastable accounts found", "Info")

            # 6.3 AS-REP Roastable Accounts
            search_filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
            conn.search(search_base=f"DC={self.domain.replace('.', ',DC=')}", 
                       search_filter=search_filter, attributes=['sAMAccountName'])
            asrep = conn.entries
            if len(asrep) > 0:
                accounts = [e['sAMAccountName'].value for e in asrep if 'sAMAccountName' in e]
                self.add_result("Active Directory", "AS-REP Roastable Accounts", "FAIL", 
                              f"{len(asrep)} accounts with pre-auth disabled: {', '.join(accounts[:5])}{'...' if len(accounts) > 5 else ''}",
                              "High", "Enable Kerberos pre-authentication for all accounts")
            else:
                self.add_result("Active Directory", "AS-REP Roastable Accounts", "PASS", 
                              "No AS-REP roastable accounts found", "Info")

            # 6.4 Unconstrained Delegation
            search_filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
            conn.search(search_base=f"DC={self.domain.replace('.', ',DC=')}", 
                       search_filter=search_filter, attributes=['dNSHostName'])
            unconstrained = conn.entries
            if len(unconstrained) > 0:
                computers = [e['dNSHostName'].value for e in unconstrained if 'dNSHostName' in e]
                self.add_result("Active Directory", "Unconstrained Delegation", "WARNING", 
                              f"{len(unconstrained)} computers with unconstrained delegation", 
                              "High", "Review delegation settings; use constrained delegation where possible")
            else:
                self.add_result("Active Directory", "Unconstrained Delegation", "PASS", 
                              "No unconstrained delegation detected", "Info")

            # 6.5 Password Policy
            conn.search(search_base=f"DC={self.domain.replace('.', ',DC=')}", 
                       search_filter="(objectClass=domain)", 
                       attributes=['minPwdLength', 'pwdHistoryLength', 'maxPwdAge', 'pwdProperties'])
            if conn.entries:
                entry = conn.entries[0]
                issues = []
                if 'minPwdLength' in entry and int(entry['minPwdLength']) < 8:
                    issues.append("Min password length < 8")
                if 'pwdHistoryLength' in entry and int(entry['pwdHistoryLength']) < 5:
                    issues.append("Password history count < 5")
                if 'pwdProperties' in entry and (int(entry['pwdProperties']) & 1) == 0:
                    issues.append("Password complexity disabled")

                if issues:
                    self.add_result("Active Directory", "Password Policy", "FAIL", 
                                  f"Issues: {'; '.join(issues)}", "High",
                                  "Align password policy with NIST/ISO standards")
                else:
                    self.add_result("Active Directory", "Password Policy", "PASS", 
                                  "Password policy meets best practices", "Info")

            conn.unbind()

        except Exception as e:
            self.add_result("Active Directory", "AD Audit", "WARNING", 
                          f"Error performing AD audit: {str(e)}", "Medium")

    # ============================================================
    # SECTION 7: MALWARE READINESS
    # ============================================================

    def audit_malware_readiness(self):
        """Check malware readiness settings."""
        print(f"\n{BLUE}[*] Checking Malware Readiness...{RESET}")

        if not self.use_winrm:
            self.add_result("Malware Readiness", "Checks", "WARNING", 
                          "WinRM not available - skipping", "Info")
            return

        # 7.1 AppLocker
        cmd = """
        $applocker = Get-AppLockerPolicy -ErrorAction SilentlyContinue
        if ($applocker.Rules.Count -gt 0) {
            Write-Output "AppLocker: $($applocker.Rules.Count) rules"
        } else {
            Write-Output "AppLocker: NoRules"
        }
        """
        output = self.run_powershell_remote(cmd)
        if output and "AppLocker: NoRules" not in output:
            self.add_result("Malware Readiness", "AppLocker", "PASS", 
                          output, "Info")
        else:
            self.add_result("Malware Readiness", "AppLocker", "WARNING", 
                          "AppLocker has no rules defined", "High",
                          "Deploy AppLocker policies to control application execution")

        # 7.2 Windows Defender ATP
        cmd = """
        $def = Get-MpComputerStatus
        Write-Output "RealTime: $($def.RealTimeProtectionEnabled)"
        Write-Output "IoavProtection: $($def.IoavProtectionEnabled)"
        Write-Output "CloudProtection: $($def.CloudProtectionEnabled)"
        """
        output = self.run_powershell_remote(cmd)
        if output:
            if "RealTime: True" in output:
                self.add_result("Malware Readiness", "Real-Time Protection", "PASS", 
                              "Real-time protection is enabled", "Info")
            else:
                self.add_result("Malware Readiness", "Real-Time Protection", "FAIL", 
                              "Real-time protection is disabled", "Critical",
                              "Enable real-time protection immediately")

    # ============================================================
    # GENERATE REPORT
    # ============================================================

    def generate_report(self):
        """Generate HTML and text reports."""
        print(f"\n{GREEN}[*] Generating reports...{RESET}")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        html_file = f"audit_report_{self.target}_{timestamp}.html"
        txt_file = f"audit_report_{self.target}_{timestamp}.txt"

        # Count statistics
        total = len(self.results)
        passed = len([r for r in self.results if r['status'] == 'PASS'])
        warnings = len([r for r in self.results if r['status'] == 'WARNING'])
        failed = len([r for r in self.results if r['status'] == 'FAIL'])
        critical = len([r for r in self.results if r['risk'] == 'Critical'])

        # Generate HTML report
        html_content = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Linux Remote Security Audit Report - {self.target}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        .summary {{ display: flex; gap: 20px; flex-wrap: wrap; margin: 20px 0; }}
        .summary-card {{ flex: 1; min-width: 120px; padding: 15px; border-radius: 8px; text-align: center; color: white; }}
        .summary-card.total {{ background: #2c3e50; }}
        .summary-card.pass {{ background: #27ae60; }}
        .summary-card.warning {{ background: #f39c12; }}
        .summary-card.fail {{ background: #e74c3c; }}
        .summary-card.critical {{ background: #c0392b; }}
        .summary-card .number {{ font-size: 32px; font-weight: bold; }}
        .summary-card .label {{ font-size: 14px; opacity: 0.9; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 13px; }}
        th {{ background: #34495e; color: white; padding: 10px; text-align: left; }}
        td {{ padding: 8px; border-bottom: 1px solid #ecf0f1; vertical-align: top; }}
        tr:hover {{ background: #f8f9fa; }}
        .status-badge {{ padding: 3px 10px; border-radius: 12px; font-weight: bold; font-size: 11px; display: inline-block; }}
        .status-pass {{ background: #d4edda; color: #155724; }}
        .status-fail {{ background: #f8d7da; color: #721c24; }}
        .status-warning {{ background: #fff3cd; color: #856404; }}
        .status-info {{ background: #d1ecf1; color: #0c5460; }}
        .risk-critical {{ background: #e74c3c; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; }}
        .risk-high {{ background: #e67e22; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; }}
        .risk-medium {{ background: #f1c40f; color: #333; padding: 2px 8px; border-radius: 4px; font-size: 11px; }}
        .risk-low {{ background: #3498db; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; }}
        .risk-info {{ background: #95a5a6; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; }}
        .recommendation {{ background: #f0f8ff; padding: 6px; border-left: 4px solid #3498db; margin-top: 4px; font-style: italic; }}
        .footer {{ margin-top: 30px; border-top: 1px solid #ecf0f1; padding-top: 20px; text-align: center; color: #7f8c8d; font-size: 12px; }}
        .metadata {{ background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 10px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Linux Remote Security Audit Report</h1>
        <div class="metadata">
            <p><strong>Target:</strong> {self.target}</p>
            <p><strong>Username:</strong> {self.username}</p>
            <p><strong>Domain:</strong> {self.domain or 'N/A'}</p>
            <p><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>

        <div class="summary">
            <div class="summary-card total"><div class="number">{total}</div><div class="label">Total Checks</div></div>
            <div class="summary-card pass"><div class="number">{passed}</div><div class="label">Passed</div></div>
            <div class="summary-card warning"><div class="number">{warnings}</div><div class="label">Warnings</div></div>
            <div class="summary-card fail"><div class="number">{failed}</div><div class="label">Failed</div></div>
            <div class="summary-card critical"><div class="number">{critical}</div><div class="label">Critical Issues</div></div>
        </div>

        <h2>📋 Executive Summary</h2>
        <p>
            <strong>Risk Score:</strong>
            {f"{RED}🔴 HIGH RISK - Immediate action required{RESET}" if critical > 0 else 
             f"{YELLOW}🟠 ELEVATED RISK - Action required within 30 days{RESET}" if len([r for r in self.results if r['risk'] in ['High', 'Medium']]) > 5 else 
             f"{GREEN}🟡 MODERATE RISK - Plan remediation{RESET}" if len([r for r in self.results if r['risk'] in ['High', 'Medium']]) > 0 else 
             f"{GREEN}🟢 LOW RISK - Maintain current posture{RESET}"}
        </p>
        <p><strong>Critical Findings:</strong> {critical}</p>

        <h2>📊 Detailed Findings</h2>
        <table>
            <thead>
                <tr><th>Category</th><th>Check</th><th>Status</th><th>Risk</th><th>Details</th><th>Recommendation</th></tr>
            </thead>
            <tbody>
'''

        for r in self.results:
            status_class = {
                'PASS': 'status-pass', 'FAIL': 'status-fail', 
                'WARNING': 'status-warning', 'INFO': 'status-info'
            }.get(r['status'], 'status-info')
            
            risk_class = {
                'Critical': 'risk-critical', 'High': 'risk-high',
                'Medium': 'risk-medium', 'Low': 'risk-low'
            }.get(r['risk'], 'risk-info')

            html_content += f'''
                <tr>
                    <td><strong>{r['category']}</strong></td>
                    <td>{r['check']}</td>
                    <td><span class="status-badge {status_class}">{r['status']}</span></td>
                    <td><span class="{risk_class}">{r['risk']}</span></td>
                    <td>{r['details']}</td>
                    <td>{r.get('recommendation', '')}</td>
                </tr>
            '''

        html_content += f'''
            </tbody>
        </table>

        <h2>⚠️ Critical Issues</h2>
        <ul>
'''

        if critical == 0:
            html_content += '<li>✅ No critical issues detected.</li>'
        else:
            for r in [r for r in self.results if r['risk'] == 'Critical']:
                html_content += f'<li><strong>{r["category"]}:</strong> {r["check"]} – {r["recommendation"]}</li>'

        html_content += f'''
        </ul>

        <h2>📝 Recommendations Summary</h2>
        <ul>
'''

        recommendations = set([r.get('recommendation', '') for r in self.results if r.get('recommendation')])
        if not recommendations:
            html_content += '<li>✅ No recommendations.</li>'
        else:
            for rec in sorted(recommendations):
                if rec:
                    html_content += f'<li>{rec}</li>'

        html_content += f'''
        </ul>

        <div class="footer">
            <p>Linux Remote Security Auditor v1.0 | Generated by Charles Ndirangu</p>
            <p>This report is for authorized internal use only. Contains confidential security audit findings.</p>
        </div>
    </div>
</body>
</html>
'''

        with open(html_file, 'w') as f:
            f.write(html_content)

        # Generate text report
        with open(txt_file, 'w') as f:
            f.write(f"""
========================================
LINUX REMOTE SECURITY AUDIT REPORT
========================================
Target: {self.target}
Username: {self.username}
Domain: {self.domain or 'N/A'}
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
========================================

SUMMARY
--------
Total Checks: {total}
Passed: {passed}
Warnings: {warnings}
Failed: {failed}
Critical Issues: {critical}

CRITICAL ISSUES
---------------
""")
            for r in [r for r in self.results if r['risk'] == 'Critical']:
                f.write(f"  [{r['category']}] {r['check']}: {r['details']}\n")
                f.write(f"    → {r.get('recommendation', 'No recommendation')}\n\n")

            f.write("""
DETAILED FINDINGS
-----------------
""")
            for r in self.results:
                f.write(f"[{r['category']}] {r['check']}\n")
                f.write(f"  Status: {r['status']} | Risk: {r['risk']}\n")
                f.write(f"  Details: {r['details']}\n")
                if r.get('recommendation'):
                    f.write(f"  → {r['recommendation']}\n")
                f.write("\n")

        print(f"\n{GREEN}✅ Reports generated:{RESET}")
        print(f"   📄 HTML: {html_file}")
        print(f"   📄 Text: {txt_file}")

        return html_file, txt_file

    # ============================================================
    # MAIN AUDIT FUNCTION
    # ============================================================

    def run_audit(self):
        """Execute the full audit."""
        self.print_banner()

        print(f"{CYAN}[*] Target: {self.target}{RESET}")
        print(f"{CYAN}[*] Username: {self.username}{RESET}")
        print(f"{CYAN}[*] Domain: {self.domain or 'N/A'}{RESET}")

        # Test connection
        if not self.test_connection():
            print(f"{RED}[!] Target {self.target} is unreachable{RESET}")
            sys.exit(1)

        print(f"{GREEN}[+] Target is reachable{RESET}")

        # Check WinRM
        if self.use_winrm and self.test_port(5985):
            print(f"{GREEN}[+] WinRM port 5985 is open{RESET}")
        elif self.use_winrm and self.test_port(5986):
            print(f"{GREEN}[+] WinRM port 5986 is open (HTTPS){RESET}")
        else:
            print(f"{YELLOW}[!] WinRM not available - some checks will be skipped{RESET}")
            self.use_winrm = False

        # Run all audit sections
        self.audit_system_info()
        self.audit_patches()
        self.audit_security_hardening()
        self.audit_network_security()
        self.audit_logs()
        self.audit_ad()
        self.audit_malware_readiness()

        # Generate reports
        html_file, txt_file = self.generate_report()

        # Print summary to console
        print(f"\n{CYAN}========================================{RESET}")
        print(f"{BOLD}{GREEN}✅ AUDIT COMPLETE!{RESET}")
        print(f"{CYAN}========================================{RESET}")
        print(f"\n{GREEN}Results:{RESET}")
        print(f"   Total Checks: {len(self.results)}")
        print(f"   {GREEN}✅ Passed: {len([r for r in self.results if r['status'] == 'PASS'])}{RESET}")
        print(f"   {YELLOW}⚠️ Warnings: {len([r for r in self.results if r['status'] == 'WARNING'])}{RESET}")
        print(f"   {RED}❌ Failed: {len([r for r in self.results if r['status'] == 'FAIL'])}{RESET}")
        print(f"   {RED}🔴 Critical Issues: {len([r for r in self.results if r['risk'] == 'Critical'])}{RESET}")

        print(f"\n{GREEN}📄 Reports saved to:{RESET}")
        print(f"   HTML: {html_file}")
        print(f"   Text: {txt_file}")

        return self.results


# ============================================================
# MAIN ENTRY POINT
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Linux Remote Security Auditor - Remote Windows Security Audit Tool",
        epilog="Example: python3 remote_audit.py -t 192.168.1.100 -u Administrator -p P@ssw0rd -d domain.local"
    )
    parser.add_argument('-t', '--target', required=True, help='Target IP or hostname')
    parser.add_argument('-u', '--username', required=True, help='Username for authentication')
    parser.add_argument('-p', '--password', required=True, help='Password for authentication')
    parser.add_argument('-d', '--domain', help='Domain name (for AD checks)')
    parser.add_argument('--no-winrm', action='store_true', help='Disable WinRM (use SMB only)')
    parser.add_argument('--port', type=int, default=445, help='SMB port (default: 445)')

    args = parser.parse_args()

    # Create auditor instance
    auditor = RemoteAuditor(
        target=args.target,
        username=args.username,
        password=args.password,
        domain=args.domain,
        port=args.port,
        use_winrm=not args.no_winrm
    )

    # Run the audit
    auditor.run_audit()


if __name__ == '__main__':
    main()
