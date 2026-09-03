# AuditForensics Ultimate - Complete Documentation

**Version**: 2.0
**Release Date**: 2026-09-03
**Author**: Enhanced from Charles Ndirangu's original work
**Repository**: [Seniorcaptain/AuditForensics](https://github.com/Seniorcaptain/AuditForensics)

---

## 📋 Table of Contents

1. [Introduction](#1-introduction)
2. [Key Features](#2-key-features)
3. [Architecture Overview](#3-architecture-overview)
4. [Installation](#4-installation)
5. [Command Reference](#5-command-reference)
6. [Usage Examples](#6-usage-examples)
7. [IP Range Scanning](#7-ip-range-scanning)
8. [Reports & Outputs](#8-reports--outputs)
9. [Enhancement Modules](#9-enhancement-modules)
10. [Customisation Guide](#10-customisation-guide)
11. [Troubleshooting](#11-troubleshooting)
12. [Security Considerations](#12-security-considerations)
13. [Performance & Scaling](#13-performance--scaling)
14. [Changelog](#14-changelog)
15. [License & Credits](#15-license--credits)
16. [Support & Community](#16-support--community)
17. [Appendix](#17-appendix)

---

## 1. Introduction

AuditForensics Ultimate is a **next-generation, enterprise-grade cybersecurity audit tool** for Windows environments. It combines a proven 70+ check auditing engine with modern security analytics to deliver comprehensive visibility into your organisation's security posture.

### 1.1 What It Does

- **Audits** Windows systems, Active Directory, GRC compliance, system hardening, network security, and malware readiness.
- **Scans** single hosts, multiple targets (hostnames/IPs), or entire IP ranges (CIDR or start-end).
- **Enhances** findings with Sigma rules, attack correlation, baseline anomaly detection, and AI-driven risk prioritisation.
- **Aggregates** results across hundreds of machines into a single fleet-wide dashboard.

### 1.2 Available Versions

| Version | Language | Best For |
|---------|----------|----------|
| **PowerShell** | `.ps1` | Native Windows, full local/remote auditing, maximum performance |
| **Python** | `.py` | Cross-platform orchestration, CI/CD pipelines, automation servers |

Both versions share the same core engine and produce identical reports. The Python version embeds the PowerShell script and acts as a wrapper, making it ideal for Linux-based automation servers.

---

## 2. Key Features

### 2.1 Core Auditing (70+ Checks)

| Category | Checks Performed |
|----------|-------------------|
| **Vulnerability Scanning** | Pending Windows Updates, SMB Signing, Open Common Ports (445, 3389, 22, 5985, 5986, 135, 139, 1433, 3306, 8080, 8443) |
| **Active Directory Auditing** | Domain Admins Count, Kerberoastable Accounts, AS-REP Roastable Accounts, Unconstrained Delegation, Password Policy (length, history, age, complexity) |
| **GRC & Compliance** | UAC Status, Logon Audit Policy (success/failure), Account Lockout Threshold, LAPS Installation |
| **System Hardening** | Windows Defender, Firewall Profiles, BitLocker, PowerShell Script Block Logging, LSASS Protection (PPL), AMSI, Sysmon |
| **Network Security** | LLMNR/mDNS, NetBIOS Status |
| **Log Analysis (30-day)** | Failed Logins (Event 4625), Privilege Escalation Events (4673), Account Lockouts (4740) |
| **Malware Readiness** | AppLocker Rules, Real-Time Protection |

### 2.2 Enhancement Modules (Optional)

| Module | Description |
|--------|-------------|
| **Sigma Engine** | 8+ built-in detection rules (e.g., SIG-001: SMB Signing Disabled, SIG-004: Firewall Disabled). Matches findings against rule conditions. |
| **Correlation Engine** | Identifies attack chains: **NTLM Reflection** (Spooler + SMB Signing off + abnormal NTLM activity), **Kerberoast** (Kerberoastable accounts), **Credential Dumping** (LSASS not protected + AV disabled). |
| **Baseline Anomaly Detection** | Stores SHA-256 hash of all results and list of finding IDs. Flags configuration changes and new findings on subsequent runs. |
| **AI-Driven Risk Prioritisation** | Sends findings to OpenAI (`gpt-4o-mini`) for a risk score (1-10), reasoning, and recommended action. Falls back to heuristic scoring if API key is missing. |

### 2.3 Target Discovery & Scanning

| Feature | Description |
|---------|-------------|
| **Single Host** | Audit the local machine only. |
| **Multiple Targets** | Scan a list of hostnames or IP addresses in parallel. |
| **IP Range** | Scan entire subnets (CIDR, e.g., `192.168.1.0/24`) or custom ranges (e.g., `10.0.0.1-10.0.0.254`). |
| **Host Discovery** | Ping and WinRM availability testing; `-PingOnly` mode lists reachable hosts without auditing. |
| **Parallel Throttling** | Control concurrent scans (default 20) to manage network load. |
| **Remote Credentials** | Support for alternate credentials (domain or local). |

---

## 3. Architecture Overview

### 3.1 PowerShell Version

```text
+-------------------------------------------------------------------+
|                    AuditForensics_Ultimate.ps1                    |
+-------------------------------------------------------------------+
|  +-------------+    +--------------+    +------------------+      |
|  |  Parameter  |--->|  Target      |--->|  Expansion &     |      |
|  |  Parsing    |    |  Resolution  |    |  Host Discovery  |      |
|  +-------------+    +--------------+    +------------------+      |
|                              |                                    |
|                              v                                    |
|  +----------------------------------------------------------+    |
|  |  LOCAL or REMOTE (WinRM)     +----------------------+     |    |
|  |  +----------------------+    |   Aggregated Report  |     |    |
|  |  | 70+ Security Checks  |    |   - HTML Dashboard   |     |    |
|  |  | - Vulnerabilities    |    |   - CSV Summary      |     |    |
|  |  | - AD Auditing        |    |   - JSON Export      |     |    |
|  |  | - GRC Compliance     |    +----------------------+     |    |
|  |  | - System Hardening   |                                 |    |
|  |  +----------------------+                                 |    |
|  +----------------------------------------------------------+    |
|                              |                                    |
|                              v                                    |
|  +----------------------------------------------------------+    |
|  |  Enhancement Engine (optional)                            |    |
|  |  +---------+ +-----------+ +---------+ +---------+        |    |
|  |  |  Sigma  | |Correlation| |Baseline | |   AI    |        |    |
|  |  +---------+ +-----------+ +---------+ +---------+        |    |
|  +----------------------------------------------------------+    |
+-------------------------------------------------------------------+
```

### 3.2 Python Version (Orchestrator)

```text
+-------------------------------------------------------------------+
|                    auditforensics_ultimate.py                     |
+-------------------------------------------------------------------+
|  +-------------+    +--------------+    +------------------+      |
|  |  CLI        |--->|  IP Range    |--->|  Host Discovery  |      |
|  |  Parsing    |    |  Expansion   |    |  (Ping + WinRM)  |      |
|  +-------------+    +--------------+    +------------------+      |
|                              |                                    |
|                              v                                    |
|  +----------------------------------------------------------+    |
|  |  Write embedded PowerShell script to temp file            |    |
|  +----------------------------------------------------------+    |
|                              |                                    |
|                              v                                    |
|  +----------------------------------------------------------+    |
|  |  Parallel Execution (ThreadPoolExecutor)                  |    |
|  |  +--------------------------------------------------+    |    |
|  |  |  For each target: subprocess -> powershell        |    |    |
|  |  |  -> Invoke-Command -ComputerName $target           |    |    |
|  |  |  -> -FilePath $temp_ps1 -Arguments ...              |    |    |
|  |  +--------------------------------------------------+    |    |
|  +----------------------------------------------------------+    |
|                              |                                    |
|                              v                                    |
|  +----------------------------------------------------------+    |
|  |  Aggregated reports (from PowerShell's output)            |    |
|  +----------------------------------------------------------+    |
+-------------------------------------------------------------------+
```

### 3.3 Key Components

| Component | Description |
|-----------|-------------|
| **Target Resolution** | Expands CIDR/range IPs and tests connectivity (ping + WinRM). |
| **Local Audit Engine** | The original `UnifiedSecurityAuditor.ps1` logic with 70+ checks. |
| **Remote Execution** | Uses WinRM (`Invoke-Command`) to run the script on multiple machines in parallel. |
| **Sigma Engine** | Built-in rule set; extensible via `$SigmaRules` array. |
| **Correlation Engine** | Pre-defined attack patterns; extensible via `$AttackPatterns` array. |
| **Baseline Manager** | Stores hashes and finding IDs in `baseline.json`; flags changes. |
| **AI Prioritizer** | Calls OpenAI API (or falls back to heuristic scoring). |
| **Report Generator** | Produces HTML, CSV, and JSON outputs (per-host and aggregated). |

---

## 4. Installation

### 4.1 PowerShell Version

#### Prerequisites

- **Windows 7 / Server 2008 R2 or later** with PowerShell 5.1+.
- **Administrator privileges** (required for system and AD checks).
- **Internet connection** (for Bootstrap/Chart.js CDN in HTML report).
- **Active Directory module** (optional; for AD checks. Install via RSAT if needed).
- **OpenAI API key** (optional; for AI enrichment; set as `$env:OPENAI_API_KEY`).

#### Steps

1. Download `AuditForensics_Ultimate.ps1` to any folder.
2. Optionally place it on a network share if you plan to run it remotely (multi-target scans).
3. No additional modules or installations are required.

#### Verify Installation

```powershell
# Quick test - should show help
Get-Help .\AuditForensics_Ultimate.ps1 -Detailed
```

---

### 4.2 Python Version

#### Prerequisites

- **Python 3.8+** (any OS: Windows, Linux, macOS).
- **pip** package manager.

#### Installation

```bash
# Install required packages
pip install click jinja2 pyyaml requests

# Download the script
curl -O https://your-repo/auditforensics_ultimate.py
# or save it manually
```

#### Verify Installation

```bash
# Quick test
python auditforensics_ultimate.py --help
```

---

### 4.3 Environment Variables (Optional)

| Variable | Purpose | Setting |
|----------|---------|---------|
| `OPENAI_API_KEY` | AI enrichment | PowerShell: `$env:OPENAI_API_KEY = "sk-..."` <br> Python: `export OPENAI_API_KEY="sk-..."` |

---

## 5. Command Reference

### 5.1 PowerShell - All Parameters

| Parameter | Type | Description | Default |
|-----------|------|--------------|---------|
| `-Targets` | `string[]` | List of computer names or IP addresses | `$null` (local only) |
| `-IPRange` | `string` | CIDR (e.g., `192.168.1.0/24`) or start-end (e.g., `10.0.0.1-10.0.0.254`) | `$null` |
| `-PingOnly` | `switch` | Only list reachable hosts; do not audit | `$false` |
| `-PingTimeout` | `int` | Milliseconds for ping timeout | `1000` |
| `-ThrottleLimit` | `int` | Max parallel remote scans | `20` |
| `-Credential` | `PSCredential` | Alternate credentials for remote access | `$null` |
| `-OutputPath` | `string` | Directory to save reports | `$env:USERPROFILE\Desktop\AuditReports` |
| `-Sigma` | `switch` | Enable Sigma rule checks | `$false` |
| `-Correlate` | `switch` | Enable attack correlation | `$false` |
| `-Baseline` | `switch` | Enable baseline anomaly detection | `$false` |
| `-AIEnrich` | `switch` | Enable AI prioritisation | `$false` |
| `-Demo` | `switch` | Run with sample data (no system scan) | `$false` |

---

### 5.2 Python - All Flags

| Flag | Type | Description | Default |
|------|------|--------------|---------|
| `--targets`, `-t` | multiple | Hostnames or IP addresses | `[]` |
| `--target-file`, `-f` | path | File with one target per line | `None` |
| `--ip-range` | string | CIDR or start-end IP range | `None` |
| `--ping-only` | flag | Only list reachable hosts | `False` |
| `--throttle` | int | Parallel threads | `20` |
| `--output-path`, `-o` | path | Output directory | `.` |
| `--sigma` | flag | Enable Sigma checks | `False` |
| `--correlate` | flag | Enable correlation | `False` |
| `--baseline` | flag | Enable baseline | `False` |
| `--ai-enrich` | flag | Enable AI prioritisation | `False` |
| `--demo` | flag | Demo mode (no real scan) | `False` |
| `--username` | string | Remote username (optional) | `None` |
| `--password` | string | Remote password (optional) | `None` |

---

## 6. Usage Examples

### 6.1 PowerShell Examples

#### Basic Local Audit

```powershell
# Simple audit of the local machine
.\AuditForensics_Ultimate.ps1

# Audit with Sigma and Correlation
.\AuditForensics_Ultimate.ps1 -Sigma -Correlate

# Full enhancement suite
.\AuditForensics_Ultimate.ps1 -Sigma -Correlate -Baseline -AIEnrich
```

#### Multi-Target (Hostnames)

```powershell
# Scan specific machines
.\AuditForensics_Ultimate.ps1 -Targets "PC01","PC02","PC03" -Sigma -Correlate

# Scan all computers from Active Directory
$computers = (Get-ADComputer -Filter *).Name
.\AuditForensics_Ultimate.ps1 -Targets $computers -ThrottleLimit 30
```

#### IP Range Scanning

```powershell
# Scan all hosts in a /24 subnet
.\AuditForensics_Ultimate.ps1 -IPRange "192.168.1.0/24" -ThrottleLimit 30 -Sigma -Correlate

# Scan a custom range
.\AuditForensics_Ultimate.ps1 -IPRange "10.0.0.1-10.0.0.100" -ThrottleLimit 15

# Discover hosts only (no audit)
.\AuditForensics_Ultimate.ps1 -IPRange "10.0.0.1-10.0.0.254" -PingOnly
```

#### With Credentials

```powershell
$cred = Get-Credential
.\AuditForensics_Ultimate.ps1 -Targets @("SRV01","SRV02") -Credential $cred -Sigma
```

#### Demo Mode (Cross-Platform Testing)

```powershell
.\AuditForensics_Ultimate.ps1 -Demo -Sigma -Correlate -Baseline
```

---

### 6.2 Python Examples

#### Basic Local Audit (Windows only)

```bash
python auditforensics_ultimate.py --sigma --correlate
```

#### Multi-Target

```bash
# Specific hosts
python auditforensics_ultimate.py --targets PC01 PC02 PC03 --sigma --correlate

# From a file
python auditforensics_ultimate.py --target-file hosts.txt --throttle 30
```

#### IP Range Scanning

```bash
# CIDR subnet
python auditforensics_ultimate.py --ip-range "192.168.1.0/24" --throttle 30 --sigma

# Custom range
python auditforensics_ultimate.py --ip-range "10.0.0.1-10.0.0.100" --correlate

# Discover hosts
python auditforensics_ultimate.py --ip-range "10.0.0.1-10.0.0.254" --ping-only
```

#### With Credentials

```bash
python auditforensics_ultimate.py --targets SERVER01 --username domain\user --password 'pass'
```

#### Demo Mode (Cross-Platform)

```bash
python auditforensics_ultimate.py --demo --sigma --correlate
```

---

## 7. IP Range Scanning

### 7.1 Supported Formats

| Format | Example | Description |
|--------|---------|--------------|
| **CIDR** | `192.168.1.0/24` | Network prefix notation - scans 256 addresses |
| **Range** | `10.0.0.1-10.0.0.254` | Start-end notation - scans 254 addresses |
| **Single IP** | `192.168.1.10` | Scans a single IP |

### 7.2 Discovery Logic

```text
+----------------------+
|  Expand IP Range     |
|  (CIDR or Range)     |
+-----------+----------+
            v
+----------------------+
|  For each IP:        |
|  1. Ping (ICMP)      |
|  2. Test-WSMan       |
+-----------+----------+
            v
+----------------------+
|  Build target list   |
|  (only alive +       |
|   WinRM reachable)   |
+----------------------+
```

### 7.3 Performance Notes

- A `/24` subnet (256 IPs) typically yields **200-230** reachable hosts in a corporate network.
- With `-ThrottleLimit 30`, scanning all 200 hosts takes ~40-100 minutes (2-5 min per host).
- Ping and WinRM checks add a small overhead (~2-3 seconds per IP).

### 7.4 WinRM over IP

**Important**: WinRM may not accept IP addresses by default. To enable:

```powershell
# Trust all hosts (not recommended for production)
winrm set winrm/config/client @{TrustedHosts="*"}

# Trust specific subnet
winrm set winrm/config/client @{TrustedHosts="192.168.1.*"}

# Trust multiple IPs
winrm set winrm/config/client @{TrustedHosts="192.168.1.10,192.168.1.20"}
```

Alternatively, use hostnames and ensure DNS resolution works.

---

## 8. Reports & Outputs

### 8.1 File Structure

```text
AuditReports/
├── AuditForensics_<hostname>_<timestamp>.html   # Per-host HTML
├── AuditForensics_<hostname>_<timestamp>.csv    # Per-host CSV
├── AuditForensics_<hostname>_<timestamp>.json   # Per-host JSON
├── AuditForensics_Aggregated_<timestamp>.html   # Fleet-wide dashboard (multi-target)
├── AuditForensics_Aggregated_<timestamp>.csv    # Fleet-wide summary
├── AuditForensics_Aggregated_<timestamp>.json   # Fleet-wide JSON
└── baseline.json                                # Baseline data (if -Baseline used)
```

### 8.2 Per-Host Reports

| File | Format | Contents |
|------|--------|----------|
| **HTML** | Bootstrap + Chart.js | Executive summary, severity doughnut chart, top AI risks, Sigma findings, attack correlations, baseline anomalies, original audit summary table |
| **CSV** | Comma-separated | All `AuditResults` (Category, Check, Status, Risk, Details, Recommendation) |
| **JSON** | Structured JSON | Complete data: `Results`, `Findings`, `SigmaFindings`, `Correlations`, `Summary` - ideal for SIEM or automation |

### 8.3 Aggregated Reports (Multi-Target Only)

| File | Format | Contents |
|------|--------|----------|
| **HTML** | Bootstrap | Summary cards (Total Machines, Critical Machines, High Machines, Clean Machines), machine-by-machine table, top 5 critical machines |
| **CSV** | Comma-separated | One row per machine: Computer, Status, TotalChecks, Passed, Failed, Warnings, Critical, High |
| **JSON** | Structured JSON | Machine-level data for all hosts, ready for further analysis |

### 8.4 Baseline File (`baseline.json`)

```json
{
  "Hash": "a1b2c3d4e5f6...",
  "FindingIDs": ["SMB Signing|FAIL", "UAC Enabled|FAIL"],
  "Timestamp": "2026-09-03 14:30:00"
}
```

---

## 9. Enhancement Modules

### 9.1 Sigma Engine

#### Built-in Rules

| ID | Title | Severity | Detection |
|----|-------|----------|-----------|
| SIG-001 | SMB Signing Disabled | High | SMB Signing = FAIL |
| SIG-002 | Spooler Running (NTLM Coercion) | Medium | Spooler = RUNNING |
| SIG-003 | UAC Disabled | Medium | UAC Enabled = FAIL |
| SIG-004 | Firewall Disabled | Critical | Windows Firewall = FAIL |
| SIG-005 | AppLocker Not Configured | High | AppLocker = WARNING |
| SIG-006 | LLMNR/mDNS Enabled | High | LLMNR / mDNS = WARNING |
| SIG-007 | AS-REP Roastable Accounts | High | AS-REP Roastable Accounts = FAIL |
| SIG-008 | LSASS Not Protected (PPL) | High | LSASS Protection (PPL) = WARNING |

#### Extending Rules

```powershell
$SigmaRules = @(
    # ... existing rules ...
    @{
        id = "SIG-009"
        title = "My Custom Rule"
        level = "high"
        description = "Description of the condition."
        detection = @{
            Check = "Windows Defender"
            Status = "FAIL"
        }
    }
)
```

---

### 9.2 Correlation Engine

#### Built-in Attack Patterns

| Attack Chain | Severity | Stages | Remediation |
|--------------|----------|--------|--------------|
| **NTLM Reflection** | Critical | 1. SMB Signing = FAIL <br> 2. Spooler = RUNNING <br> 3. Failed Logins = WARNING | Enable SMB signing, disable Spooler, deploy LAPS |
| **Kerberoast** | High | Kerberoastable Accounts = WARNING | Review SPNs, use gMSA, enforce AES |
| **Credential Dumping** | High | 1. LSASS Protection = WARNING <br> 2. Windows Defender = FAIL | Enable LSASS PPL, ensure AV/EDR running |

#### Extending Patterns

```powershell
$AttackPatterns = @(
    # ... existing patterns ...
    @{
        name = "My Attack Chain"
        severity = "critical"
        stages = @(
            @{ Check = "First Check"; Status = "FAIL" }
            @{ Check = "Second Check"; Status = "WARNING" }
        )
        remediation = "Steps to fix."
    }
)
```

---

### 9.3 Baseline Anomaly Detection

#### How It Works

1. **First run**: Creates `baseline.json` with SHA-256 hash of all results and a list of finding IDs.
2. **Subsequent runs**: Compares current hash and finding IDs against baseline.
3. **Flags anomalies**:
   - `configuration_change` - system state has changed.
   - `new_findings` - new issues detected.

#### Use Cases

- Detect configuration drift.
- Identify new vulnerabilities after patching.
- Monitor security posture over time.

---

### 9.4 AI-Driven Risk Prioritisation

#### How It Works

1. **Collects** all Sigma findings and anomalies.
2. **Sends** them to OpenAI (`gpt-4o-mini`) via API.
3. **Receives** a JSON response with:
   - `executive_summary` - plain-language overview.
   - `prioritized` - list of findings with risk scores (1-10), reasoning, and recommended actions.
4. **Fallback**: If API key is missing or API call fails, uses heuristic scoring based on severity levels.

#### Enabling AI

```powershell
# PowerShell
$env:OPENAI_API_KEY = "sk-..."
.\AuditForensics_Ultimate.ps1 -AIEnrich
```

```bash
# Python
export OPENAI_API_KEY="sk-..."
python auditforensics_ultimate.py --ai-enrich
```

---

## 10. Customisation Guide

### 10.1 Adding New System Checks (PowerShell)

Insert a new `Add-Result` block in the "Data Collection" section:

```powershell
# Check for a custom registry setting
try {
    $Custom = Get-ItemProperty -Path "HKLM:\SOFTWARE\MyApp" -Name "SecureSetting" -ErrorAction SilentlyContinue
    if ($Custom.SecureSetting -eq 1) {
        Add-Result -Category "My Checks" -Check "Custom Setting" -Status "PASS" -Details "Secure setting enabled" -Risk "Info"
    } else {
        Add-Result -Category "My Checks" -Check "Custom Setting" -Status "FAIL" -Details "Secure setting disabled" -Risk "High" -Recommendation "Enable SecureSetting"
    }
} catch {
    Add-Result -Category "My Checks" -Check "Custom Setting" -Status "WARNING" -Details "Unable to check" -Risk "Medium"
}
```

---

### 10.2 Adding New Sigma Rules

Follow the pattern in `$SigmaRules` (see Section 9.1).

---

### 10.3 Adding New Attack Patterns

Follow the pattern in `$AttackPatterns` (see Section 9.2).

---

### 10.4 Modifying AI Prompt

Inside the `$AIEnrich` block, locate `$Prompt` and modify it:

```powershell
$Prompt = @"
You are a security expert. Prioritize these audit findings.
Return JSON with "executive_summary" and "prioritized" (list of objects with id, risk_score (1-10), reasoning, recommended_action).
Findings: $FindingsForAI
System context: $Summary
Additional context: Our organisation prioritises confidentiality over availability.
"@
```

---

### 10.5 Customising HTML Template

The `$HTML` variable at the end of the script can be modified to change the report layout, add logos, or include custom sections.

---

## 11. Troubleshooting

### 11.1 Common Issues and Solutions

| Problem | Likely Cause | Solution |
|---------|---------------|----------|
| **"Access Denied"** | Insufficient privileges | Run as Administrator |
| **AD checks fail** | ActiveDirectory module not installed | Install RSAT-AD-PowerShell or skip AD checks |
| **No JSON output** | Script didn't complete | Check execution policy: `Set-ExecutionPolicy Bypass` |
| **HTML charts missing** | No internet connection | Use offline Chart.js or open report with internet |
| **Python cannot find powershell** | PowerShell not in PATH | Provide full path to `powershell.exe` |
| **New-PSSession fails** | WinRM not enabled or firewall blocking | Run `Enable-PSRemoting -Force`, open ports 5985/5986 |
| **Throttle limit too high** | Network overload | Reduce `-ThrottleLimit` to 10-15 |
| **IP range scanning finds no hosts** | WinRM not accepting IPs | Configure `TrustedHosts` (see Section 7.4) |

---

### 11.2 Diagnostic Commands

#### Test WinRM Connectivity

```powershell
Test-WSMan -ComputerName <target>
```

#### Test PowerShell Remoting

```powershell
Enter-PSSession -ComputerName <target>
```

#### Check Script Execution Policy

```powershell
Get-ExecutionPolicy
Set-ExecutionPolicy Bypass -Scope Process
```

#### Verify OpenAI API Key

```powershell
# PowerShell
if ($env:OPENAI_API_KEY) { "API key is set" } else { "API key missing" }
```

---

## 12. Security Considerations

### 12.1 Privileges Required

The script requires **local administrator** privileges to:

- Query system configurations and logs.
- Check registry settings.
- Install/query hotfixes.
- Use WinRM for remote execution.

**Recommendation**: Use a dedicated service account with appropriate permissions.

### 12.2 Data Privacy

- **No data leaves your environment** except when `-AIEnrich` is used.
- **AI enrichment** sends only the findings (rule titles, severities, descriptions). No hostnames, IPs, or PII.
- **Baseline files** are stored locally - they contain only hashes and finding IDs, not raw data.
- **Logs** are not collected or transmitted - only event counts are extracted.

### 12.3 Secure Remote Communication

- Use WinRM over **HTTPS** (port 5986) in production.
- Avoid using `-Password` in plain text (PowerShell supports `-Credential` with `SecureString`).
- For Python, use environment variables or a secure vault for credentials.

### 12.4 Trusted Hosts

Configuring `TrustedHosts=*` is **not recommended** in production. Instead:

- Add specific IPs or subnets.
- Use DNS names and ensure proper certificate validation.

---

## 13. Performance & Scaling

### 13.1 Performance Metrics

| Metric | Value |
|--------|-------|
| **Scan time (local)** | 2-5 minutes (depending on AD size, log volume) |
| **Scan time (remote)** | 2-5 minutes per machine |
| **Parallel capacity** | Up to 50 concurrent scans (adjust with `-ThrottleLimit`) |
| **Network load** | ~1-2 MB per machine (script + results) |
| **Disk space per report** | ~200-500 KB per machine |
| **Memory usage** | ~50-100 MB per scan instance |

### 13.2 Scaling Guidelines

| Number of Machines | Recommended Throttle | Estimated Total Time |
|---------------------|------------------------|-------------------------|
| 10 | 10 | 2-5 minutes |
| 50 | 20 | 5-12 minutes |
| 200 | 30 | 20-50 minutes |
| 600 | 40 | 40-100 minutes |

### 13.3 Optimisation Tips

1. **Stagger scans**: Run in smaller batches to avoid network congestion.
2. **Use hostnames**: DNS resolution is faster than IP-based WinRM (if configured).
3. **Pre-copy the script**: Place `AuditForensics_Ultimate.ps1` on a network share accessible by all targets.
4. **Reduce `-ThrottleLimit`** if you see timeouts or errors.
5. **Use `-PingOnly`** first to identify alive hosts.

---

## 14. Changelog

| Version | Date | Changes |
|---------|------|---------|
| **2.0** | 2026-09-03 | Added IP range scanning (CIDR and start-end); added host discovery (`-PingOnly`); added `-ThrottleLimit` for parallel concurrency; added `-Credential` support (PowerShell); added `--username`/`--password` (Python); added aggregated fleet-wide reporting; embedded full PowerShell script in Python version; full documentation |
| **1.0** | 2025-08-01 | Initial release (Unified Security Auditor); 70+ security checks; HTML/CSV/JSON reports; Sigma, Correlation, Baseline, AI modules |

---

## 15. License & Credits

This tool is based on the original **Unified Security Auditor** by **Charles Ndirangu**. All enhancements (Sigma, Correlation, Baseline, AI, Multi-Target, IP Range) are built on that foundation.

Licensed under the same terms as the original repository.

---

## 16. Support & Community

- **GitHub**: [Seniorcaptain/AuditForensics](https://github.com/Seniorcaptain/AuditForensics)
- **Issues**: Report bugs via GitHub Issues
- **Contributions**: Pull requests are welcome

---

## 17. Appendix

### 17.1 Quick Reference Card

| I Want To... | Command |
|----------------|---------|
| Audit my local machine | `.\AuditForensics_Ultimate.ps1` |
| Audit with Sigma + Correlation | `.\AuditForensics_Ultimate.ps1 -Sigma -Correlate` |
| Scan 3 specific machines | `.\AuditForensics_Ultimate.ps1 -Targets "PC01","PC02","PC03"` |
| Scan a /24 subnet | `.\AuditForensics_Ultimate.ps1 -IPRange "192.168.1.0/24"` |
| Discover hosts in a range | `.\AuditForensics_Ultimate.ps1 -IPRange "10.0.0.1-10.0.0.254" -PingOnly` |
| Use AI enrichment | `$env:OPENAI_API_KEY="sk-..."; .\AuditForensics_Ultimate.ps1 -AIEnrich` |
| See all options | `Get-Help .\AuditForensics_Ultimate.ps1 -Detailed` |

---

### 17.2 File Manifest

| File | Location | Purpose |
|------|----------|---------|
| `AuditForensics_Ultimate.ps1` | Any folder | The main PowerShell script |
| `auditforensics_ultimate.py` | Any folder | The Python orchestrator |
| `baseline.json` | `-OutputPath` | Baseline data (if `-Baseline` used) |
| `AuditForensics_*.html` | `-OutputPath` | Individual HTML reports |
| `AuditForensics_*.csv` | `-OutputPath` | Individual CSV exports |
| `AuditForensics_*.json` | `-OutputPath` | Individual JSON exports |
| `AuditForensics_Aggregated_*.html` | `-OutputPath` | Fleet-wide HTML dashboard |
| `AuditForensics_Aggregated_*.csv` | `-OutputPath` | Fleet-wide CSV summary |
| `AuditForensics_Aggregated_*.json` | `-OutputPath` | Fleet-wide JSON data |

---

**AuditForensics Ultimate** - Complete security auditing at scale. 🚀
