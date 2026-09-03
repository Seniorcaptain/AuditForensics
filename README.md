# AuditForensics Ultimate - Full Documentation

**Version**: 2.0
**Author**: Enhanced from Charles Ndirangu's original work
**Repository**: [Seniorcaptain/AuditForensics](https://github.com/Seniorcaptain/AuditForensics)

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Key Features & Capabilities](#2-key-features--capabilities)
3. [Requirements & Prerequisites](#3-requirements--prerequisites)
4. [Installation](#4-installation)
5. [Usage Guide](#5-usage-guide)
6. [Outputs & Reports](#6-outputs--reports)
7. [Configuration & Customisation](#7-configuration--customisation)
8. [Multi-Target Scanning in Depth](#8-multi-target-scanning-in-depth)
9. [Security & Privacy Considerations](#9-security--privacy-considerations)
10. [Troubleshooting Common Issues](#10-troubleshooting-common-issues)
11. [License & Credits](#11-license--credits)
12. [Changelog](#12-changelog)
13. [Support & Community](#13-support--community)

---

## 1. Introduction

AuditForensics Ultimate is a **next-generation, multi-sector cybersecurity audit tool** designed for Windows environments. It provides a comprehensive assessment of system security, Active Directory health, GRC compliance, and malware readiness. The tool is available in two flavours:

- **PowerShell version** (`AuditForensics_Ultimate.ps1`) - native Windows, runs on any modern PowerShell.
- **Python version** (`auditforensics_ultimate.py`) - cross-platform orchestrator, ideal for headless or automation environments.

Both versions share the same core auditing engine and produce identical reports. The PowerShell version is the primary workhorse; the Python version acts as a wrapper that invokes the PowerShell script for multi-target orchestration.

---

## 2. Key Features & Capabilities

### 2.1 Core Auditing (70+ Checks)

| Category | Checks |
|----------|--------|
| **Vulnerability Scanning** | Pending Windows Updates, SMB Signing, Open Common Ports (445, 3389, 22, 5985, 5986, 135, 139, 1433, 3306, 8080, 8443) |
| **Active Directory Auditing** | Domain Admins Count, Kerberoastable Accounts, AS-REP Roastable Accounts, Unconstrained Delegation, Password Policy (length, history, age, complexity) |
| **GRC & Compliance** | UAC Status, Logon Audit Policy (success/failure), Account Lockout Threshold, LAPS Installation |
| **System Hardening** | Windows Defender, Firewall Profiles, BitLocker, PowerShell Script Block Logging, LSASS Protection (PPL), AMSI, Sysmon |
| **Network Security** | LLMNR/mDNS, NetBIOS Status |
| **Log Analysis (30-day)** | Failed Logins (Event 4625), Privilege Escalation Events (4673), Account Lockouts (4740) |
| **Malware Readiness** | AppLocker Rules, Real-Time Protection |

### 2.2 Enhanced Modules (Optional)

| Module | Description |
|--------|-------------|
| **Sigma Engine** | 8+ built-in detection rules (e.g., SIG-001: SMB Signing Disabled, SIG-004: Firewall Disabled). Matches findings against rule conditions and flags them. |
| **Correlation Engine** | Identifies attack chains by correlating multiple findings. Examples: **NTLM Reflection** (Spooler + SMB Signing off + abnormal NTLM activity), **Kerberoast** (Kerberoastable accounts), **Credential Dumping** (LSASS not protected + AV disabled). |
| **Baseline Anomaly Detection** | Stores a SHA-256 hash of all results and a list of finding IDs. On subsequent runs, flags configuration changes and new findings. |
| **AI-Driven Risk Prioritisation** | Sends findings to OpenAI (`gpt-4o-mini`) to generate a risk score (1-10), reasoning, and recommended action. Falls back to heuristic scoring if API key is not set. |

### 2.3 Multi-Target Scanning (New in v2.0)

- Scan **hundreds of machines** in parallel using WinRM.
- **Throttle** control to manage network load.
- **Aggregated reports** showing the security posture across the entire fleet.
- Works with both PowerShell and Python orchestrators.

---

## 3. Requirements & Prerequisites

### 3.1 For the PowerShell Version (Single Host)

- **Windows 7 / Server 2008 R2 or later** with PowerShell 5.1+.
- **Administrator privileges** (required for system and AD checks).
- **Internet connection** (for Bootstrap/Chart.js CDN in HTML report).
- **Active Directory module** (optional, for AD checks; install via RSAT if needed).
- **OpenAI API key** (optional, for AI enrichment; set as environment variable `OPENAI_API_KEY`).

### 3.2 For the Python Version (Orchestrator)

- **Python 3.8+** on any OS (Windows, Linux, macOS).
- **Dependencies**: `click`, `jinja2`, `pyyaml`, `requests` (install via `pip`).
- The PowerShell script is embedded in the Python file; no separate PS1 file needed.
- For multi-target scanning, the Python version calls PowerShell remoting; therefore **WinRM must be enabled on all targets**, and the orchestrator must have network access to them.

### 3.3 For Multi-Target Scanning (Both Versions)

- **WinRM** enabled on all target machines (`Enable-PSRemoting -Force`).
- **Firewall** rules allowing ports **5985 (HTTP)** or **5986 (HTTPS)**.
- The account running the orchestration must have **local administrator privileges** on all targets.
- All machines must be **DNS-resolvable** and network-reachable.

---

## 4. Installation

### 4.1 PowerShell Version

1. Download `AuditForensics_Ultimate.ps1` (the complete single file).
2. Place it in any folder on the machine where you plan to run audits.
3. Optionally, copy it to a network share if you intend to run it remotely (for multi-target scans).
4. Run the script with appropriate parameters (see Usage).

**No additional modules are required** - all dependencies are native PowerShell cmdlets.

### 4.2 Python Version

1. Save the `auditforensics_ultimate.py` file to your working directory.
2. Install required Python packages:

   ```bash
   pip install click jinja2 pyyaml requests
   ```

3. (Optional) Set your OpenAI API key as an environment variable:

   ```bash
   export OPENAI_API_KEY="sk-..."   # Linux/macOS
   set OPENAI_API_KEY=sk-...         # Windows CMD
   $env:OPENAI_API_KEY = "sk-..."    # PowerShell
   ```

4. The script is ready to run. It embeds the entire PowerShell logic; no separate PS1 file is needed.

---

## 5. Usage Guide

### 5.1 PowerShell Version - Command Line Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-Targets` | `string[]` | List of computer names to scan. If omitted, scans **localhost**. |
| `-ThrottleLimit` | `int` | Maximum number of parallel remote scans (default **20**). |
| `-Credential` | `PSCredential` | Alternate credentials for remote authentication (if needed). |
| `-OutputPath` | `string` | Directory to save reports (default: `$env:USERPROFILE\Desktop\AuditReports`). |
| `-Sigma` | `switch` | Enable Sigma rule checks. |
| `-Correlate` | `switch` | Enable attack correlation. |
| `-Baseline` | `switch` | Enable baseline anomaly detection (per machine). |
| `-AIEnrich` | `switch` | Enable AI prioritisation (requires `OPENAI_API_KEY`). |
| `-Demo` | `switch` | Run with sample data (no system scanning) - works for single host only. |

#### Examples (PowerShell)

```powershell
# Single host audit with Sigma and Correlation
.\AuditForensics_Ultimate.ps1 -Sigma -Correlate

# Multi-target scan (3 machines)
.\AuditForensics_Ultimate.ps1 -Targets "PC01","PC02","PC03" -Sigma -Correlate -Baseline

# Scan all computers from Active Directory
$computers = (Get-ADComputer -Filter *).Name
.\AuditForensics_Ultimate.ps1 -Targets $computers -ThrottleLimit 30

# With alternate credentials
$cred = Get-Credential
.\AuditForensics_Ultimate.ps1 -Targets @("SRV01","SRV02") -Credential $cred -AIEnrich

# Demo mode (no real scan)
.\AuditForensics_Ultimate.ps1 -Demo -Sigma -Correlate
```

### 5.2 Python Version - Command Line Parameters

| Flag | Type | Description |
|------|------|-------------|
| `--targets`, `-t` | multiple | List of computer names (repeat flag, e.g., `-t PC01 -t PC02`). |
| `--target-file`, `-f` | path | File containing one hostname per line. |
| `--throttle` | int | Parallel threads (default 20). |
| `--output-path`, `-o` | path | Output directory (default current dir). |
| `--sigma` | flag | Enable Sigma checks. |
| `--correlate` | flag | Enable correlation. |
| `--baseline` | flag | Enable baseline. |
| `--ai-enrich` | flag | Enable AI (requires `OPENAI_API_KEY`). |
| `--demo` | flag | Run local demo (single host). |
| `--username` | string | Remote username (optional). |
| `--password` | string | Remote password (optional). |

#### Examples (Python)

```bash
# Single host audit (localhost) - only works on Windows
python auditforensics_ultimate.py --sigma --correlate

# Multi-target scan
python auditforensics_ultimate.py --targets PC01 PC02 PC03 --sigma --correlate --baseline

# Use a target file
python auditforensics_ultimate.py --target-file hosts.txt --throttle 30

# With credentials
python auditforensics_ultimate.py --targets SERVER01 --username domain\user --password 'pass'

# Demo mode (cross-platform)
python auditforensics_ultimate.py --demo --sigma --correlate
```

---

## 6. Outputs & Reports

All reports are saved in the specified `-OutputPath` (default: `Desktop\AuditReports` for PS, current dir for Python). For multi-target scans, the orchestrator produces both per-machine and aggregated files.

### 6.1 Per-Machine Files (one set per host)

| File | Format | Description |
|------|--------|--------------|
| `AuditForensics_<hostname>_<timestamp>.html` | HTML | Detailed dashboard for that specific machine, with charts and summaries. |
| `AuditForensics_<hostname>_<timestamp>.csv` | CSV | Raw results table (Category, Check, Status, Risk, Details, Recommendation). |
| `AuditForensics_<hostname>_<timestamp>.json` | JSON | Full structured data - used for aggregation and external integrations. |

### 6.2 Aggregated Files (multi-target only)

| File | Format | Description |
|------|--------|--------------|
| `AuditForensics_Aggregated_<timestamp>.html` | HTML | Fleet-wide dashboard: summary cards (total machines, critical/high counts), machine-by-machine table, top 5 critical hosts, etc. |
| `AuditForensics_Aggregated_<timestamp>.csv` | CSV | Summary of each machine (Computer, Status, TotalChecks, Passed, Failed, Warnings, Critical, High). |
| `AuditForensics_Aggregated_<timestamp>.json` | JSON | Full aggregated data per machine for further analysis. |

### 6.3 Baseline File (if `-Baseline` used)

`baseline.json` - stored in the output folder, contains the SHA-256 hash and finding IDs for each machine (or for localhost). Used for anomaly detection on subsequent runs.

---

## 7. Configuration & Customisation

### 7.1 Adding New Sigma Rules (PowerShell)

Locate the `$SigmaRules` array in the script (around line 350) and add a new hash:

```powershell
@{
    id = "SIG-009"
    title = "My Custom Rule"
    level = "high"
    description = "Description of the condition."
    detection = @{
        Check = "Windows Defender"   # must match a Check name in results
        Status = "FAIL"              # PASS, FAIL, or WARNING
    }
}
```

### 7.2 Adding New Attack Patterns (PowerShell)

Find the `$AttackPatterns` array and add a new chain:

```powershell
@{
    name = "My Attack Chain"
    severity = "critical"
    stages = @(
        @{ Check = "SMB Signing"; Status = "FAIL" },
        @{ Check = "Spooler"; Status = "RUNNING" }
    )
    remediation = "Steps to fix."
}
```

### 7.3 Adjusting AI Prompt

Inside the `$AIEnrich` block, modify the `$Prompt` variable to change how findings are presented to the AI model.

### 7.4 Python Version Customisation

- To modify the embedded PowerShell script, edit the `EMBEDDED_PS1` string variable at the top of the Python file.
- To change the output HTML template, modify the `$HTML` block inside the PowerShell script (embedded).

---

## 8. Multi-Target Scanning in Depth

### 8.1 How It Works (PowerShell Orchestrator)

1. The script receives a list of computer names via `-Targets`.
2. It creates a PowerShell session (`New-PSSession`) to each target, respecting the `-ThrottleLimit`.
3. It invokes the same script on each target (using `-FilePath` to send the script itself).
4. Each remote instance runs the full audit, saving its JSON output to the shared `-OutputPath` (which should be a network share accessible by all machines).
5. After all jobs complete, the orchestrator collects all JSON files, parses them, and generates the aggregated reports.

### 8.2 How It Works (Python Orchestrator)

The Python script does essentially the same but uses `subprocess` to call PowerShell with `Invoke-Command`. It can also use `--username` and `--password` for authentication.

### 8.3 Performance Considerations

- **Throttle limit**: Start with 20 and increase based on network bandwidth and CPU capacity.
- **Scan time**: Each machine takes 2-5 minutes. With 30 parallel sessions, 600 machines take roughly 40-100 minutes.
- **Network load**: Each session transfers about 1-2 MB of data (script + results). With high throttle, this can saturate the network; use caution.

### 8.4 Credentials & Security

- The orchestrator account must have **local admin** on all targets.
- For domain accounts, use `-Credential` in PS or `--username/--password` in Python.
- Ensure WinRM is configured with HTTPS for encrypted communication (recommended in production).

### 8.5 Troubleshooting Multi-Target

| Issue | Solution |
|-------|----------|
| `New-PSSession` fails | Check WinRM is running (`Enable-PSRemoting -Force`), firewall ports (5985/5986), DNS resolution, and credentials. |
| JSON files not found after scan | Verify that `-OutputPath` is a network share accessible by all machines, or that each machine writes to a local path that the orchestrator can read. |
| Throttle limit too high | Lower `-ThrottleLimit` to 10-15 to reduce load. |
| Script not found on remote | Ensure the script is available on a network share or use the `-FilePath` parameter (the orchestrator sends the script over WinRM). |

---

## 9. Security & Privacy Considerations

- **Local execution**: The PowerShell script runs entirely on the target machine - no data leaves the environment except when `-AIEnrich` is used.
- **AI enrichment**: Only the findings (rule titles, severities, descriptions) are sent to OpenAI. No hostnames, IPs, or personally identifiable information is included.
- **Baseline files**: Stored locally - they contain only hashes and finding IDs, not raw data.
- **Permissions**: The script must be run with elevated privileges to access system configurations and logs. This is intended for authorised administrators only.

---

## 10. Troubleshooting Common Issues

| Problem | Likely Cause | Solution |
|---------|---------------|----------|
| `Get-ADUser` not found | Active Directory module not installed. | Install RSAT-AD-PowerShell or run without AD checks. |
| UAC checks fail | Insufficient registry permissions. | Run as Administrator. |
| HTML report missing charts | No internet connection for CDN. | Open report offline or modify HTML to include local Chart.js. |
| Python script cannot find PowerShell | PowerShell not in PATH. | Provide full path to `powershell.exe` in the script. |
| OpenAI API error | Invalid or missing API key. | Check `OPENAI_API_KEY` environment variable. The tool will fall back to heuristic scoring. |
| Remote execution hangs | Network latency or firewall blocking WinRM. | Use `-ThrottleLimit` to reduce concurrency, and test connectivity with `Test-WSMan`. |

---

## 11. License & Credits

This tool is based on the original **Unified Security Auditor** by **Charles Ndirangu**. The enhancements (Sigma, Correlation, Baseline, AI, Multi-target) are built on that foundation and are released under the same license terms as the original repository.

For full license details, see the [original repository](https://github.com/Seniorcaptain/AuditForensics).

---

## 12. Changelog

| Version | Date | Changes |
|---------|------|---------|
| 2.0 | 2026-09-03 | Added multi-target scanning, aggregated reports, Python orchestrator, native -Targets parameter, ThrottleLimit, and remote credential support. |
| 1.0 | 2025-08-01 | Initial release (Unified Security Auditor). |

---

## 13. Support & Community

For bug reports, feature requests, or questions, please open an issue on the [GitHub repository](https://github.com/Seniorcaptain/AuditForensics). Contributions are welcome.

---

**AuditForensics Ultimate** - Transform your Windows security auditing with intelligence, scale, and clarity. 🚀
