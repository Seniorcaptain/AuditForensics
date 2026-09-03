# AuditForensics Ultimate - Complete Documentation

**Version**: 2.0
**Author**: Enhanced from Charles Ndirangu's original work
**Repository**: [Seniorcaptain/AuditForensics](https://github.com/Seniorcaptain/AuditForensics)

---

## Table of Contents

1. [Overview](#-overview)
2. [Core Capabilities](#-core-capabilities)
3. [Installation & Prerequisites](#-installation--prerequisites)
4. [Usage & Command Reference](#-usage--command-reference)
5. [Outputs & Report Files](#-outputs--report-files)
6. [Customisation Guide](#-customisation-guide)
7. [Environment Variables](#%EF%B8%8F-environment-variables)
8. [Troubleshooting](#-troubleshooting)
9. [Full Report Walkthrough](#-full-report-walkthrough)
10. [Testing & QA](#-testing--qa)
11. [Security & Privacy](#-security--privacy)
12. [Contributing & Extending](#-contributing--extending)
13. [Support](#-support)
14. [License](#-license)

---

## 📌 Overview

AuditForensics Ultimate is a **next-generation, multi-sector cybersecurity audit tool** for Windows environments. It combines a proven 70+ check audit engine with modern security analytics:

- **Sigma Rule Matching** (detection engineering)
- **Multi-stage Attack Correlation** (NTLM reflection, Kerberoast, credential dumping)
- **Baseline Anomaly Detection** (configuration drift)
- **AI-Driven Risk Prioritisation** (optional, using OpenAI)
- **Unified HTML Dashboard** (interactive charts, executive summary)

You can run it either as a **self-contained PowerShell script** (native Windows) or as a **Python script** (cross-platform or headless environments). Both versions produce identical reports and are fully portable.

---

## 🧠 Core Capabilities

| Category | Checks Included |
|----------|------------------|
| **Vulnerability Scanning** | Pending Windows updates, SMB signing, open common ports (445, 3389, 22, etc.) |
| **Active Directory Auditing** | Domain Admins count, Kerberoastable accounts, AS-REP roastable accounts, unconstrained delegation, password policy |
| **GRC & Compliance** | UAC status, logon audit policy, account lockout threshold, LAPS installation |
| **System Hardening** | Windows Defender, Firewall profiles, BitLocker, PowerShell script block logging, LSASS PPL, AMSI, Sysmon |
| **Network Security** | LLMNR/mDNS, NetBIOS status |
| **Log Analysis (30-day)** | Failed logins (4625), privilege escalation events (4673), account lockouts (4740) |
| **Malware Readiness** | AppLocker policies, real-time protection |

### 🔧 Enhanced Modules (Active by Flag)

| Module | Description |
|--------|-------------|
| **Sigma Engine** | 8+ built-in detection rules mapped to audit results (e.g., SIG-001: SMB Signing Disabled) |
| **Correlation Engine** | Identifies attack chains: NTLM reflection (Spooler + SMB signing off + NTLM events), Kerberoast, and Credential Dumping path |
| **Baseline Manager** | Stores a SHA-256 hash of all results + a list of finding IDs. Flags configuration changes and new findings on subsequent runs |
| **AI Prioritizer** | Sends findings to OpenAI (`gpt-4o-mini`) for a risk score (1-10), reasoning, and remediation action. Falls back to heuristic scoring if API key is missing |

---

## 📦 Installation & Prerequisites

### 🔵 Option A: PowerShell Version (`AuditForensics_Ultimate.ps1`)

**Prerequisites**:

- Windows 7 / Server 2008 R2 or later (PowerShell 5.1+)
- Administrator privileges (for full system and AD checks)
- Internet connection (for Bootstrap/Chart.js CDN in the report)
- Optional: OpenAI API key (if using `-AIEnrich`)

**Installation**:

1. Save the `AuditForensics_Ultimate.ps1` script to any folder.
2. No external modules are required - it uses native PowerShell cmdlets.
3. Run as **Administrator**.

**Example**:

```powershell
# Save the script, then:
Set-ExecutionPolicy Bypass -Scope Process -Force
.\AuditForensics_Ultimate.ps1 -Sigma -Correlate -Baseline
```

---

### 🐍 Option B: Python Version (`auditforensics_ultimate.py`)

**Prerequisites**:

- Python 3.8 or later (cross-platform: Windows, Linux, macOS)
- `pip` package manager
- (Optional) OpenAI API key (if using `--ai-enrich`)

**Installation**:

```bash
# Install dependencies
pip install click jinja2 pyyaml requests

# Download the script
curl -O https://your-repo/auditforensics_ultimate.py   # or save manually
```

**Running on Windows (full scan)**:

```bash
python auditforensics_ultimate.py --target localhost --sigma --correlate --baseline --ai-enrich
```

**Running on Linux/macOS (demo only)**:

```bash
python auditforensics_ultimate.py --demo --sigma --correlate --baseline
```

> ⚠️ The Python version embeds the entire PowerShell script. On non-Windows platforms, it automatically falls back to `--demo` mode, making it useful for testing or cloud-based analysis pipelines.

---

## 🚀 Usage & Command Reference

### PowerShell Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-OutputPath` | String | Directory to save reports (default: `$env:USERPROFILE\Desktop\AuditReports`) |
| `-Sigma` | Switch | Enable Sigma rule checks |
| `-Correlate` | Switch | Enable multi-stage attack correlation |
| `-Baseline` | Switch | Enable baseline anomaly detection (creates/updates `baseline.json`) |
| `-AIEnrich` | Switch | Enable AI prioritisation (requires `OPENAI_API_KEY` env var) |
| `-Demo` | Switch | Run with sample data - no system scanning |

**PowerShell Examples**:

```powershell
# Basic audit (no enhancements)
.\AuditForensics_Ultimate.ps1

# Full audit with all enhancements
.\AuditForensics_Ultimate.ps1 -Sigma -Correlate -Baseline -AIEnrich

# Audit with custom output folder
.\AuditForensics_Ultimate.ps1 -OutputPath "C:\MyAudits" -Sigma -Correlate

# Quick demo to test the reporting engine
.\AuditForensics_Ultimate.ps1 -Demo -Sigma -Correlate -Baseline

# With AI (set API key first)
$env:OPENAI_API_KEY = "sk-..."
.\AuditForensics_Ultimate.ps1 -AIEnrich
```

---

### Python Parameters

| Flag | Type | Description |
|------|------|-------------|
| `--target, -t` | String | Hostname/display name (default: `localhost`) |
| `--output-path, -o` | String | Directory to save reports (default: current directory) |
| `--sigma` | Flag | Enable Sigma rule checks |
| `--correlate` | Flag | Enable attack correlation |
| `--baseline` | Flag | Enable baseline anomaly detection |
| `--ai-enrich` | Flag | Enable AI prioritisation (requires `OPENAI_API_KEY` env var) |
| `--demo` | Flag | Run with sample data |

**Python Examples**:

```bash
# Full audit on local Windows machine
python auditforensics_ultimate.py --target localhost --sigma --correlate --baseline --ai-enrich

# Cross-platform demo
python auditforensics_ultimate.py --demo --sigma --correlate

# Custom output directory
python auditforensics_ultimate.py -o "C:\Reports" --sigma --baseline

# Set API key inline
export OPENAI_API_KEY="sk-..."
python auditforensics_ultimate.py --ai-enrich
```

---

## 📊 Outputs & Report Files

All reports are saved to the specified `OutputPath` (default: `Desktop\AuditReports` or current directory).

| File | Format | Contents |
|------|--------|----------|
| `AuditForensics_YYYYMMDD_HHMMSS.html` | **HTML** (Bootstrap + Chart.js) | Unified dashboard: executive summary, severity distribution doughnut, top AI risks, Sigma findings, attack correlations, baseline anomalies, original audit summary table |
| `AuditForensics_YYYYMMDD_HHMMSS.csv` | **CSV** | All raw `AuditResults` in tabular format (Category, Check, Status, Risk, Details, Recommendation) |
| `AuditForensics_YYYYMMDD_HHMMSS.json` | **JSON** | Complete structured export: all results, findings, sigma matches, correlations, anomalies, and summary - ideal for SIEM or automation integration |
| `baseline.json` | **JSON** | Saved baseline (if `-Baseline` used): SHA-256 hash of results + list of finding IDs + timestamp |

---

## 🔧 Customisation Guide

### Adding New Sigma Rules (PS1)

Open the script, locate the `$SigmaRules` array (around line 350) and add a new entry:

```powershell
$SigmaRules = @(
    # ... existing rules ...
    @{
        id = "SIG-009"
        title = "My Custom Rule"
        level = "high"
        description = "Checks for a specific condition"
        detection = @{
            Check = "Name of the check"   # e.g., "Windows Defender"
            Status = "FAIL"              # PASS, FAIL, or WARNING
        }
    }
)
```

### Adding New Attack Patterns (PS1)

Locate the `$AttackPatterns` array (around line 380) and add a new chain:

```powershell
$AttackPatterns = @(
    # ... existing patterns ...
    @{
        name = "My Attack Chain"
        severity = "critical"
        stages = @(
            @{ Check = "First Check"; Status = "FAIL" },
            @{ Check = "Second Check"; Status = "WARNING" }
        )
        remediation = "Steps to fix this chain."
    }
)
```

### Adjusting AI Prompt

In the `$AIEnrich` block, modify the `$Prompt` variable to change how findings are presented to the AI model.

---

## ⚙️ Environment Variables

| Variable | Required For | Description |
|----------|---------------|--------------|
| `OPENAI_API_KEY` | AI enrichment | Your OpenAI API key (e.g., `sk-...`). If not set, the tool uses a heuristic fallback. |

**Set it**:

- PowerShell: `$env:OPENAI_API_KEY = "sk-..."`
- Python (Windows): `set OPENAI_API_KEY=sk-...`
- Python (Linux/macOS): `export OPENAI_API_KEY="sk-..."`

---

## ❓ Troubleshooting

| Issue | Solution |
|-------|----------|
| **"Access Denied" or AD checks fail** | Run PowerShell **as Administrator**. AD checks require elevated privileges. |
| **"OpenAI API error"** | Check your API key and internet connection. The tool will fall back to heuristic scoring automatically. |
| **HTML report not displaying charts** | Ensure you have an internet connection (Charts use CDN). Alternatively, open the file in a modern browser (Chrome/Edge). |
| **"File not found" on Python** | Make sure `auditforensics_ultimate.py` is in the current directory, and all dependencies are installed (`pip install -r requirements.txt`). |
| **PowerShell script execution blocked** | Run `Set-ExecutionPolicy Bypass -Scope Process -Force` before running the script, or run it with `-ExecutionPolicy Bypass` directly. |
| **Baseline anomalies on first run** | This is expected - the first run creates the baseline. Anomalies will only appear on subsequent runs when changes are detected. |

---

## 📋 Full Report Walkthrough

1. **Summary Cards** - At a glance: Total Checks, Passed, Failed, Warnings, Critical Issues.
2. **Executive Summary** - Plain-language overview (AI-generated if enabled, otherwise a simple fallback).
3. **Risk Severity Chart** - Doughnut chart showing Sigma findings by severity (Critical, High, Medium, Low).
4. **Top Risks (AI)** - The 5 highest-scored risks with reasoning and recommended actions.
5. **Sigma Findings** - Table of all matched detection rules with severity labels.
6. **Attack Correlations** - Named attack chains with their stages and remediation steps.
7. **Baseline Anomalies** - Lists configuration changes and new findings since the last run.
8. **Original Audit Summary** - Full breakdown of all checks performed.

---

## 🧪 Testing & QA

The tool includes a `-Demo` (`--demo`) mode that populates realistic sample findings so you can:

- Test the reporting pipeline without affecting production systems.
- Validate the Sigma, Correlation, Baseline, and AI logic.
- Preview the HTML report structure.

Run it with:

```powershell
.\AuditForensics_Ultimate.ps1 -Demo -Sigma -Correlate -Baseline -AIEnrich
```

---

## 🔐 Security & Privacy

- The PowerShell script runs entirely **locally** - no data is sent anywhere except to OpenAI **if** you enable `-AIEnrich`.
- When using AI enrichment, only the findings summary (no hostnames or PII) is sent to OpenAI.
- Baseline files are stored locally in the output directory.
- All reports are saved with timestamps - you can archive them for historical trending.

---

## 🤝 Contributing & Extending

This tool is designed for easy extension:

1. **Add more system checks** - Insert a new `Add-Result` block anywhere in the "Data Collection" section.
2. **Add more Sigma rules** - Follow the pattern in `$SigmaRules`.
3. **Add more attack patterns** - Follow the pattern in `$AttackPatterns`.
4. **Customise the HTML template** - Modify the `$HTML` variable at the end of the script.

---

## 📞 Support

For bugs, feature requests, or contributions, please open an issue on the [original repository](https://github.com/Seniorcaptain/AuditForensics) or reach out to the maintainers.

---

## 📄 License

This tool is licensed under the same terms as the original `AuditForensics` repository.
All credit for the original audit framework goes to **Charles Ndirangu**.

---

**AuditForensics Ultimate** - Bridging traditional security auditing with modern detection engineering and AI. 🚀
