<#
.SYNOPSIS
    Unified Security Auditor (USA) - v1.0
    A comprehensive multi-sector cybersecurity audit tool for Windows environments.
    Produces readable, actionable results for vulnerability assessment, AD auditing,
    GRC compliance, and security posture analysis.

.AUTHOR
    Charles Ndirangu

.EXAMPLE
    .\UnifiedSecurityAuditor.ps1 -OutputPath "C:\AuditReports"
#>

param(
    [string]$OutputPath = "$env:USERPROFILE\Desktop\AuditReports"
)

# Ensure output directory exists
$ReportPath = $OutputPath
if (!(Test-Path $ReportPath)) {
    New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null
}

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile = Join-Path $ReportPath "SecurityAudit_$Timestamp.html"
$CsvFile = Join-Path $ReportPath "SecurityAudit_$Timestamp.csv"

# Initialize data collection
$AuditResults = @()
$Findings = @()
$ComplianceIssues = @()
$Warnings = @()

# Helper function to add results
function Add-Result {
    param(
        [string]$Category,
        [string]$Check,
        [string]$Status,
        [string]$Details,
        [string]$Risk = "Info",
        [string]$Recommendation = ""
    )
    $obj = [PSCustomObject]@{
        Category = $Category
        Check = $Check
        Status = $Status
        Details = $Details
        Risk = $Risk
        Recommendation = $Recommendation
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    $AuditResults += $obj

    if ($Status -eq "FAIL" -or $Status -eq "WARNING") {
        $Findings += $obj
        if ($Risk -eq "High" -or $Risk -eq "Critical") {
            $ComplianceIssues += $obj
        }
    } elseif ($Status -eq "WARNING") {
        $Warnings += $obj
    }
}

# ============================================================
# SECTION 1: SYSTEM VULNERABILITY SCANNING
# ============================================================

Write-Host "[*] Scanning System Vulnerabilities..." -ForegroundColor Cyan

# 1.1 Pending Windows Updates
try {
    $UpdateSession = New-Object -ComObject Microsoft.Update.Session
    $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
    $SearchResult = $UpdateSearcher.Search("IsInstalled=0")
    $PendingUpdates = $SearchResult.Updates.Count

    if ($PendingUpdates -gt 0) {
        Add-Result -Category "Vulnerability" -Check "Pending Windows Updates" -Status "FAIL" `
            -Details "$PendingUpdates critical updates missing" -Risk "Critical" `
            -Recommendation "Install all pending updates immediately"
    } else {
        Add-Result -Category "Vulnerability" -Check "Pending Windows Updates" -Status "PASS" `
            -Details "No pending critical updates" -Risk "Info"
    }
} catch {
    Add-Result -Category "Vulnerability" -Check "Pending Windows Updates" -Status "WARNING" `
        -Details "Unable to check updates" -Risk "Medium"
}

# 1.2 SMB Signing
try {
    $SMB = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    if ($SMB.EnableSecuritySignature -eq $false) {
        Add-Result -Category "Vulnerability" -Check "SMB Signing" -Status "FAIL" `
            -Details "SMB signing is disabled" -Risk "High" `
            -Recommendation "Enable SMB signing via Set-SmbServerConfiguration -EnableSecuritySignature `$true"
    } else {
        Add-Result -Category "Vulnerability" -Check "SMB Signing" -Status "PASS" `
            -Details "SMB signing is enabled" -Risk "Info"
    }
} catch {
    Add-Result -Category "Vulnerability" -Check "SMB Signing" -Status "WARNING" `
        -Details "Unable to check SMB configuration" -Risk "Medium"
}

# 1.3 Open Ports (Common attack vectors)
try {
    $Ports = @(445, 3389, 22, 5985, 5986, 135, 139, 1433, 3306, 8080, 8443)
    $OpenPorts = @()
    foreach ($Port in $Ports) {
        $Test = Test-NetConnection -ComputerName "localhost" -Port $Port -ErrorAction SilentlyContinue
        if ($Test.TcpTestSucceeded -eq $true) {
            $OpenPorts += $Port
        }
    }
    if ($OpenPorts.Count -gt 0) {
        $PortList = $OpenPorts -join ", "
        Add-Result -Category "Vulnerability" -Check "Open Ports" -Status "WARNING" `
            -Details "Open ports detected: $PortList" -Risk "Medium" `
            -Recommendation "Review firewall rules; close unnecessary ports"
    } else {
        Add-Result -Category "Vulnerability" -Check "Open Ports" -Status "PASS" `
            -Details "No common attack ports open" -Risk "Info"
    }
} catch {
    Add-Result -Category "Vulnerability" -Check "Open Ports" -Status "WARNING" `
        -Details "Unable to scan ports" -Risk "Low"
}

# ============================================================
# SECTION 2: ACTIVE DIRECTORY AUDITING
# ============================================================

if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {
    Write-Host "[*] Auditing Active Directory..." -ForegroundColor Cyan

    try {
        # 2.1 Domain Admins
        $DomainAdmins = Get-ADGroupMember -Identity "Domain Admins" -ErrorAction SilentlyContinue | Measure-Object
        Add-Result -Category "Active Directory" -Check "Domain Admins Count" -Status "PASS" `
            -Details "$($DomainAdmins.Count) Domain Admins found" -Risk "Info" `
            -Recommendation "Review members regularly; follow least privilege"

        # 2.2 Kerberoastable Accounts
        $Kerberoastable = Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName -ErrorAction SilentlyContinue
        if ($Kerberoastable.Count -gt 0) {
            Add-Result -Category "Active Directory" -Check "Kerberoastable Accounts" -Status "WARNING" `
                -Details "$($Kerberoastable.Count) accounts with SPNs set" -Risk "High" `
                -Recommendation "Review SPNs; consider using gMSA accounts"
        } else {
            Add-Result -Category "Active Directory" -Check "Kerberoastable Accounts" -Status "PASS" `
                -Details "No Kerberoastable accounts found" -Risk "Info"
        }

        # 2.3 AS-REP Roastable Accounts
        try {
            $ASREPRoastable = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth -ErrorAction SilentlyContinue
            if ($ASREPRoastable.Count -gt 0) {
                Add-Result -Category "Active Directory" -Check "AS-REP Roastable Accounts" -Status "FAIL" `
                    -Details "$($ASREPRoastable.Count) accounts with pre-auth disabled" -Risk "High" `
                    -Recommendation "Enable Kerberos pre-authentication for all accounts"
            } else {
                Add-Result -Category "Active Directory" -Check "AS-REP Roastable Accounts" -Status "PASS" `
                    -Details "No AS-REP roastable accounts found" -Risk "Info"
            }
        } catch {
            Add-Result -Category "Active Directory" -Check "AS-REP Roastable Accounts" -Status "WARNING" `
                -Details "Unable to check AS-REP roastable accounts" -Risk "Medium"
        }

        # 2.4 Unconstrained Delegation
        try {
            $Unconstrained = Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation -ErrorAction SilentlyContinue
            if ($Unconstrained.Count -gt 0) {
                Add-Result -Category "Active Directory" -Check "Unconstrained Delegation" -Status "WARNING" `
                    -Details "$($Unconstrained.Count) computers with unconstrained delegation" -Risk "High" `
                    -Recommendation "Review delegation settings; use constrained delegation where possible"
            } else {
                Add-Result -Category "Active Directory" -Check "Unconstrained Delegation" -Status "PASS" `
                    -Details "No unconstrained delegation detected" -Risk "Info"
            }
        } catch {
            Add-Result -Category "Active Directory" -Check "Unconstrained Delegation" -Status "WARNING" `
                -Details "Unable to check delegation settings" -Risk "Medium"
        }

        # 2.5 Password Policy
        try {
            $Policy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
            if ($Policy) {
                $Issues = @()
                if ($Policy.MinPasswordLength -lt 8) { $Issues += "Min password length < 8" }
                if ($Policy.PasswordHistoryCount -lt 5) { $Issues += "Password history count < 5" }
                if ($Policy.MaxPasswordAge.Days -gt 180) { $Issues += "Max password age > 180 days" }
                if ($Policy.ComplexityEnabled -eq $false) { $Issues += "Password complexity disabled" }

                if ($Issues.Count -gt 0) {
                    Add-Result -Category "GRC" -Check "Password Policy" -Status "FAIL" `
                        -Details "Issues: $($Issues -join '; ')" -Risk "High" `
                        -Recommendation "Align password policy with NIST/ISO standards"
                } else {
                    Add-Result -Category "GRC" -Check "Password Policy" -Status "PASS" `
                        -Details "Password policy meets best practices" -Risk "Info"
                }
            }
        } catch {
            Add-Result -Category "GRC" -Check "Password Policy" -Status "WARNING" `
                -Details "Unable to retrieve password policy" -Risk "Medium"
        }

    } catch {
        Add-Result -Category "Active Directory" -Check "AD Audit" -Status "WARNING" `
            -Details "Error performing AD audit: $($_.Exception.Message)" -Risk "Medium"
    }
} else {
    Add-Result -Category "Active Directory" -Check "AD Module" -Status "WARNING" `
        -Details "ActiveDirectory module not installed; AD checks skipped" -Risk "Info"
}

# ============================================================
# SECTION 3: GRC & COMPLIANCE
# ============================================================

Write-Host "[*] Checking GRC Compliance..." -ForegroundColor Cyan

# 3.1 UAC Settings
try {
    $UAC = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
    if ($UAC.EnableLUA -eq 1) {
        Add-Result -Category "GRC" -Check "UAC Enabled" -Status "PASS" `
            -Details "UAC is enabled" -Risk "Info"
    } else {
        Add-Result -Category "GRC" -Check "UAC Enabled" -Status "FAIL" `
            -Details "UAC is disabled" -Risk "High" `
            -Recommendation "Enable UAC via regedit or Group Policy"
    }
} catch {
    Add-Result -Category "GRC" -Check "UAC Enabled" -Status "WARNING" `
        -Details "Unable to check UAC status" -Risk "Medium"
}

# 3.2 Audit Policy
try {
    $AuditPolicy = auditpol /get /category:"Logon/Logoff" /subcategory:"Logon" /success:enable /failure:enable 2>&1
    if ($AuditPolicy -match "Success" -and $AuditPolicy -match "Failure") {
        Add-Result -Category "GRC" -Check "Audit Policy (Logon)" -Status "PASS" `
            -Details "Success and failure logging enabled" -Risk "Info"
    } else {
        Add-Result -Category "GRC" -Check "Audit Policy (Logon)" -Status "FAIL" `
            -Details "Logon auditing not fully enabled" -Risk "High" `
            -Recommendation "Enable success and failure logon auditing via Group Policy"
    }
} catch {
    Add-Result -Category "GRC" -Check "Audit Policy" -Status "WARNING" `
        -Details "Unable to check audit policy" -Risk "Medium"
}

# 3.3 Account Lockout Policy
try {
    $LockoutThreshold = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Account" -Name "LockoutThreshold" -ErrorAction SilentlyContinue
    if ($LockoutThreshold.LockoutThreshold -gt 0) {
        Add-Result -Category "GRC" -Check "Account Lockout Policy" -Status "PASS" `
            -Details "Lockout threshold: $($LockoutThreshold.LockoutThreshold)" -Risk "Info"
    } else {
        Add-Result -Category "GRC" -Check "Account Lockout Policy" -Status "FAIL" `
            -Details "Account lockout is disabled" -Risk "High" `
            -Recommendation "Enable account lockout to prevent brute-force attacks"
    }
} catch {
    Add-Result -Category "GRC" -Check "Account Lockout Policy" -Status "WARNING" `
        -Details "Unable to check lockout policy" -Risk "Medium"
}

# 3.4 LAPS (Local Administrator Password Solution)
try {
    $LAPSInstalled = Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%LAPS%'" -ErrorAction SilentlyContinue
    if ($LAPSInstalled) {
        Add-Result -Category "GRC" -Check "LAPS Installed" -Status "PASS" `
            -Details "LAPS is installed" -Risk "Info"
    } else {
        Add-Result -Category "GRC" -Check "LAPS Installed" -Status "WARNING" `
            -Details "LAPS not installed" -Risk "Medium" `
            -Recommendation "Consider deploying LAPS for local admin password management"
    }
} catch {
    Add-Result -Category "GRC" -Check "LAPS Installed" -Status "WARNING" `
        -Details "Unable to check LAPS installation" -Risk "Low"
}

# ============================================================
# SECTION 4: LOG ANALYSIS (Security Events)
# ============================================================

Write-Host "[*] Analyzing Security Logs..." -ForegroundColor Cyan

try {
    $StartDate = (Get-Date).AddDays(-30)
    $Events = Get-WinEvent -LogName Security -MaxEvents 10000 -ErrorAction SilentlyContinue |
        Where-Object { $_.TimeCreated -gt $StartDate }

    # 4.1 Failed Logins
    $FailedLogins = $Events | Where-Object { $_.Id -eq 4625 }
    if ($FailedLogins.Count -gt 100) {
        Add-Result -Category "Log Analysis" -Check "Failed Logins (30 days)" -Status "WARNING" `
            -Details "$($FailedLogins.Count) failed logins detected" -Risk "High" `
            -Recommendation "Investigate source IPs; consider brute-force protection"
    } elseif ($FailedLogins.Count -gt 0) {
        Add-Result -Category "Log Analysis" -Check "Failed Logins (30 days)" -Status "INFO" `
            -Details "$($FailedLogins.Count) failed logins detected" -Risk "Info" `
            -Recommendation "Monitor for unusual patterns"
    } else {
        Add-Result -Category "Log Analysis" -Check "Failed Logins (30 days)" -Status "PASS" `
            -Details "No failed logins detected in last 30 days" -Risk "Info"
    }

    # 4.2 Privilege Escalation (4673)
    $PrivEsc = $Events | Where-Object { $_.Id -eq 4673 }
    if ($PrivEsc.Count -gt 10) {
        Add-Result -Category "Log Analysis" -Check "Privilege Escalation Events" -Status "WARNING" `
            -Details "$($PrivEsc.Count) events detected" -Risk "High" `
            -Recommendation "Review privileged service usage; investigate anomalies"
    } else {
        Add-Result -Category "Log Analysis" -Check "Privilege Escalation Events" -Status "PASS" `
            -Details "$($PrivEsc.Count) events detected" -Risk "Info"
    }

    # 4.3 Account Lockouts (4740)
    $Lockouts = $Events | Where-Object { $_.Id -eq 4740 }
    if ($Lockouts.Count -gt 5) {
        Add-Result -Category "Log Analysis" -Check "Account Lockouts" -Status "WARNING" `
            -Details "$($Lockouts.Count) lockout events" -Risk "Medium" `
            -Recommendation "Investigate potential brute-force or service account issues"
    } else {
        Add-Result -Category "Log Analysis" -Check "Account Lockouts" -Status "PASS" `
            -Details "$($Lockouts.Count) lockout events" -Risk "Info"
    }

} catch {
    Add-Result -Category "Log Analysis" -Check "Security Log Scan" -Status "WARNING" `
        -Details "Unable to analyze security logs: $($_.Exception.Message)" -Risk "Medium"
}

# ============================================================
# SECTION 5: SYSTEM HARDENING
# ============================================================

Write-Host "[*] Checking System Hardening..." -ForegroundColor Cyan

# 5.1 Windows Defender
try {
    $Defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($Defender.AntivirusEnabled -eq $true) {
        Add-Result -Category "System Hardening" -Check "Windows Defender" -Status "PASS" `
            -Details "Antivirus is enabled" -Risk "Info"
    } else {
        Add-Result -Category "System Hardening" -Check "Windows Defender" -Status "FAIL" `
            -Details "Antivirus is disabled" -Risk "Critical" `
            -Recommendation "Enable Windows Defender or install alternative AV"
    }
} catch {
    Add-Result -Category "System Hardening" -Check "Windows Defender" -Status "WARNING" `
        -Details "Unable to check Defender status" -Risk "Medium"
}

# 5.2 Firewall
try {
    $Firewall = Get-NetFirewallProfile | Select-Object Name, Enabled
    $Disabled = $Firewall | Where-Object { $_.Enabled -eq $false }
    if ($Disabled) {
        Add-Result -Category "System Hardening" -Check "Windows Firewall" -Status "FAIL" `
            -Details "Firewall disabled for: $($Disabled.Name -join ', ')" -Risk "Critical" `
            -Recommendation "Enable Windows Firewall for all profiles"
    } else {
        Add-Result -Category "System Hardening" -Check "Windows Firewall" -Status "PASS" `
            -Details "Firewall is enabled for all profiles" -Risk "Info"
    }
} catch {
    Add-Result -Category "System Hardening" -Check "Windows Firewall" -Status "WARNING" `
        -Details "Unable to check firewall status" -Risk "Medium"
}

# 5.3 BitLocker
try {
    $BitLocker = Get-BitLockerVolume -ErrorAction SilentlyContinue
    if ($BitLocker.ProtectionStatus -eq "On" -or $BitLocker.ProtectionStatus -eq "On" -and $BitLocker.MountPoint -eq "C:") {
        Add-Result -Category "System Hardening" -Check "BitLocker" -Status "PASS" `
            -Details "BitLocker is enabled" -Risk "Info"
    } else {
        Add-Result -Category "System Hardening" -Check "BitLocker" -Status "WARNING" `
            -Details "BitLocker not enabled on system drive" -Risk "Medium" `
            -Recommendation "Enable BitLocker for data-at-rest protection"
    }
} catch {
    Add-Result -Category "System Hardening" -Check "BitLocker" -Status "WARNING" `
        -Details "Unable to check BitLocker status" -Risk "Low"
}

# 5.4 PowerShell Logging
try {
    $PSLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
    if ($PSLogging.EnableScriptBlockLogging -eq 1) {
        Add-Result -Category "System Hardening" -Check "PowerShell Script Block Logging" -Status "PASS" `
            -Details "Script block logging is enabled" -Risk "Info"
    } else {
        Add-Result -Category "System Hardening" -Check "PowerShell Script Block Logging" -Status "WARNING" `
            -Details "Script block logging is not enabled" -Risk "High" `
            -Recommendation "Enable PowerShell script block logging via Group Policy"
    }
} catch {
    Add-Result -Category "System Hardening" -Check "PowerShell Logging" -Status "WARNING" `
        -Details "Unable to check PowerShell logging" -Risk "Medium"
}

# 5.5 LSASS Protection
try {
    $LSASS = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
    if ($LSASS.RunAsPPL -eq 1) {
        Add-Result -Category "System Hardening" -Check "LSASS Protection (PPL)" -Status "PASS" `
            -Details "LSASS is running as Protected Process Light" -Risk "Info"
    } else {
        Add-Result -Category "System Hardening" -Check "LSASS Protection (PPL)" -Status "WARNING" `
            -Details "LSASS not running as PPL" -Risk "High" `
            -Recommendation "Enable LSASS PPL to protect against credential dumping"
    }
} catch {
    Add-Result -Category "System Hardening" -Check "LSASS Protection" -Status "WARNING" `
        -Details "Unable to check LSASS protection" -Risk "Medium"
}

# 5.6 AMSI
try {
    $AMSI = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Features" -Name "AMSIEnable" -ErrorAction SilentlyContinue
    if ($AMSI.AMSIEnable -eq 1 -or $AMSI.AMSIEnable -eq $null) {
        Add-Result -Category "System Hardening" -Check "AMSI (Antimalware Scan Interface)" -Status "PASS" `
            -Details "AMSI is enabled" -Risk "Info"
    } else {
        Add-Result -Category "System Hardening" -Check "AMSI (Antimalware Scan Interface)" -Status "FAIL" `
            -Details "AMSI is disabled" -Risk "Critical" `
            -Recommendation "Enable AMSI to prevent script-based attacks"
    }
} catch {
    Add-Result -Category "System Hardening" -Check "AMSI" -Status "WARNING" `
        -Details "Unable to check AMSI status" -Risk "Medium"
}

# 5.7 Sysmon
try {
    $Sysmon = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
    if ($Sysmon.Status -eq "Running") {
        Add-Result -Category "System Hardening" -Check "Sysmon Installed" -Status "PASS" `
            -Details "Sysmon is running" -Risk "Info"
    } else {
        Add-Result -Category "System Hardening" -Check "Sysmon Installed" -Status "WARNING" `
            -Details "Sysmon is not installed or not running" -Risk "High" `
            -Recommendation "Deploy Sysmon with a production-tuned configuration"
    }
} catch {
    Add-Result -Category "System Hardening" -Check "Sysmon" -Status "WARNING" `
        -Details "Unable to check Sysmon status" -Risk "Medium"
}

# ============================================================
# SECTION 6: NETWORK SECURITY
# ============================================================

Write-Host "[*] Checking Network Security..." -ForegroundColor Cyan

# 6.1 LLMNR / mDNS
try {
    $LLMNR = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
    if ($LLMNR.EnableMulticast -eq 0) {
        Add-Result -Category "Network Security" -Check "LLMNR / mDNS" -Status "PASS" `
            -Details "LLMNR/mDNS is disabled" -Risk "Info"
    } else {
        Add-Result -Category "Network Security" -Check "LLMNR / mDNS" -Status "WARNING" `
            -Details "LLMNR/mDNS is enabled" -Risk "High" `
            -Recommendation "Disable LLMNR/mDNS to prevent responder attacks"
    }
} catch {
    Add-Result -Category "Network Security" -Check "LLMNR / mDNS" -Status "WARNING" `
        -Details "Unable to check LLMNR/mDNS status" -Risk "Medium"
}

# 6.2 NetBIOS
try {
    $NetBIOS = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.NetBIOSEnabled -eq $true }
    if ($NetBIOS) {
        Add-Result -Category "Network Security" -Check "NetBIOS" -Status "WARNING" `
            -Details "NetBIOS is enabled on some interfaces" -Risk "High" `
            -Recommendation "Disable NetBIOS to reduce attack surface"
    } else {
        Add-Result -Category "Network Security" -Check "NetBIOS" -Status "PASS" `
            -Details "NetBIOS is disabled" -Risk "Info"
    }
} catch {
    Add-Result -Category "Network Security" -Check "NetBIOS" -Status "WARNING" `
        -Details "Unable to check NetBIOS status" -Risk "Medium"
}

# ============================================================
# SECTION 7: MALWARE READINESS
# ============================================================

Write-Host "[*] Checking Malware Readiness..." -ForegroundColor Cyan

# 7.1 AppLocker
try {
    $AppLocker = Get-AppLockerPolicy -ErrorAction SilentlyContinue
    if ($AppLocker.Rules.Count -gt 0) {
        Add-Result -Category "Malware Readiness" -Check "AppLocker" -Status "PASS" `
            -Details "AppLocker has $($AppLocker.Rules.Count) rules defined" -Risk "Info"
    } else {
        Add-Result -Category "Malware Readiness" -Check "AppLocker" -Status "WARNING" `
            -Details "AppLocker has no rules defined" -Risk "High" `
            -Recommendation "Deploy AppLocker policies to control application execution"
    }
} catch {
    Add-Result -Category "Malware Readiness" -Check "AppLocker" -Status "WARNING" `
        -Details "AppLocker not configured" -Risk "Medium" `
        -Recommendation "Consider implementing application whitelisting"
}

# 7.2 Windows Defender ATP / Microsoft Defender for Endpoint
try {
    $Defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($Defender.RealTimeProtectionEnabled -eq $true) {
        Add-Result -Category "Malware Readiness" -Check "Real-Time Protection" -Status "PASS" `
            -Details "Real-time protection is enabled" -Risk "Info"
    } else {
        Add-Result -Category "Malware Readiness" -Check "Real-Time Protection" -Status "FAIL" `
            -Details "Real-time protection is disabled" -Risk "Critical" `
            -Recommendation "Enable real-time protection immediately"
    }
} catch {
    Add-Result -Category "Malware Readiness" -Check "Real-Time Protection" -Status "WARNING" `
        -Details "Unable to check real-time protection" -Risk "Medium"
}

# ============================================================
# GENERATE REPORTS
# ============================================================

Write-Host "[*] Generating reports..." -ForegroundColor Cyan

# Generate HTML Report
$HTML = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Unified Security Audit Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        .summary { display: flex; gap: 20px; flex-wrap: wrap; margin: 20px 0; }
        .summary-card { flex: 1; min-width: 150px; padding: 15px; border-radius: 8px; text-align: center; color: white; }
        .summary-card.total { background: #2c3e50; }
        .summary-card.pass { background: #27ae60; }
        .summary-card.fail { background: #e74c3c; }
        .summary-card.warning { background: #f39c12; }
        .summary-card.critical { background: #c0392b; }
        .summary-card .number { font-size: 32px; font-weight: bold; }
        .summary-card .label { font-size: 14px; opacity: 0.9; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 14px; }
        th { background: #34495e; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ecf0f1; vertical-align: top; }
        tr:hover { background: #f8f9fa; }
        .status-badge { padding: 4px 12px; border-radius: 12px; font-weight: bold; font-size: 12px; display: inline-block; }
        .status-pass { background: #d4edda; color: #155724; }
        .status-fail { background: #f8d7da; color: #721c24; }
        .status-warning { background: #fff3cd; color: #856404; }
        .status-info { background: #d1ecf1; color: #0c5460; }
        .risk-critical { background: #e74c3c; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; }
        .risk-high { background: #e67e22; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; }
        .risk-medium { background: #f1c40f; color: #333; padding: 2px 8px; border-radius: 4px; font-size: 11px; }
        .risk-low { background: #3498db; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; }
        .risk-info { background: #95a5a6; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; }
        .recommendation { background: #f0f8ff; padding: 8px; border-left: 4px solid #3498db; margin-top: 4px; font-style: italic; }
        .timestamp { color: #7f8c8d; font-size: 14px; }
        .footer { margin-top: 30px; border-top: 1px solid #ecf0f1; padding-top: 20px; text-align: center; color: #7f8c8d; font-size: 12px; }
        @media print {
            body { background: white; }
            .container { box-shadow: none; padding: 10px; }
            .summary-card { -webkit-print-color-adjust: exact; }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Unified Security Audit Report</h1>
        <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        <p><strong>Hostname:</strong> $env:COMPUTERNAME</p>
        <p><strong>Domain:</strong> $env:USERDOMAIN</p>

        <div class="summary">
            <div class="summary-card total"><div class="number">$($AuditResults.Count)</div><div class="label">Total Checks</div></div>
            <div class="summary-card pass"><div class="number">$(($AuditResults | Where-Object { $_.Status -eq "PASS" }).Count)</div><div class="label">Passed</div></div>
            <div class="summary-card warning"><div class="number">$(($AuditResults | Where-Object { $_.Status -eq "WARNING" }).Count)</div><div class="label">Warnings</div></div>
            <div class="summary-card fail"><div class="number">$(($AuditResults | Where-Object { $_.Status -eq "FAIL" }).Count)</div><div class="label">Failed</div></div>
            <div class="summary-card critical"><div class="number">$(($AuditResults | Where-Object { $_.Risk -eq "Critical" }).Count)</div><div class="label">Critical Issues</div></div>
        </div>

        <h2>📋 Executive Summary</h2>
        <p>
            <strong>Risk Score:</strong>
            $(
                $Critical = ($AuditResults | Where-Object { $_.Risk -eq "Critical" }).Count
                $High = ($AuditResults | Where-Object { $_.Risk -eq "High" }).Count
                $Medium = ($AuditResults | Where-Object { $_.Risk -eq "Medium" }).Count
                if ($Critical -gt 0) { "🔴 HIGH RISK - Immediate action required" }
                elseif ($High -gt 5) { "🟠 ELEVATED RISK - Action required within 30 days" }
                elseif ($High -gt 0 -or $Medium -gt 5) { "🟡 MODERATE RISK - Plan remediation" }
                else { "🟢 LOW RISK - Maintain current posture" }
            )
        </p>
        <p><strong>Critical Findings:</strong> $Critical</p>
        <p><strong>High Risk Findings:</strong> $High</p>
        <p><strong>Medium Risk Findings:</strong> $Medium</p>

        <h2>📊 Detailed Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Category</th>
                    <th>Check</th>
                    <th>Status</th>
                    <th>Risk</th>
                    <th>Details</th>
                    <th>Recommendation</th>
                </tr>
            </thead>
            <tbody>
"@

foreach ($r in $AuditResults) {
    $statusClass = switch ($r.Status) {
        "PASS" { "status-pass" }
        "FAIL" { "status-fail" }
        "WARNING" { "status-warning" }
        default { "status-info" }
    }
    $riskClass = switch ($r.Risk) {
        "Critical" { "risk-critical" }
        "High" { "risk-high" }
        "Medium" { "risk-medium" }
        "Low" { "risk-low" }
        default { "risk-info" }
    }
    $HTML += @"
                <tr>
                    <td><strong>$($r.Category)</strong></td>
                    <td>$($r.Check)</td>
                    <td><span class="status-badge $statusClass">$($r.Status)</span></td>
                    <td><span class="$riskClass">$($r.Risk)</span></td>
                    <td>$($r.Details)</td>
                    <td>
                        $($r.Recommendation)
                    </td>
                </tr>
"@
}

$HTML += @"
            </tbody>
        </table>

        <h2>⚠️ Critical & High Priority Findings</h2>
        <ul>
"@

$CriticalFindings = $AuditResults | Where-Object { $_.Risk -eq "Critical" -or $_.Risk -eq "High" }
if ($CriticalFindings.Count -eq 0) {
    $HTML += "<li>✅ No critical or high priority findings detected.</li>"
} else {
    foreach ($f in $CriticalFindings) {
        $HTML += "<li><strong>$($f.Category):</strong> $($f.Check) – <span style='color:#e74c3c;'>$($f.Risk)</span><br>$($f.Recommendation)</li>"
    }
}

$HTML += @"
        </ul>

        <h2>📈 Category Breakdown</h2>
        <ul>
"@

$Categories = $AuditResults | Group-Object Category | Sort-Object Name
foreach ($cat in $Categories) {
    $Pass = ($cat.Group | Where-Object { $_.Status -eq "PASS" }).Count
    $Fail = ($cat.Group | Where-Object { $_.Status -eq "FAIL" }).Count
    $Warn = ($cat.Group | Where-Object { $_.Status -eq "WARNING" }).Count
    $HTML += "<li><strong>$($cat.Name):</strong> $($cat.Count) checks – Pass: $Pass, Fail: $Fail, Warning: $Warn</li>"
}

$HTML += @"
        </ul>

        <h2>📝 Recommendations Summary</h2>
        <ul>
"@

$Recommendations = $AuditResults | Where-Object { $_.Recommendation -ne "" } | Select-Object -Unique Recommendation
if ($Recommendations.Count -eq 0) {
    $HTML += "<li>✅ No recommendations.</li>"
} else {
    foreach ($rec in $Recommendations) {
        $HTML += "<li>$($rec.Recommendation)</li>"
    }
}

$HTML += @"
        </ul>

        <div class="footer">
            <p>Unified Security Auditor v1.0 | Generated by Charles Ndirangu</p>
            <p>This report is for authorized internal use only. Contains confidential security audit findings.</p>
        </div>
    </div>
</body>
</html>
"@

$HTML | Out-File -FilePath $ReportFile -Encoding UTF8

# Generate CSV Export
$AuditResults | Export-Csv -Path $CsvFile -NoTypeInformation

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "✅ AUDIT COMPLETE!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "📄 HTML Report: $ReportFile" -ForegroundColor Yellow
Write-Host "📊 CSV Export: $CsvFile" -ForegroundColor Yellow
Write-Host ""
Write-Host "📈 Summary:" -ForegroundColor Cyan
Write-Host "   Total Checks: $($AuditResults.Count)"
Write-Host "   ✅ Passed: $(($AuditResults | Where-Object { $_.Status -eq "PASS" }).Count)"
Write-Host "   ⚠️ Warnings: $(($AuditResults | Where-Object { $_.Status -eq "WARNING" }).Count)"
Write-Host "   ❌ Failed: $(($AuditResults | Where-Object { $_.Status -eq "FAIL" }).Count)"
Write-Host "   🔴 Critical Issues: $(($AuditResults | Where-Object { $_.Risk -eq "Critical" }).Count)"
Write-Host ""
Write-Host "🚀 Open the HTML report in your browser for a detailed, actionable view."
Write-Host ""
