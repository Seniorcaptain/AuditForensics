# AuditForensics
Comprehensive, multi-sector cybersecurity audit tool that integrates capabilities from vulnerability scanning, Active Directory auditing, GRC compliance checking, and SIEM-style log analysis. It is designed to be run on a Windows system with administrative privileges and produces readable, actionable results in HTML and CSV formats


# Right-click PowerShell > Run as Administrator

# Basic usage (reports saved to Desktop\AuditReports)
.\UnifiedSecurityAuditor.ps1

# Specify custom output path
.\UnifiedSecurityAuditor.ps1 -OutputPath "C:\AuditReports\MyAudit"

# Bypass execution policy if needed
powershell -ExecutionPolicy Bypass -File .\UnifiedSecurityAuditor.ps1



🧪 Testing & Verification
Quick Self-Test
Run the tool on your local system first to verify it works:

powershell
.\UnifiedSecurityAuditor.ps1 -OutputPath "C:\Temp\TestAudit"
Expected output: A folder containing an HTML report and a CSV file.


Validate Individual Checks
You can run specific checks manually to verify the tool's accuracy:

powershell
# Check pending updates
Get-MpComputerStatus

# Check AD users (if AD module loaded)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"}

# Check firewall status
Get-NetFirewallProfile



📊 Post-Audit Actions
Review the HTML report – Open it in any modern browser.

Prioritize critical issues – Address all Critical and High risk findings first.

Create a remediation plan – Use the Recommendations column as a starting point.

Track progress – Use the CSV export to monitor improvement over time.

Schedule regular audits – Run the tool quarterly to track progress.
