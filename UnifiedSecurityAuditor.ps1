<#
.SYNOPSIS
    AuditForensics Ultimate – Single‑host or multi‑target security audit.
.DESCRIPTION
    Scans local machine or a list of remote targets (parallel).
    Produces HTML/CSV/JSON reports, plus an aggregated dashboard.
.PARAMETER Targets
    Array of computer names to scan. If omitted, scans localhost.
.PARAMETER ThrottleLimit
    Maximum number of parallel remote scans (default 20).
.PARAMETER Credential
    PSCredential object for remote authentication (if needed).
.PARAMETER OutputPath
    Directory to save reports (default: .\AuditReports).
.PARAMETER Sigma
    Enable Sigma rule checks.
.PARAMETER Correlate
    Enable attack correlation.
.PARAMETER Baseline
    Enable baseline anomaly detection (per machine).
.PARAMETER AIEnrich
    Enable AI prioritisation (requires OPENAI_API_KEY env var).
.PARAMETER Demo
    Run with sample data (no system scanning) – works for single host only.
.EXAMPLE
    .\AuditForensics_Ultimate.ps1 -Targets @("PC01","PC02","PC03") -Sigma -Correlate -ThrottleLimit 10
#>
[CmdletBinding()]
param(
    [string[]]$Targets,
    [int]$ThrottleLimit = 20,
    [PSCredential]$Credential,
    [string]$OutputPath = "$env:USERPROFILE\Desktop\AuditReports",
    [switch]$Sigma,
    [switch]$Correlate,
    [switch]$Baseline,
    [switch]$AIEnrich,
    [switch]$Demo
)

# ---------- If Demo or no Targets, run local audit ----------
if ($Demo -or (-not $Targets)) {
    # This is the original single‑host script (embedded for brevity in this answer)
    # We will just call the original logic here. For space, we refer to the previous version.
    Write-Host "Running local audit..." -ForegroundColor Cyan
    # ... (full script from previous answer goes here) ...
    # (In practice, you would paste the entire script body here)
    return
}

# ---------- Multi‑target execution ----------
Write-Host "[*] Multi‑target scan started for $($Targets.Count) machines." -ForegroundColor Green
$StartTime = Get-Date
$ReportPath = $OutputPath
if (!(Test-Path $ReportPath)) { New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null }
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$AggregatedHtml = Join-Path $ReportPath "AuditForensics_Aggregated_$Timestamp.html"
$AggregatedCsv = Join-Path $ReportPath "AuditForensics_Aggregated_$Timestamp.csv"
$AggregatedJson = Join-Path $ReportPath "AuditForensics_Aggregated_$Timestamp.json"

# Prepare a temporary script for remote execution (copy this script to remote machines)
# Option A: Use a network share (simplest) – assume script is available at same path on all machines.
# Option B: Use Invoke-Command -FilePath to pass the script content.
# We'll use -FilePath to pass this script's full path (assuming it exists on all machines or is accessible).
$ScriptPath = $MyInvocation.MyCommand.Path
if (-not (Test-Path $ScriptPath)) {
    Write-Error "Script file not found at $ScriptPath. Please provide a valid script path."
    exit 1
}

# Build the command to run on each target
$RemoteScriptBlock = {
    param($OutputDir, $EnableSigma, $EnableCorrelate, $EnableBaseline, $EnableAI, $LocalScriptPath)
    & $LocalScriptPath -OutputPath $OutputDir -Sigma:$EnableSigma -Correlate:$EnableCorrelate -Baseline:$EnableBaseline -AIEnrich:$EnableAI
}

# Create a session for each target (throttled)
$Sessions = New-PSSession -ComputerName $Targets -ThrottleLimit $ThrottleLimit -Credential $Credential -ErrorAction SilentlyContinue
if ($Sessions.Count -eq 0) {
    Write-Error "No targets are reachable. Check network and WinRM."
    exit 1
}

Write-Host "[*] Running audit on $($Sessions.Count) reachable machines..." -ForegroundColor Cyan

# Invoke in parallel
$Jobs = Invoke-Command -Session $Sessions -ScriptBlock $RemoteScriptBlock -ArgumentList $ReportPath, $Sigma, $Correlate, $Baseline, $AIEnrich, $ScriptPath -AsJob

# Wait for all jobs to complete
$Jobs | Wait-Job | Out-Null

# Collect results (each remote job writes its JSON file; we gather them)
$MachineResults = @()
foreach ($s in $Sessions) {
    $computer = $s.ComputerName
    # Find the JSON file written by that machine
    $jsonFiles = Get-ChildItem -Path $ReportPath -Filter "AuditForensics_*_$computer.json" -ErrorAction SilentlyContinue
    if ($jsonFiles) {
        $json = Get-Content $jsonFiles[0].FullName | ConvertFrom-Json
        $MachineResults += [PSCustomObject]@{
            Computer = $computer
            Status   = "Success"
            Summary  = $json.Summary
            Findings = $json.Findings
            Sigma    = $json.SigmaFindings
            Correlations = $json.Correlations
        }
    } else {
        $MachineResults += [PSCustomObject]@{ Computer = $computer; Status = "Failed (no JSON)" }
    }
}
Remove-PSSession $Sessions

# ---------- Generate Aggregated Report ----------
Write-Host "[*] Generating aggregated report..." -ForegroundColor Cyan

# Build summary across all machines
$TotalMachines = $MachineResults.Count
$CriticalMachines = ($MachineResults | Where-Object { $_.Summary.Critical -gt 0 }).Count
$HighMachines = ($MachineResults | Where-Object { $_.Summary.High -gt 0 }).Count
$TotalCriticalIssues = ($MachineResults | Measure-Object -Property { $_.Summary.Critical } -Sum).Sum
$TotalHighIssues = ($MachineResults | Measure-Object -Property { $_.Summary.High } -Sum).Sum

# Create HTML table rows for each machine
$TableRows = ""
foreach ($m in $MachineResults | Sort-Object { $_.Summary.Critical } -Descending) {
    $cls = if ($m.Summary.Critical -gt 0) { "table-danger" } elseif ($m.Summary.High -gt 0) { "table-warning" } else { "" }
    $TableRows += @"
<tr class="$cls">
    <td><strong>$($m.Computer)</strong></td>
    <td>$($m.Status)</td>
    <td>$($m.Summary.TotalChecks)</td>
    <td>$($m.Summary.Passed)</td>
    <td>$($m.Summary.Failed)</td>
    <td>$($m.Summary.Warnings)</td>
    <td><span class="badge bg-danger">$($m.Summary.Critical)</span></td>
    <td><span class="badge bg-warning">$($m.Summary.High)</span></td>
</tr>
"@
}

$HTML = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>AuditForensics – Aggregated Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { padding: 20px; background: #f8f9fa; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .summary-card { flex: 1; min-width: 120px; padding: 15px; border-radius: 8px; text-align: center; color: white; }
        .card-total { background: #2c3e50; }
        .card-critical { background: #c0392b; }
        .card-high { background: #e67e22; }
        .card-success { background: #27ae60; }
        .number { font-size: 28px; font-weight: bold; }
    </style>
</head>
<body>
<div class="container">
    <h1>📊 Aggregated Audit Report</h1>
    <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    <p>Total machines: $TotalMachines</p>

    <div class="d-flex flex-wrap gap-3 mb-4">
        <div class="summary-card card-total"><div class="number">$TotalMachines</div><div>Machines</div></div>
        <div class="summary-card card-critical"><div class="number">$CriticalMachines</div><div>Machines with Critical</div></div>
        <div class="summary-card card-high"><div class="number">$HighMachines</div><div>Machines with High</div></div>
        <div class="summary-card card-success"><div class="number">$($TotalMachines - $CriticalMachines - $HighMachines)</div><div>Clean Machines</div></div>
    </div>

    <h2>Machine Summary</h2>
    <table class="table table-striped table-hover">
        <thead><tr><th>Computer</th><th>Status</th><th>Total</th><th>Pass</th><th>Fail</th><th>Warn</th><th>Critical</th><th>High</th></tr></thead>
        <tbody>$TableRows</tbody>
    </table>

    <h2>Top 5 Critical Machines</h2>
    <ul>
"@
$TopCritical = $MachineResults | Sort-Object { $_.Summary.Critical } -Descending | Select-Object -First 5
foreach ($m in $TopCritical) {
    $HTML += "<li><strong>$($m.Computer)</strong> – Critical: $($m.Summary.Critical), High: $($m.Summary.High)</li>"
}
$HTML += @"
    </ul>

    <footer class="text-muted">Generated by AuditForensics Ultimate – Aggregated</footer>
</div>
</body>
</html>
"@

$HTML | Out-File -FilePath $AggregatedHtml -Encoding UTF8

# Export aggregated CSV
$MachineResults | ForEach-Object {
    [PSCustomObject]@{
        Computer = $_.Computer
        Status = $_.Status
        TotalChecks = if ($_.Summary) { $_.Summary.TotalChecks } else { $null }
        Passed = if ($_.Summary) { $_.Summary.Passed } else { $null }
        Failed = if ($_.Summary) { $_.Summary.Failed } else { $null }
        Warnings = if ($_.Summary) { $_.Summary.Warnings } else { $null }
        Critical = if ($_.Summary) { $_.Summary.Critical } else { $null }
        High = if ($_.Summary) { $_.Summary.High } else { $null }
    }
} | Export-Csv -Path $AggregatedCsv -NoTypeInformation

# Export aggregated JSON
$MachineResults | ConvertTo-Json -Depth 5 | Out-File -FilePath $AggregatedJson -Encoding UTF8

$Duration = (Get-Date) - $StartTime
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "✅ MULTI‑TARGET SCAN COMPLETE!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "📄 Aggregated HTML: $AggregatedHtml" -ForegroundColor Yellow
Write-Host "📊 Aggregated CSV: $AggregatedCsv" -ForegroundColor Yellow
Write-Host "📄 Aggregated JSON: $AggregatedJson" -ForegroundColor Magenta
Write-Host "⏱️  Duration: $($Duration.TotalSeconds) seconds" -ForegroundColor Cyan
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "   Total Machines: $TotalMachines"
Write-Host "   Machines with Critical Issues: $CriticalMachines"
Write-Host "   Machines with High Issues: $HighMachines"
Write-Host ""
