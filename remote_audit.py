#!/usr/bin/env python3
"""
AuditForensics Enhanced - AI-powered, multi-stage, Sigma-integrated security audit.
Usage: python auditforensics_enhanced.py --target localhost --ai-enrich --correlate --sigma
"""

import os
import sys
import json
import yaml
import subprocess
import re
import hashlib
import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import base64

# Optional imports (warn if missing)
try:
    import click
except ImportError:
    print("Please install click: pip install click")
    sys.exit(1)
try:
    import jinja2
except ImportError:
    print("Please install jinja2: pip install jinja2")
    sys.exit(1)
try:
    import requests
except ImportError:
    requests = None
    print("Warning: requests not installed. AI enrichment will use fallback only.")

# --------------------------------------------------------------------------
# 1. CONFIGURATION LOADER
# --------------------------------------------------------------------------
DEFAULT_CONFIG = {
    "collectors": {
        "winrm": {"port": 5985, "use_ssl": False},
        "ldap": {"timeout": 30}
    },
    "analyzers": {
        "sigma": {"enabled": True, "rule_dir": None},
        "ai": {"enabled": False, "model": "gpt-4o-mini", "cost_limit": 0.50, "api_key": None},
        "correlation": {"enabled": True}
    },
    "agents": {"enable_validation": False},
    "reporting": {"format": "html", "include_ai_summary": True}
}

def load_config(config_path: str = "config.yaml") -> Dict:
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            cfg = yaml.safe_load(f)
            # merge with defaults
            for k, v in DEFAULT_CONFIG.items():
                if k not in cfg:
                    cfg[k] = v
            return cfg
    return DEFAULT_CONFIG

# --------------------------------------------------------------------------
# 2. COLLECTORS (Windows Local / AD via PowerShell)
# --------------------------------------------------------------------------
class WindowsCollector:
    def __init__(self, target: str, config: Dict):
        self.target = target
        self.config = config

    def _run_powershell(self, script: str) -> str:
        """Execute PowerShell script and return stdout."""
        try:
            result = subprocess.run(
                ["powershell", "-Command", script],
                capture_output=True, text=True, timeout=30, encoding='utf-8'
            )
            return result.stdout
        except Exception as e:
            return f"ERROR: {e}"

    def collect(self) -> Dict:
        data = {
            "target": self.target,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "os": {},
            "patches": [],
            "smb_signing": False,
            "spooler_running": False,
            "uac_enabled": False,
            "firewall_enabled": False,
            "local_admins": [],
            "domain_users": [],
            "services": [],
            "startup_items": [],
            "event_logs": {"anomalous_ntlm": False}
        }

        # OS Info
        os_info = self._run_powershell("Get-ComputerInfo | ConvertTo-Json")
        try:
            info = json.loads(os_info)
            data["os"] = {
                "name": info.get("OsName", "Unknown"),
                "version": info.get("OsVersion", "Unknown"),
                "build": info.get("OsBuildNumber", "Unknown")
            }
        except:
            pass

        # Patches
        patches_out = self._run_powershell("Get-HotFix | Select-Object HotFixID, InstalledOn | ConvertTo-Json")
        try:
            patches = json.loads(patches_out)
            if isinstance(patches, dict):
                patches = [patches]
            data["patches"] = patches
        except:
            pass

        # SMB Signing
        smb_out = self._run_powershell("Get-SmbServerConfiguration | Select-Object EnableSecuritySignature, RequireSecuritySignature | ConvertTo-Json")
        try:
            smb = json.loads(smb_out)
            if smb.get("EnableSecuritySignature") == True or smb.get("RequireSecuritySignature") == True:
                data["smb_signing"] = True
        except:
            pass

        # Spooler service
        spooler = self._run_powershell("Get-Service -Name Spooler | Select-Object Status | ConvertTo-Json")
        try:
            svc = json.loads(spooler)
            if svc.get("Status") == "Running":
                data["spooler_running"] = True
        except:
            pass

        # UAC
        uac = self._run_powershell("(Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System).EnableLUA")
        if "1" in uac:
            data["uac_enabled"] = True

        # Firewall
        fw = self._run_powershell("(Get-NetFirewallProfile | Where-Object {$_.Enabled -eq 'True'}).Count")
        if int(fw.strip() or 0) > 0:
            data["firewall_enabled"] = True

        # Local Admins
        admins = self._run_powershell("Get-LocalGroupMember -Group 'Administrators' | Select-Object Name | ConvertTo-Json")
        try:
            admins_list = json.loads(admins)
            if isinstance(admins_list, dict):
                admins_list = [admins_list]
            data["local_admins"] = [a.get("Name") for a in admins_list if a.get("Name")]
        except:
            pass

        # Domain Users (LDAP) - requires AD module
        if self._run_powershell("Get-Module -ListAvailable -Name ActiveDirectory").strip():
            users = self._run_powershell("Get-ADUser -Filter * -Properties DisplayName, PasswordLastSet, Enabled | Select-Object SamAccountName, Enabled, PasswordLastSet | ConvertTo-Json -Depth 3")
            try:
                user_data = json.loads(users)
                if isinstance(user_data, dict):
                    user_data = [user_data]
                data["domain_users"] = [{"name": u.get("SamAccountName"), "enabled": u.get("Enabled"), "pwd_last_set": u.get("PasswordLastSet")} for u in user_data]
            except:
                pass

        # Event log anomaly (simplified: check for 4776 in last 24h)
        events = self._run_powershell("Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4776; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 1")
        if "4776" in events:
            data["event_logs"]["anomalous_ntlm"] = True

        # Baseline hash (for anomaly detection)
        data["_baseline_hash"] = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

        return data

# --------------------------------------------------------------------------
# 3. SIGMA ENGINE (Built‑in rules)
# --------------------------------------------------------------------------
BUILTIN_SIGMA_RULES = [
    {
        "id": "SIG-001",
        "title": "SMB Signing Disabled",
        "level": "high",
        "description": "SMB signing is disabled, allowing NTLM relay attacks.",
        "detection": {"smb_signing": False}
    },
    {
        "id": "SIG-002",
        "title": "Print Spooler Running",
        "level": "medium",
        "description": "Print Spooler service is running – potential vector for NTLM coercion.",
        "detection": {"spooler_running": True}
    },
    {
        "id": "SIG-003",
        "title": "Missing Critical Patches",
        "level": "high",
        "description": "System has fewer than 10 installed patches – likely vulnerable.",
        "detection": {"patch_count_lt": 10}
    },
    {
        "id": "SIG-004",
        "title": "UAC Disabled",
        "level": "medium",
        "description": "User Account Control is disabled, increasing privilege escalation risk.",
        "detection": {"uac_enabled": False}
    }
]

class SigmaEngine:
    def __init__(self, rules: Optional[List[Dict]] = None):
        self.rules = rules or BUILTIN_SIGMA_RULES

    def run(self, audit_data: Dict) -> List[Dict]:
        findings = []
        for rule in self.rules:
            detection = rule.get("detection", {})
            matches = True
            matched_conditions = []
            for key, val in detection.items():
                if key == "patch_count_lt":
                    if len(audit_data.get("patches", [])) >= val:
                        matches = False
                    else:
                        matched_conditions.append(f"patches < {val}")
                elif key in audit_data:
                    if audit_data[key] != val:
                        matches = False
                    else:
                        matched_conditions.append(f"{key} = {val}")
                else:
                    matches = False
            if matches:
                findings.append({
                    "rule_id": rule.get("id"),
                    "title": rule.get("title"),
                    "severity": rule.get("level", "medium"),
                    "description": rule.get("description"),
                    "matched_conditions": matched_conditions
                })
        return findings

# --------------------------------------------------------------------------
# 4. CORRELATION ENGINE (Multi‑stage attack chains)
# --------------------------------------------------------------------------
class CorrelationEngine:
    ATTACK_PATTERNS = {
        "ntlm_reflection": {
            "stages": [
                {"key": "spooler_running", "value": True},
                {"key": "smb_signing", "value": False},
                {"key": "event_logs.anomalous_ntlm", "value": True}
            ],
            "severity": "critical",
            "remediation": "Enable SMB signing, disable Spooler where not needed, enable LAPS."
        },
        "kerberoast": {
            "stages": [
                {"key": "domain_users", "exists": True},
                {"key": "smb_signing", "value": False}  # weak AD config
            ],
            "severity": "high",
            "remediation": "Enforce AES encryption for Kerberos, rotate service account passwords."
        }
    }

    def analyze(self, audit_data: Dict) -> List[Dict]:
        correlations = []
        for name, pattern in self.ATTACK_PATTERNS.items():
            matched_stages = []
            all_match = True
            for stage in pattern["stages"]:
                if "key" in stage:
                    keys = stage["key"].split(".")
                    val = audit_data
                    for k in keys:
                        val = val.get(k, None) if isinstance(val, dict) else None
                    if "value" in stage:
                        if val == stage["value"]:
                            matched_stages.append(f"{stage['key']} = {stage['value']}")
                        else:
                            all_match = False
                    elif "exists" in stage:
                        if val is not None and (isinstance(val, list) and len(val) > 0):
                            matched_stages.append(f"{stage['key']} exists")
                        else:
                            all_match = False
            if all_match and matched_stages:
                correlations.append({
                    "attack": name,
                    "severity": pattern["severity"],
                    "stages_found": matched_stages,
                    "remediation": pattern["remediation"]
                })
        return correlations

# --------------------------------------------------------------------------
# 5. AI PRIORITIZER (with fallback)
# --------------------------------------------------------------------------
class AIPrioritizer:
    def __init__(self, config: Dict):
        self.config = config
        self.api_key = config.get("api_key") or os.environ.get("OPENAI_API_KEY")
        self.model = config.get("model", "gpt-4o-mini")
        self.cost_limit = config.get("cost_limit", 0.50)

    def prioritize(self, findings: List[Dict], all_data: Dict) -> Dict:
        if self.api_key and requests:
            return self._ai_prioritize(findings, all_data)
        else:
            return self._fallback_prioritize(findings, all_data)

    def _ai_prioritize(self, findings, all_data):
        prompt = f"""
You are a security expert. Prioritize these audit findings.
Return JSON: {{"executive_summary": "...", "prioritized": [{{"id": "...", "risk_score": 1-10, "reasoning": "...", "recommended_action": "..."}}]}}
Findings: {json.dumps(findings, indent=2)}
System context: patches={len(all_data.get('patches', []))}, smb_signing={all_data.get('smb_signing')}
"""
        try:
            resp = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.3,
                    "response_format": {"type": "json_object"}
                },
                timeout=30
            )
            if resp.status_code == 200:
                content = resp.json()["choices"][0]["message"]["content"]
                return json.loads(content)
        except Exception as e:
            print(f"AI error: {e}")
        return self._fallback_prioritize(findings, all_data)

    def _fallback_prioritize(self, findings, all_data):
        severity_scores = {"critical": 9, "high": 7, "medium": 5, "low": 3}
        prioritized = []
        for f in findings:
            score = severity_scores.get(f.get("severity", "medium"), 5)
            # Boost if exploit chain possible
            if f.get("title") == "SMB Signing Disabled" and all_data.get("spooler_running"):
                score += 2
            prioritized.append({
                "id": f.get("rule_id", "unknown"),
                "risk_score": min(score, 10),
                "reasoning": f.get("description", ""),
                "recommended_action": f.get("remediation", "Investigate and apply best practices.")
            })
        prioritized.sort(key=lambda x: x["risk_score"], reverse=True)
        summary = f"Found {len(findings)} issues. Top risk: {prioritized[0]['id'] if prioritized else 'None'}."
        return {"executive_summary": summary, "prioritized": prioritized}

# --------------------------------------------------------------------------
# 6. BASELINE MANAGER
# --------------------------------------------------------------------------
class BaselineManager:
    def __init__(self, baseline_file="baseline.json"):
        self.file = baseline_file
        self.baseline = self._load()

    def _load(self):
        if os.path.exists(self.file):
            with open(self.file, 'r') as f:
                return json.load(f)
        return {}

    def save(self, data):
        with open(self.file, 'w') as f:
            json.dump(data, f, indent=2)

    def check_anomalies(self, current_data):
        anomalies = []
        current_hash = current_data.get("_baseline_hash")
        if self.baseline.get("hash") and self.baseline["hash"] != current_hash:
            anomalies.append({
                "type": "configuration_change",
                "detail": "System state has changed since last baseline."
            })
        # Check for new admin users
        old_admins = set(self.baseline.get("local_admins", []))
        new_admins = set(current_data.get("local_admins", []))
        added = new_admins - old_admins
        if added:
            anomalies.append({"type": "new_admin", "users": list(added)})
        return anomalies

# --------------------------------------------------------------------------
# 7. HTML REPORTER (Bootstrap + Chart.js)
# --------------------------------------------------------------------------
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>AuditForensics Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { padding: 20px; }
        .severity-critical { background-color: #dc3545; color: white; }
        .severity-high { background-color: #fd7e14; color: white; }
        .severity-medium { background-color: #ffc107; color: black; }
        .severity-low { background-color: #20c997; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="mb-3">🔐 AuditForensics Enhanced Report</h1>
        <p><strong>Target:</strong> {{ target }} | <strong>Time:</strong> {{ timestamp }}</p>

        <div class="card mb-4">
            <div class="card-header bg-primary text-white">
                Executive Summary
            </div>
            <div class="card-body">
                <p>{{ executive_summary }}</p>
            </div>
        </div>

        <div class="row mb-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">Risk Severity Distribution</div>
                    <div class="card-body"><canvas id="severityChart"></canvas></div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">Top 5 Risks</div>
                    <div class="card-body">
                        <ul class="list-group">
                            {% for item in top_risks %}
                            <li class="list-group-item d-flex justify-content-between align-items-center">
                                {{ item.id }} - {{ item.reasoning[:60] }}...
                                <span class="badge bg-danger rounded-pill">{{ item.risk_score }}/10</span>
                            </li>
                            {% endfor %}
                        </ul>
                    </div>
                </div>
            </div>
        </div>

        <div class="card mb-4">
            <div class="card-header">Sigma Findings</div>
            <div class="card-body">
                {% if sigma_findings %}
                <table class="table table-striped">
                    <tr><th>ID</th><th>Title</th><th>Severity</th><th>Conditions</th></tr>
                    {% for f in sigma_findings %}
                    <tr class="severity-{{ f.severity }}">
                        <td>{{ f.rule_id }}</td><td>{{ f.title }}</td><td>{{ f.severity }}</td>
                        <td>{{ f.matched_conditions | join(', ') }}</td>
                    </tr>
                    {% endfor %}
                </table>
                {% else %}
                <p>No Sigma rule matches.</p>
                {% endif %}
            </div>
        </div>

        <div class="card mb-4">
            <div class="card-header">Attack Correlations</div>
            <div class="card-body">
                {% if correlations %}
                <ul>
                    {% for c in correlations %}
                    <li><strong>{{ c.attack }}</strong> ({{ c.severity }}) - Stages: {{ c.stages_found | join(', ') }}<br>
                        <span class="text-muted">Remediation: {{ c.remediation }}</span>
                    </li>
                    {% endfor %}
                </ul>
                {% else %}
                <p>No attack chains detected.</p>
                {% endif %}
            </div>
        </div>

        <div class="card mb-4">
            <div class="card-header">System Summary</div>
            <div class="card-body">
                <ul>
                    <li><strong>OS:</strong> {{ os_info }}</li>
                    <li><strong>Patches:</strong> {{ patch_count }}</li>
                    <li><strong>SMB Signing:</strong> {{ smb_status }}</li>
                    <li><strong>UAC:</strong> {{ uac_status }}</li>
                    <li><strong>Firewall:</strong> {{ fw_status }}</li>
                    <li><strong>Local Admins:</strong> {{ admins | join(', ') }}</li>
                </ul>
            </div>
        </div>

        <footer class="text-muted">Generated by AuditForensics Enhanced</footer>
    </div>
    <script>
        const ctx = document.getElementById('severityChart').getContext('2d');
        const severityData = {{ severity_counts | tojson }};
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: Object.keys(severityData),
                datasets: [{ data: Object.values(severityData), backgroundColor: ['#dc3545','#fd7e14','#ffc107','#20c997'] }]
            }
        });
    </script>
</body>
</html>
"""

class HTMLReporter:
    def generate(self, results: Dict, output_path: str = "report.html"):
        env = jinja2.Environment(loader=jinja2.BaseLoader())
        # Flatten data for template
        sigma_findings = results.get("sigma_findings", [])
        correlations = results.get("correlations", [])
        ai_result = results.get("ai_prioritized", {"executive_summary": "No AI analysis.", "prioritized": []})
        all_data = results.get("raw_data", {})
        top_risks = ai_result.get("prioritized", [])[:5]

        # Severity counts
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in sigma_findings:
            counts[f.get("severity", "low")] += 1

        context = {
            "target": all_data.get("target", "localhost"),
            "timestamp": all_data.get("timestamp", ""),
            "executive_summary": ai_result.get("executive_summary", "Audit completed."),
            "top_risks": top_risks,
            "sigma_findings": sigma_findings,
            "correlations": correlations,
            "severity_counts": counts,
            "os_info": f"{all_data.get('os', {}).get('name', 'N/A')} {all_data.get('os', {}).get('version', '')}",
            "patch_count": len(all_data.get("patches", [])),
            "smb_status": "Enabled" if all_data.get("smb_signing") else "Disabled",
            "uac_status": "Enabled" if all_data.get("uac_enabled") else "Disabled",
            "fw_status": "Enabled" if all_data.get("firewall_enabled") else "Disabled",
            "admins": all_data.get("local_admins", [])[:5]
        }
        template = env.from_string(HTML_TEMPLATE)
        rendered = template.render(**context)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(rendered)
        print(f"[+] HTML report saved to {output_path}")

# --------------------------------------------------------------------------
# 8. MAIN CLI TOOL
# --------------------------------------------------------------------------
@click.command()
@click.option('--target', '-t', default='localhost', help='Target to audit (localhost or hostname)')
@click.option('--config', '-c', default='config.yaml', help='Path to config YAML')
@click.option('--ai-enrich', is_flag=True, help='Enable AI prioritization (requires OPENAI_API_KEY)')
@click.option('--correlate', is_flag=True, help='Enable multi-stage attack correlation')
@click.option('--sigma', is_flag=True, help='Run Sigma rule checks')
@click.option('--baseline', is_flag=True, help='Compare against baseline and detect anomalies')
@click.option('--demo', is_flag=True, help='Generate demo data for testing (no real scan)')
@click.option('--output', '-o', default='report.html', help='Output report file')
def main(target, config, ai_enrich, correlate, sigma, baseline, demo, output):
    """AuditForensics Enhanced - Next-gen security audit tool."""
    print("[*] AuditForensics Enhanced starting...")
    cfg = load_config(config)

    # 1. Collect
    if demo:
        print("[*] Generating demo data...")
        raw_data = {
            "target": target,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "os": {"name": "Windows 10 Pro", "version": "22H2"},
            "patches": [{"HotFixID": "KB5012345"}, {"HotFixID": "KB5023456"}],
            "smb_signing": False,
            "spooler_running": True,
            "uac_enabled": False,
            "firewall_enabled": True,
            "local_admins": ["Admin", "DemoUser"],
            "domain_users": [{"name": "svc_sql", "enabled": True}],
            "event_logs": {"anomalous_ntlm": True},
            "_baseline_hash": "demo_hash_123"
        }
    else:
        if sys.platform != "win32":
            print("[-] Real collection only supported on Windows. Use --demo for testing.")
            sys.exit(1)
        print(f"[*] Collecting from {target}...")
        collector = WindowsCollector(target, cfg)
        raw_data = collector.collect()

    # 2. Sigma
    sigma_findings = []
    if sigma or cfg["analyzers"]["sigma"]["enabled"]:
        print("[*] Running Sigma engine...")
        sigma_engine = SigmaEngine()
        sigma_findings = sigma_engine.run(raw_data)

    # 3. Correlation
    correlations = []
    if correlate or cfg["analyzers"]["correlation"]["enabled"]:
        print("[*] Running correlation engine...")
        corr_engine = CorrelationEngine()
        correlations = corr_engine.analyze(raw_data)

    # 4. Baseline
    anomalies = []
    if baseline:
        print("[*] Checking baseline...")
        bm = BaselineManager()
        anomalies = bm.check_anomalies(raw_data)
        # Update baseline
        bm.save({"hash": raw_data.get("_baseline_hash"), "local_admins": raw_data.get("local_admins")})

    # 5. AI Prioritization
    ai_result = {"executive_summary": "AI not enabled.", "prioritized": []}
    if ai_enrich:
        print("[*] Enriching with AI...")
        ai_cfg = cfg["analyzers"]["ai"]
        ai_cfg["api_key"] = ai_cfg.get("api_key") or os.environ.get("OPENAI_API_KEY")
        prioritizer = AIPrioritizer(ai_cfg)
        # combine sigma + anomalies + correlations as findings
        combined_findings = sigma_findings + [{"id": f"anom_{i}", "title": a.get("type"), "severity": "high"} for i, a in enumerate(anomalies)]
        ai_result = prioritizer.prioritize(combined_findings, raw_data)

    # 6. Assemble results
    results = {
        "raw_data": raw_data,
        "sigma_findings": sigma_findings,
        "correlations": correlations,
        "anomalies": anomalies,
        "ai_prioritized": ai_result
    }

    # 7. Generate report
    print("[*] Generating HTML report...")
    reporter = HTMLReporter()
    reporter.generate(results, output)

    print("[+] Done.")
    print(f"[+] Open {output} in your browser.")

if __name__ == "__main__":
    main()
