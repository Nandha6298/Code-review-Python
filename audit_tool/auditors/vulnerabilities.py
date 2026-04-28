from __future__ import annotations

import json
import subprocess
from pathlib import Path

from .base import AuditResult, BaseAuditor


class VulnerabilityAuditor(BaseAuditor):
    category = "vuln"
    max_score = 15

    def audit(self, project_path: Path, context: dict) -> AuditResult:
        findings = []
        vulns = []
        commands = [
            (["safety", "check", "--json"], "python"),
            (["pip-audit", "--format", "json"], "python"),
            (["npm", "audit", "--json"], "node"),
            (["dotnet", "list", "package", "--vulnerable", "--format", "json"], "dotnet"),
        ]
        for cmd, _ in commands:
            try:
                out = subprocess.run(cmd, cwd=project_path, capture_output=True, text=True, check=False)
                if out.stdout.strip().startswith("{") or out.stdout.strip().startswith("["):
                    vulns.extend(self.parse_json(out.stdout))
            except FileNotFoundError:
                continue
        sev_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for v in vulns:
            sev = v.get("severity", "Low").title()
            sev_count[sev] = sev_count.get(sev, 0) + 1
            findings.append({"file_path": "dependencies", "line_number": 1, "severity": sev, "message": f"{v.get('package')} {v.get('cve_id')}", "suggested_fix": f"Upgrade to {v.get('fixed_version','latest')}", "metadata": v})
        score = self.max_score - min(10, sev_count["Critical"] * 5) - min(8, sev_count["High"] * 2) - min(5, sev_count["Medium"]) - min(2, sev_count["Low"] * 0.3)
        return AuditResult(max(score, 0), findings, {"vulnerabilities": vulns, **sev_count})

    def parse_json(self, raw: str) -> list[dict]:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []
        results = []
        if isinstance(data, list):
            for item in data:
                results.append({"cve_id": item.get("CVE") or item.get("id"), "severity": item.get("severity", "Low"), "package": item.get("package_name") or item.get("package", "unknown"), "version": item.get("installed_version"), "fixed_version": item.get("fixed_version")})
        elif isinstance(data, dict):
            vulns = data.get("vulnerabilities") or data.get("advisories") or {}
            if isinstance(vulns, dict):
                for _, item in vulns.items():
                    results.append({"cve_id": item.get("cve") or item.get("id"), "severity": item.get("severity", "Low"), "package": item.get("module_name") or item.get("name", "unknown"), "version": str(item.get("findings", [{}])[0].get("version", "")), "fixed_version": item.get("patched_versions", "")})
        return results
