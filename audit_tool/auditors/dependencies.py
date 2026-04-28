from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path


from .base import AuditResult, BaseAuditor


class DependenciesAuditor(BaseAuditor):
    category = "deps"
    max_score = 5

    def audit(self, project_path: Path, context: dict) -> AuditResult:
        findings = []
        high = med = unpinned_cdn = 0
        for f in self.iter_files(project_path):
            if f.suffix.lower() in {".html", ".cshtml"}:
                text = f.read_text(encoding="utf-8", errors="ignore")
                for m in re.finditer(r"(?:src|href)=\"(https?://[^\"]+)\"", text):
                    url = m.group(1)
                    if not re.search(r"\d+\.\d+", url):
                        unpinned_cdn += 1
                        findings.append(self._f(self.rel(project_path, f), 1, "Low", f"CDN not version pinned: {url}", "Pin CDN with explicit version"))
        pkg = project_path / "package.json"
        if pkg.exists():
            try:
                out = subprocess.run(["npm", "outdated", "--json"], cwd=project_path, capture_output=True, text=True, check=False)
                data = json.loads(out.stdout or "{}")
                for name, val in data.items():
                    cur = val.get("current", "0.0.0"); latest = val.get("latest", "0.0.0")
                    gap = self.major_gap(cur, latest)
                    if gap >= 2:
                        high += 1
                    elif gap == 1:
                        med += 1
            except Exception:
                pass
        score = self.max_score - min(3, high) - min(2, med * 0.5) - (unpinned_cdn * 0.5)
        return AuditResult(max(score, 0), findings, {"high": high, "medium": med})

    def major_gap(self, cur: str, latest: str) -> int:
        try:
            return int(latest.split(".")[0]) - int(cur.split(".")[0])
        except Exception:
            return 0

    def _f(self, file_path: str, line: int, severity: str, message: str, fix: str) -> dict:
        return {"file_path": file_path, "line_number": line, "severity": severity, "message": message, "suggested_fix": fix}
