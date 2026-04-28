from __future__ import annotations

import re
from pathlib import Path

from .base import AuditResult, BaseAuditor


class PerformanceAuditor(BaseAuditor):
    category = "perf"
    max_score = 20

    def audit(self, project_path: Path, context: dict) -> AuditResult:
        findings = []
        db_loop = select_star = nested_loop = http_in_loop = no_page = 0
        for f in self.iter_files(project_path):
            if f.suffix.lower() not in {".py", ".js", ".ts", ".cs", ".java"}:
                continue
            lines = f.read_text(encoding="utf-8", errors="ignore").splitlines()
            rel = self.rel(project_path, f)
            for i, line in enumerate(lines, 1):
                if re.search(r"SELECT\s+\*", line, re.IGNORECASE):
                    select_star += 1
                    findings.append(self._f(rel, i, "Medium", "SELECT * detected", "Select explicit columns"))
                if re.search(r"for|while|foreach", line):
                    window = "\n".join(lines[i:i+10])
                    if re.search(r"db\.query|cursor\.execute|\.Where\(|\.Find\(", window):
                        db_loop += 1
                        findings.append(self._f(rel, i, "High", "DB call inside loop", "Batch queries or prefetch data"))
                    if re.search(r"requests\.get|fetch\(|HttpClient", window):
                        http_in_loop += 1
                        findings.append(self._f(rel, i, "High", "HTTP call in loop", "Move call outside loop or use async batching"))
                    if re.search(r"for|while|foreach", window):
                        nested_loop += 1
                        findings.append(self._f(rel, i, "Medium", "Nested loop detected", "Reduce complexity with maps/indexes"))
                if re.search(r"return\s+(Json|Ok)\(", line) and "Take(" not in "\n".join(lines[max(0, i-5):i+5]):
                    no_page += 1
                    findings.append(self._f(rel, i, "Low", "Possible endpoint without pagination", "Add page/size and skip/take semantics"))
        score = self.max_score - min(9, db_loop * 3) - min(3, select_star) - min(6, nested_loop * 2) - min(4, http_in_loop * 2) - min(3, no_page)
        return AuditResult(max(score, 0), findings, {"db_in_loop": db_loop})

    def _f(self, file_path: str, line: int, severity: str, message: str, fix: str) -> dict:
        return {"file_path": file_path, "line_number": line, "severity": severity, "message": message, "suggested_fix": fix}
