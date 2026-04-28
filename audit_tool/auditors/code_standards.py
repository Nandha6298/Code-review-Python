from __future__ import annotations

import re
from pathlib import Path

try:
    from radon.complexity import cc_visit
except Exception:
    cc_visit = None

from .base import AuditResult, BaseAuditor


class CodeStandardsAuditor(BaseAuditor):
    category = "code"
    max_score = 50

    def audit(self, project_path: Path, context: dict) -> AuditResult:
        findings: list[dict] = []
        counters = {k: 0 for k in ["naming", "hardcoded", "htmljs", "comments", "exceptions", "complexity", "dead"]}
        for file in self.iter_files(project_path):
            suffix = file.suffix.lower()
            if suffix not in {".py", ".js", ".ts", ".cs", ".java", ".html", ".cshtml"}:
                continue
            text = file.read_text(encoding="utf-8", errors="ignore")
            lines = text.splitlines()
            rel = self.rel(project_path, file)
            counters["hardcoded"] += self._check_hardcoded(rel, lines, findings)
            counters["dead"] += self._check_dead(rel, lines, findings)
            if suffix in {".html", ".cshtml", ".js", ".ts"}:
                counters["htmljs"] += self._check_htmljs(rel, lines, findings)
            if suffix == ".py":
                counters["naming"] += self._check_python_naming(rel, lines, findings)
                counters["comments"] += self._check_python_comments(rel, lines, findings)
                counters["exceptions"] += self._check_python_exceptions(rel, lines, findings)
                counters["complexity"] += self._check_python_complexity(rel, text, findings)

        score = self.max_score
        score -= min(8, counters["naming"] * 0.5)
        score -= min(8, counters["hardcoded"] * 1)
        score -= min(8, counters["htmljs"] * 0.5)
        score -= min(8, counters["comments"] * 0.3)
        score -= min(8, counters["exceptions"] * 1)
        score -= min(5, counters["complexity"] * 1)
        score -= min(5, counters["dead"] * 0.3)
        return AuditResult(max(score, 0), findings, counters)

    def _check_python_naming(self, rel: str, lines: list[str], findings: list[dict]) -> int:
        c = 0
        for i, line in enumerate(lines, 1):
            fm = re.match(r"\s*def\s+([A-Za-z_][A-Za-z0-9_]*)", line)
            cm = re.match(r"\s*class\s+([A-Za-z_][A-Za-z0-9_]*)", line)
            if fm and not re.match(r"^[a-z_][a-z0-9_]*$", fm.group(1)):
                findings.append(self._f(rel, i, "Low", f"Function {fm.group(1)} should be snake_case", "Rename function")); c += 1
            if cm and not re.match(r"^[A-Z][A-Za-z0-9]+$", cm.group(1)):
                findings.append(self._f(rel, i, "Low", f"Class {cm.group(1)} should be PascalCase", "Rename class")); c += 1
        return c

    def _check_hardcoded(self, rel, lines, findings):
        pats = [r"SELECT\s+", r"INSERT\s+INTO", r"UPDATE\s+", r"DELETE\s+FROM", r"Server=", r"Data Source=", r"mongodb://", r"password=", r"api_key=", r"https?://", r"\b\d{1,3}(?:\.\d{1,3}){3}\b"]
        c = 0
        for i, line in enumerate(lines, 1):
            if any(re.search(p, line, re.IGNORECASE) for p in pats):
                findings.append(self._f(rel, i, "Medium", "Possible hardcoded query/secret/url/ip", "Move values to configuration or parameterized query")); c += 1
        return c

    def _check_htmljs(self, rel, lines, findings):
        c = 0
        for i, line in enumerate(lines, 1):
            if any(x in line for x in ["onclick=", "onload=", "onerror="]):
                findings.append(self._f(rel, i, "Low", "Inline JS event handler detected", "Move behavior to external JS")); c += 1
            if "console.log(" in line or "console.error(" in line or "debugger;" in line:
                findings.append(self._f(rel, i, "Low", "Debug JS statement present", "Remove debug statements")); c += 1
        return c

    def _check_python_comments(self, rel, lines, findings):
        c = 0
        for i, line in enumerate(lines, 1):
            if re.match(r"\s*def\s+", line):
                window = "\n".join(lines[i:i+6])
                if '"""' not in window and "'''" not in window:
                    findings.append(self._f(rel, i, "Info", "Function missing docstring", "Add docstring for maintainability")); c += 1
        return c

    def _check_python_exceptions(self, rel, lines, findings):
        c = 0
        for i, line in enumerate(lines, 1):
            if re.match(r"\s*def\s+.*(route|handler|endpoint)", line, re.IGNORECASE):
                block = "\n".join(lines[i:i+20])
                if "try:" not in block or "except" not in block:
                    findings.append(self._f(rel, i, "Medium", "Route handler missing try/except", "Add proper exception handling and logging")); c += 1
        return c

    def _check_python_complexity(self, rel, text, findings):
        c = 0
        if cc_visit is None:
            return 0
        for block in cc_visit(text):
            if block.complexity > 10:
                findings.append(self._f(rel, block.lineno, "Medium", f"Complexity {block.complexity} in {block.name}", "Consider refactoring into smaller units")); c += 1
        return c

    def _check_dead(self, rel, lines, findings):
        c = 0
        for i, line in enumerate(lines, 1):
            if "TODO" in line or "FIXME" in line or "HACK" in line:
                findings.append(self._f(rel, i, "Info", "TODO/FIXME/HACK marker found", "Track and resolve pending work")); c += 1
        return c

    def _f(self, file_path: str, line: int, severity: str, message: str, fix: str) -> dict:
        return {"file_path": file_path, "line_number": line, "severity": severity, "message": message, "suggested_fix": fix}
