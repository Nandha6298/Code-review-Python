from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

from .base import AuditResult, BaseAuditor


class FolderStandardsAuditor(BaseAuditor):
    category = "folder"
    max_score = 10

    def audit(self, project_path: Path, context: dict) -> AuditResult:
        findings: list[dict] = []
        misplaced = duplicate = bad_name = config_issues = 0
        log_violations = 0
        expected = {
            ".js": {"js", "scripts", "src", "assets"},
            ".ts": {"js", "scripts", "src", "assets"},
            ".cshtml": {"Views"},
            ".css": {"css", "styles", "assets"},
            ".scss": {"css", "styles", "assets"},
            ".py": {"src", "."},
        }
        filename_map: dict[str, list[Path]] = defaultdict(list)
        config_names = {"appsettings.json", "appsettings.Development.json", ".env", ".env.local", "web.config", "app.config"}
        appsettings_locations = 0
        for file in self.iter_files(project_path):
            rel = self.rel(project_path, file)
            filename_map[file.name].append(file)
            if " " in file.name or any(file.name.lower().startswith(p) for p in ["temp", "new_", "copy_of_", "final_"]):
                bad_name += 1
                findings.append(self._f(rel, 1, "Low", "Bad file naming pattern", "Use meaningful and clean file names"))
            if file.name.lower() in {"util.js", "helper.cs", "test.py"} or file.stem.lower() == "untitled":
                bad_name += 1
                findings.append(self._f(rel, 1, "Low", "Generic filename", "Rename file to domain-specific name"))
            suffix = file.suffix
            if suffix in expected:
                top = rel.split("/")[0] if "/" in rel else "."
                if top not in expected[suffix] and not (suffix == ".py" and "tests" in rel and file.name.startswith("test_")):
                    misplaced += 1
                    findings.append(self._f(rel, 1, "Low", f"{suffix} file in unexpected folder", "Move file to expected directory"))
            if file.name in config_names:
                if file.name.startswith("appsettings"):
                    appsettings_locations += 1

        for _, paths in filename_map.items():
            if len(paths) > 1:
                duplicate += len(paths) - 1
                for p in paths[1:]:
                    findings.append(self._f(self.rel(project_path, p), 1, "Info", "Duplicate filename detected", "Ensure duplicate filenames are intentional"))

        for log_dir_name in ["logs", "log", "error_logs"]:
            for log_dir in project_path.rglob(log_dir_name):
                if not log_dir.is_dir():
                    continue
                files = [p for p in log_dir.glob("**/*") if p.is_file()]
                too_old = [p for p in files if datetime.fromtimestamp(p.stat().st_mtime, timezone.utc) < datetime.now(timezone.utc) - timedelta(days=30)]
                if too_old or len(files) > 100:
                    log_violations += 1
                    findings.append(self._f(self.rel(project_path, log_dir), 1, "Medium", "Log policy violation", "Rotate logs and archive files older than 30 days"))

        env_files = [p for p in project_path.rglob(".env") if p.is_file()]
        if env_files:
            gitignore = (project_path / ".gitignore").read_text(encoding="utf-8", errors="ignore") if (project_path / ".gitignore").exists() else ""
            if ".env" not in gitignore:
                config_issues += 1
                findings.append(self._f(".gitignore", 1, "High", ".env not ignored", "Add .env and secret files to .gitignore"))
        if appsettings_locations > 2:
            config_issues += 1
            findings.append(self._f("appsettings.json", 1, "Medium", "appsettings files appear in >2 locations", "Consolidate configuration files"))

        score = self.max_score
        score -= min(2, misplaced * 0.2)
        score -= min(1, duplicate * 0.3)
        score -= log_violations
        score -= min(2, bad_name * 0.2)
        score -= min(2, config_issues)
        return AuditResult(max(score, 0), findings, {"misplaced": misplaced, "duplicate": duplicate})

    def _f(self, file_path: str, line: int, severity: str, message: str, fix: str) -> dict:
        return {"file_path": file_path, "line_number": line, "severity": severity, "message": message, "suggested_fix": fix}
