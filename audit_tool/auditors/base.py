from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

SKIP_DIRS = {"node_modules", ".git", "bin", "obj", "__pycache__", "dist"}


@dataclass
class AuditResult:
    score: float
    findings: list[dict]
    summary: dict


class BaseAuditor:
    category = "base"
    max_score = 0

    def audit(self, project_path: Path, context: dict) -> AuditResult:
        raise NotImplementedError

    @staticmethod
    def iter_files(project_path: Path):
        for p in project_path.rglob("*"):
            if p.is_dir() and p.name in SKIP_DIRS:
                continue
            if any(part in SKIP_DIRS for part in p.parts):
                continue
            if p.is_file():
                yield p

    @staticmethod
    def rel(project_path: Path, file_path: Path) -> str:
        return str(file_path.relative_to(project_path))
