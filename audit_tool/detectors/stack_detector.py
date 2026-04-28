from __future__ import annotations

import re
from pathlib import Path

from auditors.base import SKIP_DIRS

DB_PATTERNS = {
    "SqlClient": r"SqlClient|Data Source=",
    "mysql": r"mysql",
    "mongodb": r"mongodb",
    "postgres": r"postgres|Npgsql",
    "sqlite": r"sqlite",
}


def detect_db_technologies(project_path: Path) -> list[str]:
    hits: set[str] = set()
    config_ext = {".json", ".config", ".ini", ".env", ".yml", ".yaml", ".xml", ".txt"}
    for f in project_path.rglob("*"):
        if any(part in SKIP_DIRS for part in f.parts) or not f.is_file() or f.suffix.lower() not in config_ext:
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for name, pattern in DB_PATTERNS.items():
            if re.search(pattern, content, re.IGNORECASE):
                hits.add(name)
    return sorted(hits)
