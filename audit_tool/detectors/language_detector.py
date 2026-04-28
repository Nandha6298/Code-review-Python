from __future__ import annotations

from collections import Counter
from pathlib import Path

from auditors.base import SKIP_DIRS

EXT_LANG = {
    ".cs": ".NET",
    ".js": "JavaScript",
    ".ts": "JavaScript",
    ".py": "Python",
    ".java": "Java",
    ".php": "PHP",
}


def detect_languages(project_path: Path) -> list[str]:
    counter: Counter[str] = Counter()
    for f in project_path.rglob("*"):
        if any(part in SKIP_DIRS for part in f.parts) or not f.is_file():
            continue
        lang = EXT_LANG.get(f.suffix.lower())
        if lang:
            counter[lang] += 1
    return [k for k, _ in counter.most_common()] or ["Unknown"]
