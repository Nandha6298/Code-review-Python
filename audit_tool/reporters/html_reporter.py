from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape


class HTMLReporter:
    def __init__(self, templates_path: Path):
        self.env = Environment(loader=FileSystemLoader(templates_path), autoescape=select_autoescape())

    def render_project_report(self, payload: dict, out_dir: Path) -> Path:
        out_dir.mkdir(parents=True, exist_ok=True)
        tpl = self.env.get_template("project.html")
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        out = out_dir / f"{payload['project_name']}_{ts}.html"
        out.write_text(tpl.render(**payload), encoding="utf-8")
        return out
