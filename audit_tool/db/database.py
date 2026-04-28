from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

DB_PATH = Path(__file__).resolve().parents[1] / "audit_config.db"
SCHEMA_PATH = Path(__file__).resolve().with_name("schema.sql")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        conn.commit()


@contextmanager
def get_conn() -> Iterable[sqlite3.Connection]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def upsert_project(project: dict[str, Any]) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO projects (project_name, source_path, languages, db_technologies, audit_processes, schedule, notify_emails, created_at, last_run_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(project_name) DO UPDATE SET
                source_path=excluded.source_path,
                languages=excluded.languages,
                db_technologies=excluded.db_technologies,
                audit_processes=excluded.audit_processes,
                schedule=excluded.schedule,
                notify_emails=excluded.notify_emails
            """,
            (
                project["project_name"],
                project["source_path"],
                json.dumps(project["languages"]),
                json.dumps(project["db_technologies"]),
                project["audit_processes"],
                project["schedule"],
                json.dumps(project["notify_emails"]),
                project.get("created_at", now_iso()),
                project.get("last_run_at"),
            ),
        )
        row = conn.execute("SELECT id FROM projects WHERE project_name=?", (project["project_name"],)).fetchone()
        return int(row["id"])


def get_projects() -> list[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM projects ORDER BY project_name").fetchall()


def get_project_by_name(name: str) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM projects WHERE project_name=?", (name,)).fetchone()


def insert_audit_run(project_id: int, summary: dict[str, Any]) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO audit_runs (project_id, started_at, summary_json) VALUES (?, ?, ?)",
            (project_id, now_iso(), json.dumps(summary)),
        )
        return int(cur.lastrowid)


def finalize_audit_run(audit_run_id: int, final_score: float, grade: str, html_path: str | None, pdf_path: str | None, summary: dict[str, Any]) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE audit_runs SET completed_at=?, final_score=?, grade=?, report_html_path=?, report_pdf_path=?, summary_json=? WHERE id=?",
            (now_iso(), final_score, grade, html_path, pdf_path, json.dumps(summary), audit_run_id),
        )


def set_last_run(project_id: int) -> None:
    with get_conn() as conn:
        conn.execute("UPDATE projects SET last_run_at=? WHERE id=?", (now_iso(), project_id))


def insert_findings(audit_run_id: int, category: str, findings: list[dict[str, Any]]) -> None:
    with get_conn() as conn:
        conn.executemany(
            """
            INSERT INTO findings (audit_run_id, category, file_path, line_number, severity, message, suggested_fix, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    audit_run_id,
                    category,
                    f.get("file_path"),
                    f.get("line_number", 1),
                    f["severity"],
                    f["message"],
                    f["suggested_fix"],
                    json.dumps(f.get("metadata", {})),
                )
                for f in findings
            ],
        )


def get_latest_run(project_id: int) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM audit_runs WHERE project_id=? ORDER BY id DESC LIMIT 1", (project_id,)).fetchone()


def get_findings(audit_run_id: int) -> list[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM findings WHERE audit_run_id=? ORDER BY category", (audit_run_id,)).fetchall()


def upsert_vulnerability(project_id: int, audit_run_id: int, vuln: dict[str, Any]) -> None:
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO vulnerabilities (project_id, audit_run_id, cve_id, severity, package, version, fixed_version, status, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(project_id, cve_id, package)
            DO UPDATE SET
                audit_run_id=excluded.audit_run_id,
                severity=excluded.severity,
                version=excluded.version,
                fixed_version=excluded.fixed_version,
                updated_at=excluded.updated_at,
                status=CASE WHEN excluded.fixed_version IS NOT NULL AND excluded.fixed_version != '' THEN vulnerabilities.status ELSE vulnerabilities.status END
            """,
            (
                project_id,
                audit_run_id,
                vuln.get("cve_id"),
                vuln["severity"],
                vuln["package"],
                vuln.get("version"),
                vuln.get("fixed_version"),
                vuln.get("status", "Open"),
                now_iso(),
            ),
        )
