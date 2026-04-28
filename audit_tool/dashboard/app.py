from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from db.database import get_conn, get_findings, get_latest_run, get_projects, upsert_project
from detectors.language_detector import detect_languages
from detectors.stack_detector import detect_db_technologies

app = FastAPI(title="CodeAuditPro Dashboard")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


@app.get("/")
def index(request: Request):
    projects = []
    for p in get_projects():
        run = get_latest_run(p["id"])
        projects.append({"project": p, "run": run})
    return templates.TemplateResponse("index.html", {"request": request, "projects": projects})


@app.get("/project/{project_id}")
def project_view(request: Request, project_id: int):
    with get_conn() as conn:
        p = conn.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
    run = get_latest_run(project_id)
    findings = get_findings(run["id"]) if run else []
    return templates.TemplateResponse("project.html", {"request": request, "project_name": p["project_name"], "findings": findings, "scores": json.loads(run["summary_json"]) if run else {}})


@app.get("/project/{project_id}/download")
def download(project_id: int):
    run = get_latest_run(project_id)
    if run and run["report_pdf_path"] and Path(run["report_pdf_path"]).exists():
        return FileResponse(run["report_pdf_path"], filename=Path(run["report_pdf_path"]).name)
    return RedirectResponse("/")


@app.get("/vulnerabilities")
def vulnerabilities(request: Request, status: str = "Open"):
    with get_conn() as conn:
        vulns = conn.execute("SELECT * FROM vulnerabilities WHERE status=? ORDER BY updated_at DESC", (status,)).fetchall()
    return templates.TemplateResponse("vulnerabilities.html", {"request": request, "vulnerabilities": vulns, "status": status})


@app.post("/vulnerability/{vuln_id}/status")
def vuln_status(vuln_id: int, status: str = Form(...)):
    with get_conn() as conn:
        conn.execute("UPDATE vulnerabilities SET status=?, updated_at=datetime('now') WHERE id=?", (status, vuln_id))
    return RedirectResponse("/vulnerabilities", status_code=303)


@app.get("/configure")
def configure(request: Request):
    return templates.TemplateResponse("configure.html", {"request": request, "detected_languages": [], "detected_db": []})


@app.post("/configure")
def configure_post(request: Request, path: str = Form(...), schedule: str = Form("manual"), emails: str = Form(""), processes: list[str] = Form(default=[])):
    p = Path(path).resolve()
    project_name = p.name
    mask_map = {"folder": 1, "code": 2, "deps": 4, "vuln": 8, "perf": 16}
    bitmask = sum(mask_map.get(x, 0) for x in processes) or 31
    payload = {
        "project_name": project_name,
        "source_path": str(p),
        "languages": detect_languages(p),
        "db_technologies": detect_db_technologies(p),
        "audit_processes": bitmask,
        "schedule": schedule,
        "notify_emails": [e.strip() for e in emails.split(",") if e.strip()],
    }
    upsert_project(payload)
    return templates.TemplateResponse("configure.html", {"request": request, "detected_languages": payload["languages"], "detected_db": payload["db_technologies"], "saved": True})
