from __future__ import annotations

import argparse
import configparser
import json
from pathlib import Path

import uvicorn

from auditors import CodeStandardsAuditor, DependenciesAuditor, FolderStandardsAuditor, PerformanceAuditor, VulnerabilityAuditor
from db.database import finalize_audit_run, get_project_by_name, get_projects, init_db, insert_audit_run, insert_findings, set_last_run, upsert_project, upsert_vulnerability
from detectors.language_detector import detect_languages
from detectors.stack_detector import detect_db_technologies
from reporters.email_notifier import send_email
from reporters.html_reporter import HTMLReporter
from reporters.pdf_reporter import html_to_pdf

BIT = {"folder": 1, "code": 2, "deps": 4, "vuln": 8, "perf": 16}
AUDITORS = {
    "folder": FolderStandardsAuditor(),
    "code": CodeStandardsAuditor(),
    "deps": DependenciesAuditor(),
    "vuln": VulnerabilityAuditor(),
    "perf": PerformanceAuditor(),
}


def detect_and_configure(path: Path, schedule: str = "manual", emails: list[str] | None = None, processes: list[str] | None = None):
    emails = emails or []
    processes = processes or list(BIT.keys())
    payload = {
        "project_name": path.name,
        "source_path": str(path.resolve()),
        "languages": detect_languages(path),
        "db_technologies": detect_db_technologies(path),
        "audit_processes": sum(BIT[p] for p in processes),
        "schedule": schedule,
        "notify_emails": emails,
    }
    pid = upsert_project(payload)
    print(json.dumps(payload, indent=2))
    return pid


def grade(score: float) -> str:
    return "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"


def run_project(row, dry_run=False):
    project_path = Path(row["source_path"])
    mask = row["audit_processes"]
    run_id = -1 if dry_run else insert_audit_run(row["id"], {})
    scores = {}
    findings_all = {}
    for name, bit in BIT.items():
        if not (mask & bit):
            continue
        res = AUDITORS[name].audit(project_path, {"project": dict(row)})
        scores[name] = res.score
        findings_all[name] = res.findings
        if not dry_run:
            insert_findings(run_id, name, res.findings)
            if name == "vuln":
                for v in res.summary.get("vulnerabilities", []):
                    upsert_vulnerability(row["id"], run_id, v)
    final_score = sum(scores.values())
    g = grade(final_score)
    report_payload = {"project_name": row["project_name"], "scores": scores, "findings": [f | {"category": c} for c, fs in findings_all.items() for f in fs]}
    html_reporter = HTMLReporter(Path(__file__).parent / "dashboard" / "templates")
    html_path = html_reporter.render_project_report(report_payload, Path(__file__).parent / "audit_reports")
    pdf_path = None
    try:
        pdf_path = html_to_pdf(html_path)
    except Exception:
        pass
    if not dry_run:
        finalize_audit_run(run_id, final_score, g, str(html_path), str(pdf_path) if pdf_path else None, scores)
        set_last_run(row["id"])
    print(f"[{row['project_name']}] final score={final_score:.2f}, grade={g}")

    critical_high = [f for f in report_payload["findings"] if f["severity"] in {"Critical", "High"}]
    if critical_high and row["notify_emails"]:
        cfg = configparser.ConfigParser(); cfg.read(Path(__file__).parent / "config.ini")
        body = "<br>".join(f"{x['severity']} - {x['message']}" for x in critical_high)
        send_email(dict(cfg["SMTP"]), json.loads(row["notify_emails"]), f"[CodeAuditPro] {row['project_name']} — {len(critical_high)} new vulnerabilities found", body)


def cmd_dashboard():
    uvicorn.run("dashboard.app:app", host="127.0.0.1", port=8080, reload=False)


def main():
    init_db()
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd")

    c = sub.add_parser("configure")
    c.add_argument("--path", required=True)
    c.add_argument("--schedule", default="manual", choices=["manual", "weekly", "monthly"])
    c.add_argument("--emails", default="")

    r = sub.add_parser("run")
    r.add_argument("--project")
    r.add_argument("--all", action="store_true")
    r.add_argument("--dry-run", action="store_true")

    report = sub.add_parser("report")
    report.add_argument("--project", required=True)
    report.add_argument("--format", choices=["pdf", "html"], default="pdf")

    sub.add_parser("dashboard")
    args = p.parse_args()

    if args.cmd == "configure":
        detect_and_configure(Path(args.path), args.schedule, [e.strip() for e in args.emails.split(",") if e.strip()])
    elif args.cmd == "run":
        if args.project:
            row = get_project_by_name(args.project)
            if not row:
                raise SystemExit(f"Unknown project {args.project}")
            run_project(row, dry_run=args.dry_run)
        elif args.all:
            for row in get_projects():
                run_project(row, dry_run=args.dry_run)
        else:
            raise SystemExit("Use --project or --all")
    elif args.cmd == "report":
        row = get_project_by_name(args.project)
        if not row:
            raise SystemExit(f"Unknown project {args.project}")
        run_project(row, dry_run=True)
    elif args.cmd == "dashboard":
        cmd_dashboard()
    else:
        p.print_help()


if __name__ == "__main__":
    main()
