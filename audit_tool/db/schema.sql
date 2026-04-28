CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_name TEXT UNIQUE NOT NULL,
    source_path TEXT UNIQUE NOT NULL,
    languages TEXT NOT NULL,
    db_technologies TEXT NOT NULL,
    audit_processes INTEGER NOT NULL DEFAULT 31,
    schedule TEXT NOT NULL DEFAULT 'manual',
    notify_emails TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    last_run_at TEXT
);

CREATE TABLE IF NOT EXISTS audit_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    final_score REAL DEFAULT 0,
    grade TEXT,
    report_html_path TEXT,
    report_pdf_path TEXT,
    summary_json TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_run_id INTEGER NOT NULL,
    category TEXT NOT NULL,
    file_path TEXT,
    line_number INTEGER,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    suggested_fix TEXT NOT NULL,
    metadata_json TEXT DEFAULT '{}',
    FOREIGN KEY (audit_run_id) REFERENCES audit_runs(id)
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    audit_run_id INTEGER NOT NULL,
    cve_id TEXT,
    severity TEXT NOT NULL,
    package TEXT NOT NULL,
    version TEXT,
    fixed_version TEXT,
    status TEXT NOT NULL DEFAULT 'Open',
    assigned_to TEXT,
    updated_at TEXT NOT NULL,
    UNIQUE(project_id, cve_id, package),
    FOREIGN KEY (project_id) REFERENCES projects(id),
    FOREIGN KEY (audit_run_id) REFERENCES audit_runs(id)
);
