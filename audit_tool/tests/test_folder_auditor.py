from pathlib import Path

from auditors.folder_standards import FolderStandardsAuditor


def test_folder_auditor_runs(tmp_path: Path):
    (tmp_path / "bad name.js").write_text("console.log('x')")
    result = FolderStandardsAuditor().audit(tmp_path, {})
    assert result.score <= 10
    assert result.findings
