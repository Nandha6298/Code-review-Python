from pathlib import Path

from auditors.code_standards import CodeStandardsAuditor


def test_code_auditor_detects_issue(tmp_path: Path):
    p = tmp_path / "sample.py"
    p.write_text("def BadName():\n    return 1\n")
    result = CodeStandardsAuditor().audit(tmp_path, {})
    assert result.findings
