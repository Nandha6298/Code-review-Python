from pathlib import Path

from weasyprint import HTML


def html_to_pdf(html_path: Path) -> Path:
    pdf = html_path.with_suffix(".pdf")
    HTML(filename=str(html_path)).write_pdf(str(pdf))
    return pdf
