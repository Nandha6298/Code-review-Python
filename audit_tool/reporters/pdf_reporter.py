from __future__ import annotations

from pathlib import Path


def html_to_pdf(html_path: Path) -> Path:
    """
    Convert HTML to PDF in a cross-platform way.

    Strategy:
    1. Prefer WeasyPrint (best fidelity where native deps are present).
    2. Fall back to xhtml2pdf (pure-Python friendly option for Windows/Linux).
    """
    pdf = html_path.with_suffix(".pdf")

    weasyprint_error: Exception | None = None
    try:
        from weasyprint import HTML  # type: ignore

        HTML(filename=str(html_path)).write_pdf(str(pdf))
        return pdf
    except Exception as exc:  # noqa: BLE001 - runtime fallback logic
        weasyprint_error = exc

    try:
        from xhtml2pdf import pisa  # type: ignore

        with html_path.open("r", encoding="utf-8") as src, pdf.open("wb") as dst:
            result = pisa.CreatePDF(src.read(), dest=dst)
        if result.err:
            raise RuntimeError(f"xhtml2pdf conversion failed with err count {result.err}")
        return pdf
    except Exception as xhtml_error:  # noqa: BLE001 - runtime fallback logic
        raise RuntimeError(
            "PDF export failed for both WeasyPrint and xhtml2pdf. "
            f"WeasyPrint error: {weasyprint_error}; xhtml2pdf error: {xhtml_error}"
        ) from xhtml_error
