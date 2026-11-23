"""Report generation helpers."""

from pathlib import Path

from rich.console import Console

from nessus_organiser.models.finding import Finding
from nessus_organiser.reporting.html import generate_html


def generate_report(
    findings: list[Finding],
    output_path: Path,
    title: str,
    introduction: str | None = None,
    remediation_introduction: str | None = None,
    statistics: dict | None = None,
    ithc: bool = False,
) -> bool:
    if output_path.suffix.lower() != ".html":
        raise ValueError("Report output must have a .html extension.")
    if not findings:
        message = f"No findings for {title}; no report was generated."
        if output_path.exists():
            message += f" Existing report '{output_path}' was not updated."
        Console(stderr=True).print(message, markup=False)
        return False
    generate_html(
        findings=findings,
        output_path=output_path,
        title=title,
        introduction=introduction,
        remediation_introduction=remediation_introduction,
        statistics=statistics,
        ithc=ithc,
    )
    return True