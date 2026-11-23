"""Report generation helpers."""

from datetime import datetime
from pathlib import Path

from rich.console import Console

from nessus_organiser.models.finding import Finding
from nessus_organiser.reporting.html import generate_html


def report_path(name: str, timestamp: datetime | None = None) -> Path:
    timestamp = timestamp or datetime.now()
    return Path("nessus-organiser") / f"{name}-{timestamp:%Y%m%d-%H%M%S}.html"


def generate_report(
    findings: list[Finding],
    output_path: Path,
    title: str,
    introduction: str | None = None,
    remediation_introduction: str | None = None,
    statistics: dict | None = None,
    ithc: bool = False,
    grouped: bool = False,
    show_severity: bool = False,
) -> Path | None:
    if output_path.suffix.lower() != ".html":
        raise ValueError("Report output must have a .html extension.")
    if not findings:
        Console(stderr=True).print(
            f"No findings for {title}; no report was generated.", markup=False
        )
        return None
    return generate_html(
        findings=findings,
        output_path=output_path,
        title=title,
        introduction=introduction,
        remediation_introduction=remediation_introduction,
        statistics=statistics,
        ithc=ithc,
        grouped=grouped,
        show_severity=show_severity,
    )