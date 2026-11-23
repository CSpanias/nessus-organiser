"""Report generation helpers."""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from rich.console import Console

from nessus_organiser.common.tables import print_summary_table
from nessus_organiser.models.finding import Finding
from nessus_organiser.reporting.html import (
    ReportTab, generate_html, render_combined_html, write_html,
)
from nessus_organiser.reporting.markdown import build_report_sections


@dataclass(slots=True)
class AnalysisReport:
    label: str
    title: str
    findings: list[Finding]
    summary_title: str
    summary_rows: list[tuple[str, str]]
    introduction: str | None = None
    remediation_introduction: str | None = None
    statistics: dict | None = None
    ithc: bool = False
    closure_review: bool = False
    grouped: bool = False
    show_severity: bool = False
    references_in_remediation: bool = False


def print_report_summary(
    report: AnalysisReport, output_path: Path, console: Console | None = None,
) -> None:
    print()
    print_summary_table(
        title=report.summary_title,
        console=console,
        rows=report.summary_rows + [
            ("Output Directory", str(output_path.parent)),
            ("Output File", output_path.name),
        ],
    )


def generate_combined_report(reports: list[AnalysisReport], output_path: Path) -> Path | None:
    if output_path.suffix.lower() != ".html":
        raise ValueError("Report output must have a .html extension.")
    if not reports:
        return None
    tabs = [
        ReportTab(
            label=report.label,
            sections=build_report_sections(
                report.findings, report.title, report.introduction,
                report.remediation_introduction, report.statistics, report.ithc,
            ),
            closure_review=report.closure_review,
            grouped=report.grouped,
            show_severity=report.show_severity,
            references_in_remediation=report.references_in_remediation,
        )
        for report in reports
    ]
    return write_html(render_combined_html(tabs), output_path)


def generate_analysis_report(report: AnalysisReport, output_path: Path) -> Path:
    if not report.closure_review and output_path.suffix.lower() != ".html":
        raise ValueError("Report output must have a .html extension.")
    return generate_html(
        findings=report.findings, output_path=output_path, title=report.title,
        introduction=report.introduction,
        remediation_introduction=report.remediation_introduction,
        statistics=report.statistics, ithc=report.ithc, closure_review=report.closure_review,
        grouped=report.grouped, show_severity=report.show_severity,
        references_in_remediation=report.references_in_remediation,
    )


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
    references_in_remediation: bool = False,
) -> Path | None:
    if output_path.suffix.lower() != ".html":
        raise ValueError("Report output must have a .html extension.")
    if not findings:
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
        references_in_remediation=references_in_remediation,
    )