"""
nessus_organiser.cli.tls

TLS report generation commands.
"""

from pathlib import Path

from rich.console import Console

from nessus_organiser.analysis.tls import analyse_tls_finding
from nessus_organiser.common.counting import (
    count_analysed_plugins,
    count_categories,
    count_findings,
)
from nessus_organiser.common.progress import load_scan
from nessus_organiser.content.loader import load_tls_content
from nessus_organiser.findings.factory import build_findings
from nessus_organiser.organising.tls import organise_tls, build_evidence
from nessus_organiser.models.plugin import PluginFinding
from nessus_organiser.reporting import AnalysisReport, generate_analysis_report, print_report_summary


def run(
    nessus_file: Path,
    output_file: Path,
    scope: str,
    plugin_findings: list[PluginFinding] | None = None,
    console: Console | None = None,
    exclude_ips: list[str] | None = None,
) -> None:
    """
    Generate a TLS report from a Nessus scan.

    Args:
        nessus_file:
            Path to the Nessus (.nessus) file.

        output_file:
            Path to the generated HTML report.

        scope:
            Assessment scope (internal or external).

        exclude_ips:
            Host IP addresses to exclude from the report.

    Returns:
        None.
    """

    if plugin_findings is None:
        plugin_findings = load_scan(nessus_file, exclude_ips=exclude_ips)
    report = analyse(plugin_findings, scope)
    if report is None:
        return
    generated = generate_analysis_report(report, output_file)
    print_report_summary(report, generated, console)


def analyse(plugin_findings: list[PluginFinding], scope: str) -> AnalysisReport | None:
    excluded_plugins = 0

    # Organised findings
    grouped_findings = organise_tls(findings=plugin_findings)

    tls_content = load_tls_content()

    # Polished findings
    report_findings = build_findings(
        grouped_findings=grouped_findings,
        content=tls_content,
        evidence_builder=build_evidence,
    )

    report_findings = [
        analyse_tls_finding(
            finding=finding,
            scope=scope,
            content=tls_content,
        )
        for finding in report_findings
    ]

    identified_categories = count_categories(grouped_findings)

    analysed_plugins = count_analysed_plugins(
        parsed_plugins=len(plugin_findings),
        excluded_plugins=0,
    )

    tls_vulnerability_count = sum(
        count_findings(category_findings)
        for category_findings in grouped_findings.values()
    )

    if not report_findings:
        return None
    return AnalysisReport(
        label="TLS/SSL",
        findings=report_findings,
        title=tls_content["title"],
        introduction=tls_content.get("introduction"),
        remediation_introduction=tls_content.get("remediation_introduction"),
        grouped=True,
        show_severity=True,
        references_in_remediation=True,
        summary_title="TLS Analysis Summary",
        summary_rows=[
            ("Parsed Plugins", f"{len(plugin_findings):,}"),
            ("Excluded Plugins", f"{excluded_plugins}"),
            ("Processed Plugins", f"{analysed_plugins:,}"),
            ("TLS Vulnerabilities", f"{tls_vulnerability_count:,}"),
            ("Identified Categories", str(identified_categories)),
            ("Generated Findings", str(len(report_findings))),
        ],
    )