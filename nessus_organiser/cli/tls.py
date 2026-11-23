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
from nessus_organiser.common.tables import print_summary_table
from nessus_organiser.common.progress import load_scan
from nessus_organiser.content.loader import load_tls_content
from nessus_organiser.findings.factory import build_findings
from nessus_organiser.organising.tls import organise_tls, build_evidence
from nessus_organiser.models.plugin import PluginFinding
from nessus_organiser.reporting import generate_report


def run(
    nessus_file: Path,
    output_file: Path,
    scope: str,
    plugin_findings: list[PluginFinding] | None = None,
    console: Console | None = None,
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

    Returns:
        None.
    """

    excluded_plugins=0

    # Raw Nessus findings
    if plugin_findings is None:
        plugin_findings = load_scan(nessus_file)

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

    generated = generate_report(
        findings=report_findings,
        output_path=output_file,
        title=tls_content["title"],
        introduction=tls_content.get("introduction"),
        remediation_introduction=tls_content.get("remediation_introduction"),
        grouped=True,
        show_severity=True,
        references_in_remediation=True,
    )
    if generated is None:
        return

    print()
    print_summary_table(
        title="TLS Analysis Summary",
        console=console,
        rows=[
            ("Parsed Plugins", f"{len(plugin_findings):,}"),
            ("Excluded Plugins", f"{excluded_plugins}"),
            ("Processed Plugins", f"{analysed_plugins:,}"),
            ("TLS Vulnerabilities", f"{tls_vulnerability_count:,}"),
            ("Identified Categories", str(identified_categories)),
            ("Generated Findings", str(len(report_findings))),
            ("Output Directory", str(generated.parent)),
            ("Output File", generated.name),
        ],
    )