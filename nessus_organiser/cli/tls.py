"""
nessus_organiser.cli.tls

TLS report generation commands.
"""

from pathlib import Path

from nessus_organiser.analysis.tls import analyse_tls_finding
from nessus_organiser.common.counting import (
    count_analysed_plugins,
    count_categories,
    count_findings,
)
from nessus_organiser.common.tables import print_summary_table
from nessus_organiser.content.loader import load_tls_content
from nessus_organiser.findings.factory import build_findings
from nessus_organiser.organising.tls import organise_tls, build_evidence
from nessus_organiser.parsing.nessus import load_nessus
from nessus_organiser.reporting.markdown import generate_markdown


def run(
    nessus_file: Path,
    output_file: Path,
    scope: str,
) -> None:
    """
    Generate a TLS report from a Nessus scan.

    Args:
        nessus_file:
            Path to the Nessus (.nessus) file.

        output_file:
            Path to the generated Markdown report.

        scope:
            Assessment scope (internal or external).

    Returns:
        None.
    """

    excluded_plugins=0

    # Raw Nessus findings
    plugin_findings = load_nessus(path=nessus_file)

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

    generate_markdown(
        findings=report_findings,
        output_path=output_file,
        title=tls_content["title"],
        introduction=tls_content.get("introduction")
    )

    print()
    print_summary_table(
        title="TLS Analysis Summary",
        rows=[
            ("Parsed Plugins", f"{len(plugin_findings):,}"),
            ("Excluded Plugins", f"{excluded_plugins}"),
            ("Processed Plugins", f"{analysed_plugins:,}"),
            ("TLS Vulnerabilities", f"{tls_vulnerability_count:,}"),
            ("Identified Categories", str(identified_categories)),
            ("Generated Findings", str(len(report_findings))),
            ("Output File", output_file.name),
        ],
    )