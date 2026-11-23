"""
nessus_organiser.cli.ssh

SSH report generation commands.
"""

from pathlib import Path

from rich.console import Console

from nessus_organiser.analysis.ssh import analyse_ssh_finding
from nessus_organiser.common.counting import (
    count_analysed_plugins,
    count_categories,
    count_findings,
)
from nessus_organiser.common.tables import print_summary_table
from nessus_organiser.common.progress import load_scan
from nessus_organiser.content.loader import load_ssh_content
from nessus_organiser.findings.factory import build_findings
from nessus_organiser.organising.ssh import organise_ssh, build_evidence
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
    Generate an SSH report from a Nessus scan.

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

    excluded_plugins = 0

    # Raw Nessus findings
    if plugin_findings is None:
        plugin_findings = load_scan(nessus_file)

    # Organised findings
    grouped_findings = organise_ssh(findings=plugin_findings)

    ssh_content = load_ssh_content()

    # Polished findings
    report_findings = build_findings(
        grouped_findings=grouped_findings,
        content=ssh_content,
        evidence_builder=build_evidence,
    )

    report_findings = [
        analyse_ssh_finding(
            finding=finding,
            scope=scope,
            content=ssh_content,
        )
        for finding in report_findings
    ]

    # Enforce findings order
    ORDER = (
        "terrapin_prefix_truncation",
        "weak_mac_algorithms",
        "weak_key_exchange_algorithms",
        "cbc_mode_ciphers",
        "weak_algorithms_supported",
        "ssh_protocol_v1",
    )
    report_findings.sort(key=lambda f: ORDER.index(f.category))

    identified_categories = count_categories(grouped_findings)

    analysed_plugins = count_analysed_plugins(
        parsed_plugins=len(plugin_findings),
        excluded_plugins=excluded_plugins,
    )

    ssh_vulnerability_count = sum(
        count_findings(category_findings)
        for category_findings in grouped_findings.values()
    )

    generated = generate_report(
        findings=report_findings,
        output_path=output_file,
        title=ssh_content["title"],
        introduction=ssh_content.get("introduction"),
        remediation_introduction=ssh_content.get(
            "remediation_introduction"
        ),
    )
    if generated is None:
        return

    print()
    print_summary_table(
        title="SSH Analysis Summary",
        console=console,
        rows=[
            ("Parsed Plugins", f"{len(plugin_findings):,}"),
            ("Excluded Plugins", f"{excluded_plugins}"),
            ("Processed Plugins", f"{analysed_plugins:,}"),
            ("SSH Vulnerabilities", f"{ssh_vulnerability_count:,}"),
            ("Identified Categories", str(identified_categories)),
            ("Generated Findings", str(len(report_findings))),
            ("Output Directory", str(generated.parent)),
            ("Output File", generated.name),
        ],
    )