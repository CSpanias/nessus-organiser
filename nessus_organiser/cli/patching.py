"""
nessus_organiser.cli.patch_management

Patch management report generation commands.
"""

from pathlib import Path

from rich.console import Console

from nessus_organiser.analysis.patching import (
    analyse_patch_management_finding,
    build_patch_management_statistics
)
from nessus_organiser.common.counting import (
    count_legacy_instances,
    count_categories,
    count_analysed_plugins,
    count_unique_host_plugin_findings,
)
from nessus_organiser.common.progress import load_scan
from nessus_organiser.content.loader import load_patch_management_content
from nessus_organiser.findings.factory import build_findings
from nessus_organiser.organising.patching import organise_patch_management
from nessus_organiser.models.plugin import PluginFinding
from nessus_organiser.reporting import AnalysisReport, generate_analysis_report, print_report_summary

def run(
    nessus_file: Path,
    output_file: Path,
    scope: str,
    ithc: bool = False,
    plugin_findings: list[PluginFinding] | None = None,
    console: Console | None = None,
) -> None:
    """
    Generate a Patch Management report from a Nessus scan.

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

    if plugin_findings is None:
        plugin_findings = load_scan(nessus_file)
    report = analyse(plugin_findings, scope, ithc)
    if report is None:
        return
    generated = generate_analysis_report(report, output_file)
    print_report_summary(report, generated, console)


def analyse(
    plugin_findings: list[PluginFinding], scope: str, ithc: bool = False,
) -> AnalysisReport | None:

    # Organised findings
    organisation_result = organise_patch_management(findings=plugin_findings)

    patch_management_content = (load_patch_management_content())

    # Polished findings
    report_findings = build_findings(
        grouped_findings=organisation_result.grouped_findings,
        content=patch_management_content,
    )

    report_findings = [
        analyse_patch_management_finding(
            finding=finding,
            scope=scope,
            content=patch_management_content,
        )
        for finding in report_findings
    ]

    identified_categories = count_categories(
        organisation_result.grouped_findings
    )

    analysed_plugins = count_analysed_plugins(
        parsed_plugins=len(plugin_findings),
        excluded_plugins=organisation_result.excluded_findings,
    )

    patch_vulnerability_count = (
        count_unique_host_plugin_findings(
            organisation_result.grouped_findings["missing_security_patches"]
        )
    )

    legacy_vulnerability_count = (
        count_legacy_instances(
            organisation_result.grouped_findings["unsupported_software"]
        )
    )

    statistics = (
        build_patch_management_statistics(
            grouped_findings=(
                organisation_result.grouped_findings
            )
        )
    )

    # Enforce findings order
    ORDER = ("unsupported_software", "missing_security_patches")
    report_findings.sort(key=lambda f: ORDER.index(f.category))

    if not report_findings:
        return None
    return AnalysisReport(
        label="Patch Management",
        findings=report_findings,
        statistics=statistics,
        title=patch_management_content["title"],
        introduction=patch_management_content.get("introduction"),
        remediation_introduction=patch_management_content.get("remediation_introduction"),
        ithc=ithc,
        grouped=True,
        references_in_remediation=True,
        summary_title="Patch Management Analysis Summary",
        summary_rows=[
            ("Parsed Plugins", f"{len(plugin_findings):,}"),
            ("Excluded Plugins", str(organisation_result.excluded_findings)),
            ("Processed Plugins", f"{analysed_plugins:,}"),
            ("Patch Vulnerabilities", f"{patch_vulnerability_count:,}"),
            ("Legacy Vulnerabilities", f"{legacy_vulnerability_count:,}"),
            ("Identified Categories", str(identified_categories)),
            ("Generated Findings", str(len(report_findings))),
        ],
    )