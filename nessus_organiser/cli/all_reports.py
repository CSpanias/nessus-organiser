"""
nessus_organiser.cli.all

Generate all supported Nessus Organiser reports from a single Nessus scan.

This command acts as a convenience wrapper around the individual report 
modules, allowing consultants to produce all available report types from a 
single command execution.
"""

from datetime import datetime
from pathlib import Path

from nessus_organiser.cli import patching
from nessus_organiser.cli import closure
from nessus_organiser.cli import ssh
from nessus_organiser.cli import tls
from nessus_organiser.common.progress import load_scan, report_progress
from nessus_organiser.reporting import (
    AnalysisReport, generate_combined_report, print_report_summary, report_path,
)


def run(
    nessus_file: Path,
    scope: str,
    ithc: bool = False,
    csacyber: bool = False,
) -> None:
    """
    Generate all supported reports.

    Args:
        nessus_file:
            Path to the Nessus (.nessus) file.

        scope:
            Assessment scope. Expected values are
            'internal' or 'external'.

    Returns:
        None.
    """

    timestamp = datetime.now()
    plugin_findings = load_scan(nessus_file)
    reports: list[AnalysisReport] = []
    with report_progress(transient=False, spinner=False) as progress:
        task = progress.add_task("Analysing TLS findings...", total=4)
        console = progress.console if progress.console.is_terminal else None
        report = tls.analyse(plugin_findings, scope)
        if report:
            reports.append(report)
        progress.update(
            task, advance=1, description="Analysing patch management findings...", refresh=True
        )
        report = patching.analyse(plugin_findings, scope, ithc)
        if report:
            reports.append(report)
        progress.update(task, advance=1, description="Analysing SSH findings...", refresh=True)
        report = ssh.analyse(plugin_findings, scope)
        if report:
            reports.append(report)
        progress.update(task, advance=1, description="Analysing closure findings...", refresh=True)
        report = closure.analyse(plugin_findings, scope, csacyber, console)
        if report:
            reports.append(report)
        progress.update(task, description="Generating combined report...", refresh=True)
        generated = generate_combined_report(reports, report_path("nessus-review", timestamp))
        if generated is not None:
            for report in reports:
                print_report_summary(report, generated, console)
        if console is not None:
            console.print()
        progress.update(task, advance=1, description="Reports complete", refresh=True)