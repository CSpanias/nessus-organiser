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
from nessus_organiser.reporting import report_path


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
    with report_progress() as progress:
        task = progress.add_task("Generating TLS report...", total=4)
        tls.run(
            nessus_file=nessus_file,
            output_file=report_path("tls-review", timestamp),
            scope=scope,
            plugin_findings=plugin_findings,
        )
        progress.update(task, advance=1, description="Generating patch management report...")
        patching.run(
            nessus_file=nessus_file,
            output_file=report_path("patch-management-review", timestamp),
            scope=scope,
            ithc=ithc,
            plugin_findings=plugin_findings,
        )
        progress.update(task, advance=1, description="Generating SSH report...")
        ssh.run(
            nessus_file=nessus_file,
            output_file=report_path("ssh-review", timestamp),
            scope=scope,
            plugin_findings=plugin_findings,
        )
        progress.update(task, advance=1, description="Generating closure review...")
        closure.run(
            nessus_file=nessus_file,
            output_file=report_path("closure-review", timestamp),
            scope=scope,
            csacyber=csacyber,
            plugin_findings=plugin_findings,
        )
        progress.advance(task)