"""
nessus_organiser.cli.all

Generate all supported Nessus Organiser reports from a single Nessus scan.

This command acts as a convenience wrapper around the individual report 
modules, allowing consultants to produce all available report types from a 
single command execution.
"""

from pathlib import Path

from nessus_organiser.cli import patching
from nessus_organiser.cli import tls


def run(
    nessus_file: Path,
    scope: str,
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

    tls.run(
        nessus_file=nessus_file,
        output_file=Path("tls-review.md"),
        scope=scope,
    )

    patching.run(
        nessus_file=nessus_file,
        output_file=Path("patch-management-review.md"),
        scope=scope,
    )