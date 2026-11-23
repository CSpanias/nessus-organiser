"""
nessus_organiser.cli.all

Generate all supported Nessus Organiser reports from a single Nessus scan.

This command acts as a convenience wrapper around the individual report 
modules, allowing consultants to produce all available report types from a 
single command execution.
"""

from pathlib import Path

from nessus_organiser.cli import patching
from nessus_organiser.cli import closure
from nessus_organiser.cli import ssh
from nessus_organiser.cli import tls


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

    tls.run(
        nessus_file=nessus_file,
        output_file=Path("tls-review.html"),
        scope=scope,
    )

    patching.run(
        nessus_file=nessus_file,
        output_file=Path("patch-management-review.html"),
        scope=scope,
        ithc=ithc,
    )

    ssh.run(
        nessus_file=nessus_file,
        output_file=Path("ssh-review.html"),
        scope=scope,
    )

    closure.run(
        nessus_file=nessus_file,
        output_file=Path("closure-review.html"),
        scope=scope,
        csacyber=csacyber,
    )