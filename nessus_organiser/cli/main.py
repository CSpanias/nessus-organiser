"""
nessus_organiser.cli.main

Application entry point.
"""

import argparse

from pathlib import Path
from textwrap import dedent

from nessus_organiser.cli import all_reports
from nessus_organiser.cli.patching import run as run_patching
from nessus_organiser.cli.tls import run as run_tls


def main() -> None:
    """
    Application entry point.
    """

     # Parsers configuration
    class CustomFormatter(
        argparse.ArgumentDefaultsHelpFormatter,
        argparse.RawDescriptionHelpFormatter,
    ):
        pass

    parser = argparse.ArgumentParser(
        prog="nessus-organiser",
        description=(
            "Generate TLS and Patch Management assessment reports from Nessus "
            "(.nessus) scan files."
        ),
        formatter_class=CustomFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    #---------------------------------------------------------------------------
    # All module
    #---------------------------------------------------------------------------
    all_parser = subparsers.add_parser(
        "all",
        help=("Generate all supported reports."),
        description=("Generate all supported reports from a Nessus scan."),
        formatter_class=CustomFormatter,
        epilog=dedent("""
        Example:
            nessus-organiser all internal.nessus
            nessus-organiser all -S external external.nessus
        """),
    )

    all_parser.add_argument(
        "nessus_file",
        type=Path,
        help=("Path to the Nessus (.nessus) file to analyse."),
    )

    all_parser.add_argument(
        "-S",
        "--scope",
        choices=["internal", "external"],
        default="internal",
        help=("Assessment scope used when generating commentary."),
    )

    #---------------------------------------------------------------------------
    # TLS module
    #---------------------------------------------------------------------------
    tls_parser = subparsers.add_parser(
        "tls",
        help="Generate a TLS report.",
        description=(
            "Analyse TLS-related findings and generate a TLS-related report"
        ),
        formatter_class=CustomFormatter,
        epilog=dedent("""
        Examples:
            nessus-organiser tls internal.nessus
            nessus-organiser tls -S external external.nessus
        """),
    )

    tls_parser.add_argument(
        "nessus_file",
        type=Path,
        help="Path to the Nessus (.nessus) file to analyse.",
    )

    tls_parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("tls-review.md"),
        help="Output Markdown file.",
    )

    tls_parser.add_argument(
        "-S",
        "--scope",
        choices=["internal", "external"],
        default="internal",
        help=("Assessment scope."),
    )

    #---------------------------------------------------------------------------
    # Patching module
    #---------------------------------------------------------------------------
    patching_parser = subparsers.add_parser(
        "patching",
        help="Generate a Patch Management report.",
        description=(
            "Analyse missing security updates and unsupported software "
            "findings."
        ),
        formatter_class=CustomFormatter,
        epilog=dedent("""
        Examples:
            nessus-organiser patching internal.nessus
            nessus-organiser patching -S internal internal.nessus
        """),
    )

    patching_parser.add_argument(
        "nessus_file",
        type=Path,
        help=("Path to the Nessus (.nessus) file to analyse."),
    )

    patching_parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("patch-management-review.md"),
        help="Output Markdown file.",
    )

    patching_parser.add_argument(
        "-S",
        "--scope",
        choices=["internal", "external"],
        default="internal",
        help="Assessment scope.",
    )

    #---------------------------------------------------------------------------
    # Parser Assembly
    #---------------------------------------------------------------------------
    args = parser.parse_args()

    match args.command:

        case "all":
            all_reports.run(
                nessus_file=args.nessus_file,
                scope=args.scope,
            )

        case "tls":
            run_tls(
                nessus_file=args.nessus_file,
                output_file=args.output,
                scope=args.scope,
            )

        case "patching":
            run_patching(
                nessus_file=args.nessus_file,
                output_file=args.output,
                scope=args.scope,
            )


if __name__ == "__main__":
    main()