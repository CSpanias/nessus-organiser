"""
nessus_organiser.cli.main

Application entry point.
"""

import argparse
import ipaddress
import sys

from pathlib import Path
from textwrap import dedent

from rich_argparse import RawDescriptionRichHelpFormatter

from nessus_organiser.cli import all_reports
from nessus_organiser.cli.closure import run as run_closure
from nessus_organiser.cli.patching import run as run_patching
from nessus_organiser.cli.plugins import run as run_plugins
from nessus_organiser.cli.ssh import run as run_ssh
from nessus_organiser.cli.tls import run as run_tls
from nessus_organiser.reporting import report_path

_SUPPORTED_COMMANDS = ("all", "tls", "patching", "ssh", "closure")


def _parse_ip_address(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"invalid IP address: {value}") from error


def _add_exclude_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--exclude",
        action="append",
        type=_parse_ip_address,
        metavar="IP",
        help="Exclude findings from this host IP; repeat for additional hosts.",
    )


def _detect_module(argv: list[str]) -> str | None:
    """
    Return the report module present on the command line, if any.
    """

    for token in argv[1:]:
        if token in _SUPPORTED_COMMANDS:
            return token

    return None


def main() -> None:
    """
    Application entry point.
    """

    if "--list-plugin-ids" in sys.argv:
        run_plugins(module=_detect_module(sys.argv))
        return

     # Parsers configuration
    class CustomFormatter(
        argparse.ArgumentDefaultsHelpFormatter,
        RawDescriptionRichHelpFormatter,
    ):
        pass

    parser = argparse.ArgumentParser(
        prog="nessus-organiser",
        description=(
            "Generate TLS, Patch Management, SSH and closure review reports "
            "from Nessus (.nessus) scan files."
        ),
        formatter_class=CustomFormatter,
    )
    parser.add_argument(
        "--list-plugin-ids",
        action="store_true",
        help=(
            "List the Nessus plugin IDs recognised by each report module, "
            "then exit."
        ),
    )

    subparsers = parser.add_subparsers(dest="command")

    #---------------------------------------------------------------------------
    # All modules
    #---------------------------------------------------------------------------
    all_parser = subparsers.add_parser(
        "all",
        help=("Generate a combined tabbed report."),
        description=("Generate one tabbed HTML report from a Nessus scan."),
        formatter_class=CustomFormatter,
        epilog=dedent("""
        Example:
            nessus-organiser all -S internal internal.nessus
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
        required=True,
        help=("Assessment scope used when generating commentary."),
    )

    all_parser.add_argument(
        "--ithc",
        action="store_true",
        help="Enable ITHC-specific reporting.",
    )
    all_parser.add_argument("--csacyber", action="store_true", help=argparse.SUPPRESS)
    _add_exclude_argument(all_parser)

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
            nessus-organiser tls -S internal internal.nessus
            nessus-organiser tls -S external external.nessus
        """),
    )

    tls_parser.add_argument(
        "nessus_file",
        type=Path,
        help="Path to the Nessus (.nessus) file to analyse.",
    )

    tls_parser.add_argument(
        "-S",
        "--scope",
        choices=["internal", "external"],
        required=True,
        help=("Assessment scope."),
    )
    _add_exclude_argument(tls_parser)

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
            nessus-organiser patching -S external external.nessus
            nessus-organiser patching -S internal internal.nessus
        """),
    )

    patching_parser.add_argument(
        "nessus_file",
        type=Path,
        help=("Path to the Nessus (.nessus) file to analyse."),
    )

    patching_parser.add_argument(
        "-S",
        "--scope",
        choices=["internal", "external"],
        required=True,
        help="Assessment scope.",
    )

    patching_parser.add_argument(
        "--ithc",
        action="store_true",
        help="Enable ITHC-specific reporting.",
    )
    _add_exclude_argument(patching_parser)

    #---------------------------------------------------------------------------
    # SSH module
    #---------------------------------------------------------------------------
    ssh_parser = subparsers.add_parser(
        "ssh",
        help="Generate an SSH report.",
        description=(
            "Analyse SSH-related findings and generate an SSH cryptographic "
            "review report."
        ),
        formatter_class=CustomFormatter,
        epilog=dedent("""
        Examples:
            nessus-organiser ssh -S internal internal.nessus
            nessus-organiser ssh -S external external.nessus
        """),
    )

    ssh_parser.add_argument(
        "nessus_file",
        type=Path,
        help="Path to the Nessus (.nessus) file to analyse.",
    )

    ssh_parser.add_argument(
        "-S",
        "--scope",
        choices=["internal", "external"],
        required=True,
        help="Assessment scope.",
    )
    _add_exclude_argument(ssh_parser)

    closure_parser = subparsers.add_parser(
        "closure",
        help="Review findings that may be candidates for closure.",
        description="Generate scope-specific closure suggestions for recognised plugins.",
        formatter_class=CustomFormatter,
    )
    closure_parser.add_argument("nessus_file", type=Path, help="Nessus scan file.")
    closure_parser.add_argument(
        "-S", "--scope", choices=["internal", "external"], required=True,
        help="Assessment scope.",
    )
    closure_parser.add_argument("--csacyber", action="store_true", help=argparse.SUPPRESS)
    _add_exclude_argument(closure_parser)

    #---------------------------------------------------------------------------
    # Parser Assembly
    #---------------------------------------------------------------------------
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return

    if not args.nessus_file.is_file():
        parser.error(f"Nessus input file not found or not a file: {args.nessus_file}")

    match args.command:

        case "all":
            all_reports.run(
                nessus_file=args.nessus_file,
                scope=args.scope,
                ithc=args.ithc,
                csacyber=args.csacyber,
                exclude_ips=args.exclude,
            )

        case "tls":
            run_tls(
                nessus_file=args.nessus_file,
                output_file=report_path("tls-review"),
                scope=args.scope,
                exclude_ips=args.exclude,
            )

        case "patching":
            run_patching(
                nessus_file=args.nessus_file,
                output_file=report_path("patch-management-review"),
                scope=args.scope,
                ithc=args.ithc,
                exclude_ips=args.exclude,
            )

        case "ssh":
            run_ssh(
                nessus_file=args.nessus_file,
                output_file=report_path("ssh-review"),
                scope=args.scope,
                exclude_ips=args.exclude,
            )

        case "closure":
            run_closure(
                nessus_file=args.nessus_file,
                output_file=report_path("closure-review"),
                scope=args.scope,
                csacyber=args.csacyber,
                exclude_ips=args.exclude,
            )


if __name__ == "__main__":
    main()