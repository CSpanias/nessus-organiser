"""
nessus_organiser.cli.plugins

List the Nessus plugin IDs recognised by each report module.
"""

from nessus_organiser.common.exclusions import GLOBAL_EXCLUDED_PLUGIN_IDS
from nessus_organiser.common.tables import print_table
from nessus_organiser.content.loader import load_ssh_content, load_tls_content
from nessus_organiser.rules.patching import (
    PATCH_MANAGEMENT_RULES,
    PATCHING_EXCLUDED_PLUGIN_IDS,
    PATCHING_PLUGIN_IDS,
    LEGACY_PLUGIN_IDS,
)
from nessus_organiser.rules.ssh import SSH_CATEGORIES
from nessus_organiser.rules.tls import TLS_CATEGORIES


PATCHING_PLUGIN_DESCRIPTIONS = {
    "324932": "7-Zip <= 26.02 Mark-of-the-Web Bypass (CVE-2026-58052)",
    "134942": "Microsoft Windows Type 1 Font Parsing Remote Code Execution Vulnerability (ADV200006)",
    "128764": "CredSSP Remote Code Execution Vulnerability March 2018 Security Update",
    "134204": "MS15-124: Cumulative Security Update for Internet Explorer (CVE-2015-6161) (3125869)",
    "146272": "SAP BusinessObjects Business Intelligence Platform SSRF Vulnerability (direct check)",
    "90510": "MS16-047: Security Update for SAM and LSAD Remote Protocols (3148527) (Badlock) (uncredentialed check)",
}

LEGACY_PLUGIN_DESCRIPTIONS = {
    "156103": "Apache Log4j 1.2 JMSAppender Remote Code Execution",
    "156860": "Apache Log4j 1.x Multiple Vulnerabilities",
}

PATCHING_EXCLUDED_DESCRIPTIONS = {
    "136946": "CVE-2017-8529 protection registry key",
    "87252": "MS KB3123040: Improperly Issued Digital Certificates Could Allow Spoofing",
    "87313": "MS KB3119884: Improperly Issued Digital Certificates Could Allow Spoofing",
}

GLOBAL_EXCLUDED_DESCRIPTIONS = {
    "57033": "Microsoft Patch Bulletin Feasibility Check",
    "38153": "Microsoft Windows Summary of Missing Patches",
    "66334": "Patch Report",
    "60119": "Microsoft Windows SMB Share Permissions Enumeration",
    "103569": "Windows Defender Signature Definition Check",
}

_KEYWORD_FIELD_LABELS = {
    "synopsis": "Synopsis",
    "solution": "Solution",
    "plugin_output": "Plugin Output",
    "description": "Description",
}


def run() -> None:
    """
    Print the plugin IDs recognised by each report module.
    """

    _print_ssh()
    print()
    _print_tls()
    print()
    _print_patching()
    print()
    _print_global_exclusions()


def _sorted_ids(plugin_ids) -> list[str]:
    return sorted(plugin_ids, key=lambda plugin_id: int(plugin_id))


def _print_ssh() -> None:
    content = load_ssh_content()

    rows = []
    for category, rule in SSH_CATEGORIES.items():

        title = content.get(category, {}).get("title", category)

        for plugin_id in _sorted_ids(rule["plugin_ids"]):
            rows.append((plugin_id, title))

    print_table(
        title="SSH Plugin IDs",
        columns=["Plugin ID", "Finding"],
        rows=rows,
    )


def _print_tls() -> None:
    content = load_tls_content()

    rows = []
    for category, rule in TLS_CATEGORIES.items():

        title = content.get(category, {}).get("title", category)

        for plugin_id in _sorted_ids(rule["plugin_ids"]):
            rows.append((plugin_id, title))

    print_table(
        title="TLS Plugin IDs",
        columns=["Plugin ID", "Category"],
        rows=rows,
    )


def _print_patching() -> None:
    rows = []

    for plugin_id in _sorted_ids(PATCHING_PLUGIN_IDS):
        rows.append(
            (
                plugin_id,
                "Explicit match",
                PATCHING_PLUGIN_DESCRIPTIONS.get(plugin_id, ""),
            )
        )

    for plugin_id in _sorted_ids(LEGACY_PLUGIN_IDS):
        rows.append(
            (
                plugin_id,
                "Legacy software",
                LEGACY_PLUGIN_DESCRIPTIONS.get(plugin_id, ""),
            )
        )

    for plugin_id in _sorted_ids(PATCHING_EXCLUDED_PLUGIN_IDS):
        rows.append(
            (
                plugin_id,
                "Patching exclusion",
                PATCHING_EXCLUDED_DESCRIPTIONS.get(plugin_id, ""),
            )
        )

    print_table(
        title="Patching Plugin IDs",
        columns=["Plugin ID", "Type", "Description"],
        rows=rows,
    )

    keyword_rows = [
        (
            _KEYWORD_FIELD_LABELS.get(field, field),
            ", ".join(sorted(indicators)),
        )
        for field, indicators in PATCH_MANAGEMENT_RULES.items()
    ]

    print()
    print_table(
        title="Patching Keyword Rules",
        columns=["Field", "Indicators"],
        rows=keyword_rows,
    )


def _print_global_exclusions() -> None:
    rows = [
        (
            plugin_id,
            GLOBAL_EXCLUDED_DESCRIPTIONS.get(plugin_id, ""),
        )
        for plugin_id in _sorted_ids(GLOBAL_EXCLUDED_PLUGIN_IDS)
    ]

    print_table(
        title="Global Exclusions",
        columns=["Plugin ID", "Description"],
        rows=rows,
    )