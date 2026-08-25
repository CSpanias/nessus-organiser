"""
nessus_organiser.common.counting

Counting helpers used by organising, analysis, and reporting modules.
"""

from collections.abc import Sized

from nessus_organiser.models.plugin import PluginFinding


def count_hosts(
    findings: list[PluginFinding],
) -> int:
    """
    Count unique affected hosts.

    Args:
        findings:
            Plugin findings.

    Returns:
        Number of unique hosts.
    """

    return len({finding.host for finding in findings})


def count_services(
    findings: list[PluginFinding],
) -> int:
    """
    Count unique affected services.

    Args:
        findings:
            Plugin findings.

    Returns:
        Number of unique services.
    """

    return len(
        {
            (
                finding.host,
                finding.port,
                finding.protocol,
            )
            for finding in findings
        }
    )


def count_legacy_instances(
    findings: list[PluginFinding],
) -> int:
    """
    Count unique legacy software instances.

    Legacy findings are deduplicated by plugin ID and host.

    Args:
        findings:
            Legacy software findings.

    Returns:
        Number of unique legacy software instances.
    """

    return len({(finding.plugin_id, finding.host) for finding in findings})


def count_categories(
    grouped_findings: dict,
) -> int:
    """
    Count categories containing findings.
    """

    return len(
        [
            findings
            for findings in grouped_findings.values()
            if findings
        ]
    )


def count_analysed_plugins(
    parsed_plugins: int,
    excluded_plugins: int,
) -> int:
    """
    Count analysed plugins.
    """

    return (
        parsed_plugins
        - excluded_plugins
    )


def count_findings(
    findings: Sized,
) -> int:
    """
    Count findings.

    Returns:
        Number of findings.
    """

    return len(findings)


def count_unique_host_plugin_findings(
    findings: list[PluginFinding],
) -> int:
    """
    Count unique findings by host and plugin ID.
    """

    return len(
        {
            (
                finding.host,
                finding.plugin_id,
            )
            for finding in findings
        }
    )