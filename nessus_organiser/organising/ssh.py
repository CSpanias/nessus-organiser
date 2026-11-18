"""
nessus_organiser.organising.ssh

This module converts individual Nessus findings into logical groupings that can
later be transformed into consultant-facing findings and reports.

The module is responsible only for categorisation. Reporting logic and finding
content should remain in their respective modules.
"""

from collections import defaultdict

from nessus_organiser.models.plugin import PluginFinding
from nessus_organiser.rules.ssh import SSH_CATEGORIES, SSH_EVIDENCE


__all__ = [
    "organise_ssh",
    "build_evidence",
]


def organise_ssh(
    findings: list[PluginFinding],
) -> dict[str, list[PluginFinding]]:
    """
    Organise Nessus findings into SSH root cause categories.

    Args:
        findings:
            Plugin findings extracted from a Nessus scan.

    Returns:
        Dictionary containing category names and the associated plugin findings.
    """

    grouped: dict[str, list[PluginFinding]] = defaultdict(list)

    for finding in findings:

        category = _get_category(plugin_id=finding.plugin_id)

        if category is None:
            continue

        grouped[category].append(finding)

    return dict(grouped)


def _get_category(
    plugin_id: str,
) -> str | None:
    """
    Resolve an SSH category for a Nessus plugin.

    Args:
        plugin_id:
            Nessus plugin identifier.

    Returns:
        SSH category identifier if a matching rule exists, otherwise None.
    """

    for category, rule in SSH_CATEGORIES.items():

        if plugin_id in rule["plugin_ids"]:
            return category

    return None


def build_evidence(
    findings: list[PluginFinding],
) -> list[str]:
    """
    Build evidence statements for an SSH category.

    Args:
        findings:
            Plugin findings associated with a category.

    Returns:
        Sorted evidence statements.
    """

    evidence = set()

    for finding in findings:

        item = SSH_EVIDENCE.get(finding.plugin_id)

        if item:
            evidence.add(item)

    return sorted(evidence)