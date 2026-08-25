"""
nessus_organiser.organising.patching

Organise Nessus plugin findings into patch-management-related categories.
"""

from nessus_organiser.classifiers.patching import is_patch_management
from nessus_organiser.classifiers.legacy import is_legacy_software
from nessus_organiser.common.exclusions import is_globally_excluded
from nessus_organiser.models.organisation import OrganisationResult
from nessus_organiser.models.plugin import PluginFinding
from nessus_organiser.rules.patching import PATCHING_EXCLUDED_PLUGIN_IDS


def organise_patch_management(
    findings: list[PluginFinding],
) -> OrganisationResult:
    """
    Organise Nessus plugin findings into patch-management categories.

    Args:
        findings:
            Parsed Nessus plugin findings.

    Returns:
        Organisation result containing grouped findings and organisation 
        statistics.
    """

    grouped_findings = {
        "missing_security_patches": [],
        "unsupported_software": [],
    }

    excluded_count = 0

    for finding in findings:

        # Exclude non-vulnerability plugins
        if is_globally_excluded(finding):

            excluded_count += 1
            continue

        # Filtered as patching but are not
        if finding.plugin_id in PATCHING_EXCLUDED_PLUGIN_IDS:

            excluded_count += 1
            continue

        if is_legacy_software(finding):

            grouped_findings["unsupported_software"].append(finding)
            continue

        if is_patch_management(finding):

            grouped_findings["missing_security_patches"].append(finding)
            continue

    return OrganisationResult(
        grouped_findings=grouped_findings,
        excluded_findings=excluded_count,
    )