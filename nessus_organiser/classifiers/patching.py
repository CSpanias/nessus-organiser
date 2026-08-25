"""
nessus_organiser.organising.patch_management

Helpers used to identify patch-management-related vulnerabilities from Nessus 
plugin metadata.
"""

from nessus_organiser.models.plugin import PluginFinding
from nessus_organiser.rules.patching import (
    PATCH_MANAGEMENT_RULES,
    PATCHING_PLUGIN_IDS,
)


def is_patch_management(
    plugin: PluginFinding,
) -> bool:
    """
    Determine whether a Nessus plugin finding is related to patch management.

    A finding is considered patch-management-related when it matches known 
    patch-management plugin identifiers or contains indicators of missing 
    security updates, vendor patches, software upgrades, or fixed versions.

    Args:
        plugin:
            Nessus plugin finding to evaluate.

    Returns:
        True if the finding relates to a vendor patch or security update; 
        otherwise False.
    """

    # Define filtering strings
    synopsis = (plugin.synopsis or "").lower()
    solution = (plugin.solution or "").lower()
    plugin_output = (plugin.plugin_output or "").lower()
    description = (plugin.description or "").lower()

    if plugin.plugin_id in PATCHING_PLUGIN_IDS:
        return True

    has_patch_wording = (
        any(
            indicator in synopsis
            for indicator in PATCH_MANAGEMENT_RULES["synopsis"]
        )
        or any(
            indicator in solution
            for indicator in PATCH_MANAGEMENT_RULES["solution"]
        )
        or any(
            indicator in plugin_output
            for indicator in PATCH_MANAGEMENT_RULES["plugin_output"]
        )
    )

    if has_patch_wording:
        return True

    if any(
        indicator in description
        for indicator in PATCH_MANAGEMENT_RULES["description"]
    ):
        return True

    return False