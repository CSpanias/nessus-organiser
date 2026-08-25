"""
nessus_organiser.common.exclusions

Shared exclusion helpers used across all organisers.
"""

from nessus_organiser.models.plugin import PluginFinding

GLOBAL_EXCLUDED_PLUGIN_IDS = {

    # Nessus
    "57033", # Microsoft Patch Bulletin Feasibility Check

    # Patching
    "38153", # Microsoft Windows Summary of Missing Patches
    "66334", # Patch Report
    "60119", # Microsoft Windows SMB Share Permissions Enumeration
    "103569", # Windows Defender Signature Definition Check
}


def is_globally_excluded(
    plugin: PluginFinding,
) -> bool:
    """
    Determine whether a plugin should be excluded from all classification and 
    reporting.
    """

    return (plugin.plugin_id in GLOBAL_EXCLUDED_PLUGIN_IDS)

