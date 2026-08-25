"""
nessus_organiser.classifiers.legacy

Classification helpers for identifying legacy and unsupported software findings.
"""

from nessus_organiser.models.plugin import PluginFinding
from nessus_organiser.rules.patching import LEGACY_PLUGIN_IDS

def is_legacy_software(
    plugin: PluginFinding,
) -> bool:
    """
    Determine whether a Nessus plugin finding relates to unsupported or 
    end-of-life software.

    Args:
        plugin:
            Nessus plugin finding to evaluate.

    Returns:
        True if the affected software or operating system is no longer 
        supported by the vendor; otherwise False.
    """

    if plugin.unsupported_by_vendor:
        return True

    if plugin.plugin_id in LEGACY_PLUGIN_IDS:
        return True

    return False