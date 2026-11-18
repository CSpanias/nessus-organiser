"""
nessus_organiser.analysis.ssh

Apply SSH-specific analysis and contextualisation to consultant-facing
findings.
"""

from nessus_organiser.models.finding import Finding


def analyse_ssh_finding(
    finding: Finding,
    scope: str,
    content: dict,
) -> Finding:
    """
    Apply SSH-specific analysis and contextualisation to a generated finding.

    This currently resolves scope-dependent severity ratings defined within
    content definitions.

    Args:
        finding:
            Finding to analyse.

        scope:
            Assessment environment. Expected values are 'internal' or
            'external'.

        content:
            Loaded SSH content definitions.

    Returns:
        Analysed finding.
    """

    finding = _apply_scope(finding=finding, scope=scope)

    return finding


def _apply_scope(
    finding: Finding,
    scope: str,
) -> Finding:
    """
    Apply scope-specific reporting adjustments.

    This currently resolves scope-dependent severity ratings defined within
    content definitions.
    """

    if isinstance(finding.severity, dict):
        finding.severity = finding.severity[scope]

    return finding