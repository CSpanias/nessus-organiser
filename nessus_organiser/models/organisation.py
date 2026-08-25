"""
nessus_organiser.models.organisation

Defines organisation results produced by finding organisation modules.
"""

from dataclasses import dataclass, field

from nessus_organiser.models.plugin import PluginFinding


@dataclass(slots=True)
class OrganisationResult:
    """
    Represents the result of organising Nessus plugin findings into reporting 
    categories.

    Attributes:
        grouped_findings:
            Findings organised by category.

        excluded_findings:
            Number of findings excluded during organisation.
    """

    grouped_findings: dict[str, list[PluginFinding]]
    excluded_findings: int = 0