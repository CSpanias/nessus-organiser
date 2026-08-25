"""
nessus_organiser.findings.factory

Build consultant-facing Finding objects from
organised Nessus findings.
"""

from nessus_organiser.models.finding import Finding
from nessus_organiser.models.plugin import PluginFinding
from nessus_organiser.common.counting import count_hosts, count_services


def build_finding(
    category: str,
    findings: list[PluginFinding],
    definition: dict,
    evidence_builder=None,
) -> Finding:
    """
    Build a consultant-facing Finding object from a TLS category and its 
    associated Nessus findings.

    Args:
        category:
            TLS category identifier.

        findings:
            Nessus findings contained within the
            category.

        definition:
            YAML finding definition.

        evidence_builder:
            Optional callable used to generate evidence statements from the 
            supplied findings.

    Returns:
        Populated Finding object.
    """

    evidence = []

    if evidence_builder:
        evidence = evidence_builder(findings)

    return Finding(
        id=definition["id"],
        title=definition["title"],
        category=category,
        severity=definition["severity"],
        cvss_score=None,
        instances=len(findings),
        hosts=count_hosts(findings),
        services=count_services(findings),
        evidence=evidence,
        references=definition.get("references", []),
        commentary=definition.get("commentary"),
        solution=definition.get("solution"),
        affected_plugins=findings,
    )


def build_findings(
    grouped_findings: dict[str, list[PluginFinding]],
    content: dict,
    evidence_builder=None,
) -> list:
    """
    Build Finding objects for all organised categories.

    Args:
        grouped_findings:
            Findings organised by category.

        content:
            Loaded finding definitions.

        evidence_builder:
            Optional callable used to generate evidence statements for findings.

    Returns:
        Generated Finding objects.
    """

    findings: list[Finding] = []

    for category, category_findings in grouped_findings.items():

        if not category_findings:
            continue

        definition = content.get(category)

        if definition is None:
            continue

        findings.append(
            build_finding(
                category=category,
                findings=category_findings,
                definition=definition,
                evidence_builder=evidence_builder,
            )
        )

    return findings