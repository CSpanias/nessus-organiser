"""
nessus_organiser.analysis.patch_management

Apply patch-management-specific analysis and contextualisation to 
consultant-facing findings.
"""
from collections import Counter

from nessus_organiser.models.finding import Finding
from nessus_organiser.models.plugin import PluginFinding


SEVERITY_ORDER = (
    "Critical",
    "High",
    "Medium",
    "Low",
)


def analyse_patch_management_finding(
    finding: Finding,
    scope: str,
    content: dict,
) -> Finding:
    """
    Apply patch-management-specific analysis and contextualisation to a 
    generated finding.

    This function performs scope-aware adjustments and evidence-aware 
    refinements to produce consultant-facing report content.

    Args:
        finding:
            Finding to analyse.

        scope:
            Assessment environment. Expected values are 'internal' or 
            'external'.

        content:
            Loaded patch management content definitions.

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
        finding.severity = (finding.severity[scope])

    return finding


def _deduplicate_findings(
    findings: list[PluginFinding],
) -> list:
    """
    Deduplicate findings by host and plugin ID.
    """

    unique = {}

    for finding in findings:

        unique.setdefault((finding.host, finding.plugin_id), finding)

    return list(unique.values())


def _get_percentage(
    count: int,
    total: int,
) -> float:
    """
    Calculate a percentage.
    """

    if not total:
        return 0

    return round((count / total) * 100, 2)


def _build_frequency_table(
    data: dict,
    total: int,
) -> list[tuple[str, float | None, int, float]]:
    """
    Build a frequency table containing names, CVSS scores,
    counts, and percentages.
    """

    results = []

    sorted_items = sorted(
        data.items(),
        key=lambda item: item[1]["count"],
        reverse=True,
    )

    for name, info in sorted_items[:10]:

        count = info["count"]

        results.append(
            (
                name,
                info["cvss"],
                count,
                _get_percentage(count=count, total=total),
            )
        )

    return results


def build_patch_management_statistics(
    grouped_findings: dict,
) -> dict:
    """
    Build patch-management report statistics.

    Args:
        grouped_findings:
            Organised patch-management findings.

    Returns:
        Dictionary containing summary metrics, severity distributions, and top 
        finding frequency statistics for the generated patch management report.
    """

    patch_findings = _deduplicate_findings(
        grouped_findings["missing_security_patches"]
    )

    print("\n=== PATCH FINDINGS ===\n")

    for finding in sorted(
        patch_findings,
        key=lambda x: (
            x.plugin_id,
            x.host,
        ),
    ):
        print(
            f"{finding.host:<15} "
            f"{finding.plugin_id:<8} "
            f"{finding.plugin_name}"
        )

    print(
        f"\nTotal Patch Findings: "
        f"{len(patch_findings)}"
    )

    legacy_findings = _deduplicate_findings(
        grouped_findings["unsupported_software"]
    )

    patch_count = len(patch_findings)
    legacy_count = len(legacy_findings)
    total_count = patch_count + legacy_count

    #-----------------------------------------------------------------------
    # Severity Distribution
    #-----------------------------------------------------------------------
    severity_counter = Counter()

    for finding in patch_findings:

        score = (finding.cvss3_base_score or 0.0)

        if score >= 9.0:
            severity_counter["Critical"] += 1

        elif score >= 7.0:
            severity_counter["High"] += 1

        elif score >= 4.0:
            severity_counter["Medium"] += 1

        else:
            severity_counter["Low"] += 1

    severity_distribution = []

    for severity in SEVERITY_ORDER:

        count = severity_counter.get(severity, 0)
        percentage = _get_percentage(count=count, total=patch_count)
        severity_distribution.append((severity, count, percentage))

    #-----------------------------------------------------------------------
    # Top Unsupported Software
    #-----------------------------------------------------------------------
    legacy_data = {}

    for finding in legacy_findings:

        if finding.plugin_name not in legacy_data:

            legacy_data[finding.plugin_name] = {
                "count": 0,
                "cvss": finding.cvss3_base_score,
            }

        legacy_data[finding.plugin_name]["count"] += 1

    #---------------------------------------------------------------------------
    # Top Missing Security Updates
    #---------------------------------------------------------------------------
    patch_data = {}

    for finding in patch_findings:

        if finding.plugin_name not in patch_data:

            patch_data[finding.plugin_name] = {
                "count": 0,
                "cvss": finding.cvss3_base_score,
            }

        patch_data[finding.plugin_name]["count"] += 1

    top_legacy_findings = _build_frequency_table(
        data=legacy_data,
        total=legacy_count,
    )

    top_patch_findings = _build_frequency_table(
        data=patch_data,
        total=patch_count,
    )

    return {
        "summary": {
            "patch_vulnerabilities": patch_count,
            "legacy_vulnerabilities": legacy_count,
            "total_vulnerabilities": total_count,
        },
        "severity_distribution": severity_distribution,
        "top_patch_findings": top_patch_findings,
        "top_legacy_findings": top_legacy_findings,
    }