"""
nessus_organiser.reporting.markdown

Build Markdown for report content and clipboard copying.
"""

import re

from typing import NamedTuple

from nessus_organiser.models.finding import Finding

_LIST_ITEM_PATTERN = re.compile(r"^(\s*)([-*+]|\d+[.)])\s+(.*)$")
_HEADING_PATTERN = re.compile(r"^#{1,6}\s+")
_CODE_FENCE_PATTERN = re.compile(r"^\s*(`{3}|~{3})")


class ReportSections(NamedTuple):
    title: str
    overview: str
    commentary: list[tuple[Finding, str]]
    remediation_introduction: str
    remediation: list[tuple[Finding, str]]
    references: str


def escape_markdown_text(value: str) -> str:
    """Keep scanner-provided text literal in Markdown output."""
    value = " ".join(value.splitlines())
    return re.sub(r"([\\`*_{}\[\]()#+.!|<>-])", r"\\\1", value)


def _reflow_markdown(text: str | None) -> str:
    """Normalise hard-wrapped prose into flowing paragraphs."""

    if not text:
        return ""

    lines = text.splitlines()

    output: list[str] = []
    paragraph: list[str] = []
    list_item: dict | None = None
    in_fence = False

    def flush_paragraph() -> None:
        if paragraph:
            output.append(" ".join(paragraph))
            paragraph.clear()

    def flush_list_item() -> None:
        nonlocal list_item
        if list_item is not None:
            output.append(list_item["text"])
            list_item = None

    for line in lines:

        if _CODE_FENCE_PATTERN.match(line):
            flush_paragraph()
            flush_list_item()
            in_fence = not in_fence
            output.append(line.rstrip())
            continue

        if in_fence:
            output.append(line.rstrip())
            continue

        stripped = line.strip()

        if not stripped:
            flush_paragraph()
            flush_list_item()
            output.append("")
            continue

        if _HEADING_PATTERN.match(stripped):
            flush_paragraph()
            flush_list_item()
            output.append(stripped)
            continue

        list_match = _LIST_ITEM_PATTERN.match(line)
        if list_match:

            indent = len(list_match.group(1))
            marker = list_match.group(2)
            content = list_match.group(3)

            flush_paragraph()
            flush_list_item()

            list_item = {
                "indent": indent,
                "text": f"{' ' * indent}{marker} {content.strip()}",
            }
            continue

        if list_item is not None:

            line_indent = len(line) - len(line.lstrip(" "))

            if line_indent > list_item["indent"]:
                list_item["text"] += " " + stripped
            else:
                flush_list_item()
                paragraph.append(stripped)

            continue

        paragraph.append(stripped)

    flush_paragraph()
    flush_list_item()

    return "\n".join(output)


def build_report_sections(
    findings: list[Finding],
    title: str,
    introduction: str | None = None,
    remediation_introduction: str | None = None,
    statistics: dict | None = None,
    ithc: bool = False,
) -> ReportSections:
    """
    Build the shared Markdown sections used by report renderers.

    Args:
        findings:
            Consultant-facing findings to include in
            the report.

        title:
            Report title.

        introduction:
            Optional introductory text displayed before
            the finding sections.

        remediation_introduction:
            Optional introductory text displayed before
            the remediation sections.

        statistics:
            Optional assessment statistics displayed within the report. These 
            may include patching and legacy vulnerability counts, severity 
            distributions, and other summary information generated from the 
            identified findings.
    """

    overview: list[str] = []
    commentary_sections: list[tuple[Finding, str]] = []
    remediation_sections: list[tuple[Finding, str]] = []

    references = set()

    #---------------------------------------------------------------------------
    # Finding Introduction Section
    #---------------------------------------------------------------------------
    if introduction:
        overview.append(_reflow_markdown(introduction))
        overview.append("")

    #---------------------------------------------------------------------------
    # Overview Table
    #---------------------------------------------------------------------------
    if statistics:

        severity_distribution = statistics.get("severity_distribution", [])
        if any(count for _, count, _ in severity_distribution):
            overview.append(
                "The following table summarises the CVSSv3 severity "
                "distribution of missing security patch vulnerabilities:"
            )
            overview.append("")
            overview.append(
                "| Severity | Count | Percentage of Patch Vulnerabilities |"
            )
            overview.append("|----------|------:|-------------------------------------:|")

            for severity, count, percentage in severity_distribution:
                if count:
                    overview.append(
                        f"| {severity} | {count:,} | {percentage}% |"
                    )

            overview.append("")

        # Assessment Summary Table
        overview.append(
            "The below table provides a summary of the identified "
            "patch-management-related vulnerabilities across the assessed "
            "environment:"
        )
        overview.append("")

        overview.append("| Metric | Value |")
        overview.append("|--------|------:|")

        overview.append(
            f"| Legacy Vulnerabilities | "
            f"{statistics['summary']['legacy_vulnerabilities']:,} |"
        )

        overview.append(
            f"| Patch Vulnerabilities | "
            f"{statistics['summary']['patch_vulnerabilities']:,} |"
        )

        overview.append(
            f"| Total Vulnerabilities | "
            f"{statistics['summary']['total_vulnerabilities']:,} |"
        )

        overview.append("")
        overview.append(
            "**Note**: Counts are deduplicated by host and Nessus plugin ID. A finding "
            "detected on multiple ports of the same host is counted once; "
            "the same plugin on different hosts is counted separately."
        )
        overview.append("")
    

    for finding in findings:
        commentary_output: list[str] = []

        #-----------------------------------------------------------------------
        # Vulnerability Title Section
        #-----------------------------------------------------------------------
        commentary_output.append(f"### {finding.title}")
        commentary_output.append("")

        #-----------------------------------------------------------------------
        # Vulnerability Evidence Section
        #-----------------------------------------------------------------------
        if finding.commentary_evidence:

            commentary_output.append(_reflow_markdown(finding.commentary_evidence))
            commentary_output.append("")

        if finding.commentary:

            commentary_output.append(_reflow_markdown(finding.commentary))
            commentary_output.append("")

        #-----------------------------------------------------------------------
        # ITHC STATISTICS
        #-----------------------------------------------------------------------

        if ithc and finding.category == "unsupported_software":
            legacy_count = statistics["summary"]["legacy_vulnerabilities"]
            instance_label = "instance" if legacy_count == 1 else "instances"

            commentary_output.append(
                "For ITHC reporting purposes, unsupported software findings "
                "associated with High and Critical severity vulnerabilities "
                "require particular consideration, as unresolved issues may "
                "need to be addressed through the organisation's remediation "
                "activities or documented within a Remediation Action Plan. "
                f"Of the {legacy_count:,} unsupported software {instance_label} "
                "identified during testing, "
                f"{statistics['high_risk']['legacy_vulnerabilities']:,} "
                "had a CVSSv3 base score of 7.0 or greater. These findings "
                "relate to software that no longer receives vendor security "
                "updates, increasing the risk that affected systems remain "
                "exposed to known and future vulnerabilities."
            )

            commentary_output.append("")

        if ithc and finding.category == "missing_security_patches":
            high_risk_count = statistics["high_risk"]["patch_vulnerabilities"]
            instance_label = "instance" if high_risk_count == 1 else "instances"

            commentary_output.append(
                "ITHC guidance requires organisations to demonstrate how "
                "identified High and Critical severity vulnerabilities have "
                "been remediated or are being managed through a documented "
                "remediation plan. Analysis of the identified missing security "
                "updates found that "
                f"{high_risk_count:,} vulnerability {instance_label} "
                "had a CVSSv3 base score of 7.0 or "
                "greater. These vulnerabilities represent the highest-risk "
                "subset of the identified patching issues and should be "
                "prioritised for remediation to reduce exposure to publicly "
                "known attack techniques and vendor-addressed security "
                "weaknesses."
            )

            commentary_output.append("")

        #-----------------------------------------------------------------------
        # Legacy Frequency Table
        #-----------------------------------------------------------------------
        if finding.category == "unsupported_software":

            commentary_output.append(
                "The following table shows the most frequently identified "
                "unsupported software components, alongside their associated "
                "CVSSv3 base scores and the percentage each represents of the "
                "total unsupported software findings identified during testing:"
            )
            commentary_output.append("")

            commentary_output.append("| Vulnerability | CVSSv3 | Count | Percentage |")
            commentary_output.append("|---------------|-------:|-------|-----------:|")

            for name, cvss, count, percentage in (statistics["top_legacy_findings"]):

                safe_name = escape_markdown_text(str(name))
                score = cvss if cvss is not None else "N/A"
                commentary_output.append(f"| {safe_name} | {score} | {count:,} | {percentage}% |")

            commentary_output.append("")

        #-----------------------------------------------------------------------
        # Patching Frequency Table
        #-----------------------------------------------------------------------
        if finding.category == "missing_security_patches":

            commentary_output.append(
                "The following table shows the most frequently identified "
                "missing security updates, alongside their associated CVSSv3 "
                "base scores and the percentage each represents of the total "
                "patching vulnerabilities identified during testing:"
            )
            commentary_output.append("")
    
            commentary_output.append("| Vulnerability | CVSSv3 | Count | Percentage |")
            commentary_output.append("|---------------|-------:|-------|-----------:|")
    
            for name, cvss, count, percentage in (statistics["top_patch_findings"]):
    
                safe_name = escape_markdown_text(str(name))
                score = cvss if cvss is not None else "N/A"
                commentary_output.append(f"| {safe_name} | {score} | {count:,} | {percentage}% |")
    
            commentary_output.append("")

        references.update(finding.references)
        commentary_sections.append((finding, "\n".join(commentary_output).strip()))

    #---------------------------------------------------------------------------
    # Remediation Section
    #---------------------------------------------------------------------------
    for finding in findings:

        if not finding.solution:
            continue

        remediation_sections.append((
            finding,
            f"### {finding.title}\n\n{_reflow_markdown(finding.solution)}",
        ))

    reference_output: list[str] = []
    if references:
        for reference in sorted(references):
            reference_output.append(f"- [{reference}]({reference})")

    return ReportSections(
        title=title,
        overview="\n".join(overview).strip(),
        commentary=commentary_sections,
        remediation_introduction=_reflow_markdown(remediation_introduction),
        remediation=remediation_sections,
        references="\n".join(reference_output),
    )


def format_markdown(sections: ReportSections) -> str:
    output = [f"# {sections.title}"]
    if sections.overview:
        output.append(sections.overview)
    output.extend(text for _, text in sections.commentary)
    if sections.remediation or sections.remediation_introduction:
        output.append("# Remediation")
        if sections.remediation_introduction:
            output.append(sections.remediation_introduction)
        output.extend(text for _, text in sections.remediation)
    if sections.references:
        output.extend(["# References", sections.references])
    return "\n\n".join(output) + "\n"
