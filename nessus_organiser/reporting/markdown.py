"""
nessus_organiser.reporting.markdown

Generate Markdown reports from Finding objects.
"""

import re

from pathlib import Path

from nessus_organiser.models.finding import Finding

_LIST_ITEM_PATTERN = re.compile(r"^(\s*)([-*+]|\d+[.)])\s+(.*)$")
_HEADING_PATTERN = re.compile(r"^#{1,6}\s+")
_CODE_FENCE_PATTERN = re.compile(r"^\s*(`{3}|~{3})")


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


def generate_markdown(
    findings: list[Finding],
    output_path: Path,
    title: str,
    introduction: str | None = None,
    remediation_introduction: str | None = None,
    statistics: dict | None = None,
    ithc: bool = False,
) -> None:
    """
    Generate a Markdown report from Finding objects.

    Args:
        findings:
            Consultant-facing findings to include in
            the report.

        output_path:
            Destination path for the generated Markdown
            document.

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

    output: list[str] = []

    commentary_output = []
    remediation_output = []

    references = set()

    #---------------------------------------------------------------------------
    # Technical Commentary Section
    #---------------------------------------------------------------------------
    output.append(f"# {title}")
    output.append("")

    #---------------------------------------------------------------------------
    # Finding Introduction Section
    #---------------------------------------------------------------------------
    if introduction:
        output.append(_reflow_markdown(introduction))
        output.append("")

    #---------------------------------------------------------------------------
    # Overview Table
    #---------------------------------------------------------------------------
    if statistics:

        # Assessment Summary Table
        output.append(
            "The below table provides a summary of the identified "
            "patch-management-related vulnerabilities across the assessed "
            "environment:"
        )
        output.append("")

        output.append("| Metric | Value |")
        output.append("|--------|------:|")

        output.append(
            f"| Legacy Vulnerabilities | "
            f"{statistics['summary']['legacy_vulnerabilities']:,} |"
        )

        output.append(
            f"| Patch Vulnerabilities | "
            f"{statistics['summary']['patch_vulnerabilities']:,} |"
        )

        output.append(
            f"| Total Vulnerabilities | "
            f"{statistics['summary']['total_vulnerabilities']:,} |"
        )

        output.append("")
        output.append(
            "Counts are deduplicated by host and Nessus plugin ID. A finding "
            "detected on multiple ports of the same host is counted once; "
            "the same plugin on different hosts is counted separately."
        )
        output.append("")
    

    for finding in findings:

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

            commentary_output.append(
                "For ITHC reporting purposes, unsupported software findings "
                "associated with High and Critical severity vulnerabilities "
                "require particular consideration, as unresolved issues may "
                "need to be addressed through the organisation's remediation "
                "activities or documented within a Remediation Action Plan. "
                f"Of the {statistics['summary']['legacy_vulnerabilities']:,} "
                "unsupported software instances identified during testing, "
                f"{statistics['high_risk']['legacy_vulnerabilities']:,} "
                "had a CVSSv3 base score of 7.0 or greater. These findings "
                "relate to software that no longer receives vendor security "
                "updates, increasing the risk that affected systems remain "
                "exposed to known and future vulnerabilities."
            )

            commentary_output.append("")

        if ithc and finding.category == "missing_security_patches":

            commentary_output.append(
                "ITHC guidance requires organisations to demonstrate how "
                "identified High and Critical severity vulnerabilities have "
                "been remediated or are being managed through a documented "
                "remediation plan. Analysis of the identified missing security "
                "updates found that "
                f"{statistics['high_risk']['patch_vulnerabilities']:,} "
                "vulnerability instances had a CVSSv3 base score of 7.0 or "
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

                commentary_output.append(f"| {name} | {cvss} | {count:,} | {percentage}% |")

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
    
                commentary_output.append(f"| {name} | {cvss} | {count:,} | {percentage}% |")
    
            commentary_output.append("")

        references.update(finding.references)

    #---------------------------------------------------------------------------
    # Remediation Section
    #---------------------------------------------------------------------------
    remediation_output.append("# Remediation")
    remediation_output.append("")

    if remediation_introduction:
        remediation_output.append(_reflow_markdown(remediation_introduction))
        remediation_output.append("")

    for finding in findings:

        if not finding.solution:
            continue

        remediation_output.append(f"### {finding.title}")
        remediation_output.append("")

        remediation_output.append(_reflow_markdown(finding.solution))
        remediation_output.append("")

    #---------------------------------------------------------------------------
    # Print Commentary
    #---------------------------------------------------------------------------
    output.extend(commentary_output)
    output.append("")

    #---------------------------------------------------------------------------
    # Print Remediation
    #---------------------------------------------------------------------------
    output.extend(remediation_output)
    output.append("")

    #---------------------------------------------------------------------------
    # References Section
    #---------------------------------------------------------------------------
    if references:
        output.append("")
        output.append("# References")
        output.append("")

        for reference in sorted(references):

            output.append(f"- [{reference}]({reference})")

    with open(output_path, "w", encoding="utf-8",) as fp:
        fp.write("\n".join(output))