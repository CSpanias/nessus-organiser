"""
nessus_organiser.parsing.nessus

Parse Nessus XML files and convert ReportItem elements into normalised
PluginFinding objects.

This module is the only component responsible for interacting with Nessus XML
structures. Downstream modules should consume PluginFinding objects and avoid
parsing XML directly.
"""

from pathlib import Path
import xml.etree.ElementTree as ET

from nessus_organiser.models.plugin import PluginFinding

#-------------------------------------------------------------------------------
# Constants
#-------------------------------------------------------------------------------

SEVERITY_MAP = {
    "0": "Informational",
    "1": "Low",
    "2": "Medium",
    "3": "High",
    "4": "Critical",
}


def load_nessus(path: Path) -> list[PluginFinding]:
    """
    Parse a Nessus XML file.

    Args:
        path:
            Path to the Nessus (.nessus) file.

    Returns:
        A list of PluginFinding objects extracted from
        all ReportItem elements contained within the file.

    Raises:
        FileNotFoundError:
            If the supplied file does not exist.

        ET.ParseError:
            If the Nessus file is malformed XML.
    """

    findings: list[PluginFinding] = []

    tree = ET.parse(path)
    root = tree.getroot()

    for report_host in root.findall(".//ReportHost"):

        host = report_host.attrib.get("name", "")

        findings.extend(
            parse_report_host(
                report_host=report_host,
                host=host,
            )
        )

    return findings


def parse_report_host(report_host: ET.Element, host: str) -> list[PluginFinding]:
    """
    Parse all ReportItem elements associated with a
    Nessus ReportHost.

    Args:
        report_host:
            XML ReportHost element.

        host:
            Hostname or IP address extracted from the
            ReportHost name attribute.

    Returns:
        A list of PluginFinding objects.
    """

    findings: list[PluginFinding] = []

    for report_item in report_host.findall("ReportItem"):

        findings.append(
            parse_report_item(
                report_item=report_item,
                host=host,
            )
        )

    return findings


def _safe_float(
    value: str | None,
) -> float | None:

    if not value:
        return None

    try:
        return float(value)

    except ValueError:
        return None


def parse_report_item(
    report_item: ET.Element,
    host: str,
) -> PluginFinding:
    """
    Convert a Nessus ReportItem element into a
    PluginFinding object.

    Args:
        report_item:
            Nessus ReportItem XML element.

        host:
            Hostname or IP associated with the finding.

        msft:
            Microsoft bulletin identifiers associated with the finding.

    Returns:
        A populated PluginFinding instance.
    """

    severity = SEVERITY_MAP.get(
        report_item.attrib.get("severity", "0"),
        "Informational",
    )

    port = report_item.attrib.get("port")

    # Patching Vulnerabilities
    mskb = [
        element.text.strip()
        for element in report_item.findall("mskb")
        if element.text
    ]

    patch_publication_date = (report_item.findtext("patch_publication_date"))

    msft = [
        node.text
        for node in report_item.findall("msft")
        if node.text
    ]

    return PluginFinding(
        plugin_id=report_item.attrib.get("pluginID", ""),
        plugin_name=report_item.attrib.get("pluginName", ""),
        host=host,
        port=int(port) if port else None,
        protocol=report_item.attrib.get("protocol"),
        severity=severity,
        plugin_output=_extract_text(report_item, "plugin_output"),
        synopsis=_extract_text(report_item, "synopsis"),
        description=_extract_text(report_item, "description"),
        solution=_extract_text(report_item, "solution"),
        # TODO: Delete or add!
        #see_also=_extract_list(report_item, "see_also"),
        plugin_family=report_item.attrib.get("pluginFamily"),
        service=report_item.attrib.get("svc_name"),
        cves=_extract_cves(report_item),
        unsupported_by_vendor = (report_item.findtext("unsupported_by_vendor") == "true"),
        mskb=mskb,
        patch_publication_date=patch_publication_date,
        msft=msft,
        cvss3_base_score=_safe_float(report_item.findtext("cvss3_base_score")),
        cvss_base_score=_safe_float(report_item.findtext("cvss_base_score")),
    )


def _extract_text(
    parent: ET.Element,
    tag: str,
) -> str:
    """
    Extract text from a child XML element.

    Args:
        parent:
            Parent XML element.

        tag:
            Child tag name.

    Returns:
        Element text if present, otherwise an empty string.
    """

    element = parent.find(tag)

    if element is None:
        return ""

    return (element.text or "").strip()


def _extract_list(parent: ET.Element, tag: str) -> list:
    """
    Extract all matching child element values.

    Args:
        parent:
            Parent XML element.

        tag:
            Child tag name.

    Returns:
            List containing the text value of each matching
            child element.
    """

    values: list[str] = []

    for element in parent.findall(tag):

        if element.text:
            values.append(element.text.strip())

    return values


def _extract_cves(report_item: ET.Element) -> list:
    """
    Extract CVE identifiers from a Nessus ReportItem.

    Args:
        report_item:
            Nessus ReportItem XML element.

    Returns:
        A list of CVE identifiers associated with the plugin finding.
    """

    cves: list[str] = []

    for element in report_item.findall("cve"):

        if element.text:
            cves.append(element.text.strip())

    return cves