"""
nessus_organiser.models.plugin

Defines the PluginFinding model used throughout the application.

The Nessus parser is responsible for converting raw XML ReportItem entries into
PluginFinding objects. All downstream modules should consume this model rather
than interacting directly with Nessus XML.
"""

from dataclasses import dataclass, field


@dataclass(slots=True)
class PluginFinding:
    """
    Represents a single Nessus plugin finding.

    Attributes:
        plugin_id:
            Nessus plugin identifier.

        plugin_name:
            Human-readable plugin name.

        host:
            Target hostname or IP address.

        port:
            Affected port.

        protocol:
            Protocol associated with the port
            (e.g. tcp, udp).

        severity:
            Nessus severity rating.

        plugin_output:
            Raw plugin output produced by Nessus.

        synopsis:
            Vulnerability synopsis.

        description:
            Detailed vulnerability description.

        solution:
            Vendor or Nessus remediation guidance.

        cves:
            Associated CVEs reported by the plugin.

        cpe:
            Common Platform Enumeration (CPE) identifiers associated with the 
            affected software, operating system, application, or component. 
            These may be used for product identification, categorisation, and
            reporting purposes.

        see_also:
            Reference URLs supplied by the plugin.

        plugin_family:
            Nessus plugin family.

        unsupported_by_vendor:
            Indicates whether the affected software, operating system, or
            component is no longer supported by the vendor and may no longer 
            receive security updates.
    """

    plugin_id: str
    plugin_name: str

    host: str

    port: int | None
    protocol: str | None
    service: str | None

    severity: str
 
    plugin_output: str
    plugin_family: str | None = None

    synopsis: str | None = None
    description: str | None = None
    solution: str | None = None

    cvss3_base_score: float | None = None
    cvss_base_score: float | None = None

    # Legacy Software Vulnerabilities
    unsupported_by_vendor: bool = False

    # Patching Vulnerabilities
    mskb: list[str] = field(default_factory=list)
    patch_publication_date: str | None = None
    msft: list[str] = field(default_factory=list)
    

    cves: list[str] = field(default_factory=list)
    cpe: list[str] = field(default_factory=list)
    # TODO: Produces a list of URLs
    #see_also: list[str] = field(default_factory=list)

    