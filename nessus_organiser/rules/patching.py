"""
nessus_organiser.rules.patch_management

Rules used to identify unsupported or end-of-life software.
"""

#-------------------------------------------------------------------------------
# Patching 
#-------------------------------------------------------------------------------
PATCH_MANAGEMENT_RULES = {

    "synopsis": {
        "vendor-supplied security patch",
        "missing security update",
        "missing a security update",
    },

    "solution": {
        "apply security update",
        "apply updates",
        "upgrade to",
        "apply the appropriate patch",
        "upgrade to the relevant fixed version",
    },

    "plugin_output": {
        "fixed version",
        "installed version",
        "the remote host is missing",
    },
    "description": {
        "missing security update",
        "missing security updates",
        "missing a security update",
        "security updates",
        },
}

PATCHING_PLUGIN_IDS = {
    "324932", # 7-Zip <= 26.02 Mark-of-the-Web Bypass (CVE-2026-58052),
    "134942", # Microsoft Windows Type 1 Font Parsing Remote Code Execution Vulnerability (ADV200006)
    "128764", # CredSSP Remote Code Execution Vulnerability March 2018 Security Update
    "134204", # MS15-124: Cumulative Security Update for Internet Explorer (CVE-2015-6161) (3125869)
    "146272", # SAP BusinessObjects Business Intelligence Platform SSRF Vulnerability (direct check)
    "90510",  # MS16-047: Security Update for SAM and LSAD Remote Protocols (3148527) (Badlock) (uncredentialed check)
}

PATCHING_EXCLUDED_PLUGIN_IDS = {
    # Registry / GPO / mitigation checks
    "136946",  # CVE-2017-8529 protection registry key
    "87252",   # MS KB3123040: Improperly Issued Digital Certificates Could Allow Spoofing
    "87313",   # MS KB3119884: Improperly Issued Digital Certificates Could Allow Spoofing
    "166555",  # EnableCertPaddingCheck mitigation registry check
}

#-------------------------------------------------------------------------------
# Legacy
#-------------------------------------------------------------------------------
LEGACY_PLUGIN_IDS = {
    "156860",  # Apache Log4j 1.x Multiple Vulnerabilities
}