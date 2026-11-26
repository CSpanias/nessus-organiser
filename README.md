# nessus-organiser

A Python-based framework for transforming raw Nessus vulnerability
data into consultant-facing assessment reports.

Nessus Organiser automates the analysis, categorisation, and report
generation of common vulnerability assessment workstreams, enabling
consultants to convert large volumes of Nessus findings into concise,
review-ready reporting outputs.

Currently supported report types include:

- TLS Reviews
- Patch Management Reviews
- SSH Reviews
- Internal finding closure reviews

## Installation

```bash
# Install UV
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install nessus-organiser via UV
uv tool install git+https://github.com/CSpanias/nessus-organiser

# Verify installation
nessus-organiser -h

# Update
uv tool upgrade nessus-organiser
```

## Features

### Nessus Processing

- Parse Nessus (`.nessus`) files directly
- Show scan parsing and report-generation progress in interactive terminals
- Extract host, service, plugin, CVSS, and reference information
- Deduplicate findings where appropriate
- Generate reporting statistics automatically
- Generate technical commentary and remediation guidance
- Produce consultant-ready HTML reports with copyable Markdown

### TLS Reviews

- Identify TLS-related vulnerabilities
- Consolidate related findings into root-cause observations
- Group findings, remediation and severity guidance into copyable sections
- List the associated Nessus plugin IDs under each severity heading
- Copy each severity finding's plugin IDs or justification separately
- Include TLS references in the remediation section
- Include severity justifications for internal assessments
- Preserve plugin 51893's scanner severity for external assessments when it is
  higher than the existing weak-cipher group rating

### Patch Management Reviews

- Identify missing security updates
- Identify unsupported and end-of-life software
- Calculate vulnerability statistics
- Group findings and remediation into copyable sections
- Include patch management references in the remediation section

### SSH Reviews

- Identify SSH cryptographic hardening weaknesses
- Consolidate related findings into root-cause observations

### Finding Closure Reviews

- Suggest internal-scope closure justifications for selected Nessus plugin IDs
- Keep closure decisions subject to manual risk and policy review
- Include each plugin's references alongside its closure justification
- Copy each closure justification without its evidence or references
- Currently recognise plugins 10114 (ICMP Timestamp Request Remote Date
  Disclosure), 10884 (NTP Server Detection), and 35371 (DNS hostname.bind
  hostname disclosure) for internal assessments only

### Reporting

- Generate self-contained, searchable HTML reports that work offline
- Copy report sections or the complete report as Markdown
- Deduplicate references
- Produce reusable reporting outputs
- Generate one tabbed HTML report containing all applicable report types
- Parse the input once when generating all report types

## Supported Plugin IDs

The tables below list the Nessus plugin IDs recognised by each report module.
TLS and SSH reviews are driven by explicit plugin IDs. Patch Management
Reviews are primarily keyword-driven, so their table lists only the IDs that
are matched or excluded explicitly rather than an exhaustive list.

### SSH Reviews

| Plugin ID | Finding |
|-----------|---------|
| 187315 | Terrapin Prefix Truncation Weakness (CVE-2023-48795) |
| 71049 | Weak MAC Algorithms Enabled |
| 153953 | Weak Key Exchange Algorithms Enabled |
| 70658 | CBC Mode Ciphers Enabled |
| 90317 | Weak Algorithms Supported |
| 10882 | Protocol Version 1 Session Key Retrieval |

### TLS Reviews

| Category | Plugin IDs |
|----------|------------|
| Deprecated SSL Support | 20007, 78447, 78479, 89058 |
| Deprecated TLS Support | 104743, 157288, 42880 |
| Weak Cipher Suites | 26928, 65821, 42873, 81606, 51893 |
| Invalid Certificate Configuration | 51192, 57582, 45410, 45411, 15901, 56284 |
| Weak Certificate Cryptography | 35291, 69551, 60108, 86067 |
| Weak Diffie-Hellman Parameters | 83875 |
| Weak Diffie-Hellman Key Validation | 53360 |
| Anonymous Cipher Suites | 31705 |

### Patch Management Reviews

Patch Management classification matches findings whose synopsis, solution,
plugin output, or description contains the following indicators:

| Field | Indicators |
|-------|------------|
| Synopsis | vendor-supplied security patch; missing security update; missing a security update |
| Solution | apply security update; apply updates; upgrade to; upgrade firmware; apply the appropriate patch; upgrade to the relevant fixed version; update .net core; update to .net core; update asp.net core |
| Plugin Output | fixed version; installed version; the remote host is missing |
| Description | missing security update; missing security updates; missing a security update; security updates |

In addition, the following plugin IDs are matched explicitly:

| Plugin ID | Description |
|-----------|-------------|
| 324932 | 7-Zip <= 26.02 Mark-of-the-Web Bypass (CVE-2026-58052) |
| 134942 | Microsoft Windows Type 1 Font Parsing Remote Code Execution Vulnerability (ADV200006) |
| 128764 | CredSSP Remote Code Execution Vulnerability March 2018 Security Update |
| 134204 | MS15-124: Cumulative Security Update for Internet Explorer (CVE-2015-6161) (3125869) |
| 146272 | SAP BusinessObjects Business Intelligence Platform SSRF Vulnerability (direct check) |
| 90510 | MS16-047: Security Update for SAM and LSAD Remote Protocols (3148527) (Badlock) (uncredentialed check) |

The following IDs are classified as unsupported/end-of-life software:

| Plugin ID | Description |
|-----------|-------------|
| 156103 | Apache Log4j 1.2 JMSAppender Remote Code Execution |
| 156860 | Apache Log4j 1.x Multiple Vulnerabilities |

The following IDs are excluded from reporting:

| Plugin ID | Description |
|-----------|-------------|
| 57033 | Microsoft Patch Bulletin Feasibility Check |
| 38153 | Microsoft Windows Summary of Missing Patches |
| 66334 | Patch Report |
| 60119 | Microsoft Windows SMB Share Permissions Enumeration |
| 103569 | Windows Defender Signature Definition Check |
| 136946 | CVE-2017-8529 protection registry key |
| 87252 | MS KB3123040: Improperly Issued Digital Certificates Could Allow Spoofing |
| 87313 | MS KB3119884: Improperly Issued Digital Certificates Could Allow Spoofing |

## Usage

```bash
# Generate a TLS Review
nessus-organiser tls -S internal internal.nessus

# Generate a Patch Management Report
nessus-organiser patching -S internal internal.nessus

# Generate an SSH Report
nessus-organiser ssh -S internal internal.nessus

# Generate one combined report, including closure review when applicable
nessus-organiser all -S internal internal.nessus

# Exclude findings affecting the testing VM (repeat --exclude for more IPs)
nessus-organiser all -S internal --exclude 192.0.2.10 internal.nessus

# Generate only a closure review
nessus-organiser closure -S internal internal.nessus

# List supported plugin IDs for every module
nessus-organiser --list-plugin-ids

# List plugin IDs for a single module
nessus-organiser ssh --list-plugin-ids
nessus-organiser tls --list-plugin-ids
nessus-organiser patching --list-plugin-ids
nessus-organiser closure --list-plugin-ids
```

`-S` / `--scope` is required for every scan command and must be either
`internal` or `external`. The closure report contains suggestions for
manual review, not automatic changes to findings. Plugins 10114, 10884 and
35371 have internal justifications only; no external closure suggestions are
generated for them. A closure report is created only when a rule applies to the
selected scope and at least one matching plugin is found.

Patch Management reports show severity distribution for all vulnerabilities
in the overview, with separate distributions for unsupported software and
missing security patches in their respective finding sections.

Use `--exclude IP` to omit all findings for a host IP from a scan. The option
can be repeated and matches either the Nessus report host name or its
`host-ip` property.

Reports are created in a `nessus-organiser` directory under the current
working directory. Filenames include the local date and time, for example
`tls-review-20261123-215356.html`. Runs never overwrite existing
reports, including if filenames collide. A report and its summary table are
omitted without a message when there are no applicable findings. A message is
shown when no closure rules are defined for the selected scope.

The `all` command writes one `nessus-review-<timestamp>.html` with separate tabs
for report types that have findings. Individual commands continue to write their
own reports. Tabs, search and copy controls work offline.

Each command accepts one complete `.nessus` XML export; concatenating files
does not produce valid XML.