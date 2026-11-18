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
- Extract host, service, plugin, CVSS, and reference information
- Deduplicate findings where appropriate
- Generate reporting statistics automatically

### TLS Reviews

- Identify TLS-related vulnerabilities
- Consolidate related findings into root-cause observations
- Generate technical commentary and remediation guidance
- Produce consultant-ready Markdown reports

### Patch Management Reviews

- Identify missing security updates
- Identify unsupported and end-of-life software
- Calculate vulnerability statistics
- Generate technical commentary and remediation guidance
- Produce consultant-ready Markdown reports

### SSH Reviews

- Identify SSH cryptographic hardening weaknesses
- Consolidate related findings into root-cause observations
- Generate technical commentary and remediation guidance
- Produce consultant-ready Markdown reports

### Reporting

- Generate Markdown reports automatically
- Deduplicate references
- Produce reusable reporting outputs
- Generate multiple report types from a single Nessus scan

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
| Weak Cipher Suites | 26928, 65821, 42873, 81606 |
| Invalid Certificate Configuration | 51192, 57582, 45410, 45411, 15901, 56284 |
| Weak Certificate Cryptography | 35291, 69551, 60108, 86067 |
| Weak Diffie-Hellman Parameters | 83875, 53360 |
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
nessus-organiser tls internal.nessus

# Generate a Patch Management Report
nessus-organiser patching internal.nessus

# Generate an SSH Report
nessus-organiser ssh internal.nessus

# Generate All Support Reports
nessus-organiser all internal.nessus

# List supported plugin IDs per module
nessus-organiser --list-plugin-ids
```

## Example Output

```bash
$ nessus-organiser all internal.nessus

          TLS Analysis Summary
╭───────────────────────┬───────────────╮
│ Metric                │         Value │
├───────────────────────┼───────────────┤
│ Parsed Plugins        │         2,644 │
│ Excluded Plugins      │             0 │
│ Processed Plugins     │         2,644 │
│ TLS Vulnerabilities   │           115 │
│ Identified Categories │             4 │
│ Generated Findings    │             4 │
│ Output File           │ tls-review.md │
╰───────────────────────┴───────────────╯

           Patch Management Analysis Summary
╭────────────────────────┬────────────────────────────╮
│ Metric                 │                      Value │
├────────────────────────┼────────────────────────────┤
│ Parsed Plugins         │                      2,644 │
│ Excluded Plugins       │                         11 │
│ Processed Plugins      │                      2,633 │
│ Patch Vulnerabilities  │                         43 │
│ Legacy Vulnerabilities │                          4 │
│ Identified Categories  │                          2 │
│ Generated Findings     │                          2 │
│ Output File            │ patch-management-review.md │
╰────────────────────────┴────────────────────────────╯

          SSH Analysis Summary
╭───────────────────────┬───────────────╮
│ Metric                │         Value │
├───────────────────────┼───────────────┤
│ Parsed Plugins        │         2,644 │
│ Excluded Plugins      │             0 │
│ Processed Plugins     │         2,644 │
│ SSH Vulnerabilities   │             9 │
│ Identified Categories │             4 │
│ Generated Findings    │             4 │
│ Output File           │ ssh-review.md │
╰───────────────────────┴───────────────╯
```