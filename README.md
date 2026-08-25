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

### Reporting

- Generate Markdown reports automatically
- Deduplicate references
- Produce reusable reporting outputs
- Generate multiple report types from a single Nessus scan

## Usage

```bash
# Generate a TLS Review
nessus-organiser tls internal.nessus

# Generate a Patch Management Report
nessus-organiser patching internal.nessus

# Generate All Support Reports
nessus-organiser all internal.nessus
```

## Example Output

```bash
$ nessus-organiser all internal.nessus

          TLS Analysis Summary
┏━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┓
┃ Metric                ┃         Value ┃
┡━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━┩
│ Parsed Plugins        │        21,619 │
│ Excluded Plugins      │             0 │
│ Processed Plugins     │        21,619 │
│ TLS Vulnerabilities   │           922 │
│ Identified Categories │             7 │
│ Generated Findings    │             7 │
│ Output File           │ tls-review.md │
└───────────────────────┴───────────────┘

           Patch Management Analysis Summary
┏━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Metric                 ┃                      Value ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Parsed Plugins         │                     21,619 │
│ Excluded Plugins       │                        212 │
│ Processed Plugins      │                     21,407 │
│ Patch Vulnerabilities  │                        831 │
│ Legacy Vulnerabilities │                         45 │
│ Identified Categories  │                          2 │
│ Generated Findings     │                          2 │
│ Output File            │ patch-management-review.md │
└────────────────────────┴────────────────────────────┘
```