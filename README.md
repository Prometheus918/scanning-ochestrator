# Automated Vulnerability Scanner Wrapper

A lightweight Python tool that automates vulnerability scanning using
multiple Kali Linux security tools and generates a consolidated HTML
report.

Instead of manually running several scanners one by one, this wrapper
orchestrates them automatically, parses their outputs, and merges the
results into a structured vulnerability report.

The tool is designed for security testers, pentesters, red teams, and
security engineers who want a simple way to perform automated
vulnerability assessments across multiple targets.

------------------------------------------------------------------------

## What This Tool Does

This project acts as a scanner orchestrator. It reads targets from a
file, runs multiple vulnerability scanners against each target, and
consolidates the findings into a single report.

### Integrated Tools

  Tool         Purpose
  ------------ ---------------------------------------------
  Nmap         Service detection and vulnerability scripts
  Nuclei       Template‑based vulnerability scanning
  Nikto        Web server vulnerability scanning
  Wapiti       Web application vulnerability scanning
  OWASP ZAP    Spider + active scanning
  SSLScan      SSL/TLS configuration analysis
  testssl.sh   Deep SSL/TLS vulnerability testing

------------------------------------------------------------------------

## Features

### Automated Multi‑Tool Scanning

Runs several security scanners automatically against each target.

### Parallel Execution

Multiple scanners can run simultaneously to reduce scan time.

### Smart Target Handling

The tool automatically handles inputs such as:

    example.com
    https://example.com
    www.example.com
    example.com:8443
    10.10.10.10
    hxxp://example.com

### Live Target Detection

Before launching web scanners, the script checks if the host is alive
using httpx.

### Consolidated HTML Report

All findings are merged into a single interactive HTML report with
filtering capabilities.

------------------------------------------------------------------------


## Requirements

Designed primarily for Kali Linux.

Required tools:

    nmap
    nuclei
    nikto
    wapiti
    zaproxy
    sslscan
    testssl.sh
    httpx

Python:

    Python 3.9+

------------------------------------------------------------------------

## Installation

### 1. Clone Repository

    git clone https://github.com/your-org/scanner-wrapper.git
    cd scanner-wrapper

### 2. Install Dependencies

Run the setup script:

    sudo python3 setup.py

The script installs all required tools and verifies that they are
available.

------------------------------------------------------------------------

## Usage

### Create a Targets File

Example `targets.txt`:

    example.com
    scanme.nmap.org
    https://testphp.vulnweb.com
    10.10.10.10

Lines starting with `#` are ignored.

### Run the Scanner

    python3 scanner_wrapper.py --targets-file targets.txt

The scanner will:

1.  Normalize targets
2.  Detect live hosts
3.  Run scanners
4.  Parse outputs
5.  Generate an HTML report

------------------------------------------------------------------------

## Example Command

    python3 scanner_wrapper.py   --targets-file targets.txt   --results-dir results   --reports-dir reports   --max-parallel-tools 4

------------------------------------------------------------------------

## Output Example

After a scan:

    results/
     ├── nmap_example.com.xml
     ├── nuclei_example.com.jsonl
     ├── nikto_example.com.txt
     ├── wapiti_example.com/
     │    └── wapiti_report.json
     ├── zap_example.com.json
     ├── sslscan_example.com.txt
     └── testssl_example.com.txt

    reports/
     └── vulnerability_report.html

------------------------------------------------------------------------

## HTML Report Contents

The generated report includes:

-   Total vulnerabilities
-   Severity distribution
-   Vulnerabilities by target
-   Detailed findings table
-   Request/response evidence
-   Interactive filters

------------------------------------------------------------------------

## Logging

During scanning a log file is generated:

    results/scan.log

Example:

    [+] Running Nmap
    [+] Running Nuclei
    [+] Running Nikto
    [*] Status: target 2/5, tools 6/30 complete

------------------------------------------------------------------------

## Troubleshooting

### Tool Not Found

    which nmap
    which nuclei
    which nikto

### ZAP Not Starting

    zap.sh -daemon -port 8090

### Nuclei Templates Missing

    nuclei -update-templates

------------------------------------------------------------------------

## Security Notice

This tool must only be used for authorized security testing.

Do not scan systems without permission.

------------------------------------------------------------------------

## License

[MIT License
](https://github.com/Prometheus918/scanning-ochestrator/blob/main/LICENSE)
