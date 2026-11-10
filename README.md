# Syntecxhub CVE Scanner

![CI](https://github.com/<your-username>/Syntecxhub_CVE_Scanner/actions/workflows/ci.yml/badge.svg)

A lightweight vulnerability scanner built for the **Syntecxhub Internship - Project 1**.
It probes TCP ports, grabs service banners, detects product/version, matches them
against known CVEs and produces a report with severity notes.

> ⚠️ **Legal notice:** scan only systems you own or have **written permission**
> to test. Unauthorized scanning may be illegal.

## Features

- Concurrent port probing with banner grabbing (plain TCP, HTTP and HTTPS)
- Service/version detection (SSH, FTP, HTTP `Server` header, generic banners)
- CVE matching via the **NVD API 2.0** plus an **offline signature database**
- Severity (CVSS) sorting and a Markdown or JSON report
- Built-in triage & responsible-disclosure guidance in every report
- Unit tests and GitHub Actions CI

## Installation

```bash
git clone https://github.com/<your-username>/Syntecxhub_CVE_Scanner.git
cd Syntecxhub_CVE_Scanner
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```bash
python -m cve_scanner 192.168.1.10                       # default ports
python -m cve_scanner scanme.example.org -p 21,22,80,8000-8010
python -m cve_scanner 127.0.0.1 --offline -o report.md   # no internet needed
python -m cve_scanner 10.0.0.5 --format json -o out.json
python -m cve_scanner 10.0.0.5 --api-key YOUR_NVD_KEY    # faster NVD rate limit
```

| Option | Description |
|---|---|
| `-p, --ports` | Ports/ranges (default: common service ports) |
| `-o, --out` | Report path (default `report.md`) |
| `--format` | `md` or `json` |
| `--offline` | Use only the bundled signatures |
| `--api-key` | NVD API key ([request one](https://nvd.nist.gov/developers/request-an-api-key)) |
| `--timeout` | Socket timeout in seconds |

## How it works

1. **Scan** - connect to each port concurrently; read (or elicit) the banner.
2. **Detect** - regex-based extraction of `product` and `version`.
3. **Match** - query bundled signatures and NVD (`keywordSearch`); NVD results
   are filtered to descriptions mentioning the product.
4. **Report** - summary table, per-port CVE list sorted by severity, and
   triage/disclosure notes.

## Limitations

- Banner-based detection can be wrong (hidden banners, backported patches).
- NVD keyword search is fuzzy: results are **candidates**, not confirmed vulns.
- No exploitation is performed - detection only.

## Testing

```bash
pip install -r requirements-dev.txt
python -m pytest
```

## Project layout

```
cve_scanner/   banner.py (scan+detect) · nvd.py (lookups) · report.py · cli.py
tests/         unit tests (local socket servers, mocked NVD)
```

## Responsible disclosure

Report findings privately to the owner/vendor, give reasonable time to fix
(commonly 90 days) and never exploit or access data beyond what is needed to verify.

## License

MIT
