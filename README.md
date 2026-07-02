# e8scan

[![CI](https://github.com/sumeetghimire/e8scan/actions/workflows/ci.yml/badge.svg)](https://github.com/sumeetghimire/e8scan/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/e8scan)](https://pypi.org/project/e8scan/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/e8scan)](https://pypi.org/project/e8scan/)
[![Coverage](https://img.shields.io/badge/coverage-84%25-brightgreen)](https://github.com/sumeetghimire/e8scan/actions/workflows/ci.yml)

**Cross-platform CLI tool that scans your machine's configuration against the Australian ACSC Essential Eight mitigation strategies and maps every check to official ISM (Information Security Manual) control IDs.**

---

## Why e8scan?

The [Essential Eight](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight) is Australia's baseline cybersecurity framework developed by the Australian Cyber Security Centre (ACSC). Despite being widely referenced, there is a notable lack of open-source tooling that allows developers and sysadmins to self-assess their machines against it.

e8scan fills that gap: it runs **real checks** against your system configuration — registry keys, commands, files, services — and maps each finding to its ISM control ID and maturity level. Results can be exported as a rich terminal table, JSON, SARIF (for GitHub code scanning), or a self-contained HTML report.

> **DISCLAIMER:** Results are indicative only and do not constitute a formal ASD/ACSC Essential Eight assessment. This tool is not affiliated with the Australian Government. Always engage an accredited assessor for compliance verification.

---

## Install

```bash
pip install e8scan
```

Requires Python 3.10+. No heavy dependencies — just `typer`, `rich`, and `PyYAML`.

---

## Quickstart

```bash
# Run all checks and display a rich terminal report
e8scan scan

# Filter to a single strategy
e8scan scan --strategy configure_office_macros

# Only ML1 checks
e8scan scan --maturity-level 1

# Export to HTML
e8scan scan --format html --output report.html

# Export to SARIF for GitHub code scanning
e8scan scan --format sarif --output results.sarif

# List all available checks
e8scan list-checks

# Explain a specific check
e8scan explain E8-OM-001
```

### Example terminal output

```
  e8scan — Essential Eight Configuration Scanner
  Platform: Linux

  Configure Office Macros
  ┌──────────────┬────┬────────┬─────────────────────────────────────────┬──────────────────────────────────┐
  │ ID           │ ML │ Status │ Title                                   │ Actual / Note                    │
  ├──────────────┼────┼────────┼─────────────────────────────────────────┼──────────────────────────────────┤
  │ E8-OM-001    │ 1  │ SKIP   │ Office macros from the internet blocked │ Not applicable on [windows]      │
  ...

  Scan Summary
  PASS       3
  FAIL       2
  ERROR      0
  MANUAL     4
  SKIPPED   12
  TOTAL     21

  Indicative Maturity Level: ML0

  Per-strategy pass rate:
  Configure Office Macros              ░░░░░░░░░░░░░░░░░░░░   0.0%
  Patch Operating Systems              ████████░░░░░░░░░░░░  40.0%
  ...
```

---

## Strategy coverage

| Strategy | Checks | ISM Controls |
|---|---|---|
| Configure Microsoft Office Macro Settings | 8 | ISM-1671, ISM-1488, ISM-1489, ISM-1705 |
| Patch Operating Systems | 5 | ISM-1694, ISM-1695 |
| Restrict Administrative Privileges | 4 | ISM-1507, ISM-1508, ISM-1684 |
| User Application Hardening | 5 | ISM-1621, ISM-1622, ISM-1623, ISM-1543, ISM-1486 |
| Multi-Factor Authentication | 2 | ISM-1401, ISM-1679 |
| Regular Backups | 3 | ISM-1511, ISM-1512, ISM-1515 |
| Application Control | 3 | ISM-1490, ISM-1491, ISM-1492 |
| Patch Applications | 3 | ISM-1493, ISM-1494 |

---

## Writing custom checks

Add YAML files to any directory and pass it with `--checks-dir`:

```bash
e8scan scan --checks-dir ./my-checks/
```

See [docs/check-schema.md](docs/check-schema.md) for the full schema reference.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions are welcome — new checks, new platforms, bug fixes.

Good first issues:
- Add ML2/ML3 macro checks
- Add Linux patch recency checks
- Add macOS backup agent detection
- Improve HTML report design

---

## Security

See [SECURITY.md](SECURITY.md) for how to report vulnerabilities.
