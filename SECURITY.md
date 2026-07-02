# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in e8scan, please **do not** open a public GitHub issue.

Instead, please report it privately by emailing the maintainers or using GitHub's private security advisory feature:
GitHub > Security > Advisories > Report a vulnerability.

We will acknowledge receipt within 48 hours and aim to release a fix within 7 days for critical issues.

## Scope

e8scan is a read-only diagnostic tool. It does not modify system configuration. The main security concern would be:
- A malicious YAML check file causing command injection via the `command` runner
- Path traversal in file checks

Always review custom check files before running them with `--checks-dir`.
