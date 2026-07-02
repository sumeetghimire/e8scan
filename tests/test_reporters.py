"""Tests for reporters."""

from __future__ import annotations

import json

from rich.console import Console

from e8scan.models import CheckDefinition, CheckResult, ResultStatus, ScanReport
from e8scan.reporters import html_, json_, sarif, terminal


def make_report() -> ScanReport:
    def make_check(check_id: str, strategy: str, ml: int, severity: str = "high") -> CheckDefinition:
        return CheckDefinition(
            id=check_id,
            strategy=strategy,
            title=f"Test check {check_id}",
            ism_controls=["ISM-1234"],
            maturity_level=ml,
            platforms=["all"],
            severity=severity,
            check={"type": "manual"},
            remediation="Remediate this.",
            references=["https://example.com"],
        )

    return ScanReport(
        results=[
            CheckResult(
                check=make_check("E8-OM-001", "configure_office_macros", 1),
                status=ResultStatus.PASS,
                actual_value="1",
            ),
            CheckResult(
                check=make_check("E8-POS-001", "patch_operating_systems", 1),
                status=ResultStatus.FAIL,
                actual_value="0",
                message="Expected 1, got 0",
            ),
            CheckResult(
                check=make_check("E8-MFA-001", "multi_factor_authentication", 1),
                status=ResultStatus.MANUAL,
                message="Verify in IdP",
            ),
            CheckResult(
                check=make_check("E8-UAH-001", "user_application_hardening", 1),
                status=ResultStatus.SKIPPED,
                message="Not applicable on linux",
            ),
        ],
        scan_platform="Linux",
        scan_platform_version="5.15.0",
    )


# --- JSON reporter ---

def test_json_reporter_valid_json() -> None:
    report = make_report()
    output = json_.render(report)
    data = json.loads(output)
    assert "results" in data
    assert data["summary"]["total"] == 4
    assert data["summary"]["pass"] == 1
    assert data["summary"]["fail"] == 1


def test_json_reporter_schema_version() -> None:
    report = make_report()
    data = json.loads(json_.render(report))
    assert data["schema_version"] == "1.0"


def test_json_reporter_result_fields() -> None:
    report = make_report()
    data = json.loads(json_.render(report))
    result = data["results"][0]
    required_fields = {"id", "title", "strategy", "maturity_level", "severity",
                       "ism_controls", "status", "actual_value", "message", "remediation", "references"}
    assert required_fields.issubset(set(result.keys()))


# --- SARIF reporter ---

def test_sarif_reporter_valid_json() -> None:
    report = make_report()
    output = sarif.render(report)
    data = json.loads(output)
    assert data["version"] == "2.1.0"
    assert "runs" in data
    assert len(data["runs"]) == 1


def test_sarif_reporter_has_rules() -> None:
    report = make_report()
    data = json.loads(sarif.render(report))
    rules = data["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) >= 1
    rule_ids = [r["id"] for r in rules]
    assert "E8-OM-001" in rule_ids


def test_sarif_reporter_only_fail_error_in_results() -> None:
    report = make_report()
    data = json.loads(sarif.render(report))
    results = data["runs"][0]["results"]
    # Only FAIL results should appear (no PASS/MANUAL/SKIPPED)
    for r in results:
        assert r["level"] in ("error", "warning", "note")
    rule_ids = [r["ruleId"] for r in results]
    assert "E8-POS-001" in rule_ids
    assert "E8-OM-001" not in rule_ids  # PASS should not appear


# --- HTML reporter ---

def test_html_reporter_returns_html() -> None:
    report = make_report()
    output = html_.render(report)
    assert output.startswith("<!DOCTYPE html>")
    assert "<html" in output
    assert "</html>" in output


def test_html_reporter_contains_disclaimer() -> None:
    report = make_report()
    output = html_.render(report)
    assert "indicative only" in output.lower()
    assert "not affiliated with the Australian Government" in output


def test_html_reporter_contains_check_ids() -> None:
    report = make_report()
    output = html_.render(report)
    assert "E8-OM-001" in output
    assert "E8-POS-001" in output


def test_html_reporter_self_contained() -> None:
    """No external assets — all CSS and JS must be inline."""
    report = make_report()
    output = html_.render(report)
    assert 'src="http' not in output
    assert 'href="http' not in output
    assert "<style>" in output
    assert "<script>" in output


# --- Terminal reporter ---

def test_terminal_reporter_runs_without_error() -> None:
    from io import StringIO
    report = make_report()
    console = Console(file=StringIO(), force_terminal=True, width=120)
    terminal.render(report, console=console)
    output = console.file.getvalue()  # type: ignore[union-attr]
    assert "e8scan" in output
    assert "DISCLAIMER" in output


def test_terminal_reporter_shows_strategy_sections() -> None:
    from io import StringIO
    report = make_report()
    console = Console(file=StringIO(), force_terminal=True, width=120)
    terminal.render(report, console=console)
    output = console.file.getvalue()  # type: ignore[union-attr]
    assert "Configure Office Macros" in output
    assert "Patch Operating Systems" in output


def test_terminal_reporter_shows_summary() -> None:
    from io import StringIO
    report = make_report()
    console = Console(file=StringIO(), force_terminal=True, width=120)
    terminal.render(report, console=console)
    output = console.file.getvalue()  # type: ignore[union-attr]
    assert "Scan Summary" in output
    assert "PASS" in output
    assert "FAIL" in output


def test_terminal_reporter_default_console() -> None:
    """render() with no console arg should not raise."""
    import sys
    from io import StringIO
    report = make_report()
    # Patch stdout to avoid polluting test output
    old_stdout = sys.stdout
    sys.stdout = StringIO()
    try:
        terminal.render(report)
    finally:
        sys.stdout = old_stdout
