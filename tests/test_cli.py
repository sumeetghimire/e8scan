"""Tests for the CLI commands."""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from typer.testing import CliRunner

from e8scan.cli import app

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "e8scan" in result.output
    assert "0.1.0" in result.output


def test_list_checks() -> None:
    result = runner.invoke(app, ["list-checks"])
    assert result.exit_code == 0
    assert "E8-OM-001" in result.output
    assert "Configure Office Macros" in result.output


def test_list_checks_filter_strategy() -> None:
    result = runner.invoke(app, ["list-checks", "--strategy", "configure_office_macros"])
    assert result.exit_code == 0
    assert "E8-OM-001" in result.output
    assert "E8-POS-001" not in result.output


def test_list_checks_filter_maturity_level() -> None:
    result = runner.invoke(app, ["list-checks", "--maturity-level", "1"])
    assert result.exit_code == 0
    # ML2/3 checks should not appear — spot-check one
    assert "E8-OM-004" not in result.output  # ML2


def test_explain_valid_check() -> None:
    result = runner.invoke(app, ["explain", "E8-OM-001"])
    assert result.exit_code == 0
    assert "E8-OM-001" in result.output
    assert "ISM-" in result.output
    assert "Remediation" in result.output


def test_explain_invalid_check() -> None:
    result = runner.invoke(app, ["explain", "E8-INVALID-999"])
    assert result.exit_code == 1


def test_scan_terminal_format() -> None:
    result = runner.invoke(app, ["scan", "--format", "terminal", "--skip-manual"])
    # Exit code 0 (all pass) or 1 (failures) — both are valid; it must not crash
    assert result.exit_code in (0, 1)
    assert "e8scan" in result.output
    assert "DISCLAIMER" in result.output


def test_scan_json_format() -> None:
    result = runner.invoke(app, ["scan", "--format", "json", "--skip-manual"])
    assert result.exit_code in (0, 1)
    data = json.loads(result.output)
    assert "results" in data
    assert "summary" in data
    assert data["schema_version"] == "1.0"


def test_scan_sarif_format() -> None:
    result = runner.invoke(app, ["scan", "--format", "sarif", "--skip-manual"])
    assert result.exit_code in (0, 1)
    data = json.loads(result.output)
    assert data["version"] == "2.1.0"
    assert "runs" in data


def test_scan_html_format() -> None:
    result = runner.invoke(app, ["scan", "--format", "html", "--skip-manual"])
    assert result.exit_code in (0, 1)
    assert "<!DOCTYPE html>" in result.output
    assert "Essential Eight" in result.output


def test_scan_output_to_file(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    result = runner.invoke(app, ["scan", "--format", "json", "--output", str(out), "--skip-manual"])
    assert result.exit_code in (0, 1)
    assert out.exists()
    data = json.loads(out.read_text())
    assert "results" in data


def test_scan_strategy_filter() -> None:
    result = runner.invoke(app, ["scan", "--format", "json", "--strategy", "configure_office_macros"])
    assert result.exit_code in (0, 1)
    data = json.loads(result.output)
    strategies = {r["strategy"] for r in data["results"]}
    assert strategies == {"configure_office_macros"}


def test_scan_maturity_level_filter() -> None:
    result = runner.invoke(app, ["scan", "--format", "json", "--maturity-level", "1", "--skip-manual"])
    assert result.exit_code in (0, 1)
    data = json.loads(result.output)
    for r in data["results"]:
        assert r["maturity_level"] <= 1


def test_scan_invalid_format() -> None:
    result = runner.invoke(app, ["scan", "--format", "xml"])
    assert result.exit_code == 1


def test_scan_invalid_strategy() -> None:
    result = runner.invoke(app, ["scan", "--strategy", "not_a_real_strategy"])
    assert result.exit_code == 1


def test_scan_custom_checks_dir(tmp_path: Path) -> None:
    check = {
        "id": "E8-TST-CLI-001",
        "strategy": "regular_backups",
        "title": "CLI custom check test",
        "ism_controls": ["ISM-9999"],
        "maturity_level": 1,
        "platforms": ["all"],
        "severity": "low",
        "check": {"type": "manual", "guidance": "Check manually."},
        "remediation": "Fix it.",
    }
    (tmp_path / "custom.yaml").write_text(yaml.dump(check))
    result = runner.invoke(app, [
        "scan", "--format", "json",
        "--checks-dir", str(tmp_path),
        "--strategy", "regular_backups",
    ])
    assert result.exit_code in (0, 1)
    data = json.loads(result.output)
    ids = [r["id"] for r in data["results"]]
    assert "E8-TST-CLI-001" in ids
