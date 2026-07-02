"""Tests for check runners with mocked subprocess and winreg."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

from e8scan.models import CheckDefinition, ResultStatus


def make_check(check_cfg: dict, strategy: str = "patch_operating_systems") -> CheckDefinition:
    return CheckDefinition(
        id="E8-TST-001",
        strategy=strategy,
        title="Test check",
        ism_controls=["ISM-9999"],
        maturity_level=1,
        platforms=["all"],
        severity="high",
        check=check_cfg,
        remediation="Fix it.",
    )


# --- Manual runner ---

def test_manual_runner_returns_manual_status() -> None:
    from e8scan.runners.manual import run
    check = make_check({"type": "manual", "guidance": "Verify manually."})
    result = run(check)
    assert result.status == ResultStatus.MANUAL
    assert "Verify manually" in result.message


# --- File runner ---

def test_file_runner_exists_pass(tmp_path) -> None:
    from e8scan.runners.file import run
    f = tmp_path / "testfile.txt"
    f.write_text("hello")
    check = make_check({"type": "file", "path": str(f), "operator": "exists"})
    result = run(check)
    assert result.status == ResultStatus.PASS


def test_file_runner_exists_fail(tmp_path) -> None:
    from e8scan.runners.file import run
    check = make_check({"type": "file", "path": str(tmp_path / "nonexistent.txt"), "operator": "exists"})
    result = run(check)
    assert result.status == ResultStatus.FAIL


def test_file_runner_not_exists_pass(tmp_path) -> None:
    from e8scan.runners.file import run
    check = make_check({"type": "file", "path": str(tmp_path / "nonexistent.txt"), "operator": "not_exists"})
    result = run(check)
    assert result.status == ResultStatus.PASS


def test_file_runner_contains_pass(tmp_path) -> None:
    from e8scan.runners.file import run
    f = tmp_path / "test.conf"
    f.write_text("APT::Periodic::Unattended-Upgrade \"1\";")
    check = make_check({
        "type": "file",
        "path": str(f),
        "operator": "contains",
        "expected": "Unattended-Upgrade",
    })
    result = run(check)
    assert result.status == ResultStatus.PASS


def test_file_runner_contains_fail(tmp_path) -> None:
    from e8scan.runners.file import run
    f = tmp_path / "test.conf"
    f.write_text("nothing useful here")
    check = make_check({
        "type": "file",
        "path": str(f),
        "operator": "contains",
        "expected": "Unattended-Upgrade",
    })
    result = run(check)
    assert result.status == ResultStatus.FAIL


def test_file_runner_missing_path() -> None:
    from e8scan.runners.file import run
    check = make_check({"type": "file", "operator": "exists"})
    result = run(check)
    assert result.status == ResultStatus.ERROR


# --- Command runner ---

def test_command_runner_equals_pass() -> None:
    from e8scan.runners.command import run
    check = make_check({
        "type": "command",
        "cmd": "echo hello",
        "shell": True,
        "operator": "equals",
        "expected": "hello",
    })
    result = run(check)
    assert result.status == ResultStatus.PASS


def test_command_runner_equals_fail() -> None:
    from e8scan.runners.command import run
    check = make_check({
        "type": "command",
        "cmd": "echo world",
        "shell": True,
        "operator": "equals",
        "expected": "hello",
    })
    result = run(check)
    assert result.status == ResultStatus.FAIL


def test_command_runner_contains_pass() -> None:
    from e8scan.runners.command import run
    check = make_check({
        "type": "command",
        "cmd": "echo hello world",
        "shell": True,
        "operator": "contains",
        "expected": "world",
    })
    result = run(check)
    assert result.status == ResultStatus.PASS


def test_command_runner_regex_pass() -> None:
    from e8scan.runners.command import run
    check = make_check({
        "type": "command",
        "cmd": "echo 5.15.0-generic",
        "shell": True,
        "operator": "regex",
        "expected": r"^[5-9]\.",
    })
    result = run(check)
    assert result.status == ResultStatus.PASS


def test_command_runner_version_gte_pass() -> None:
    from e8scan.runners.command import run
    check = make_check({
        "type": "command",
        "cmd": "echo 14.2.1",
        "shell": True,
        "operator": "version_gte",
        "expected": "13.0",
    })
    result = run(check)
    assert result.status == ResultStatus.PASS


def test_command_runner_version_gte_fail() -> None:
    from e8scan.runners.command import run
    check = make_check({
        "type": "command",
        "cmd": "echo 12.6.0",
        "shell": True,
        "operator": "version_gte",
        "expected": "13.0",
    })
    result = run(check)
    assert result.status == ResultStatus.FAIL


def test_command_runner_exit_code_pass() -> None:
    from e8scan.runners.command import run
    # Exit code 0
    check = make_check({
        "type": "command",
        "cmd": "true" if sys.platform != "win32" else "cmd /c exit 0",
        "shell": True,
        "operator": "exit_code",
        "expected": 0,
    })
    result = run(check)
    assert result.status == ResultStatus.PASS


def test_command_runner_command_not_found() -> None:
    from e8scan.runners.command import run
    check = make_check({
        "type": "command",
        "cmd": ["absolutely_nonexistent_command_xyz123"],
        "shell": False,
        "operator": "equals",
        "expected": "anything",
    })
    result = run(check)
    assert result.status == ResultStatus.ERROR


def test_command_runner_timeout() -> None:
    from e8scan.runners.command import run
    check = make_check({
        "type": "command",
        "cmd": "sleep 10" if sys.platform != "win32" else "timeout 10",
        "shell": True,
        "operator": "equals",
        "expected": "anything",
        "timeout": 1,
    })
    result = run(check)
    assert result.status == ResultStatus.ERROR
    assert "timed out" in result.message.lower()


def test_command_runner_platform_dict_cmd() -> None:
    from e8scan.runners.command import run
    plat = "windows" if sys.platform == "win32" else ("macos" if sys.platform == "darwin" else "linux")
    cmd_dict = {"windows": "echo win", "linux": "echo linux", "macos": "echo mac"}
    check = make_check({
        "type": "command",
        "cmd": cmd_dict,
        "shell": True,
        "operator": "contains",
        "expected": plat if plat != "macos" else "mac",
    })
    result = run(check)
    assert result.status == ResultStatus.PASS


# --- Registry runner (Windows-only, mock on other platforms) ---

@pytest.mark.skipif(sys.platform == "win32", reason="Tests mocked winreg on non-Windows")
def test_registry_runner_skipped_on_non_windows() -> None:
    from e8scan.runners.registry import run
    check = make_check({
        "type": "registry",
        "hive": "HKLM",
        "path": "SOFTWARE\\Test",
        "key": "TestKey",
        "expected": 1,
    })
    result = run(check)
    assert result.status == ResultStatus.SKIPPED


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
def test_registry_runner_key_not_found_windows() -> None:
    from e8scan.runners.registry import run
    check = make_check({
        "type": "registry",
        "hive": "HKLM",
        "path": "SOFTWARE\\NonExistentE8ScanTest12345",
        "key": "NonExistentKey",
        "expected": 1,
    })
    result = run(check)
    assert result.status == ResultStatus.FAIL
    assert "not found" in result.message.lower()


# --- Service runner ---

@pytest.mark.skipif(sys.platform == "win32", reason="systemd not on Windows")
def test_service_runner_unknown_service_linux() -> None:
    from e8scan.runners.service import run
    check = make_check({
        "type": "service",
        "name": "absolutely-nonexistent-service-xyz",
        "expected_state": "running",
    })
    result = run(check)
    # Should be FAIL (service inactive/dead) or SKIPPED (no systemctl), not crash
    assert result.status in (ResultStatus.FAIL, ResultStatus.SKIPPED, ResultStatus.ERROR)
