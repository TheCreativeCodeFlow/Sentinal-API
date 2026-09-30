"""
Integration tests for Sentinel CLI command suites using Click's CliRunner.
All backend interactions are mocked to guarantee strictly zero target HTTP requests.
"""

import json
from unittest.mock import MagicMock, patch
from click.testing import CliRunner
import pytest

from sentinel.main import cli


@pytest.fixture
def runner():
    return CliRunner()


# =============================================================================
# PROJECT COMMANDS
# =============================================================================

def test_project_list(runner):
    """Test 'sentinel project list' table and JSON output."""
    mock_projects = [
        {"id": 1, "name": "Payment Service", "authorization_status": "authorized", "environment": "prod", "base_url": "https://api.payments.com"},
        {"id": 2, "name": "User Service", "authorization_status": "authorized", "environment": "staging", "base_url": "https://api.users.com"},
    ]
    with patch("sentinel.client.SentinelClient.list_projects", return_value=mock_projects):
        result = runner.invoke(cli, ["project", "list"])
        assert result.exit_code == 0
        assert "Payment Service" in result.output
        assert "User Service" in result.output

        # JSON mode
        json_result = runner.invoke(cli, ["--json", "project", "list"])
        assert json_result.exit_code == 0
        parsed = json.loads(json_result.output)
        assert len(parsed) == 2
        assert parsed[0]["name"] == "Payment Service"


def test_project_get(runner):
    """Test 'sentinel project get <id>'."""
    mock_project = {
        "id": 1,
        "name": "Payment Service",
        "description": "Core payments",
        "authorization_status": "authorized",
        "environment": "prod",
        "base_url": "https://api.payments.com",
        "created_at": "2026-09-30T12:00:00Z",
    }
    with patch("sentinel.client.SentinelClient.get_project", return_value=mock_project):
        result = runner.invoke(cli, ["project", "get", "1"])
        assert result.exit_code == 0
        assert "Project #1" in result.output
        assert "Payment Service" in result.output


def test_project_current(runner):
    """Test 'sentinel project current'."""
    mock_project = {"id": 10, "name": "Auth API", "authorization_status": "authorized", "environment": "dev"}
    with patch("sentinel.client.SentinelClient.get_project", return_value=mock_project):
        result = runner.invoke(cli, ["--project", "10", "project", "current"])
        assert result.exit_code == 0
        assert "Auth API" in result.output


# =============================================================================
# PROFILE COMMANDS
# =============================================================================

def test_profile_list_and_get(runner):
    """Test profile list and get commands."""
    mock_profiles = [
        {"id": "prof-1", "name": "Standard Scan", "profile_type": "STANDARD", "status": "ACTIVE", "description": "Standard OWASP tests"}
    ]
    with patch("sentinel.client.SentinelClient.list_profiles", return_value=mock_profiles):
        res = runner.invoke(cli, ["--project", "1", "profile", "list"])
        assert res.exit_code == 0
        assert "Standard Scan" in res.output

    with patch("sentinel.client.SentinelClient.get_profile", return_value=mock_profiles[0]):
        res = runner.invoke(cli, ["profile", "get", "prof-1"])
        assert res.exit_code == 0
        assert "Scan Profile: Standard Scan" in res.output


def test_profile_preview(runner):
    """Test 'sentinel profile preview <id>' deterministic reason output."""
    mock_preview = {
        "profile_id": "prof-standard",
        "profile_name": "Standard API Security",
        "profile_type": "STANDARD",
        "selected_test_count": 3,
        "selected_tests": [
            {"security_test_id": "t1", "test_type": "AUTH_MISSING", "endpoint": "/api/v1/auth", "priority": "HIGH", "reason": "Endpoint requires authentication"},
            {"security_test_id": "t2", "test_type": "BOLA", "endpoint": "/api/v1/users/{id}", "priority": "HIGH", "reason": "Endpoint has resource ownership model"},
            {"security_test_id": "t3", "test_type": "PROPERTY_EXPOSURE", "endpoint": "/api/v1/records", "priority": "NORMAL", "reason": "Sensitive properties configured"},
        ],
    }
    with patch("sentinel.client.SentinelClient.preview_profile", return_value=mock_preview):
        res = runner.invoke(cli, ["profile", "preview", "prof-standard"])
        assert res.exit_code == 0
        assert "Profile: Standard API Security" in res.output
        assert "Selected Tests: 3" in res.output
        assert "AUTH_MISSING" in res.output
        assert "BOLA" in res.output
        assert "PROPERTY_EXPOSURE" in res.output


# =============================================================================
# SCAN COMMAND
# =============================================================================

def test_scan_command_no_wait(runner):
    """Test launching a background scan without --wait."""
    mock_profile = {"id": "prof-1", "name": "Quick Audit", "profile_type": "QUICK", "status": "ACTIVE", "project_id": 1}
    mock_plan = {"id": "plan-12345", "status": "RUNNING"}

    with patch("sentinel.client.SentinelClient.get_profile", return_value=mock_profile), \
         patch("sentinel.client.SentinelClient.create_plan_from_profile", return_value=mock_plan), \
         patch("sentinel.client.SentinelClient.start_execution_plan", return_value=mock_plan):

        res = runner.invoke(cli, ["scan", "--profile", "prof-1"])
        assert res.exit_code == 0
        assert "SentinelAPI Security Scan" in res.output
        assert "Execution ID: plan-12345" in res.output


def test_scan_command_with_wait(runner):
    """Test scan with --wait and progress polling."""
    mock_profile = {"id": "prof-1", "name": "Quick Audit", "profile_type": "QUICK", "status": "ACTIVE", "project_id": 1}
    mock_plan = {"id": "plan-12345", "status": "RUNNING"}
    mock_progress_running = {"status": "RUNNING", "total_tests": 5, "completed_tests": 3, "confirmed_findings": 1, "inconclusive_tests": 0, "failed_tests": 0}
    mock_progress_completed = {"status": "COMPLETED", "total_tests": 5, "completed_tests": 5, "confirmed_findings": 1, "inconclusive_tests": 0, "failed_tests": 0}
    mock_final_plan = {
        "id": "plan-12345",
        "status": "COMPLETED",
        "total_tests": 5,
        "completed_tests": 5,
        "confirmed_findings": 1,
        "inconclusive_tests": 0,
        "failed_tests": 0,
    }

    with patch("sentinel.client.SentinelClient.get_profile", return_value=mock_profile), \
         patch("sentinel.client.SentinelClient.create_plan_from_profile", return_value=mock_plan), \
         patch("sentinel.client.SentinelClient.start_execution_plan", return_value=mock_plan), \
         patch("sentinel.client.SentinelClient.get_execution_progress", side_effect=[mock_progress_running, mock_progress_completed]), \
         patch("sentinel.client.SentinelClient.get_execution_plan", return_value=mock_final_plan), \
         patch("time.sleep", return_value=None):

        res = runner.invoke(cli, ["scan", "--profile", "prof-1", "--wait"])
        assert res.exit_code == 0
        assert "Scan completed" in res.output
        assert "Confirmed Findings  : 1" in res.output


# =============================================================================
# GATE COMMAND
# =============================================================================

def test_gate_list_and_get(runner):
    """Test gate list and get commands."""
    mock_gates = [
        {"id": "gate-1", "name": "PR Security Gate", "status": "ACTIVE", "baseline_id": "base-1", "scan_profile_id": "prof-1"}
    ]
    with patch("sentinel.client.SentinelClient.list_gates", return_value=mock_gates):
        res = runner.invoke(cli, ["--project", "1", "gate", "list"])
        assert res.exit_code == 0
        assert "PR Security Gate" in res.output

    with patch("sentinel.client.SentinelClient.get_gate", return_value=mock_gates[0]):
        res = runner.invoke(cli, ["gate", "get", "gate-1"])
        assert res.exit_code == 0
        assert "Security Gate: PR Security Gate" in res.output


def test_gate_run_pass(runner):
    """Test 'sentinel gate run' when gate evaluation passes (exit 0)."""
    mock_gate = {"id": "gate-1", "baseline_id": "base-1"}
    mock_comp = {"id": "comp-1"}
    mock_eval = {"id": "eval-1"}
    mock_ci_result = {
        "gate_id": "gate-1",
        "evaluation_id": "eval-1",
        "status": "PASS",
        "exit_code": 0,
        "metrics": {"failure_count": 0, "warning_count": 0, "confirmed_findings": 0, "regressions": 0, "new_violations": 0, "failed_tests": 0},
        "failures": [],
    }

    with patch("sentinel.client.SentinelClient.get_gate", return_value=mock_gate), \
         patch("sentinel.client.SentinelClient.compare_baseline_with_plan", return_value=mock_comp), \
         patch("sentinel.client.SentinelClient.evaluate_gate", return_value=mock_eval), \
         patch("sentinel.client.SentinelClient.get_evaluation_result", return_value=mock_ci_result):

        res = runner.invoke(cli, ["gate", "run", "gate-1", "--execution", "plan-1"])
        assert res.exit_code == 0
        assert "Verdict        : PASS" in res.output


# =============================================================================
# RESULT COMMAND
# =============================================================================

def test_result_command(runner):
    """Test 'sentinel result <evaluation_id>'."""
    mock_ci_result = {
        "gate_id": "gate-1",
        "evaluation_id": "eval-123",
        "status": "PASS",
        "exit_code": 0,
        "metrics": {"failure_count": 0, "warning_count": 0},
    }
    with patch("sentinel.client.SentinelClient.get_evaluation_result", return_value=mock_ci_result):
        res = runner.invoke(cli, ["result", "eval-123"])
        assert res.exit_code == 0
        assert "Evaluation ID : eval-123" in res.output
        assert "Status        : PASS" in res.output


# =============================================================================
# REPORT COMMANDS
# =============================================================================

def test_report_commands(runner):
    """Test report list, get, json, manifest, package commands."""
    mock_report = {
        "id": "rep-1",
        "name": "Q3 Security Report",
        "report_type": "SECURITY_ASSESSMENT",
        "status": "PUBLISHED",
        "version": 1,
        "latest_snapshot_checksum": "a" * 64,
    }
    mock_manifest = {
        "report_id": "rep-1",
        "report_name": "Q3 Security Report",
        "version": 1,
        "schema_version": "1.0",
        "checksum": "a" * 64,
        "findings_count": 2,
        "evidence_records_count": 2,
    }
    mock_json = {"report_metadata": {"id": "rep-1"}, "verified_findings": []}

    with patch("sentinel.client.SentinelClient.list_reports", return_value=[mock_report]):
        res = runner.invoke(cli, ["--project", "1", "report", "list"])
        assert res.exit_code == 0
        assert "Q3 Security Report" in res.output

    with patch("sentinel.client.SentinelClient.get_report", return_value=mock_report):
        res = runner.invoke(cli, ["report", "get", "rep-1"])
        assert res.exit_code == 0
        assert "Security Report: Q3 Security Report" in res.output

    with patch("sentinel.client.SentinelClient.get_report_json", return_value=mock_json):
        res = runner.invoke(cli, ["report", "json", "rep-1"])
        assert res.exit_code == 0
        parsed = json.loads(res.output)
        assert parsed["report_metadata"]["id"] == "rep-1"

    with patch("sentinel.client.SentinelClient.get_report_manifest", return_value=mock_manifest):
        res = runner.invoke(cli, ["report", "manifest", "rep-1"])
        assert res.exit_code == 0
        assert "Evidence Package Manifest" in res.output

    with patch("sentinel.client.SentinelClient.get_report_package", return_value={"package": "full"}):
        res = runner.invoke(cli, ["report", "package", "rep-1"])
        assert res.exit_code == 0
        parsed = json.loads(res.output)
        assert parsed["package"] == "full"
