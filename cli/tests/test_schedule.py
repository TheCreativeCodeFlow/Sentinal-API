"""
Unit and integration tests for Sentinel CLI schedule commands.
All HTTP client calls are mocked to verify CLI behavior without network or target calls.
"""

import json
from unittest.mock import patch
from click.testing import CliRunner
import pytest

from sentinel.main import cli


@pytest.fixture
def runner():
    return CliRunner()


def test_schedule_list(runner):
    """Test 'sentinel schedule list' command."""
    mock_schedules = [
        {
            "id": "sched-1",
            "name": "Nightly Regression",
            "status": "ACTIVE",
            "schedule_type": "DAILY",
            "timezone": "UTC",
            "next_run_at": "2026-10-01T00:00:00Z",
            "scan_profile_id": "prof-1",
        }
    ]
    with patch("sentinel.client.SentinelClient.list_schedules", return_value=mock_schedules):
        result = runner.invoke(cli, ["schedule", "list", "--project", "1"])
        assert result.exit_code == 0
        assert "Nightly Regression" in result.output
        assert "DAILY" in result.output

        # JSON mode
        json_result = runner.invoke(cli, ["--json", "schedule", "list", "--project", "1"])
        assert json_result.exit_code == 0
        data = json.loads(json_result.output)
        assert len(data) == 1
        assert data[0]["name"] == "Nightly Regression"


def test_schedule_list_requires_project(runner):
    """Test 'sentinel schedule list' without project fails."""
    from sentinel.errors import ConfigurationError
    result = runner.invoke(cli, ["schedule", "list"])
    assert result.exit_code != 0
    assert isinstance(result.exception, ConfigurationError)
    assert "Project ID required" in str(result.exception)



def test_schedule_get(runner):
    """Test 'sentinel schedule get <id>' command."""
    mock_schedule = {
        "id": "sched-1",
        "project_id": 1,
        "name": "Nightly Regression",
        "description": "Daily automated scan",
        "status": "ACTIVE",
        "schedule_type": "DAILY",
        "timezone": "America/New_York",
        "cron_expression": "0 0 * * *",
        "next_run_at": "2026-10-01T04:00:00Z",
        "last_run_at": None,
        "scan_profile_id": "prof-1",
        "security_gate_id": "gate-1",
        "max_concurrent_runs": 1,
        "timeout_seconds": 600,
        "created_at": "2026-09-30T12:00:00Z",
    }
    with patch("sentinel.client.SentinelClient.get_schedule", return_value=mock_schedule):
        result = runner.invoke(cli, ["schedule", "get", "sched-1"])
        assert result.exit_code == 0
        assert "Nightly Regression" in result.output
        assert "America/New_York" in result.output


def test_schedule_preview(runner):
    """Test 'sentinel schedule preview <id>' command."""
    mock_preview = {
        "schedule_id": "sched-1",
        "name": "Nightly Regression",
        "schedule_type": "DAILY",
        "timezone": "UTC",
        "is_active": True,
        "is_expired": False,
        "next_occurrences": [
            "2026-10-01T00:00:00Z",
            "2026-10-02T00:00:00Z",
            "2026-10-03T00:00:00Z",
        ],
    }
    with patch("sentinel.client.SentinelClient.preview_schedule", return_value=mock_preview):
        result = runner.invoke(cli, ["schedule", "preview", "sched-1", "--count", "3"])
        assert result.exit_code == 0
        assert "2026-10-01T00:00:00Z" in result.output
        assert "2026-10-02T00:00:00Z" in result.output


def test_schedule_run(runner):
    """Test 'sentinel schedule run <id>' command."""
    mock_execution = {
        "id": "exec-1",
        "schedule_id": "sched-1",
        "status": "COMPLETED",
        "trigger_type": "MANUAL",
        "execution_plan_id": "plan-1",
        "gate_evaluation_id": "gate-eval-1",
        "report_id": "rep-1",
        "started_at": "2026-09-30T12:00:00Z",
        "completed_at": "2026-09-30T12:01:00Z",
        "error_message": None,
    }
    with patch("sentinel.client.SentinelClient.run_schedule", return_value=mock_execution):
        result = runner.invoke(cli, ["schedule", "run", "sched-1"])
        assert result.exit_code == 0
        assert "exec-1" in result.output
        assert "COMPLETED" in result.output


def test_schedule_enable_and_disable(runner):
    """Test 'sentinel schedule enable' and 'disable' commands."""
    mock_enabled = {
        "id": "sched-1",
        "name": "Nightly Regression",
        "status": "ACTIVE",
        "next_run_at": "2026-10-01T00:00:00Z",
    }
    with patch("sentinel.client.SentinelClient.enable_schedule", return_value=mock_enabled):
        result = runner.invoke(cli, ["schedule", "enable", "sched-1"])
        assert result.exit_code == 0
        assert "ACTIVE" in result.output

    mock_disabled = {
        "id": "sched-1",
        "name": "Nightly Regression",
        "status": "DISABLED",
        "next_run_at": None,
    }
    with patch("sentinel.client.SentinelClient.disable_schedule", return_value=mock_disabled):
        result = runner.invoke(cli, ["schedule", "disable", "sched-1"])
        assert result.exit_code == 0
        assert "DISABLED" in result.output


def test_schedule_executions(runner):
    """Test 'sentinel schedule executions <id>' command."""
    mock_executions = [
        {
            "id": "exec-1",
            "status": "COMPLETED",
            "trigger_type": "SCHEDULED",
            "execution_plan_id": "plan-1",
            "gate_verdict": "PASS",
            "started_at": "2026-09-30T12:00:00Z",
        }
    ]
    with patch("sentinel.client.SentinelClient.list_scheduled_executions", return_value=mock_executions):
        result = runner.invoke(cli, ["schedule", "executions", "sched-1"])
        assert result.exit_code == 0
        assert "exec-1" in result.output
        assert "COMPLETED" in result.output
        assert "PASS" in result.output
