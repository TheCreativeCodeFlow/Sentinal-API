"""
Tests verifying exact deterministic CI/CD exit codes:
PASS = 0
WARN = 0
FAIL = 1
ERROR = 2
"""

from unittest.mock import patch
from click.testing import CliRunner
import pytest

from sentinel.errors import EXIT_ERROR, EXIT_FAIL, EXIT_PASS, EXIT_WARN
from sentinel.main import cli


@pytest.fixture
def runner():
    return CliRunner()


def test_exit_codes_constants():
    """Verify constant values match specification."""
    assert EXIT_PASS == 0
    assert EXIT_WARN == 0
    assert EXIT_FAIL == 1
    assert EXIT_ERROR == 2


def test_gate_run_exit_pass(runner):
    """Test gate run with status PASS yields exit code 0."""
    ci_result = {
        "gate_id": "gate-1",
        "evaluation_id": "eval-1",
        "status": "PASS",
        "exit_code": 0,
        "metrics": {"failure_count": 0},
    }
    with patch("sentinel.client.SentinelClient.get_gate", return_value={"id": "gate-1", "baseline_id": "b1"}), \
         patch("sentinel.client.SentinelClient.compare_baseline_with_plan", return_value={"id": "c1"}), \
         patch("sentinel.client.SentinelClient.evaluate_gate", return_value={"id": "eval-1"}), \
         patch("sentinel.client.SentinelClient.get_evaluation_result", return_value=ci_result):

        res = runner.invoke(cli, ["gate", "run", "gate-1", "--execution", "plan-1"])
        assert res.exit_code == 0


def test_gate_run_exit_warn(runner):
    """Test gate run with status WARN yields exit code 0."""
    ci_result = {
        "gate_id": "gate-1",
        "evaluation_id": "eval-2",
        "status": "WARN",
        "exit_code": 0,
        "metrics": {"warning_count": 2},
    }
    with patch("sentinel.client.SentinelClient.get_gate", return_value={"id": "gate-1", "baseline_id": "b1"}), \
         patch("sentinel.client.SentinelClient.compare_baseline_with_plan", return_value={"id": "c1"}), \
         patch("sentinel.client.SentinelClient.evaluate_gate", return_value={"id": "eval-2"}), \
         patch("sentinel.client.SentinelClient.get_evaluation_result", return_value=ci_result):

        res = runner.invoke(cli, ["gate", "run", "gate-1", "--execution", "plan-1"])
        assert res.exit_code == 0


def test_gate_run_exit_fail(runner):
    """Test gate run with status FAIL yields exit code 1."""
    ci_result = {
        "gate_id": "gate-1",
        "evaluation_id": "eval-3",
        "status": "FAIL",
        "exit_code": 1,
        "metrics": {"failure_count": 1},
        "failures": [{"rule_type": "REGRESSION", "message": "Baseline regression detected"}],
    }
    with patch("sentinel.client.SentinelClient.get_gate", return_value={"id": "gate-1", "baseline_id": "b1"}), \
         patch("sentinel.client.SentinelClient.compare_baseline_with_plan", return_value={"id": "c1"}), \
         patch("sentinel.client.SentinelClient.evaluate_gate", return_value={"id": "eval-3"}), \
         patch("sentinel.client.SentinelClient.get_evaluation_result", return_value=ci_result):

        res = runner.invoke(cli, ["gate", "run", "gate-1", "--execution", "plan-1"])
        assert res.exit_code == 1


def test_gate_run_exit_error(runner):
    """Test gate run with status ERROR yields exit code 2."""
    ci_result = {
        "gate_id": "gate-1",
        "evaluation_id": "eval-4",
        "status": "ERROR",
        "exit_code": 2,
        "metrics": {"failure_count": 0},
    }
    with patch("sentinel.client.SentinelClient.get_gate", return_value={"id": "gate-1", "baseline_id": "b1"}), \
         patch("sentinel.client.SentinelClient.compare_baseline_with_plan", return_value={"id": "c1"}), \
         patch("sentinel.client.SentinelClient.evaluate_gate", return_value={"id": "eval-4"}), \
         patch("sentinel.client.SentinelClient.get_evaluation_result", return_value=ci_result):

        res = runner.invoke(cli, ["gate", "run", "gate-1", "--execution", "plan-1"])
        assert res.exit_code == 2


def test_result_command_exit_codes(runner):
    """Test 'sentinel result' exits with matching exit code."""
    ci_result_fail = {
        "gate_id": "g1",
        "status": "FAIL",
        "exit_code": 1,
        "metrics": {},
    }
    with patch("sentinel.client.SentinelClient.get_evaluation_result", return_value=ci_result_fail):
        res = runner.invoke(cli, ["result", "eval-fail"])
        assert res.exit_code == 1
