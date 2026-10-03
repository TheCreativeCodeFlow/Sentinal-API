"""
Unit and integration tests for Sentinel CLI auth commands.
All HTTP client calls are mocked to verify CLI behavior deterministically.
"""

import json
from unittest.mock import patch
from click.testing import CliRunner
import pytest

from sentinel.main import cli
from sentinel.errors import AuthenticationError, ForbiddenError


@pytest.fixture
def runner():
    return CliRunner()


def test_auth_verify_success(runner):
    """Test 'sentinel auth verify' command."""
    mock_verify = {
        "authenticated": True,
        "is_development_bypass": False,
        "user": {
            "id": "u-123",
            "email": "alice@example.com",
            "display_name": "Alice Admin",
        },
        "token_id": "tok-456",
        "token_name": "CI Token",
        "expires_at": "2026-12-31T23:59:59Z",
    }
    with patch("sentinel.client.SentinelClient.verify_auth", return_value=mock_verify):
        result = runner.invoke(cli, ["auth", "verify"])
        assert result.exit_code == 0
        assert "Alice Admin" in result.output
        assert "alice@example.com" in result.output
        assert "CI Token" in result.output

        # JSON mode
        json_result = runner.invoke(cli, ["--json", "auth", "verify"])
        assert json_result.exit_code == 0
        data = json.loads(json_result.output)
        assert data["authenticated"] is True
        assert data["user"]["email"] == "alice@example.com"


def test_auth_verify_unauthenticated(runner):
    """Test 'sentinel auth verify' fails when unauthenticated (401)."""
    with patch("sentinel.client.SentinelClient.verify_auth", side_effect=AuthenticationError("Invalid API token.")):
        result = runner.invoke(cli, ["auth", "verify"])
        assert result.exit_code != 0
        assert isinstance(result.exception, AuthenticationError)


def test_auth_token_status(runner):
    """Test 'sentinel auth token-status' command."""
    mock_status = {
        "valid": True,
        "status": "ACTIVE",
        "token_name": "Production Key",
        "user_id": "u-123",
        "expires_at": "2026-11-01T00:00:00Z",
        "last_used_at": "2026-10-03T18:00:00Z",
        "days_until_expiration": 28,
    }
    with patch("sentinel.client.SentinelClient.get_token_status", return_value=mock_status):
        result = runner.invoke(cli, ["auth", "token-status"])
        assert result.exit_code == 0
        assert "ACTIVE" in result.output
        assert "Production Key" in result.output
        assert "28" in result.output

        # JSON mode
        json_result = runner.invoke(cli, ["--json", "auth", "token-status"])
        assert json_result.exit_code == 0
        data = json.loads(json_result.output)
        assert data["valid"] is True
        assert data["days_until_expiration"] == 28


def test_auth_audit_list(runner):
    """Test 'sentinel auth audit' command."""
    mock_events = [
        {
            "id": "evt-12345678-abcd",
            "created_at": "2026-10-03T18:30:00Z",
            "event_type": "SCAN",
            "action": "EXECUTE",
            "outcome": "SUCCESS",
            "actor_email": "analyst@sentinel.local",
            "resource_type": "PLAN",
            "resource_id": "plan-1",
        }
    ]
    with patch("sentinel.client.SentinelClient.list_audit_events", return_value=mock_events):
        result = runner.invoke(cli, ["auth", "audit", "--project", "1"])
        assert result.exit_code == 0
        assert "SCAN" in result.output
        assert "EXECUTE" in result.output
        assert "SUCCESS" in result.output
        assert "analyst@sentinel.local" in result.output
