"""
Tests for SentinelClient HTTP communication and error mapping.
"""

from unittest.mock import MagicMock, patch
import httpx
import pytest

from sentinel.client import SentinelClient
from sentinel.config import Config
from sentinel.errors import (
    AuthenticationError,
    ConflictError,
    ConnectionError,
    ForbiddenError,
    NotFoundError,
    SentinelError,
    TimeoutError,
    ValidationError,
)


@pytest.fixture
def test_config():
    return Config(
        api_url="http://testbackend:8000",
        token="test_bearer_token_xyz",
        project_id=1,
        timeout=10.0,
    )


def test_client_headers(test_config):
    """Verify authorization and API key headers are included."""
    with SentinelClient(test_config) as client:
        headers = client._client.headers
        assert headers.get("Authorization") == "Bearer test_bearer_token_xyz"
        assert headers.get("X-API-Key") == "test_bearer_token_xyz"
        assert headers.get("User-Agent") == "SentinelCLI/1.0"


def test_client_connection_error(test_config):
    """Verify httpx.ConnectError maps to ConnectionError."""
    with SentinelClient(test_config) as client:
        with patch.object(client._client, "request", side_effect=httpx.ConnectError("Connection refused")):
            with pytest.raises(ConnectionError) as exc_info:
                client.list_projects()
            assert "Failed to connect to SentinelAPI" in str(exc_info.value)


def test_client_timeout_error(test_config):
    """Verify httpx.TimeoutException maps to TimeoutError."""
    with SentinelClient(test_config) as client:
        with patch.object(client._client, "request", side_effect=httpx.ReadTimeout("Read timed out")):
            with pytest.raises(TimeoutError) as exc_info:
                client.list_projects()
            assert "timed out" in str(exc_info.value)


def test_client_http_401_authentication_error(test_config):
    """Verify HTTP 401 raises AuthenticationError."""
    resp = httpx.Response(401, json={"detail": "Invalid or missing API token."})
    with SentinelClient(test_config) as client:
        with patch.object(client._client, "request", return_value=resp):
            with pytest.raises(AuthenticationError):
                client.verify_auth()


def test_client_http_403_forbidden_error(test_config):
    """Verify HTTP 403 raises ForbiddenError."""
    resp = httpx.Response(403, json={"detail": "Tenant boundary violation."})
    with SentinelClient(test_config) as client:
        with patch.object(client._client, "request", return_value=resp):
            with pytest.raises(ForbiddenError):
                client.get_project(999)


def test_client_http_404_not_found_error(test_config):
    """Verify HTTP 404 raises NotFoundError."""
    resp = httpx.Response(404, json={"detail": "Scan profile not found."})
    with SentinelClient(test_config) as client:
        with patch.object(client._client, "request", return_value=resp):
            with pytest.raises(NotFoundError):
                client.get_profile("nonexistent-id")


def test_client_http_409_conflict_error(test_config):
    """Verify HTTP 409 raises ConflictError."""
    resp = httpx.Response(409, json={"detail": "Entity with name already exists."})
    with SentinelClient(test_config) as client:
        with patch.object(client._client, "request", return_value=resp):
            with pytest.raises(ConflictError):
                client.create_plan_from_profile("p1", name="Duplicate")


def test_client_http_422_validation_error(test_config):
    """Verify HTTP 422 raises ValidationError."""
    resp = httpx.Response(422, json={"detail": "Unprocessable entity"})
    with SentinelClient(test_config) as client:
        with patch.object(client._client, "request", return_value=resp):
            with pytest.raises(ValidationError):
                client.compare_baseline_with_plan("b1", "")


def test_client_http_500_server_error(test_config):
    """Verify HTTP 500 raises SentinelError."""
    resp = httpx.Response(500, json={"detail": "Internal error"})
    with SentinelClient(test_config) as client:
        with patch.object(client._client, "request", return_value=resp):
            with pytest.raises(SentinelError):
                client.list_projects()
