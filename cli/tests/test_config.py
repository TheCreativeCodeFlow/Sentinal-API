"""
Tests for CLI configuration loading and precedence.
"""

import os
import pytest
from sentinel.config import Config, DEFAULT_API_URL, DEFAULT_TIMEOUT
from sentinel.errors import ConfigurationError


def test_config_defaults(monkeypatch):
    """Verify default values when no args or env vars are provided."""
    monkeypatch.delenv("SENTINEL_API_URL", raising=False)
    monkeypatch.delenv("SENTINEL_API_TOKEN", raising=False)
    monkeypatch.delenv("SENTINEL_PROJECT_ID", raising=False)
    monkeypatch.delenv("SENTINEL_TIMEOUT", raising=False)
    monkeypatch.delenv("SENTINEL_OUTPUT_FORMAT", raising=False)

    cfg = Config.load()
    assert cfg.api_url == DEFAULT_API_URL
    assert cfg.token is None
    assert cfg.project_id is None
    assert cfg.timeout == DEFAULT_TIMEOUT
    assert cfg.output_format == "table"
    assert not cfg.is_json()


def test_config_env_vars(monkeypatch):
    """Verify loading from environment variables."""
    monkeypatch.setenv("SENTINEL_API_URL", "https://sentinel.corp.internal")
    monkeypatch.setenv("SENTINEL_API_TOKEN", "token_12345")
    monkeypatch.setenv("SENTINEL_PROJECT_ID", "42")
    monkeypatch.setenv("SENTINEL_TIMEOUT", "60")
    monkeypatch.setenv("SENTINEL_OUTPUT_FORMAT", "json")

    cfg = Config.load()
    assert cfg.api_url == "https://sentinel.corp.internal"
    assert cfg.token == "token_12345"
    assert cfg.project_id == 42
    assert cfg.timeout == 60.0
    assert cfg.output_format == "json"
    assert cfg.is_json()


def test_config_cli_precedence(monkeypatch):
    """Verify CLI arguments take precedence over environment variables."""
    monkeypatch.setenv("SENTINEL_API_URL", "https://env-url.internal")
    monkeypatch.setenv("SENTINEL_API_TOKEN", "env-token")
    monkeypatch.setenv("SENTINEL_PROJECT_ID", "10")
    monkeypatch.setenv("SENTINEL_TIMEOUT", "20")

    cfg = Config.load(
        api_url="https://cli-url.internal",
        token="cli-token",
        project_id=99,
        timeout=120,
        output_format="json",
    )
    assert cfg.api_url == "https://cli-url.internal"
    assert cfg.token == "cli-token"
    assert cfg.project_id == 99
    assert cfg.timeout == 120.0
    assert cfg.output_format == "json"


def test_config_invalid_project_id(monkeypatch):
    """Verify error on non-integer project ID in env."""
    monkeypatch.setenv("SENTINEL_PROJECT_ID", "not_an_int")
    with pytest.raises(ConfigurationError) as exc_info:
        Config.load()
    assert "Invalid SENTINEL_PROJECT_ID" in str(exc_info.value)


def test_config_invalid_timeout(monkeypatch):
    """Verify error on invalid timeout value."""
    with pytest.raises(ConfigurationError):
        Config.load(timeout=-5)


def test_config_secret_masking_in_repr():
    """Verify tokens are never printed in config string representation."""
    cfg = Config.load(
        api_url="http://testserver",
        token="super_secret_token_val_999",
    )
    repr_str = repr(cfg)
    assert "super_secret_token_val_999" not in repr_str
    assert "[REDACTED]" in repr_str
