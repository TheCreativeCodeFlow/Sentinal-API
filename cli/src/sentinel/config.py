"""
Configuration management for Sentinel CLI.
Precedence: CLI argument -> Environment variable -> Default
"""

import os
from dataclasses import dataclass
from typing import Optional

from sentinel.errors import ConfigurationError

DEFAULT_API_URL = "http://localhost:8000"
DEFAULT_TIMEOUT = 30
DEFAULT_OUTPUT_FORMAT = "table"


@dataclass
class Config:
    """Holds configuration for Sentinel CLI sessions."""

    api_url: str
    token: Optional[str] = None
    project_id: Optional[int] = None
    timeout: float = DEFAULT_TIMEOUT
    output_format: str = DEFAULT_OUTPUT_FORMAT
    quiet: bool = False
    verbose: bool = False

    @classmethod
    def load(
        cls,
        api_url: Optional[str] = None,
        token: Optional[str] = None,
        project_id: Optional[int] = None,
        timeout: Optional[float] = None,
        output_format: Optional[str] = None,
        quiet: bool = False,
        verbose: bool = False,
    ) -> "Config":
        """
        Resolve configuration values using precedence:
        CLI arg -> Environment variable -> Default
        """
        # Resolve API URL
        resolved_api_url = (
            api_url
            or os.environ.get("SENTINEL_API_URL")
            or DEFAULT_API_URL
        ).strip().rstrip("/")

        if not resolved_api_url:
            raise ConfigurationError(
                "Sentinel API URL is required.",
                reason="Set --api-url or the SENTINEL_API_URL environment variable.",
            )

        # Resolve Token
        resolved_token = token or os.environ.get("SENTINEL_API_TOKEN")
        if resolved_token:
            resolved_token = resolved_token.strip()

        # Resolve Project ID
        resolved_project_id: Optional[int] = None
        if project_id is not None:
            resolved_project_id = project_id
        else:
            env_project = os.environ.get("SENTINEL_PROJECT_ID")
            if env_project:
                try:
                    resolved_project_id = int(env_project.strip())
                except ValueError:
                    raise ConfigurationError(
                        f"Invalid SENTINEL_PROJECT_ID: '{env_project}'",
                        reason="Project ID must be an integer.",
                    )

        # Resolve Timeout
        resolved_timeout = DEFAULT_TIMEOUT
        if timeout is not None:
            resolved_timeout = float(timeout)
        else:
            env_timeout = os.environ.get("SENTINEL_TIMEOUT")
            if env_timeout:
                try:
                    resolved_timeout = float(env_timeout.strip())
                except ValueError:
                    raise ConfigurationError(
                        f"Invalid SENTINEL_TIMEOUT: '{env_timeout}'",
                        reason="Timeout must be a numeric value in seconds.",
                    )

        if resolved_timeout <= 0:
            raise ConfigurationError("Timeout must be a positive number of seconds.")

        # Resolve Output Format
        resolved_format = (
            output_format
            or os.environ.get("SENTINEL_OUTPUT_FORMAT")
            or DEFAULT_OUTPUT_FORMAT
        ).strip().lower()

        if resolved_format not in ("table", "json"):
            resolved_format = "table"

        return cls(
            api_url=resolved_api_url,
            token=resolved_token,
            project_id=resolved_project_id,
            timeout=resolved_timeout,
            output_format=resolved_format,
            quiet=quiet,
            verbose=verbose,
        )

    def is_json(self) -> bool:
        """Returns True if JSON output mode is active."""
        return self.output_format == "json"

    def __repr__(self) -> str:
        """Safe string representation that never exposes tokens or credentials."""
        masked_token = "[REDACTED]" if self.token else "None"
        return (
            f"Config(api_url='{self.api_url}', "
            f"token={masked_token}, "
            f"project_id={self.project_id}, "
            f"timeout={self.timeout}, "
            f"output_format='{self.output_format}', "
            f"quiet={self.quiet}, "
            f"verbose={self.verbose})"
        )
