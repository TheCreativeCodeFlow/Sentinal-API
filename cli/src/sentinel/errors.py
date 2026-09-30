"""
Typed CLI errors and centralized exit codes for SentinelAPI CLI.
"""

from typing import Optional

# Standard CI/CD Exit Codes matching Stage 10.3 / 10.5 specification:
EXIT_PASS = 0
EXIT_WARN = 0
EXIT_FAIL = 1
EXIT_ERROR = 2


class SentinelError(Exception):
    """Base exception for all Sentinel CLI errors."""

    def __init__(
        self,
        message: str,
        reason: Optional[str] = None,
        exit_code: int = EXIT_ERROR,
    ):
        super().__init__(message)
        self.message = message
        self.reason = reason
        self.exit_code = exit_code

    def __str__(self) -> str:
        if self.reason:
            return f"{self.message}\nReason: {self.reason}"
        return self.message


class ConfigurationError(SentinelError):
    """Raised when required configuration or CLI flags are missing or invalid."""

    def __init__(self, message: str, reason: Optional[str] = None):
        super().__init__(message, reason=reason, exit_code=EXIT_ERROR)


class AuthenticationError(SentinelError):
    """Raised when authentication against SentinelAPI backend fails (HTTP 401)."""

    def __init__(
        self,
        message: str = "Authentication failed against SentinelAPI.",
        reason: Optional[str] = "Invalid, missing, or expired API token.",
    ):
        super().__init__(message, reason=reason, exit_code=EXIT_ERROR)


class ForbiddenError(SentinelError):
    """Raised when the caller is not authorized for the requested resource (HTTP 403)."""

    def __init__(
        self,
        message: str = "Access forbidden.",
        reason: Optional[str] = "Insufficient permissions or unauthorized project access.",
    ):
        super().__init__(message, reason=reason, exit_code=EXIT_ERROR)


class NotFoundError(SentinelError):
    """Raised when a requested resource is not found (HTTP 404)."""

    def __init__(self, message: str, reason: Optional[str] = None):
        super().__init__(message, reason=reason, exit_code=EXIT_ERROR)


class ConflictError(SentinelError):
    """Raised when a conflict occurs (HTTP 409)."""

    def __init__(self, message: str, reason: Optional[str] = None):
        super().__init__(message, reason=reason, exit_code=EXIT_ERROR)


class ValidationError(SentinelError):
    """Raised when request payload or parameters are invalid (HTTP 400 / 422)."""

    def __init__(self, message: str, reason: Optional[str] = None):
        super().__init__(message, reason=reason, exit_code=EXIT_ERROR)


class ConnectionError(SentinelError):
    """Raised when the SentinelAPI backend is unreachable."""

    def __init__(
        self,
        message: str = "Unable to connect to SentinelAPI backend.",
        reason: Optional[str] = "Network failure or server is not running.",
    ):
        super().__init__(message, reason=reason, exit_code=EXIT_ERROR)


class TimeoutError(SentinelError):
    """Raised when a CLI timeout or polling duration expires."""

    def __init__(
        self,
        message: str = "Operation timed out.",
        reason: Optional[str] = "The execution did not complete within the specified timeout.",
    ):
        super().__init__(message, reason=reason, exit_code=EXIT_ERROR)


class GateEvaluationError(SentinelError):
    """
    Raised when a SecurityGate evaluation fails or errors.
    Deterministic Exit Code:
    - FAIL -> EXIT_FAIL (1)
    - ERROR -> EXIT_ERROR (2)
    """

    def __init__(
        self,
        status: str,
        message: str,
        reason: Optional[str] = None,
        evaluation_id: Optional[str] = None,
    ):
        self.status = status.upper()
        self.evaluation_id = evaluation_id
        exit_code = EXIT_FAIL if self.status == "FAIL" else EXIT_ERROR
        super().__init__(message, reason=reason, exit_code=exit_code)
