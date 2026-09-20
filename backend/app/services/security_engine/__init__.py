"""
SentinelAPI Security Testing Engine package.
Provides modular, controlled authorization testing (Stage 3 BOLA).
"""

from app.services.security_engine.client import AsyncSecurityHttpClient, ExecutionResult
from app.services.security_engine.evaluator import BOLAEngine
from app.services.security_engine.redactor import redact_headers, redact_text

__all__ = [
    "AsyncSecurityHttpClient",
    "ExecutionResult",
    "BOLAEngine",
    "redact_headers",
    "redact_text",
]
