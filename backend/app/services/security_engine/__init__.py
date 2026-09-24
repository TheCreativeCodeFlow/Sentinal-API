"""
SentinelAPI Security Testing Engine package.
Provides modular, controlled authorization testing (Stage 3 BOLA).
"""

from app.services.security_engine.client import AsyncSecurityHttpClient, ExecutionResult
from app.services.security_engine.evaluator import BOLAEngine
from app.services.security_engine.bfla_engine import BFLAEngine
from app.services.security_engine.property_engine import PropertyExposureEngine
from app.services.security_engine.auth_engine import AuthenticationEngine
from app.services.security_engine.auth_generator import AuthenticationTestGenerator
from app.services.security_engine.workflow_engine import WorkflowEngine

__all__ = [
    "AsyncSecurityHttpClient",
    "ExecutionResult",
    "BOLAEngine",
    "BFLAEngine",
    "PropertyExposureEngine",
    "AuthenticationEngine",
    "AuthenticationTestGenerator",
    "WorkflowEngine",
    "redact_headers",
    "redact_text",
]

