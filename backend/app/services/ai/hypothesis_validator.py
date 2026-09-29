"""
Stage 9.2: Hypothesis Validation Layer
Author: SentinelAPI Security Architecture Team

Strictly validates AI security test hypotheses before human review, approval, and conversion.
Enforces:
- Entity existence and project boundary isolation.
- Allowlisted security test types.
- Zero executable code injection.
- Zero destructive HTTP methods.
- Zero credential attacks (brute force, dictionary, password spraying).
- Zero token forging or signature forgery.
- Zero authorization boundary bypasses.
"""

import re
from typing import Dict, Any, Optional, Set
from sqlalchemy.orm import Session

from app.models import (
    Project,
    Finding,
    AttackPath,
    AIHypothesis,
    Endpoint,
    Identity,
    Resource,
)

# Allowlisted existing deterministic test types
SUPPORTED_TEST_TYPES: Set[str] = {
    "BOLA",
    "BFLA",
    "PROPERTY_EXPOSURE",
    "AUTH_MISSING",
    "AUTH_INVALID",
    "AUTH_MALFORMED",
    "AUTH_EXPIRED",
    "AUTH_SCHEME",
    "WORKFLOW",
}

# Forbidden executable code patterns
EXECUTABLE_CODE_PATTERNS = [
    r"<script[^>]*>",
    r"javascript:",
    r"eval\s*\(",
    r"exec\s*\(",
    r"os\.system",
    r"subprocess\.",
    r"__import__",
    r"/bin/(ba)?sh",
    r"cmd\.exe",
    r"rm\s+-rf",
    r"drop\s+table",
    r"truncate\s+table",
]

# Forbidden destructive action patterns
DESTRUCTIVE_METHOD_PATTERNS = [
    r"\bDELETE\b",
    r"\bDROP\b",
    r"\bTRUNCATE\b",
    r"\bPURGE\b",
    r"\bDESTROY\b",
]

# Forbidden credential attack patterns
CREDENTIAL_ATTACK_PATTERNS = [
    r"brute[- ]?force",
    r"credential stuffing",
    r"password spray(ing)?",
    r"dictionary attack",
    r"crack(ing)? password",
    r"hash crack(ing)?",
]

# Forbidden token forging patterns
TOKEN_FORGING_PATTERNS = [
    r"forge(d|ry)? token",
    r"token forging",
    r"fake jwt",
    r"fake token",
    r"forge signature",
    r"signature forgery",
    r"none algorithm",
    r'["\']alg["\']\s*:\s*["\']none["\']',
    r"sign with none",
    r"tamper jwt signature",
]

# Forbidden authorization bypass patterns
AUTH_BYPASS_PATTERNS = [
    r"bypass authorization check",
    r"disable authorization",
    r"disable auth",
    r"override rbac",
    r"grant admin directly",
    r"grant superuser directly",
]


class HypothesisValidationError(ValueError):
    """Raised when an AI hypothesis violates security constraints or schema boundaries."""
    pass


class HypothesisValidator:
    """Validates AI hypotheses against strict security rules and data integrity boundaries."""

    def __init__(self, db: Session):
        self.db = db

    def validate(self, hypothesis: AIHypothesis) -> bool:
        """
        Validate hypothesis attributes, relationships, project boundaries, and security rules.
        Raises HypothesisValidationError on any violation.
        """
        # 1. Project existence & authorization check
        project = self.db.query(Project).filter(Project.id == hypothesis.project_id).first()
        if not project:
            raise HypothesisValidationError(f"Referenced project {hypothesis.project_id} does not exist.")
        if project.authorization_status != "authorized":
            raise HypothesisValidationError(
                f"Project {project.id} is not authorized for security testing (status: {project.authorization_status})."
            )

        # 2. Supported Test Type Check
        if hypothesis.suggested_test_type not in SUPPORTED_TEST_TYPES:
            raise HypothesisValidationError(
                f"Unsupported test type '{hypothesis.suggested_test_type}'. "
                f"Supported types: {sorted(list(SUPPORTED_TEST_TYPES))}"
            )

        # 3. Referenced Finding Boundary Check
        if hypothesis.finding_id:
            finding = self.db.query(Finding).filter(Finding.id == hypothesis.finding_id).first()
            if not finding:
                raise HypothesisValidationError(f"Referenced finding {hypothesis.finding_id} does not exist.")
            if finding.project_id != hypothesis.project_id:
                raise HypothesisValidationError(
                    f"Cross-project isolation breach: finding {finding.id} belongs to project {finding.project_id}, "
                    f"not hypothesis project {hypothesis.project_id}."
                )

        # 4. Referenced Attack Path Boundary Check
        if hypothesis.attack_path_id:
            path = self.db.query(AttackPath).filter(AttackPath.id == hypothesis.attack_path_id).first()
            if not path:
                raise HypothesisValidationError(f"Referenced attack path {hypothesis.attack_path_id} does not exist.")
            if path.project_id != hypothesis.project_id:
                raise HypothesisValidationError(
                    f"Cross-project isolation breach: attack path {path.id} belongs to project {path.project_id}, "
                    f"not hypothesis project {hypothesis.project_id}."
                )

        # 5. Required Context Entity Checks (if present)
        req_context = hypothesis.required_context
        if isinstance(req_context, dict):
            # Endpoint existence check
            ep_id = req_context.get("endpoint_id")
            if ep_id:
                endpoint = self.db.query(Endpoint).filter(Endpoint.id == ep_id).first()
                if not endpoint or endpoint.api.project_id != hypothesis.project_id:
                    raise HypothesisValidationError(
                        f"Required context references endpoint {ep_id} that does not exist in project {hypothesis.project_id}."
                    )

            # Identity existence check
            identity_id = req_context.get("identity_id") or req_context.get("attacker_identity_id")
            if identity_id:
                identity = self.db.query(Identity).filter(Identity.id == identity_id).first()
                if not identity or identity.project_id != hypothesis.project_id:
                    raise HypothesisValidationError(
                        f"Required context references identity {identity_id} that does not exist in project {hypothesis.project_id}."
                    )

            # Resource existence check
            res_id = req_context.get("resource_id") or req_context.get("victim_resource_id")
            if res_id:
                resource = self.db.query(Resource).filter(Resource.id == res_id).first()
                if not resource or resource.project_id != hypothesis.project_id:
                    raise HypothesisValidationError(
                        f"Required context references resource {res_id} that does not exist in project {hypothesis.project_id}."
                    )

        # 6. Text-based Security Checks on hypothesis & reason
        combined_text = f"{hypothesis.hypothesis} {hypothesis.reason}".lower()

        # Check for executable code injection
        for pat in EXECUTABLE_CODE_PATTERNS:
            if re.search(pat, combined_text, re.IGNORECASE):
                raise HypothesisValidationError(f"Hypothesis contains prohibited executable code or injection pattern: {pat}")

        # Check for destructive HTTP methods / commands
        for pat in DESTRUCTIVE_METHOD_PATTERNS:
            if re.search(pat, combined_text, re.IGNORECASE):
                raise HypothesisValidationError(f"Hypothesis requests prohibited destructive action or method: {pat}")

        # Check for credential attacks (brute force, spray)
        for pat in CREDENTIAL_ATTACK_PATTERNS:
            if re.search(pat, combined_text, re.IGNORECASE):
                raise HypothesisValidationError(f"Hypothesis requests prohibited credential attack: {pat}")

        # Check for token forging
        for pat in TOKEN_FORGING_PATTERNS:
            if re.search(pat, combined_text, re.IGNORECASE):
                raise HypothesisValidationError(f"Hypothesis requests prohibited token forging: {pat}")

        # Check for authorization boundary bypass
        for pat in AUTH_BYPASS_PATTERNS:
            if re.search(pat, combined_text, re.IGNORECASE):
                raise HypothesisValidationError(f"Hypothesis requests prohibited authorization bypass: {pat}")

        return True
