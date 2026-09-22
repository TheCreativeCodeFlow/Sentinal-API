import json
import re
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple
from sqlalchemy.orm import Session

from app.models import (
    SecurityTest,
    TestExecution,
    Finding,
    Evidence,
    Project,
    Endpoint,
    Identity,
    Role,
    AuthenticationPolicy,
)
from app.services.security_engine.client import AsyncSecurityHttpClient, ExecutionResult
from app.services.security_engine.auth_adapters import AuthAdapter
from app.services.security_engine.response_analyzer import ResponseAnalyzer, ResponseSignature


REMEDIATION_MAP = {
    "AUTHENTICATION_BYPASS": (
        "Enforce mandatory authentication verification middleware on the endpoint before "
        "dispatching request handlers. Ensure requests without valid authentication credentials "
        "are automatically rejected with HTTP 401 Unauthorized."
    ),
    "INVALID_AUTH_ACCEPTED": (
        "Verify authentication token signatures and validate session authenticity against the "
        "identity provider or session store. Ensure invalid or tampered tokens are rejected with "
        "HTTP 401 Unauthorized."
    ),
    "MALFORMED_AUTH_HANDLING": (
        "Implement resilient header parsing and input validation for authentication credentials. "
        "Return HTTP 400 Bad Request or HTTP 401 Unauthorized on malformed headers, preventing "
        "unhandled exceptions and server crashes (HTTP 500)."
    ),
    "EXPIRED_AUTH_ACCEPTED": (
        "Validate token expiration claims ('exp') and reject expired sessions or tokens with "
        "HTTP 401 Unauthorized, prompting the client to re-authenticate or refresh credentials."
    ),
    "AUTHENTICATION_INCONSISTENCY": (
        "Enforce strict authentication scheme checks according to the endpoint's configured security "
        "specification. Reject mismatched or unrecognized authentication schemes with HTTP 401 Unauthorized."
    ),
}

TITLE_MAP = {
    "AUTHENTICATION_BYPASS": "Authentication Bypass Detected",
    "INVALID_AUTH_ACCEPTED": "Invalid Authentication Credential Accepted",
    "MALFORMED_AUTH_HANDLING": "Improper Handling of Malformed Authentication",
    "EXPIRED_AUTH_ACCEPTED": "Expired Authentication Credential Accepted",
    "AUTHENTICATION_INCONSISTENCY": "Authentication Scheme Enforcement Inconsistency",
}


class AuthenticationEngine:
    """
    Controlled Authentication Security Testing Engine.
    Validates whether protected API endpoints correctly enforce authentication and
    whether authentication mechanisms behave consistently.
    Supports: AUTH_MISSING, AUTH_INVALID, AUTH_MALFORMED, AUTH_EXPIRED, AUTH_SCHEME.
    """

    def __init__(self, db: Session, app: Optional[Any] = None):
        self.db = db
        self.app = app

    async def execute_test(self, security_test: SecurityTest) -> TestExecution:
        """
        Executes a configured Authentication Security Test and records execution,
        evidence, and findings in the database.
        """
        now = datetime.now(timezone.utc)
        execution = TestExecution(
            security_test_id=security_test.id,
            status="RUNNING",
            started_at=now,
        )
        self.db.add(execution)
        self.db.commit()
        self.db.refresh(execution)

        # Parse test configuration
        config: Dict[str, Any] = {}
        if security_test.configuration:
            try:
                config = json.loads(security_test.configuration)
            except Exception:
                config = {}

        # 1. Fetch and validate entities
        project = self.db.query(Project).filter(Project.id == security_test.project_id).first()
        endpoint = self.db.query(Endpoint).filter(Endpoint.id == security_test.endpoint_id).first()
        attacker = None
        if security_test.attacker_identity_id:
            attacker = self.db.query(Identity).filter(Identity.id == security_test.attacker_identity_id).first()

        # 2. Target authorization validation (SAFETY)
        if not project or project.authorization_status.lower() != "authorized":
            execution.status = "FAILED"
            execution.result = "ERROR"
            execution.error_category = "unauthorized_target"
            execution.result_reason = "Target project has not been explicitly authorized for security testing."
            execution.completed_at = datetime.now(timezone.utc)
            self.db.commit()
            return execution

        # 3. Parameter validation
        if not endpoint:
            execution.status = "FAILED"
            execution.result = "ERROR"
            execution.error_category = "invalid_configuration"
            execution.result_reason = "Target endpoint not found."
            execution.completed_at = datetime.now(timezone.utc)
            self.db.commit()
            return execution

        if endpoint.api and endpoint.api.project_id != project.id:
            execution.status = "FAILED"
            execution.result = "ERROR"
            execution.error_category = "cross_project_mismatch"
            execution.result_reason = "Endpoint must belong to the target project."
            execution.completed_at = datetime.now(timezone.utc)
            self.db.commit()
            return execution

        if attacker and attacker.project_id != project.id:
            execution.status = "FAILED"
            execution.result = "ERROR"
            execution.error_category = "cross_project_mismatch"
            execution.result_reason = "Attacker identity must belong to the target project."
            execution.completed_at = datetime.now(timezone.utc)
            self.db.commit()
            return execution

        # 4. Safe HTTP method validation (GET/HEAD only)
        if endpoint.method.upper() not in ("GET", "HEAD"):
            execution.status = "FAILED"
            execution.result = "ERROR"
            execution.error_category = "unsafe_method"
            execution.result_reason = (
                f"Security testing method '{endpoint.method}' is not permitted. "
                "Only safe methods (GET, HEAD) are allowed."
            )
            execution.completed_at = datetime.now(timezone.utc)
            self.db.commit()
            return execution

        # 5. Fetch or infer Authentication Policy
        policy = (
            self.db.query(AuthenticationPolicy)
            .filter(AuthenticationPolicy.endpoint_id == endpoint.id)
            .first()
        )
        auth_scheme = policy.authentication_scheme if policy else "bearer_token"
        expected_denial_status = policy.expected_denial_status if policy else 401

        # 6. Build Request Headers and Cookies for Test Type
        test_type = security_test.test_type.upper().strip()
        headers: Dict[str, str] = {}
        cookies: Dict[str, str] = {}
        sensitive_values: List[str] = []

        if attacker and attacker.credential_value:
            sensitive_values.append(attacker.credential_value.strip())

        if test_type == "AUTH_MISSING":
            # Strip all authentication parameters
            headers = {}
            cookies = {}

        elif test_type == "AUTH_INVALID":
            # Inject forged / invalid credential
            invalid_token = config.get("invalid_token", "invalid-token-forged-9999")
            sensitive_values.append(invalid_token)
            if auth_scheme == "bearer_token":
                headers["Authorization"] = f"Bearer {invalid_token}"
            elif auth_scheme == "api_key":
                headers["X-API-Key"] = invalid_token
            elif auth_scheme == "basic_auth":
                headers["Authorization"] = "Basic aW52YWxpZDppbnZhbGlk"  # invalid:invalid
            elif auth_scheme == "cookie_session":
                cookies["session"] = invalid_token
            else:
                headers["Authorization"] = f"Bearer {invalid_token}"

        elif test_type == "AUTH_MALFORMED":
            # Inject malformed credential header / format
            if auth_scheme == "bearer_token":
                headers["Authorization"] = "Bearer malformed%%gibberish--invalid"
            elif auth_scheme == "api_key":
                headers["X-API-Key"] = "???malformed???%%"
            elif auth_scheme == "basic_auth":
                headers["Authorization"] = "Basic not-valid-base64%%#$"
            elif auth_scheme == "cookie_session":
                cookies["session"] = "%%malformed%%session"
            else:
                headers["Authorization"] = "Bearer malformed"

        elif test_type == "AUTH_EXPIRED":
            # Inject expired credential
            expired_token = config.get("expired_token", "demo-token-expired")
            sensitive_values.append(expired_token)
            if auth_scheme == "bearer_token":
                headers["Authorization"] = f"Bearer {expired_token}"
            elif auth_scheme == "api_key":
                headers["X-API-Key"] = f"expired-{expired_token}"
            elif auth_scheme == "basic_auth":
                headers["Authorization"] = f"Basic {expired_token}"
            elif auth_scheme == "cookie_session":
                cookies["session"] = expired_token
            else:
                headers["Authorization"] = f"Bearer {expired_token}"

        elif test_type == "AUTH_SCHEME":
            # Inject mismatched scheme
            if auth_scheme == "bearer_token":
                headers["Authorization"] = "Basic dXNlcjpwYXNz"  # Basic scheme instead of Bearer
            elif auth_scheme == "api_key":
                headers["Authorization"] = "Bearer demo-token-alice"
            elif auth_scheme == "basic_auth":
                headers["Authorization"] = "Bearer demo-token-alice"
            elif auth_scheme == "cookie_session":
                headers["Authorization"] = "Bearer demo-token-alice"
            else:
                headers["Authorization"] = "Token raw-token-12345"

        else:
            execution.status = "FAILED"
            execution.result = "ERROR"
            execution.error_category = "unsupported_test_type"
            execution.result_reason = f"Unsupported authentication test type: {test_type}"
            execution.completed_at = datetime.now(timezone.utc)
            self.db.commit()
            return execution

        # 7. Construct target URL and substitute path parameters
        resolved_path = endpoint.path
        path_params = config.get("path_params", {})
        if "{" in resolved_path and "}" in resolved_path:
            for param_key, param_val in path_params.items():
                resolved_path = resolved_path.replace(f"{{{param_key}}}", str(param_val))
            # Substitute remaining {param} with default placeholder '1' or 'auth'
            resolved_path = re.sub(r"\{[^}]+\}", "1", resolved_path)

        base_url = project.base_url.rstrip("/") if project.base_url else "http://localhost:8000"
        if self.app is not None and ("localhost" in base_url or "127.0.0.1" in base_url):
            url = f"http://testserver{resolved_path}"
        else:
            url = f"{base_url}{resolved_path}"

        # 8. Execute HTTP request safely
        client = AsyncSecurityHttpClient(timeout=10.0, follow_redirects=False, app=self.app)
        try:
            http_result: ExecutionResult = await client.execute(
                method=endpoint.method,
                url=url,
                headers=headers,
                cookies=cookies,
                sensitive_values=sensitive_values,
            )
        except Exception as exc:
            execution.status = "FAILED"
            execution.result = "ERROR"
            execution.error_category = "network_error"
            execution.result_reason = f"Request execution failed: {str(exc)}"
            execution.completed_at = datetime.now(timezone.utc)
            self.db.commit()
            return execution

        # 9. Build response signature and evaluate authentication result
        signature: ResponseSignature = ResponseAnalyzer.analyze(
            status_code=http_result.status_code or 0,
            headers=http_result.headers,
            body=http_result.body,
        )

        parsed_json = None
        if signature.is_json:
            try:
                parsed_json = json.loads(http_result.body)
            except Exception:
                parsed_json = None

        outcome_result, reason, finding_type, error_cat = ResponseAnalyzer.evaluate_authentication_result(
            test_type=test_type,
            signature=signature,
            expected_denial_status=expected_denial_status,
            parsed_json=parsed_json,
            raw_text=http_result.body,
        )

        # 10. Update test execution record
        execution.status = "COMPLETED"
        execution.result = outcome_result
        execution.result_reason = reason
        execution.http_status = http_result.status_code
        execution.duration_ms = http_result.duration_ms
        execution.error_category = error_cat
        execution.completed_at = datetime.now(timezone.utc)
        security_test.status = "executed"

        # 11. Process Finding if vulnerability confirmed
        finding_id = None
        if outcome_result == "CONFIRMED" and finding_type:
            # Check for existing open finding (deduplication)
            existing_finding = (
                self.db.query(Finding)
                .filter(
                    Finding.project_id == project.id,
                    Finding.endpoint_id == endpoint.id,
                    Finding.type == finding_type,
                    Finding.status == "OPEN",
                )
                .first()
            )

            severity = "HIGH"
            if finding_type in ("AUTHENTICATION_INCONSISTENCY", "MALFORMED_AUTH_HANDLING"):
                if http_result.status_code == 500:
                    severity = "MEDIUM"
                else:
                    severity = "HIGH"

            title = f"{TITLE_MAP.get(finding_type, 'Authentication Vulnerability')} on {endpoint.method} {endpoint.path}"
            remediation = REMEDIATION_MAP.get(finding_type, "Enforce strict authentication.")

            if existing_finding:
                existing_finding.updated_at = datetime.now(timezone.utc)
                existing_finding.execution_id = execution.id
                existing_finding.actual_behavior = f"HTTP {http_result.status_code}"
                finding_id = existing_finding.id
            else:
                new_finding = Finding(
                    project_id=project.id,
                    security_test_id=security_test.id,
                    execution_id=execution.id,
                    endpoint_id=endpoint.id,
                    attacker_identity_id=attacker.id if attacker else None,
                    attacker_role_id=attacker.role_id if attacker else None,
                    type=finding_type,
                    severity=severity,
                    confidence="HIGH",
                    status="OPEN",
                    title=title,
                    description=reason,
                    expected_authorization=f"HTTP {expected_denial_status} Denial",
                    actual_behavior=f"HTTP {http_result.status_code}",
                    authentication_mechanism=auth_scheme,
                    remediation=remediation,
                )
                self.db.add(new_finding)
                self.db.commit()
                self.db.refresh(new_finding)
                finding_id = new_finding.id

        # 12. Create Evidence Record
        redacted_request_summary = (
            f"{endpoint.method} {url}\n"
            f"Headers: {json.dumps(http_result.redacted_request_headers, indent=2)}"
        )
        evidence = Evidence(
            execution_id=execution.id,
            finding_id=finding_id,
            request_metadata=json.dumps({
                "method": endpoint.method,
                "url": url,
                "headers": http_result.redacted_request_headers,
                "correlation_id": http_result.correlation_id,
                "test_type": test_type,
                "auth_scheme": auth_scheme,
            }),
            response_metadata=json.dumps({
                "status_code": http_result.status_code,
                "duration_ms": http_result.duration_ms,
                "headers": http_result.redacted_headers,
                "is_json": signature.is_json,
                "is_auth_failure": signature.is_auth_failure,
            }),
            expected_behavior=f"Rejection with HTTP {expected_denial_status} or application-level denial",
            actual_behavior=reason,
            redacted_request=redacted_request_summary,
            redacted_response=http_result.redacted_body,
            reproducibility_status="REPRODUCIBLE",
        )
        self.db.add(evidence)
        self.db.commit()
        self.db.refresh(execution)
        return execution
