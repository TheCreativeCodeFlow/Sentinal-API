import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple
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
    AuthorizationMatrixRule,
    EndpointAuthorizationPolicy,
)
from app.services.security_engine.client import AsyncSecurityHttpClient, ExecutionResult
from app.services.security_engine.auth_adapters import AuthAdapter
from app.services.security_engine.response_analyzer import ResponseAnalyzer


class BFLAEngine:
    """
    Controlled BFLA (Broken Function Level Authorization) Testing Engine.
    Executes controlled role-boundary probes against authorized targets.
    """

    def __init__(self, db: Session, app: Optional[Any] = None):
        self.db = db
        self.app = app

    async def execute_test(self, security_test: SecurityTest) -> TestExecution:
        """
        Executes a single configured BFLA security test and records execution,
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
        attacker = self.db.query(Identity).filter(Identity.id == security_test.attacker_identity_id).first()

        # 2. Target authorization validation
        if not project or project.authorization_status.lower() != "authorized":
            execution.status = "FAILED"
            execution.result = "ERROR"
            execution.error_category = "unauthorized_target"
            execution.result_reason = "Target project has not been explicitly authorized for security testing."
            execution.completed_at = datetime.now(timezone.utc)
            self.db.commit()
            return execution

        # 3. Ownership & boundary validation
        if not endpoint or not attacker:
            execution.status = "FAILED"
            execution.result = "ERROR"
            execution.error_category = "invalid_configuration"
            execution.result_reason = "Endpoint or attacker identity not found."
            execution.completed_at = datetime.now(timezone.utc)
            self.db.commit()
            return execution

        if attacker.project_id != project.id or (endpoint.api and endpoint.api.project_id != project.id):
            execution.status = "FAILED"
            execution.result = "ERROR"
            execution.error_category = "cross_project_mismatch"
            execution.result_reason = "Attacker identity and endpoint must belong to the target project."
            execution.completed_at = datetime.now(timezone.utc)
            self.db.commit()
            return execution

        # 4. Safe HTTP Method enforcement (GET, HEAD only)
        if endpoint.method.upper() not in ["GET", "HEAD"]:
            execution.status = "FAILED"
            execution.result = "ERROR"
            execution.error_category = "unsafe_method"
            execution.result_reason = f"Method '{endpoint.method}' is not permitted for safe BFLA testing (only GET/HEAD allowed)."
            execution.completed_at = datetime.now(timezone.utc)
            self.db.commit()
            return execution

        # 5. Resolve expected access
        expected_access = self._resolve_expected_access(security_test, endpoint, attacker)

        # 6. Credentials check
        is_anonymous = (
            attacker.auth_type.lower() == "none"
            or attacker.name.lower() == "anonymous"
            or not attacker.credential_value
        )

        # Build request headers and cookies using AuthAdapter if credentials exist
        req_headers: Dict[str, str] = dict(config.get("headers", {}))
        req_cookies: Dict[str, str] = dict(config.get("cookies", {}))
        sensitive_values = []

        if not is_anonymous and attacker.credential_value:
            req_headers, req_cookies = AuthAdapter.apply_auth(
                auth_type=attacker.auth_type,
                credential_value=attacker.credential_value,
                headers=req_headers,
                cookies=req_cookies,
                config=config,
            )
            sensitive_values.append(attacker.credential_value)

        # 7. Resolve Base URL
        base_url = (project.base_url or "http://localhost:8000").rstrip("/")
        if not base_url.startswith("http://") and not base_url.startswith("https://"):
            base_url = f"http://{base_url}"

        # Clean endpoint path
        test_path = endpoint.path
        if not test_path.startswith("/"):
            test_path = f"/{test_path}"
        test_url = f"{base_url}{test_path}"

        # 8. Execute probe request
        timeout = float(config.get("timeout", 10.0))
        client = AsyncSecurityHttpClient(timeout=timeout, follow_redirects=False, app=self.app)

        test_result = await client.execute(
            method=endpoint.method,
            url=test_url,
            headers=dict(req_headers),
            cookies=dict(req_cookies),
            sensitive_values=sensitive_values,
        )

        execution.completed_at = datetime.now(timezone.utc)
        execution.http_status = test_result.status_code
        execution.duration_ms = test_result.duration_ms

        # 9. Response Signature Analysis
        signature = ResponseAnalyzer.analyze(
            status_code=test_result.status_code or 0,
            headers=test_result.redacted_headers,
            body=test_result.body or "",
        )

        # 10. Evaluate authorization boundary outcome
        if test_result.error:
            result = "ERROR"
            reason = test_result.error
            error_category = test_result.error_category or "execution_error"
        else:
            result, reason, error_category = ResponseAnalyzer.evaluate_access(signature, expected_access)

        execution.status = "COMPLETED" if result != "ERROR" else "FAILED"
        execution.result = result
        execution.result_reason = reason
        execution.error_category = error_category

        # 11. Create Evidence record
        evidence = Evidence(
            execution_id=execution.id,
            request_metadata=json.dumps({
                "method": test_result.method,
                "url": test_result.url,
                "correlation_id": test_result.correlation_id,
                "headers": test_result.redacted_request_headers,
            }),
            response_metadata=json.dumps({
                "status_code": test_result.status_code,
                "headers": test_result.redacted_headers,
                "duration_ms": test_result.duration_ms,
                "response_signature": signature.model_dump(),
            }),
            expected_behavior=(
                f"Endpoint access should be {expected_access} for role '{attacker.role.name if attacker.role else 'Unassigned'}'."
            ),
            actual_behavior=(
                f"HTTP {test_result.status_code} returned. {reason}"
                if test_result.status_code
                else f"Execution error: {test_result.error}"
            ),
            redacted_request=json.dumps({
                "method": test_result.method,
                "url": test_result.url,
                "headers": test_result.redacted_request_headers,
            }),
            redacted_response=test_result.redacted_body[:2000] if test_result.redacted_body else (test_result.error or ""),
            reproducibility_status="REPRODUCIBLE" if result in ["CONFIRMED", "PASS"] else "UNVERIFIED",
        )
        self.db.add(evidence)
        self.db.flush()

        # 12. Generate or update Finding if BFLA is CONFIRMED
        if result == "CONFIRMED":
            severity = config.get("severity", "HIGH").upper()
            if severity not in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                severity = "HIGH"

            attacker_role = attacker.role if attacker else None
            role_name = attacker_role.name if attacker_role else "Unassigned"

            # Duplicate Prevention: Look for existing matching finding
            existing_finding = self.db.query(Finding).filter(
                Finding.project_id == security_test.project_id,
                Finding.type == "BFLA",
                Finding.endpoint_id == security_test.endpoint_id,
                Finding.attacker_identity_id == security_test.attacker_identity_id,
                Finding.status != "RESOLVED",
            ).first()

            if existing_finding:
                existing_finding.execution_id = execution.id
                existing_finding.confidence = "HIGH"
                existing_finding.expected_authorization = expected_access
                existing_finding.actual_behavior = reason
                existing_finding.updated_at = datetime.now(timezone.utc)
                evidence.finding_id = existing_finding.id
            else:
                finding = Finding(
                    project_id=security_test.project_id,
                    security_test_id=security_test.id,
                    execution_id=execution.id,
                    endpoint_id=security_test.endpoint_id,
                    attacker_identity_id=security_test.attacker_identity_id,
                    attacker_role_id=attacker_role.id if attacker_role else None,
                    type="BFLA",
                    severity=severity,
                    confidence="HIGH",
                    status="OPEN",
                    title=f"Broken Function Level Authorization on {endpoint.method} {endpoint.path}",
                    description=(
                        f"The endpoint '{endpoint.method} {endpoint.path}' granted access to identity '{attacker.name}' "
                        f"with role '{role_name}' despite expected policy being {expected_access}. "
                        f"The server failed to enforce function-level authorization boundaries."
                    ),
                    expected_authorization=expected_access,
                    actual_behavior=reason,
                    remediation=(
                        "Enforce strict function-level authorization and role-based access control (RBAC) on the endpoint. "
                        "Verify that the caller's role is explicitly authorized before executing administrative operations."
                    ),
                )
                self.db.add(finding)
                self.db.flush()
                evidence.finding_id = finding.id

        # Update test status
        security_test.status = "completed"
        security_test.updated_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(execution)
        return execution

    def _resolve_expected_access(
        self,
        security_test: SecurityTest,
        endpoint: Endpoint,
        attacker: Identity,
    ) -> str:
        """
        Resolves expected access ('ALLOW', 'DENY', 'UNKNOWN') by consulting:
        1. Test explicit expected_access
        2. AuthorizationMatrixRule for (endpoint_id, attacker.role_id, endpoint.method)
        3. EndpointAuthorizationPolicy (allowed_roles / denied_roles / authentication_required)
        4. Default fallback: 'DENY'
        """
        if security_test.expected_access and security_test.expected_access.upper() in ["ALLOW", "DENY"]:
            return security_test.expected_access.upper()

        # Check Matrix rule
        if attacker.role_id:
            rule = (
                self.db.query(AuthorizationMatrixRule)
                .filter(
                    AuthorizationMatrixRule.endpoint_id == endpoint.id,
                    AuthorizationMatrixRule.role_id == attacker.role_id,
                    AuthorizationMatrixRule.http_method == endpoint.method.upper(),
                )
                .first()
            )
            if rule and rule.expected_access in ["ALLOW", "DENY"]:
                return rule.expected_access

        # Check Endpoint Policy
        policy = self.db.query(EndpointAuthorizationPolicy).filter(EndpointAuthorizationPolicy.endpoint_id == endpoint.id).first()
        if policy:
            if attacker.role:
                if any(r.id == attacker.role.id for r in policy.allowed_roles):
                    return "ALLOW"
                if any(r.id == attacker.role.id for r in policy.denied_roles):
                    return "DENY"
            elif policy.authentication_required and (attacker.auth_type == "none" or attacker.name.lower() == "anonymous"):
                return "DENY"

        return "DENY"
