import json
import re
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
    Resource,
)
from app.services.security_engine.client import AsyncSecurityHttpClient, ExecutionResult
from app.services.security_engine.auth_adapters import AuthAdapter


def substitute_resource_id(path: str, resource_instance_id: Optional[str]) -> str:
    """
    Substitutes path parameter (e.g. {id}, {order_id}) with the given resource instance ID.
    If no placeholder is found and resource_instance_id is provided, appends it as a path segment or query param.
    """
    if not resource_instance_id:
        return path

    # If path has {param} template
    if "{" in path and "}" in path:
        return re.sub(r"\{[^}]+\}", str(resource_instance_id), path, count=1)
    
    # If path ends with trailing slash, append ID
    if path.endswith("/"):
        return f"{path}{resource_instance_id}"
    return f"{path}/{resource_instance_id}"


class BOLAEngine:
    """
    Controlled BOLA (Broken Object Level Authorization) Testing Engine.
    Executes controlled baseline and cross-owner HTTP probes against authorized targets.
    """

    def __init__(self, db: Session, app: Optional[Any] = None):
        self.db = db
        self.app = app

    async def execute_test(self, security_test: SecurityTest) -> TestExecution:
        """
        Executes a single configured BOLA security test and records execution,
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

        # Fetch entities
        project = self.db.query(Project).filter(Project.id == security_test.project_id).first()
        endpoint = self.db.query(Endpoint).filter(Endpoint.id == security_test.endpoint_id).first()
        attacker = self.db.query(Identity).filter(Identity.id == security_test.attacker_identity_id).first()
        victim_ident = (
            self.db.query(Identity).filter(Identity.id == security_test.victim_identity_id).first()
            if security_test.victim_identity_id
            else None
        )
        victim_res = (
            self.db.query(Resource).filter(Resource.id == security_test.victim_resource_id).first()
            if security_test.victim_resource_id
            else None
        )

        # Safety Check: Target authorization check
        if not project or project.authorization_status.lower() != "authorized":
            execution.status = "FAILED"
            execution.result = "ERROR"
            execution.error_category = "unauthorized_target"
            execution.result_reason = "Target project has not been explicitly authorized for security testing."
            execution.completed_at = datetime.now(timezone.utc)
            self.db.commit()
            return execution

        if not endpoint or endpoint.method.upper() not in ["GET", "HEAD"]:
            execution.status = "FAILED"
            execution.result = "ERROR"
            execution.error_category = "unsafe_method"
            execution.result_reason = f"Method '{endpoint.method if endpoint else 'None'}' is not a safe testing method."
            execution.completed_at = datetime.now(timezone.utc)
            self.db.commit()
            return execution

        if not attacker or not attacker.credential_value:
            execution.status = "FAILED"
            execution.result = "ERROR"
            execution.error_category = "missing_credentials"
            execution.result_reason = "Attacker identity does not have configured authentication credentials."
            execution.completed_at = datetime.now(timezone.utc)
            self.db.commit()
            return execution

        # Resolve Base URL
        base_url = (project.base_url or "http://localhost:8000").rstrip("/")
        if not base_url.startswith("http://") and not base_url.startswith("https://"):
            base_url = f"http://{base_url}"

        # Setup Client
        timeout = float(config.get("timeout", 10.0))
        client = AsyncSecurityHttpClient(timeout=timeout, follow_redirects=False, app=self.app)

        # Build headers & cookies using AuthAdapter
        req_headers: Dict[str, str] = dict(config.get("headers", {}))
        req_cookies: Dict[str, str] = dict(config.get("cookies", {}))
        req_headers, req_cookies = AuthAdapter.apply_auth(
            auth_type=attacker.auth_type,
            credential_value=attacker.credential_value,
            headers=req_headers,
            cookies=req_cookies,
            config=config,
        )

        sensitive_values = [attacker.credential_value]
        if victim_ident and victim_ident.credential_value:
            sensitive_values.append(victim_ident.credential_value)

        # A. Baseline Request (optional, if attacker has a known owned resource instance)
        baseline_result: Optional[ExecutionResult] = None
        if security_test.attacker_resource_instance_id:
            baseline_path = substitute_resource_id(endpoint.path, security_test.attacker_resource_instance_id)
            baseline_url = f"{base_url}{baseline_path}"
            baseline_result = await client.execute(
                method=endpoint.method,
                url=baseline_url,
                headers=dict(req_headers),
                cookies=dict(req_cookies),
                sensitive_values=sensitive_values,
            )

        # B. Cross-Owner Request (Attacker targeting Victim instance)
        victim_instance_id = security_test.victim_resource_instance_id or ""
        test_path = substitute_resource_id(endpoint.path, victim_instance_id)
        test_url = f"{base_url}{test_path}"

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

        # Classification Logic
        result, reason, error_category = self._classify_result(
            test_result=test_result,
            victim_instance_id=victim_instance_id,
            baseline_result=baseline_result,
        )

        execution.status = "COMPLETED" if result != "ERROR" else "FAILED"
        execution.result = result
        execution.result_reason = reason
        execution.error_category = error_category

        # Generate Evidence
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
            }),
            expected_behavior="Cross-owner access must be denied with HTTP 401, 403, or 404 without exposing victim resource data.",
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

        # Generate Finding if BOLA is CONFIRMED
        if result == "CONFIRMED":
            severity = config.get("severity", "HIGH").upper()
            if severity not in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                severity = "HIGH"

            victim_name = victim_ident.name if victim_ident else "victim user"
            victim_res_name = victim_res.name if victim_res else "resource"

            finding = Finding(
                project_id=security_test.project_id,
                security_test_id=security_test.id,
                execution_id=execution.id,
                type="BOLA",
                severity=severity,
                confidence="HIGH",
                status="OPEN",
                title="Broken Object Level Authorization",
                description=(
                    f"The endpoint '{endpoint.method} {endpoint.path}' allows authenticated identity '{attacker.name}' "
                    f"to access private {victim_res_name} instance '{victim_instance_id}' belonging to '{victim_name}'. "
                    f"The server failed to enforce object-level authorization on the requested resource."
                ),
                remediation=(
                    "Enforce server-side object-level authorization and verify that the authenticated principal "
                    "is explicitly permitted to access the requested resource before returning it."
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

    def _classify_result(
        self,
        test_result: ExecutionResult,
        victim_instance_id: str,
        baseline_result: Optional[ExecutionResult],
    ) -> Tuple[str, str, Optional[str]]:
        """
        Classifies the BOLA test into PASS, CONFIRMED, INCONCLUSIVE, or ERROR.
        """
        if test_result.error:
            return "ERROR", test_result.error, test_result.error_category or "execution_error"

        status = test_result.status_code
        body = test_result.body

        # HTTP 401, 403, 404 indicate successful object authorization defense
        if status in [401, 403, 404]:
            return "PASS", f"Cross-owner access was properly denied with HTTP {status}.", None

        # HTTP 200 OK: Inspect whether victim resource is returned
        if status == 200:
            if victim_instance_id and victim_instance_id in body:
                return (
                    "CONFIRMED",
                    f"Attacker received victim resource data containing instance ID '{victim_instance_id}' with HTTP 200 OK.",
                    None,
                )
            
            # Check if response has non-empty JSON object indicating success
            try:
                data = json.loads(body)
                if isinstance(data, dict) and len(data) > 0:
                    # If it's a non-empty dict and status is 200, unauthorized resource data was leaked
                    return (
                        "CONFIRMED",
                        "Attacker received an unauthorized object response with HTTP 200 OK.",
                        None,
                    )
            except Exception:
                pass

            if len(body.strip()) > 0:
                return (
                    "CONFIRMED",
                    "Attacker received a successful HTTP 200 OK response with resource payload.",
                    None,
                )

            return "INCONCLUSIVE", "Received HTTP 200 OK, but response body was empty or indeterminate.", None

        if status in [500, 502, 503, 504]:
            return "INCONCLUSIVE", f"Target returned server error HTTP {status}; authorization status cannot be determined.", "server_error"

        return "INCONCLUSIVE", f"Target returned unexpected HTTP status {status}.", "unexpected_status"
