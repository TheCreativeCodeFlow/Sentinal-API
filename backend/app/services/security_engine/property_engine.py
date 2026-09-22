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
    Resource,
    ResourceProperty,
    PropertyAuthorizationRule,
    ResourceOwnership,
)
from app.services.security_engine.client import AsyncSecurityHttpClient, ExecutionResult
from app.services.security_engine.auth_adapters import AuthAdapter
from app.services.security_engine.response_analyzer import ResponseAnalyzer, ResponseSignature


class PropertyExposureEngine:
    """
    Controlled Property-Level Authorization Testing Engine.
    Executes safe GET/HEAD requests to detect unauthorized exposure of protected
    object properties through API responses.
    """

    def __init__(self, db: Session, app: Optional[Any] = None):
        self.db = db
        self.app = app

    async def execute_test(self, security_test: SecurityTest) -> TestExecution:
        """
        Executes a configured PROPERTY_EXPOSURE security test and records execution,
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

        # Resolve tested resource (from security_test.victim_resource_id or endpoint.resource_id)
        resource_id = security_test.victim_resource_id or (endpoint.resource_id if endpoint else None)
        resource = self.db.query(Resource).filter(Resource.id == resource_id).first() if resource_id else None

        # 2. Target authorization validation (SAFETY)
        if not project or project.authorization_status.lower() != "authorized":
            execution.status = "FAILED"
            execution.result = "ERROR"
            execution.error_category = "unauthorized_target"
            execution.result_reason = "Target project has not been explicitly authorized for security testing."
            execution.completed_at = datetime.now(timezone.utc)
            self.db.commit()
            return execution

        # 3. Parameter & configuration validation
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

        if not resource:
            execution.status = "FAILED"
            execution.result = "ERROR"
            execution.error_category = "invalid_configuration"
            execution.result_reason = "Resource not specified or linked to endpoint. Property testing requires an associated resource."
            execution.completed_at = datetime.now(timezone.utc)
            self.db.commit()
            return execution

        # 4. Safe HTTP Method enforcement (GET, HEAD only)
        if endpoint.method.upper() not in ["GET", "HEAD"]:
            execution.status = "FAILED"
            execution.result = "ERROR"
            execution.error_category = "unsafe_method"
            execution.result_reason = f"Method '{endpoint.method}' is not permitted for safe property exposure testing (only GET/HEAD allowed)."
            execution.completed_at = datetime.now(timezone.utc)
            self.db.commit()
            return execution

        # 5. Resolve property authorization rules for the attacker's role
        property_rules = self._resolve_property_rules(resource, attacker, config)

        # 6. Resolve Target URL and substitute path parameters
        base_url = (project.base_url or "http://localhost:8000").rstrip("/")
        if not base_url.startswith("http://") and not base_url.startswith("https://"):
            base_url = f"http://{base_url}"

        test_path = endpoint.path
        if not test_path.startswith("/"):
            test_path = f"/{test_path}"

        # Resolve instance ID if path parameters exist (e.g. {id}, {user_id}, {order_id})
        instance_id = (
            security_test.victim_resource_instance_id
            or self._resolve_resource_instance_id(resource, security_test)
        )

        if "{" in test_path and "}" in test_path:
            if instance_id:
                test_path = re.sub(r"\{[^{}]+\}", str(instance_id), test_path)
            else:
                # Default fallback instance
                test_path = re.sub(r"\{[^{}]+\}", "user_alice_001", test_path)

        test_url = f"{base_url}{test_path}"

        # 7. Credentials setup
        is_anonymous = (
            attacker.auth_type.lower() == "none"
            or attacker.name.lower() == "anonymous"
            or not attacker.credential_value
        )

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

        # 10. Evaluate Property Exposure Outcome
        if test_result.error:
            result = "ERROR"
            reason = test_result.error
            error_category = test_result.error_category or "execution_error"
            exposed_deny_props = []
        else:
            result, reason, exposed_deny_props = ResponseAnalyzer.evaluate_property_exposure(
                signature=signature,
                property_rules=property_rules,
            )
            error_category = None

        execution.result = result
        execution.result_reason = reason
        execution.error_category = error_category
        execution.status = "COMPLETED" if result != "ERROR" else "FAILED"

        role_name = attacker.role.name if attacker.role else "Unassigned"
        deny_props_list = [prop for prop, acc in property_rules.items() if acc.upper() == "DENY"]

        # 11. Create Evidence Record
        evidence = Evidence(
            execution_id=execution.id,
            request_metadata=json.dumps({
                "method": endpoint.method,
                "url": test_url,
                "headers": test_result.redacted_request_headers,
                "attacker_identity": attacker.name,
                "attacker_role": role_name,
                "configured_deny_properties": deny_props_list,
            }),
            response_metadata=json.dumps({
                "status_code": test_result.status_code,
                "headers": test_result.redacted_headers,
                "duration_ms": test_result.duration_ms,
                "all_property_paths": signature.all_property_paths,
                "exposed_deny_properties": exposed_deny_props,
                "candidate_sensitive_properties": signature.candidate_sensitive_properties,
            }),
            expected_behavior=(
                f"Properties marked DENY ({', '.join(deny_props_list) if deny_props_list else 'none'}) "
                f"must be omitted from the response for role '{role_name}'."
            ),
            actual_behavior=(
                f"HTTP {test_result.status_code} returned. "
                + (f"PRESENT IN RESPONSE: {', '.join(exposed_deny_props)}" if exposed_deny_props else reason)
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

        # 12. Create or Update Finding if CONFIRMED (Deduplication)
        if result == "CONFIRMED":
            severity = config.get("severity", "HIGH").upper()
            if severity not in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                severity = "HIGH"

            # Deduplication condition: project, type, endpoint, attacker identity, resource
            existing_finding = self.db.query(Finding).filter(
                Finding.project_id == security_test.project_id,
                Finding.type == "PROPERTY_EXPOSURE",
                Finding.endpoint_id == security_test.endpoint_id,
                Finding.attacker_identity_id == security_test.attacker_identity_id,
                Finding.resource_id == resource.id,
                Finding.status != "RESOLVED",
            ).first()

            if existing_finding:
                existing_finding.execution_id = execution.id
                existing_finding.confidence = "HIGH"
                existing_finding.actual_behavior = f"PRESENT IN RESPONSE: {', '.join(exposed_deny_props)}"
                existing_finding.exposed_properties = json.dumps(exposed_deny_props)
                existing_finding.updated_at = datetime.now(timezone.utc)
                evidence.finding_id = existing_finding.id
            else:
                finding = Finding(
                    project_id=security_test.project_id,
                    security_test_id=security_test.id,
                    execution_id=execution.id,
                    endpoint_id=security_test.endpoint_id,
                    resource_id=resource.id,
                    attacker_identity_id=security_test.attacker_identity_id,
                    attacker_role_id=attacker.role_id,
                    type="PROPERTY_EXPOSURE",
                    severity=severity,
                    confidence="HIGH",
                    status="OPEN",
                    title=f"Property Exposure: Unauthorized properties exposed at {endpoint.method} {endpoint.path}",
                    description=(
                        f"Endpoint exposed {len(exposed_deny_props)} protected propert(ies) "
                        f"({', '.join(exposed_deny_props)}) marked DENY for role '{role_name}'."
                    ),
                    expected_authorization="DENY",
                    actual_behavior=f"PRESENT IN RESPONSE: {', '.join(exposed_deny_props)}",
                    exposed_properties=json.dumps(exposed_deny_props),
                    remediation=(
                        "Filter response serialization schemas to omit protected properties for unauthorized roles, "
                        "or implement field-level data projection/DTO masking before returning HTTP response payloads."
                    ),
                )
                self.db.add(finding)
                self.db.flush()
                evidence.finding_id = finding.id

        self.db.commit()
        return execution

    def _resolve_property_rules(
        self,
        resource: Resource,
        attacker: Identity,
        config: Dict[str, Any],
    ) -> Dict[str, str]:
        """
        Builds a map of {property_name: access} ("ALLOW", "DENY", "UNKNOWN")
        for the attacker's assigned role against the target resource.
        """
        role_id = attacker.role_id
        rules_map: Dict[str, str] = {}

        # 1. Fetch all defined properties on this resource
        properties = (
            self.db.query(ResourceProperty)
            .filter(ResourceProperty.resource_id == resource.id)
            .all()
        )

        for prop in properties:
            # Default access based on sensitivity or UNKNOWN
            default_access = "ALLOW" if prop.sensitivity.upper() == "PUBLIC" else "UNKNOWN"

            # Check if an explicit rule exists for this role
            if role_id:
                rule = (
                    self.db.query(PropertyAuthorizationRule)
                    .filter(
                        PropertyAuthorizationRule.resource_property_id == prop.id,
                        PropertyAuthorizationRule.role_id == role_id,
                    )
                    .first()
                )
                if rule and rule.access:
                    rules_map[prop.name] = rule.access.upper()
                    continue

            rules_map[prop.name] = default_access

        # 2. Allow configuration overrides if provided in test settings
        config_rules = config.get("property_rules", {})
        for prop_name, access in config_rules.items():
            rules_map[prop_name] = access.upper()

        return rules_map

    def _resolve_resource_instance_id(self, resource: Resource, test: SecurityTest) -> Optional[str]:
        """Looks up a known resource instance identifier from ResourceOwnership."""
        ownership = (
            self.db.query(ResourceOwnership)
            .filter(
                ResourceOwnership.resource_id == resource.id,
                ResourceOwnership.resource_instance_id.isnot(None),
            )
            .first()
        )
        if ownership and ownership.resource_instance_id:
            return ownership.resource_instance_id
        return None
