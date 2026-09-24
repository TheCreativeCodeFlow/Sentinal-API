import re
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.models import (
    Workflow,
    WorkflowStep,
    WorkflowState,
    WorkflowTransition,
    WorkflowExecution,
    WorkflowStepExecution,
    Finding,
    Evidence,
    Project,
    Endpoint,
    Identity,
    Role,
)
from app.services.security_engine.client import (
    AsyncSecurityHttpClient,
    ExecutionResult,
    SAFE_HTTP_METHODS,
)
from app.services.security_engine.auth_adapters import AuthAdapter
from app.services.security_engine.redactor import redact_headers, redact_text


def resolve_placeholders_in_string(text: str, context: Dict[str, Any]) -> str:
    """
    Safely resolves supported placeholders in a string:
    - {{token}}
    - {{identity_id}}
    - {{resource_id}}
    - {{previous.status_code}}

    If any unknown placeholder remains like {{foo}}, raises ValueError.
    """
    if not text or "{{" not in text:
        return text

    resolved = text
    token = str(context.get("token", "") or "")
    identity_id = str(context.get("identity_id", "") or "")
    resource_id = str(context.get("resource_id", "") or "")
    prev_status = str(context.get("previous_status_code", "") or "")

    resolved = resolved.replace("{{token}}", token)
    resolved = resolved.replace("{{identity_id}}", identity_id)
    resolved = resolved.replace("{{resource_id}}", resource_id)
    resolved = resolved.replace("{{previous.status_code}}", prev_status)

    # Check for any remaining unknown placeholders
    remaining = re.findall(r"\{\{([^}]+)\}\}", resolved)
    if remaining:
        raise ValueError(
            f"WORKFLOW_CONFIGURATION_ERROR: Unknown or unresolvable placeholder '{{{{{remaining[0]}}}}}'"
        )

    return resolved


def resolve_placeholders_in_object(obj: Any, context: Dict[str, Any]) -> Any:
    """Recursively resolves placeholders in dicts, lists, or strings."""
    if isinstance(obj, str):
        return resolve_placeholders_in_string(obj, context)
    elif isinstance(obj, dict):
        return {k: resolve_placeholders_in_object(v, context) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [resolve_placeholders_in_object(item, context) for item in obj]
    return obj


class WorkflowEngine:
    """
    Stateful Workflow & Business Logic Security Execution Engine.
    Executes ordered GET/HEAD steps across workflow states, validates state transitions,
    captures sanitized evidence, and identifies logic vulnerabilities.
    """

    def __init__(self, db: Session, app: Optional[Any] = None):
        self.db = db
        self.app = app

    async def execute_workflow(
        self,
        workflow: Workflow,
        triggered_by: str = "MANUAL",
    ) -> WorkflowExecution:
        """
        Executes a workflow statefully, validating states and transitions.
        Records WorkflowExecution, WorkflowStepExecution, Evidence, and Findings.
        """
        now = datetime.now(timezone.utc)
        execution = WorkflowExecution(
            workflow_id=workflow.id,
            status="QUEUED",
            triggered_by=triggered_by,
            started_at=now,
        )
        self.db.add(execution)
        self.db.commit()
        self.db.refresh(execution)

        # 1. Pre-flight check: Target project authorization
        project = (
            self.db.query(Project).filter(Project.id == workflow.project_id).first()
        )
        if not project or project.authorization_status.lower() != "authorized":
            execution.status = "FAILED"
            execution.result = "ERROR"
            execution.result_reason = (
                "Target project has not been explicitly authorized for security testing."
            )
            execution.error_message = (
                "Project authorization status is not 'authorized'."
            )
            execution.completed_at = datetime.now(timezone.utc)
            self.db.commit()
            self.db.refresh(execution)
            return execution

        # 2. Pre-flight check: Workflow status must be ACTIVE
        if workflow.status.upper() != "ACTIVE":
            execution.status = "FAILED"
            execution.result = "ERROR"
            execution.result_reason = (
                f"Workflow '{workflow.name}' is in status '{workflow.status}'. "
                f"Only ACTIVE workflows can be executed."
            )
            execution.error_message = (
                f"Workflow status is '{workflow.status}', expected 'ACTIVE'."
            )
            execution.completed_at = datetime.now(timezone.utc)
            self.db.commit()
            self.db.refresh(execution)
            return execution

        # 3. Pre-flight check: Steps must exist
        steps = sorted(workflow.steps, key=lambda s: s.step_order)
        if not steps:
            execution.status = "FAILED"
            execution.result = "ERROR"
            execution.result_reason = "Workflow contains no steps to execute."
            execution.error_message = (
                "WORKFLOW_CONFIGURATION_ERROR: Workflow has no steps."
            )
            execution.completed_at = datetime.now(timezone.utc)
            self.db.commit()
            self.db.refresh(execution)
            return execution

        # 4. Pre-flight check: Exactly ONE initial state
        initial_states = [s for s in workflow.states if s.is_initial]
        if len(initial_states) != 1:
            count = len(initial_states)
            execution.status = "FAILED"
            execution.result = "ERROR"
            execution.result_reason = (
                f"Workflow must have exactly one initial state, but found {count}."
            )
            execution.error_message = (
                f"WORKFLOW_CONFIGURATION_ERROR: Expected exactly 1 initial state, found {count}."
            )
            execution.completed_at = datetime.now(timezone.utc)
            self.db.commit()
            self.db.refresh(execution)
            return execution

        current_state = initial_states[0]
        execution.current_state_id = current_state.id
        execution.status = "RUNNING"
        correlation_id = str(uuid.uuid4())
        execution.correlation_id = correlation_id
        self.db.commit()

        client = AsyncSecurityHttpClient(
            timeout=10.0,
            follow_redirects=False,
            app=self.app,
        )

        previous_status_code: Optional[int] = None
        has_confirmed = False
        has_inconclusive = False
        has_error = False

        for step in steps:
            # 5. Method safety check
            upper_method = step.http_method.upper()
            if upper_method not in SAFE_HTTP_METHODS:
                execution.status = "FAILED"
                execution.result = "ERROR"
                execution.result_reason = (
                    f"Step {step.step_order} specifies disallowed HTTP method '{step.http_method}'. "
                    f"Only safe methods ({', '.join(SAFE_HTTP_METHODS)}) are permitted."
                )
                execution.error_message = f"Unsafe method: {step.http_method}"
                execution.completed_at = datetime.now(timezone.utc)
                self.db.commit()
                self.db.refresh(execution)
                return execution

            endpoint = step.endpoint
            if not endpoint:
                endpoint = (
                    self.db.query(Endpoint)
                    .filter(Endpoint.id == step.endpoint_id)
                    .first()
                )
            if not endpoint:
                execution.status = "FAILED"
                execution.result = "ERROR"
                execution.result_reason = (
                    f"Step {step.step_order} references non-existent endpoint {step.endpoint_id}."
                )
                execution.error_message = "Endpoint not found"
                execution.completed_at = datetime.now(timezone.utc)
                self.db.commit()
                self.db.refresh(execution)
                return execution

            # Identity lookup
            identity = None
            if step.identity_id:
                identity = (
                    self.db.query(Identity)
                    .filter(Identity.id == step.identity_id)
                    .first()
                )

            # Build placeholder context
            token_val = identity.credential_value if (identity and identity.credential_value) else ""
            res_val = str(endpoint.resource_id) if endpoint.resource_id else ""
            context = {
                "token": token_val,
                "identity_id": identity.id if identity else "",
                "resource_id": res_val,
                "previous_status_code": (
                    str(previous_status_code)
                    if previous_status_code is not None
                    else ""
                ),
            }

            # Resolve placeholders in path and request_template
            raw_path = endpoint.path
            template = step.request_template or {}

            try:
                resolved_path = resolve_placeholders_in_string(raw_path, context)
                resolved_template = resolve_placeholders_in_object(template, context)
            except ValueError as exc:
                step_exec = WorkflowStepExecution(
                    workflow_execution_id=execution.id,
                    step_id=step.id,
                    step_order=step.step_order,
                    http_method=upper_method,
                    endpoint_path=raw_path,
                    status="ERROR",
                    state_before=current_state.name,
                    state_after=current_state.name,
                    error_message=str(exc),
                )
                self.db.add(step_exec)
                execution.status = "FAILED"
                execution.result = "ERROR"
                execution.result_reason = str(exc)
                execution.error_message = str(exc)
                execution.completed_at = datetime.now(timezone.utc)
                self.db.commit()
                self.db.refresh(execution)
                return execution

            # Resolve OpenAPI path parameters (e.g. {order_id} or {id})
            path_params = dict(resolved_template.get("path_params", {}))
            for k, v in list(resolved_template.get("params", {}).items()) + list(resolved_template.get("query_params", {}).items()):
                if f"{{{k}}}" in resolved_path:
                    path_params[k] = v

            for p_k, p_v in path_params.items():
                resolved_path = resolved_path.replace(f"{{{p_k}}}", str(p_v))

            if "{" in resolved_path and "}" in resolved_path and context.get("resource_id"):
                resolved_path = re.sub(r"\{[a-zA-Z0-9_]+\}", str(context["resource_id"]), resolved_path, count=1)

            # Build URL
            base_url = project.base_url or ""
            if base_url:
                target_url = (
                    f"{base_url.rstrip('/')}/{resolved_path.lstrip('/')}"
                )
            else:
                target_url = resolved_path

            # Request headers, cookies, params
            req_headers = dict(resolved_template.get("headers", {}))
            req_cookies = dict(resolved_template.get("cookies", {}))
            req_params = {
                k: v
                for k, v in dict(
                    resolved_template.get(
                        "query_params", resolved_template.get("params", {})
                    )
                ).items()
                if f"{{{k}}}" not in raw_path
            }

            # Apply authentication if identity credentials exist
            sensitive_values = []
            if identity and identity.credential_value:
                req_headers, req_cookies = AuthAdapter.apply_auth(
                    auth_type=identity.auth_type,
                    credential_value=identity.credential_value,
                    headers=req_headers,
                    cookies=req_cookies,
                )
                sensitive_values.append(identity.credential_value.strip())

            # Look up transition from current state for this step
            transition = (
                self.db.query(WorkflowTransition)
                .filter(
                    WorkflowTransition.workflow_id == workflow.id,
                    WorkflowTransition.from_state_id == current_state.id,
                    WorkflowTransition.step_id == step.id,
                )
                .first()
            )
            # Fallback to wildcard transition (step_id is None) from current state
            if not transition:
                transition = (
                    self.db.query(WorkflowTransition)
                    .filter(
                        WorkflowTransition.workflow_id == workflow.id,
                        WorkflowTransition.from_state_id == current_state.id,
                        WorkflowTransition.step_id == None,
                    )
                    .first()
                )

            step_cid = f"{correlation_id}-step-{step.step_order}"
            state_before = current_state

            # Execute HTTP request
            res: ExecutionResult = await client.execute(
                method=upper_method,
                url=target_url,
                headers=req_headers,
                cookies=req_cookies,
                params=req_params,
                correlation_id=step_cid,
                sensitive_values=sensitive_values,
            )

            previous_status_code = res.status_code

            # Determine if target endpoint accepted the request
            expected_codes = step.expected_status_codes or [200]
            if res.status_code is not None:
                request_succeeded = res.status_code in expected_codes or (
                    not step.expected_status_codes
                    and 200 <= res.status_code < 300
                )
            else:
                request_succeeded = False

            # Request and response summaries for sanitized evidence/metadata
            req_summary = {
                "method": upper_method,
                "url": target_url,
                "path": resolved_path,
                "headers": redact_headers(req_headers),
                "params": req_params,
                "correlation_id": step_cid,
            }
            resp_summary = {
                "status_code": res.status_code,
                "latency_ms": res.duration_ms,
                "headers": res.redacted_headers,
                "correlation_id": step_cid,
                "error": res.error,
            }

            # Evaluate step transition and security result
            finding_to_create = None

            if res.error or res.status_code is None or (res.status_code >= 500 and 500 not in expected_codes):
                step_status = "INCONCLUSIVE"
                trans_result = "INCONCLUSIVE"
                state_after = current_state
                has_inconclusive = True
                step_error = res.error or f"Target returned unexpected HTTP {res.status_code}"
            elif transition is not None:
                if transition.expected_behavior == "ALLOW":
                    if request_succeeded:
                        step_status = "PASS"
                        trans_result = "VALID"
                        state_after = transition.to_state
                        current_state = transition.to_state
                    else:
                        step_status = "ERROR"
                        trans_result = "UNEXPECTED_STATE"
                        state_after = current_state
                        has_error = True
                        step_error = f"Expected transition ALLOW with status in {expected_codes}, got HTTP {res.status_code}"
                else:  # expected_behavior == "DENY"
                    if request_succeeded:
                        # VULNERABILITY: Endpoint permitted an invalid state transition!
                        step_status = "CONFIRMED"
                        trans_result = "INVALID_STATE_TRANSITION"
                        state_after = transition.to_state
                        current_state = transition.to_state
                        has_confirmed = True

                        finding_to_create = {
                            "type": "INVALID_STATE_TRANSITION",
                            "severity": "HIGH",
                            "title": (
                                f"Invalid State Transition: {state_before.name} -> {transition.to_state.name} "
                                f"on {upper_method} {endpoint.path}"
                            ),
                            "description": (
                                f"In step {step.step_order} ('{step.name}'), the server permitted a state transition "
                                f"from '{state_before.name}' to '{transition.to_state.name}' despite workflow policy requiring DENY. "
                                f"The API failed to enforce server-side business logic and state machine constraints."
                            ),
                            "expected_authorization": "DENY",
                            "actual_behavior": f"HTTP {res.status_code} OK (Expected denial in state '{state_before.name}')",
                            "remediation": (
                                "Enforce strict server-side state checks before processing entity state mutations. "
                                "Reject disallowed state transitions with HTTP 400 Bad Request or HTTP 409 Conflict."
                            ),
                        }
                    else:
                        # Denied as expected!
                        step_status = "PASS"
                        trans_result = "VALID"
                        state_after = current_state
            else:
                # No transition defined from current_state for this step
                if request_succeeded:
                    step_status = "CONFIRMED"
                    trans_result = "UNEXPECTED_STATE"
                    state_after = current_state
                    has_confirmed = True

                    finding_to_create = {
                        "type": "UNEXPECTED_WORKFLOW_STATE",
                        "severity": "MEDIUM",
                        "title": f"Unexpected Workflow State Transition on {upper_method} {endpoint.path}",
                        "description": (
                            f"Step {step.step_order} ('{step.name}') executed successfully in state '{current_state.name}', "
                            f"where no transition was defined or expected."
                        ),
                        "expected_authorization": "DENY",
                        "actual_behavior": f"HTTP {res.status_code} OK in undefined transition state",
                        "remediation": "Define explicit state machine transition boundaries and reject requests from invalid precursor states.",
                    }
                else:
                    step_status = "PASS"
                    trans_result = "VALID"
                    state_after = current_state

            # Record WorkflowStepExecution
            step_exec = WorkflowStepExecution(
                workflow_execution_id=execution.id,
                step_id=step.id,
                step_order=step.step_order,
                http_method=upper_method,
                endpoint_path=endpoint.path,
                status=step_status,
                request_summary=req_summary,
                response_summary=resp_summary,
                status_code=res.status_code,
                latency_ms=res.duration_ms,
                state_before=state_before.name,
                state_after=state_after.name,
                transition_expected=(
                    transition.expected_behavior if transition else None
                ),
                transition_result=trans_result,
                correlation_id=step_cid,
                error_message=res.error,
            )
            self.db.add(step_exec)
            self.db.flush()

            # Record Evidence
            evidence = Evidence(
                workflow_execution_id=execution.id,
                workflow_step_execution_id=step_exec.id,
                request_metadata=json.dumps(req_summary),
                response_metadata=json.dumps(resp_summary),
                expected_behavior=(
                    f"Transition from '{state_before.name}': {transition.expected_behavior if transition else 'NO_TRANSITION'}"
                ),
                actual_behavior=(
                    f"HTTP {res.status_code} - Result: {trans_result}"
                ),
                redacted_request=f"{upper_method} {target_url}\n{json.dumps(req_summary['headers'], indent=2)}",
                redacted_response=res.redacted_body[:3000] if res.redacted_body else (res.error or ""),
                reproducibility_status="REPRODUCIBLE",
            )
            self.db.add(evidence)
            self.db.flush()

            # Create or update Finding if vulnerability found
            if finding_to_create:
                # Deduplication: look for existing open finding for this workflow & endpoint
                existing_finding = (
                    self.db.query(Finding)
                    .filter(
                        Finding.project_id == project.id,
                        Finding.type == finding_to_create["type"],
                        Finding.workflow_id == workflow.id,
                        Finding.endpoint_id == endpoint.id,
                        Finding.status != "RESOLVED",
                    )
                    .first()
                )

                attacker_role_id = None
                if identity and identity.role_id:
                    attacker_role_id = identity.role_id

                if existing_finding:
                    existing_finding.workflow_execution_id = execution.id
                    existing_finding.workflow_step_id = step.id
                    existing_finding.actual_behavior = finding_to_create["actual_behavior"]
                    existing_finding.updated_at = datetime.now(timezone.utc)
                    evidence.finding_id = existing_finding.id
                else:
                    new_finding = Finding(
                        project_id=project.id,
                        workflow_id=workflow.id,
                        workflow_execution_id=execution.id,
                        workflow_step_id=step.id,
                        endpoint_id=endpoint.id,
                        attacker_identity_id=identity.id if identity else None,
                        attacker_role_id=attacker_role_id,
                        type=finding_to_create["type"],
                        severity=finding_to_create["severity"],
                        confidence="HIGH",
                        status="OPEN",
                        title=finding_to_create["title"],
                        description=finding_to_create["description"],
                        expected_authorization=finding_to_create["expected_authorization"],
                        actual_behavior=finding_to_create["actual_behavior"],
                        remediation=finding_to_create["remediation"],
                    )
                    self.db.add(new_finding)
                    self.db.flush()
                    evidence.finding_id = new_finding.id

            # Update execution current state
            execution.current_state_id = current_state.id
            self.db.commit()

            # Break early if inconclusive connection error/timeout
            if step_status == "INCONCLUSIVE":
                break

        # 6. Finalize execution status and result
        execution.completed_at = datetime.now(timezone.utc)
        if has_confirmed:
            execution.status = "COMPLETED"
            execution.result = "CONFIRMED"
            execution.result_reason = (
                "Workflow execution identified unauthorized state transition vulnerabilities."
            )
        elif has_inconclusive:
            execution.status = "COMPLETED"
            execution.result = "INCONCLUSIVE"
            execution.result_reason = (
                "Workflow execution was inconclusive due to network or server failure."
            )
        elif has_error:
            execution.status = "FAILED"
            execution.result = "ERROR"
            execution.result_reason = (
                "Workflow execution failed due to an unexpected step response."
            )
        else:
            execution.status = "COMPLETED"
            execution.result = "PASS"
            execution.result_reason = (
                "All workflow steps completed successfully and state transitions behaved as expected."
            )

        self.db.commit()
        self.db.refresh(execution)
        return execution
