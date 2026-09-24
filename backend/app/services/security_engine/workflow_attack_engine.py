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
    WorkflowAttackScenario,
    WorkflowAttackStep,
    Finding,
    Evidence,
    Project,
    Endpoint,
    Identity,
)
from app.services.security_engine.client import (
    AsyncSecurityHttpClient,
    ExecutionResult,
    SAFE_HTTP_METHODS,
)
from app.services.security_engine.auth_adapters import AuthAdapter
from app.services.security_engine.redactor import redact_headers, redact_text
from app.services.security_engine.workflow_engine import (
    resolve_placeholders_in_string,
    resolve_placeholders_in_object,
)


SCENARIO_TYPE_TO_FINDING_TYPE = {
    "INVALID_STATE_TRANSITION": "INVALID_STATE_TRANSITION",
    "STEP_REPLAY": "WORKFLOW_STEP_REPLAY",
    "STEP_SKIP": "WORKFLOW_STEP_SKIPPING",
    "STEP_REORDER": "WORKFLOW_STEP_REORDER",
    "IDENTITY_SWITCH": "WORKFLOW_IDENTITY_SWITCH",
    "CROSS_IDENTITY_CONTINUATION": "WORKFLOW_CROSS_IDENTITY_ACCESS",
}


class WorkflowAttackEngine:
    """
    Stateful Attack Scenario Execution Engine.
    Executes controlled adversarial workflow sequences against target endpoints using safe GET/HEAD requests.
    Validates state invariants, records attack step traces and evidence chains,
    and identifies business logic vulnerabilities.
    """

    def __init__(self, db: Session, app: Optional[Any] = None):
        self.db = db
        self.app = app

    async def execute_scenario(
        self,
        scenario: WorkflowAttackScenario,
        triggered_by: str = "MANUAL",
    ) -> WorkflowExecution:
        """
        Executes an attack scenario statefully and records results, step traces, evidence chain, and findings.
        """
        now = datetime.now(timezone.utc)
        execution = WorkflowExecution(
            workflow_id=scenario.workflow_id,
            attack_scenario_id=scenario.id,
            status="QUEUED",
            triggered_by=triggered_by,
            started_at=now,
        )
        self.db.add(execution)
        self.db.commit()
        self.db.refresh(execution)

        workflow = scenario.workflow
        if not workflow:
            workflow = (
                self.db.query(Workflow)
                .filter(Workflow.id == scenario.workflow_id)
                .first()
            )

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

        # 2. Pre-flight check: Workflow and Scenario must be ACTIVE
        if workflow.status.upper() != "ACTIVE":
            execution.status = "FAILED"
            execution.result = "ERROR"
            execution.result_reason = (
                f"Workflow '{workflow.name}' is in status '{workflow.status}'. "
                f"Only ACTIVE workflows can be executed."
            )
            execution.error_message = f"Workflow status is '{workflow.status}', expected 'ACTIVE'."
            execution.completed_at = datetime.now(timezone.utc)
            self.db.commit()
            self.db.refresh(execution)
            return execution

        if scenario.status.upper() != "ACTIVE":
            execution.status = "FAILED"
            execution.result = "ERROR"
            execution.result_reason = (
                f"Attack scenario '{scenario.name}' is in status '{scenario.status}'. "
                f"Only ACTIVE scenarios can be executed."
            )
            execution.error_message = f"Scenario status is '{scenario.status}', expected 'ACTIVE'."
            execution.completed_at = datetime.now(timezone.utc)
            self.db.commit()
            self.db.refresh(execution)
            return execution

        # 3. Pre-flight check: Cross-project validation
        for step in scenario.steps:
            if step.source_step_id:
                src = (
                    self.db.query(WorkflowStep)
                    .filter(WorkflowStep.id == step.source_step_id)
                    .first()
                )
                if not src or src.workflow.project_id != project.id:
                    execution.status = "FAILED"
                    execution.result = "ERROR"
                    execution.result_reason = "Cross-project reference detected in attack step source."
                    execution.error_message = "Source step belongs to a different project."
                    execution.completed_at = datetime.now(timezone.utc)
                    self.db.commit()
                    self.db.refresh(execution)
                    return execution
            if step.identity_id:
                ident = (
                    self.db.query(Identity)
                    .filter(Identity.id == step.identity_id)
                    .first()
                )
                if not ident or ident.project_id != project.id:
                    execution.status = "FAILED"
                    execution.result = "ERROR"
                    execution.result_reason = "Cross-project reference detected in attack step identity."
                    execution.error_message = "Identity belongs to a different project."
                    execution.completed_at = datetime.now(timezone.utc)
                    self.db.commit()
                    self.db.refresh(execution)
                    return execution

        # 4. Pre-flight check: Initial state
        initial_states = [s for s in workflow.states if s.is_initial]
        if len(initial_states) != 1:
            count = len(initial_states)
            execution.status = "FAILED"
            execution.result = "ERROR"
            execution.result_reason = (
                f"Workflow must have exactly one initial state, but found {count}."
            )
            execution.error_message = f"Expected 1 initial state, found {count}."
            execution.completed_at = datetime.now(timezone.utc)
            self.db.commit()
            self.db.refresh(execution)
            return execution

        # 5. Attack steps
        attack_steps = sorted(scenario.steps, key=lambda s: s.position)
        if not attack_steps:
            execution.status = "FAILED"
            execution.result = "ERROR"
            execution.result_reason = "Attack scenario contains no steps to execute."
            execution.error_message = "Scenario has no attack steps."
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
        evidence_chain: List[Dict[str, Any]] = []
        has_confirmed = False
        has_inconclusive = False
        has_error = False

        violating_step_data: Optional[Dict[str, Any]] = None
        last_step_exec_id: Optional[str] = None

        for attack_step in attack_steps:
            action = attack_step.action.upper()
            expected_behavior = attack_step.expected_behavior.upper()
            source_step = attack_step.source_step
            if not source_step and attack_step.source_step_id:
                source_step = (
                    self.db.query(WorkflowStep)
                    .filter(WorkflowStep.id == attack_step.source_step_id)
                    .first()
                )

            # --- A. ACTION: SKIP ---
            if action == "SKIP":
                step_cid = f"{correlation_id}-step-{attack_step.position}"
                step_exec = WorkflowStepExecution(
                    workflow_execution_id=execution.id,
                    attack_step_id=attack_step.id,
                    step_id=source_step.id if source_step else None,
                    step_order=attack_step.position,
                    http_method=source_step.http_method if source_step else "GET",
                    endpoint_path=source_step.endpoint.path if (source_step and source_step.endpoint) else None,
                    action="SKIP",
                    identity_id=attack_step.identity_id or (source_step.identity_id if source_step else None),
                    identity_name="None (Skipped)",
                    status="PASS",
                    latency_ms=0,
                    state_before=current_state.name,
                    state_after=current_state.name,
                    transition_expected=expected_behavior,
                    transition_result="SKIPPED",
                    correlation_id=step_cid,
                    request_summary={"action": "SKIP", "notes": "Step deliberately omitted from execution sequence"},
                    response_summary={"status": "SKIPPED"},
                )
                self.db.add(step_exec)
                self.db.commit()
                self.db.refresh(step_exec)
                last_step_exec_id = step_exec.id

                evidence_chain.append(
                    {
                        "position": attack_step.position,
                        "action": "SKIP",
                        "identity": "Skipped",
                        "endpoint": (
                            f"[{source_step.http_method}] {source_step.endpoint.path}"
                            if (source_step and source_step.endpoint)
                            else "N/A"
                        ),
                        "status": "SKIPPED",
                        "state_before": current_state.name,
                        "state_after": current_state.name,
                        "expected_behavior": expected_behavior,
                        "is_violating_step": False,
                    }
                )
                continue

            # --- B. ACTIONS: EXECUTE, REPLAY, SWITCH_IDENTITY ---
            if not source_step:
                execution.status = "FAILED"
                execution.result = "ERROR"
                execution.result_reason = f"Attack step #{attack_step.position} has no associated source workflow step."
                execution.error_message = "Missing source step"
                execution.completed_at = datetime.now(timezone.utc)
                self.db.commit()
                self.db.refresh(execution)
                return execution

            upper_method = source_step.http_method.upper()
            if upper_method not in SAFE_HTTP_METHODS:
                execution.status = "FAILED"
                execution.result = "ERROR"
                execution.result_reason = (
                    f"Attack step #{attack_step.position} specifies non-safe method '{source_step.http_method}'. "
                    f"Only safe methods ({', '.join(SAFE_HTTP_METHODS)}) are allowed."
                )
                execution.error_message = f"Disallowed method: {source_step.http_method}"
                execution.completed_at = datetime.now(timezone.utc)
                self.db.commit()
                self.db.refresh(execution)
                return execution

            endpoint = source_step.endpoint
            if not endpoint:
                endpoint = (
                    self.db.query(Endpoint)
                    .filter(Endpoint.id == source_step.endpoint_id)
                    .first()
                )
            if not endpoint:
                execution.status = "FAILED"
                execution.result = "ERROR"
                execution.result_reason = f"Step references missing endpoint {source_step.endpoint_id}."
                execution.error_message = "Endpoint not found"
                execution.completed_at = datetime.now(timezone.utc)
                self.db.commit()
                self.db.refresh(execution)
                return execution

            # Resolve Identity
            identity = None
            ident_id_to_use = attack_step.identity_id or source_step.identity_id
            if ident_id_to_use:
                identity = (
                    self.db.query(Identity)
                    .filter(Identity.id == ident_id_to_use)
                    .first()
                )
            identity_name = identity.name if identity else "Anonymous"

            # Context for placeholders
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

            raw_path = endpoint.path
            template = dict(source_step.request_template or {})

            # Merge any configuration overrides
            if attack_step.configuration:
                if "params" in attack_step.configuration:
                    template.setdefault("params", {}).update(attack_step.configuration["params"])
                if "path_params" in attack_step.configuration:
                    template.setdefault("path_params", {}).update(attack_step.configuration["path_params"])
                if "headers" in attack_step.configuration:
                    template.setdefault("headers", {}).update(attack_step.configuration["headers"])

            try:
                resolved_path = resolve_placeholders_in_string(raw_path, context)
                resolved_template = resolve_placeholders_in_object(template, context)
            except ValueError as exc:
                step_exec = WorkflowStepExecution(
                    workflow_execution_id=execution.id,
                    attack_step_id=attack_step.id,
                    step_id=source_step.id,
                    step_order=attack_step.position,
                    http_method=upper_method,
                    endpoint_path=raw_path,
                    action=action,
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

            # Resolve path parameters (e.g. {order_id})
            path_params = dict(resolved_template.get("path_params", {}))
            for k, v in list(resolved_template.get("params", {}).items()) + list(resolved_template.get("query_params", {}).items()):
                if f"{{{k}}}" in resolved_path:
                    path_params[k] = v

            for p_k, p_v in path_params.items():
                resolved_path = resolved_path.replace(f"{{{p_k}}}", str(p_v))

            if "{" in resolved_path and "}" in resolved_path and context.get("resource_id"):
                resolved_path = re.sub(r"\{[a-zA-Z0-9_]+\}", str(context["resource_id"]), resolved_path, count=1)

            # URL and Parameters
            base_url = project.base_url or ""
            target_url = (
                f"{base_url.rstrip('/')}/{resolved_path.lstrip('/')}"
                if base_url
                else resolved_path
            )

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

            sensitive_values = []
            if identity and identity.credential_value:
                req_headers, req_cookies = AuthAdapter.apply_auth(
                    auth_type=identity.auth_type,
                    credential_value=identity.credential_value,
                    headers=req_headers,
                    cookies=req_cookies,
                )
                sensitive_values.append(identity.credential_value.strip())

            # Transition lookup
            transition = (
                self.db.query(WorkflowTransition)
                .filter(
                    WorkflowTransition.workflow_id == workflow.id,
                    WorkflowTransition.from_state_id == current_state.id,
                    WorkflowTransition.step_id == source_step.id,
                )
                .first()
            )
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

            step_cid = f"{correlation_id}-step-{attack_step.position}"
            state_before = current_state

            # HTTP Request Execution
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

            # Summaries for evidence
            req_summary = {
                "method": upper_method,
                "url": target_url,
                "path": resolved_path,
                "headers": redact_headers(req_headers),
                "params": req_params,
                "correlation_id": step_cid,
                "identity": identity_name,
                "action": action,
            }
            resp_summary = {
                "status_code": res.status_code,
                "latency_ms": res.duration_ms,
                "headers": res.redacted_headers,
                "body": res.body,
                "correlation_id": step_cid,
                "error": res.error,
            }

            state_after = current_state
            is_violating = False

            # Check response body for soft denial / error
            resp_body_str = (res.body or "").lower() if res.body else ""
            is_soft_denial = any(
                term in resp_body_str
                for term in [
                    "access denied",
                    "forbidden",
                    "unauthorized",
                    "invalid state",
                    "cannot refund",
                    "cannot pay",
                    "cannot cancel",
                    "belongs to a different",
                ]
            )

            if res.error or res.status_code is None or res.status_code >= 500:
                step_status = "INCONCLUSIVE"
                trans_result = "INCONCLUSIVE"
                has_inconclusive = True
                step_error = res.error or f"Target returned unexpected HTTP {res.status_code}"
            elif expected_behavior == "DENY":
                # Forbidden action expected to be rejected
                if 200 <= res.status_code < 300 and not is_soft_denial:
                    # VULNERABILITY CONFIRMED! Target accepted adversarial action!
                    step_status = "CONFIRMED"
                    trans_result = "FORBIDDEN_ACTION_ACCEPTED"
                    has_confirmed = True
                    is_violating = True

                    if transition and transition.to_state:
                        state_after = transition.to_state
                        current_state = transition.to_state

                    violating_step_data = {
                        "position": attack_step.position,
                        "action": action,
                        "source_step": source_step,
                        "endpoint": endpoint,
                        "identity": identity,
                        "state_before": state_before,
                        "state_after": state_after,
                        "status_code": res.status_code,
                        "req_summary": req_summary,
                        "resp_summary": resp_summary,
                    }
                elif res.status_code in (400, 401, 403, 404, 409, 422) or is_soft_denial:
                    # Correctly rejected!
                    step_status = "PASS"
                    trans_result = "CORRECTLY_DENIED"
                    state_after = current_state
                else:
                    step_status = "INCONCLUSIVE"
                    trans_result = "INCONCLUSIVE"
                    has_inconclusive = True
            else:  # expected_behavior == "ALLOW"
                if 200 <= res.status_code < 300 and not is_soft_denial:
                    step_status = "PASS"
                    trans_result = "VALID"
                    if transition and transition.to_state:
                        state_after = transition.to_state
                        current_state = transition.to_state
                elif res.status_code in (400, 401, 403, 404, 409, 422) or is_soft_denial:
                    step_status = "ERROR"
                    trans_result = "PREREQUISITE_FAILED"
                    has_error = True
                else:
                    step_status = "INCONCLUSIVE"
                    trans_result = "INCONCLUSIVE"
                    has_inconclusive = True

            step_exec = WorkflowStepExecution(
                workflow_execution_id=execution.id,
                attack_step_id=attack_step.id,
                step_id=source_step.id,
                step_order=attack_step.position,
                http_method=upper_method,
                endpoint_path=resolved_path,
                action=action,
                identity_id=identity.id if identity else None,
                identity_name=identity_name,
                status=step_status,
                request_summary=req_summary,
                response_summary=resp_summary,
                status_code=res.status_code,
                latency_ms=res.duration_ms,
                state_before=state_before.name,
                state_after=state_after.name,
                transition_expected=expected_behavior,
                transition_result=trans_result,
                correlation_id=step_cid,
                error_message=res.error if res.error else None,
            )
            self.db.add(step_exec)
            self.db.commit()
            self.db.refresh(step_exec)
            last_step_exec_id = step_exec.id

            evidence_chain.append(
                {
                    "position": attack_step.position,
                    "action": action,
                    "identity": identity_name,
                    "endpoint": f"[{upper_method}] {resolved_path}",
                    "status": res.status_code,
                    "state_before": state_before.name,
                    "state_after": state_after.name,
                    "expected_behavior": expected_behavior,
                    "is_violating_step": is_violating,
                }
            )

        # 6. Overall Classification & Findings
        execution.completed_at = datetime.now(timezone.utc)
        execution.current_state_id = current_state.id

        finding_created = None

        if has_confirmed and violating_step_data:
            execution.result = "CONFIRMED"
            execution.status = "COMPLETED"
            execution.result_reason = (
                f"Adversarial scenario '{scenario.name}' ({scenario.scenario_type}) accepted by target: "
                f"Step #{violating_step_data['position']} allowed forbidden action '{violating_step_data['action']}' "
                f"with HTTP {violating_step_data['status_code']}."
            )

            # Map scenario type to finding type
            f_type = SCENARIO_TYPE_TO_FINDING_TYPE.get(
                scenario.scenario_type, "INVALID_STATE_TRANSITION"
            )
            violating_step = violating_step_data["source_step"]
            violating_endpoint = violating_step_data["endpoint"]
            violating_identity = violating_step_data["identity"]

            # Deduplication: check for open finding
            existing_finding = (
                self.db.query(Finding)
                .filter(
                    Finding.project_id == project.id,
                    Finding.workflow_id == workflow.id,
                    Finding.endpoint_id == violating_endpoint.id,
                    Finding.type == f_type,
                    Finding.status == "OPEN",
                )
                .first()
            )

            title = (
                f"Stateful Workflow Vulnerability ({scenario.scenario_type}): "
                f"[{violating_step.http_method}] {violating_endpoint.path}"
            )
            description = (
                f"In adversarial scenario '{scenario.name}' ({scenario.scenario_type}), "
                f"the server accepted a forbidden sequence transition at step #{violating_step_data['position']} "
                f"('{violating_step.name}'). The API returned HTTP {violating_step_data['status_code']} "
                f"when DENY was expected. State changed from '{violating_step_data['state_before'].name}' "
                f"to '{violating_step_data['state_after'].name}'."
            )
            remediation = (
                "Enforce strict server-side state machine authorization and sequence validation. "
                "Ensure steps cannot be replayed, skipped, reordered, or executed under switched identities "
                "without proper authorization checks."
            )

            if existing_finding:
                finding_created = existing_finding
            else:
                finding_created = Finding(
                    project_id=project.id,
                    workflow_id=workflow.id,
                    workflow_execution_id=execution.id,
                    workflow_step_id=violating_step.id,
                    attack_scenario_id=scenario.id,
                    endpoint_id=violating_endpoint.id,
                    attacker_identity_id=violating_identity.id if violating_identity else None,
                    attacker_role_id=violating_identity.role_id if violating_identity else None,
                    type=f_type,
                    severity="HIGH",
                    confidence="HIGH",
                    status="OPEN",
                    title=title,
                    description=description,
                    expected_authorization="DENY",
                    actual_behavior=f"HTTP {violating_step_data['status_code']} OK (Accepted forbidden adversarial action)",
                    remediation=remediation,
                )
                self.db.add(finding_created)
                self.db.commit()
                self.db.refresh(finding_created)

            # Create Evidence chain
            violating_pos = violating_step_data["position"]
            chain_evidence = Evidence(
                workflow_execution_id=execution.id,
                workflow_step_execution_id=last_step_exec_id,
                attack_scenario_id=scenario.id,
                finding_id=finding_created.id,
                request_metadata=json.dumps(
                    {
                        "scenario_name": scenario.name,
                        "scenario_type": scenario.scenario_type,
                        "violating_step_position": violating_pos,
                        "attack_sequence_chain": evidence_chain,
                    }
                ),
                response_metadata=json.dumps(violating_step_data["resp_summary"]),
                expected_behavior="DENY (Reject adversarial sequence or invalid state transition)",
                actual_behavior=(
                    f"HTTP {violating_step_data['status_code']} OK: Target accepted forbidden "
                    f"action '{violating_step_data['action']}' at step #{violating_pos}"
                ),
                redacted_request=json.dumps(violating_step_data["req_summary"], indent=2),
                redacted_response=json.dumps(violating_step_data["resp_summary"], indent=2),
                reproducibility_status="REPRODUCIBLE",
            )
            self.db.add(chain_evidence)
            self.db.commit()

        elif has_inconclusive:
            execution.result = "INCONCLUSIVE"
            execution.status = "COMPLETED"
            execution.result_reason = (
                "Attack scenario was inconclusive due to target server error (5xx) or timeout."
            )
        elif has_error:
            execution.result = "ERROR"
            execution.status = "FAILED"
            execution.result_reason = (
                "Attack scenario encountered an error executing prerequisite steps."
            )
        else:
            execution.result = "PASS"
            execution.status = "COMPLETED"
            execution.result_reason = (
                f"Adversarial scenario '{scenario.name}' ({scenario.scenario_type}) was correctly rejected. "
                "Target enforced sequence and state invariants."
            )

        self.db.commit()
        self.db.refresh(execution)
        return execution
