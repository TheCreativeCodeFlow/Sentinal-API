import json
import pytest
from fastapi.testclient import TestClient
from app.models import (
    Project,
    API,
    Endpoint,
    Identity,
    Workflow,
    WorkflowStep,
    WorkflowState,
    WorkflowTransition,
    WorkflowExecution,
    WorkflowStepExecution,
    Finding,
    Evidence,
)

# Avoid pytest trying to collect Execution classes as test suites
WorkflowExecution.__test__ = False
WorkflowStepExecution.__test__ = False


def _setup_authorized_project(client: TestClient, db_session, name: str = "Workflow Test Project"):
    resp = client.post(
        "/api/v1/projects/",
        json={
            "name": name,
            "environment": "staging",
            "base_url": "http://testserver",
            "authorization_status": "authorized",
        },
    )
    assert resp.status_code == 201
    proj_id = resp.json()["id"]

    # Create API & Endpoints
    api = API(
        project_id=proj_id,
        name="Orders API",
        version="v1",
        format="openapi3",
        url="http://testserver",
    )
    db_session.add(api)
    db_session.commit()
    db_session.refresh(api)

    ep_status = Endpoint(
        api_id=api.id,
        method="GET",
        path="/demo-target/workflow/orders/{order_id}/status",
        summary="Get Order Status",
    )
    ep_cancel = Endpoint(
        api_id=api.id,
        method="GET",
        path="/demo-target/workflow/orders/{order_id}/cancel",
        summary="Cancel Order",
    )
    ep_refund = Endpoint(
        api_id=api.id,
        method="GET",
        path="/demo-target/workflow/orders/{order_id}/refund",
        summary="Refund Order",
    )
    ep_error = Endpoint(
        api_id=api.id,
        method="GET",
        path="/demo-target/auth/server-error",
        summary="Server Error",
    )
    db_session.add_all([ep_status, ep_cancel, ep_refund, ep_error])
    db_session.commit()
    db_session.refresh(ep_status)
    db_session.refresh(ep_cancel)
    db_session.refresh(ep_refund)
    db_session.refresh(ep_error)

    endpoints = {
        "status": ep_status.id,
        "cancel": ep_cancel.id,
        "refund": ep_refund.id,
        "error": ep_error.id,
    }
    return proj_id, endpoints


def test_workflow_execution_unauthorized_project_rejection(client: TestClient, db_session):
    """Refuse execution if project authorization_status is not 'authorized'."""
    p_resp = client.post(
        "/api/v1/projects/",
        json={"name": "Unauthorized Project", "authorization_status": "pending"},
    )
    proj_id = p_resp.json()["id"]

    wf_resp = client.post(
        f"/api/v1/projects/{proj_id}/workflows",
        json={"name": "Pending Project Workflow", "status": "ACTIVE"},
    )
    assert wf_resp.status_code == 201
    wf_id = wf_resp.json()["id"]

    # Attempt to execute
    exec_resp = client.post(f"/api/v1/workflows/{wf_id}/execute")
    assert exec_resp.status_code == 200
    data = exec_resp.json()
    assert data["status"] == "FAILED"
    assert data["result"] == "ERROR"
    assert "not been explicitly authorized" in data["result_reason"]


def test_workflow_execution_non_active_workflow_rejection(client: TestClient, db_session):
    """Refuse execution if workflow status is DRAFT or DISABLED."""
    proj_id, endpoints = _setup_authorized_project(client, db_session, "Active Status Test Project")

    wf_resp = client.post(
        f"/api/v1/projects/{proj_id}/workflows",
        json={"name": "Draft Workflow", "status": "DRAFT"},
    )
    wf_id = wf_resp.json()["id"]

    exec_resp = client.post(f"/api/v1/workflows/{wf_id}/execute")
    assert exec_resp.status_code == 200
    data = exec_resp.json()
    assert data["status"] == "FAILED"
    assert data["result"] == "ERROR"
    assert "Only ACTIVE workflows can be executed" in data["result_reason"]


def test_workflow_execution_initial_state_validation(client: TestClient, db_session):
    """Refuse execution if workflow has 0 or >1 initial states."""
    proj_id, endpoints = _setup_authorized_project(client, db_session, "Initial State Validation Project")

    # Workflow with 0 initial states
    wf_resp = client.post(
        f"/api/v1/projects/{proj_id}/workflows",
        json={"name": "Zero Initial States WF", "status": "ACTIVE"},
    )
    wf_id = wf_resp.json()["id"]

    # Add a non-initial state
    client.post(
        f"/api/v1/workflows/{wf_id}/states",
        json={"name": "CREATED", "is_initial": False},
    )

    # Add step
    client.post(
        f"/api/v1/workflows/{wf_id}/steps",
        json={"step_order": 1, "endpoint_id": endpoints["status"], "name": "Step 1"},
    )

    exec_resp = client.post(f"/api/v1/workflows/{wf_id}/execute")
    assert exec_resp.status_code == 200
    data = exec_resp.json()
    assert data["status"] == "FAILED"
    assert data["result"] == "ERROR"
    assert "WORKFLOW_CONFIGURATION_ERROR" in data["error_message"]
    assert "exactly one initial state" in data["result_reason"]


def test_workflow_execution_placeholder_resolution_and_rejection(client: TestClient, db_session):
    """Validate placeholder resolution and rejection of unknown placeholders."""
    proj_id, endpoints = _setup_authorized_project(client, db_session, "Placeholder Test Project")

    wf_resp = client.post(
        f"/api/v1/projects/{proj_id}/workflows",
        json={"name": "Placeholder Workflow", "status": "ACTIVE"},
    )
    wf_id = wf_resp.json()["id"]

    client.post(
        f"/api/v1/workflows/{wf_id}/states",
        json={"name": "INITIAL", "is_initial": True},
    )

    # Unknown placeholder in request template
    client.post(
        f"/api/v1/workflows/{wf_id}/steps",
        json={
            "step_order": 1,
            "endpoint_id": endpoints["status"],
            "name": "Bad Placeholder Step",
            "request_template": {
                "headers": {"X-Custom": "{{unknown_injection_attempt}}"}
            },
        },
    )

    exec_resp = client.post(f"/api/v1/workflows/{wf_id}/execute")
    assert exec_resp.status_code == 200
    data = exec_resp.json()
    assert data["status"] == "FAILED"
    assert data["result"] == "ERROR"
    assert "WORKFLOW_CONFIGURATION_ERROR" in data["error_message"]
    assert "unknown_injection_attempt" in data["error_message"]


def test_workflow_execution_valid_flow_pass(client: TestClient, db_session):
    """
    Test legitimate order workflow execution:
    CREATED -> cancel -> CANCELLED (ALLOW, 200)
    CANCELLED -> refund (DENY). Target returns 409 Conflict as expected.
    Overall result: PASS.
    """
    client.get("/demo-target/workflow/reset")
    proj_id, endpoints = _setup_authorized_project(client, db_session, "Valid Flow Project")

    wf_resp = client.post(
        f"/api/v1/projects/{proj_id}/workflows",
        json={"name": "Order Lifecycle Workflow", "status": "ACTIVE"},
    )
    wf_id = wf_resp.json()["id"]

    # States: CREATED (initial), CANCELLED, REFUNDED
    s1 = client.post(f"/api/v1/workflows/{wf_id}/states", json={"name": "CREATED", "is_initial": True}).json()["id"]
    s2 = client.post(f"/api/v1/workflows/{wf_id}/states", json={"name": "CANCELLED"}).json()["id"]
    s3 = client.post(f"/api/v1/workflows/{wf_id}/states", json={"name": "REFUNDED", "is_terminal": True}).json()["id"]

    # Steps (order-valid-1)
    step1 = client.post(
        f"/api/v1/workflows/{wf_id}/steps",
        json={
            "step_order": 1,
            "endpoint_id": endpoints["status"],
            "name": "Check Created Status",
            "request_template": {"query_params": {"order_id": "order-valid-1"}},
            "expected_status_codes": [200],
        },
    ).json()["id"]

    step2 = client.post(
        f"/api/v1/workflows/{wf_id}/steps",
        json={
            "step_order": 2,
            "endpoint_id": endpoints["cancel"],
            "name": "Cancel Order",
            "request_template": {"query_params": {"order_id": "order-valid-1"}},
            "expected_status_codes": [200],
        },
    ).json()["id"]

    step3 = client.post(
        f"/api/v1/workflows/{wf_id}/steps",
        json={
            "step_order": 3,
            "endpoint_id": endpoints["refund"],
            "name": "Attempt Refund on Cancelled Order",
            "request_template": {"query_params": {"order_id": "order-valid-1"}},
            "expected_status_codes": [200],
        },
    ).json()["id"]

    # Transitions
    # Step 1: CREATED -> CREATED (ALLOW)
    client.post(
        f"/api/v1/workflows/{wf_id}/transitions",
        json={"from_state_id": s1, "to_state_id": s1, "step_id": step1, "expected_behavior": "ALLOW"},
    )
    # Step 2: CREATED -> CANCELLED (ALLOW)
    client.post(
        f"/api/v1/workflows/{wf_id}/transitions",
        json={"from_state_id": s1, "to_state_id": s2, "step_id": step2, "expected_behavior": "ALLOW"},
    )
    # Step 3: CANCELLED -> REFUNDED (DENY - refunding cancelled order is forbidden)
    client.post(
        f"/api/v1/workflows/{wf_id}/transitions",
        json={"from_state_id": s2, "to_state_id": s3, "step_id": step3, "expected_behavior": "DENY"},
    )

    # Execute workflow
    exec_resp = client.post(f"/api/v1/workflows/{wf_id}/execute")
    assert exec_resp.status_code == 200
    data = exec_resp.json()
    assert data["status"] == "COMPLETED"
    assert data["result"] == "PASS"
    assert len(data["step_executions"]) == 3
    assert all(se["status"] == "PASS" for se in data["step_executions"])
    assert len(data["findings"]) == 0


def test_workflow_execution_invalid_state_transition_confirmed(client: TestClient, db_session):
    """
    Test detecting invalid state transition vulnerability:
    CREATED -> cancel -> CANCELLED (ALLOW, 200)
    CANCELLED -> refund (DENY). Flawed target accepts refund with 200 OK!
    Overall result: CONFIRMED.
    Finding emitted: INVALID_STATE_TRANSITION.
    """
    client.get("/demo-target/workflow/reset")
    proj_id, endpoints = _setup_authorized_project(client, db_session, "Vulnerable Flow Project")

    wf_resp = client.post(
        f"/api/v1/projects/{proj_id}/workflows",
        json={"name": "Vulnerable Order Workflow", "status": "ACTIVE"},
    )
    wf_id = wf_resp.json()["id"]

    s1 = client.post(f"/api/v1/workflows/{wf_id}/states", json={"name": "CREATED", "is_initial": True}).json()["id"]
    s2 = client.post(f"/api/v1/workflows/{wf_id}/states", json={"name": "CANCELLED"}).json()["id"]
    s3 = client.post(f"/api/v1/workflows/{wf_id}/states", json={"name": "REFUNDED", "is_terminal": True}).json()["id"]

    step1 = client.post(
        f"/api/v1/workflows/{wf_id}/steps",
        json={
            "step_order": 1,
            "endpoint_id": endpoints["cancel"],
            "name": "Cancel Vulnerable Order",
            "request_template": {"query_params": {"order_id": "order-vuln-1"}},
            "expected_status_codes": [200],
        },
    ).json()["id"]

    step2 = client.post(
        f"/api/v1/workflows/{wf_id}/steps",
        json={
            "step_order": 2,
            "endpoint_id": endpoints["refund"],
            "name": "Refund Vulnerable Order",
            "request_template": {"query_params": {"order_id": "order-vuln-1"}},
            "expected_status_codes": [200],
        },
    ).json()["id"]

    # Step 1: CREATED -> CANCELLED (ALLOW)
    client.post(
        f"/api/v1/workflows/{wf_id}/transitions",
        json={"from_state_id": s1, "to_state_id": s2, "step_id": step1, "expected_behavior": "ALLOW"},
    )
    # Step 2: CANCELLED -> REFUNDED (DENY)
    client.post(
        f"/api/v1/workflows/{wf_id}/transitions",
        json={"from_state_id": s2, "to_state_id": s3, "step_id": step2, "expected_behavior": "DENY"},
    )

    # Execute workflow
    exec_resp = client.post(f"/api/v1/workflows/{wf_id}/execute")
    assert exec_resp.status_code == 200
    data = exec_resp.json()
    assert data["status"] == "COMPLETED"
    assert data["result"] == "CONFIRMED"
    assert len(data["step_executions"]) == 2
    assert data["step_executions"][0]["status"] == "PASS"
    assert data["step_executions"][1]["status"] == "CONFIRMED"
    assert data["step_executions"][1]["transition_result"] == "INVALID_STATE_TRANSITION"

    # Verify Finding was created
    assert len(data["findings"]) == 1
    finding = data["findings"][0]
    assert finding["type"] == "INVALID_STATE_TRANSITION"
    assert finding["severity"] == "HIGH"
    assert finding["expected_authorization"] == "DENY"
    assert "Invalid State Transition" in finding["title"]

    # Verify project findings listing includes it
    p_findings = client.get(f"/api/v1/projects/{proj_id}/findings?category=WORKFLOW").json()
    assert len(p_findings) == 1
    assert p_findings[0]["type"] == "INVALID_STATE_TRANSITION"


def test_workflow_execution_unexpected_state_detection(client: TestClient, db_session):
    """Test when endpoint succeeds but no transition was modeled for this state."""
    client.get("/demo-target/workflow/reset")
    proj_id, endpoints = _setup_authorized_project(client, db_session, "Unexpected State Project")

    wf_resp = client.post(
        f"/api/v1/projects/{proj_id}/workflows",
        json={"name": "Undefined Transition Workflow", "status": "ACTIVE"},
    )
    wf_id = wf_resp.json()["id"]

    client.post(f"/api/v1/workflows/{wf_id}/states", json={"name": "START", "is_initial": True})

    # Step without any defined transition from START
    client.post(
        f"/api/v1/workflows/{wf_id}/steps",
        json={
            "step_order": 1,
            "endpoint_id": endpoints["status"],
            "name": "Check Status Without Transition",
            "request_template": {"query_params": {"order_id": "order-valid-1"}},
            "expected_status_codes": [200],
        },
    )

    exec_resp = client.post(f"/api/v1/workflows/{wf_id}/execute")
    assert exec_resp.status_code == 200
    data = exec_resp.json()
    assert data["result"] == "CONFIRMED"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["type"] == "UNEXPECTED_WORKFLOW_STATE"


def test_workflow_execution_inconclusive_server_error(client: TestClient, db_session):
    """Test 500 error produces INCONCLUSIVE execution result."""
    proj_id, endpoints = _setup_authorized_project(client, db_session, "Inconclusive Error Project")

    wf_resp = client.post(
        f"/api/v1/projects/{proj_id}/workflows",
        json={"name": "Server Error Workflow", "status": "ACTIVE"},
    )
    wf_id = wf_resp.json()["id"]

    client.post(f"/api/v1/workflows/{wf_id}/states", json={"name": "INITIAL", "is_initial": True})

    client.post(
        f"/api/v1/workflows/{wf_id}/steps",
        json={
            "step_order": 1,
            "endpoint_id": endpoints["error"],
            "name": "Server Error Step",
            "expected_status_codes": [200],
        },
    )

    exec_resp = client.post(f"/api/v1/workflows/{wf_id}/execute")
    assert exec_resp.status_code == 200
    data = exec_resp.json()
    assert data["status"] == "COMPLETED"
    assert data["result"] == "INCONCLUSIVE"
    assert data["step_executions"][0]["status"] == "INCONCLUSIVE"


def test_workflow_execution_finding_deduplication(client: TestClient, db_session):
    """Re-executing a workflow with vulnerabilities updates existing finding rather than duplicating."""
    client.get("/demo-target/workflow/reset")
    proj_id, endpoints = _setup_authorized_project(client, db_session, "Deduplication Project")

    wf_resp = client.post(
        f"/api/v1/projects/{proj_id}/workflows",
        json={"name": "Dedup Workflow", "status": "ACTIVE"},
    )
    wf_id = wf_resp.json()["id"]

    s1 = client.post(f"/api/v1/workflows/{wf_id}/states", json={"name": "CREATED", "is_initial": True}).json()["id"]
    s2 = client.post(f"/api/v1/workflows/{wf_id}/states", json={"name": "CANCELLED"}).json()["id"]
    s3 = client.post(f"/api/v1/workflows/{wf_id}/states", json={"name": "REFUNDED", "is_terminal": True}).json()["id"]

    step1 = client.post(
        f"/api/v1/workflows/{wf_id}/steps",
        json={
            "step_order": 1,
            "endpoint_id": endpoints["cancel"],
            "name": "Cancel Step",
            "request_template": {"query_params": {"order_id": "order-vuln-1"}},
        },
    ).json()["id"]

    step2 = client.post(
        f"/api/v1/workflows/{wf_id}/steps",
        json={
            "step_order": 2,
            "endpoint_id": endpoints["refund"],
            "name": "Refund Step",
            "request_template": {"query_params": {"order_id": "order-vuln-1"}},
        },
    ).json()["id"]

    client.post(
        f"/api/v1/workflows/{wf_id}/transitions",
        json={"from_state_id": s1, "to_state_id": s2, "step_id": step1, "expected_behavior": "ALLOW"},
    )
    client.post(
        f"/api/v1/workflows/{wf_id}/transitions",
        json={"from_state_id": s2, "to_state_id": s3, "step_id": step2, "expected_behavior": "DENY"},
    )

    # First execution -> creates finding
    client.post(f"/api/v1/workflows/{wf_id}/execute")
    findings_1 = client.get(f"/api/v1/projects/{proj_id}/findings").json()
    assert len(findings_1) == 1

    # Second execution -> updates existing finding, does NOT create duplicate
    client.get("/demo-target/workflow/reset")
    client.post(f"/api/v1/workflows/{wf_id}/execute")
    findings_2 = client.get(f"/api/v1/projects/{proj_id}/findings").json()
    assert len(findings_2) == 1
    assert findings_2[0]["id"] == findings_1[0]["id"]


def test_workflow_execution_replay_endpoint(client: TestClient, db_session):
    """Replaying an execution records triggered_by='REPLAY'."""
    client.get("/demo-target/workflow/reset")
    proj_id, endpoints = _setup_authorized_project(client, db_session, "Replay Project")

    wf_resp = client.post(
        f"/api/v1/projects/{proj_id}/workflows",
        json={"name": "Replay Test Workflow", "status": "ACTIVE"},
    )
    wf_id = wf_resp.json()["id"]

    s1 = client.post(f"/api/v1/workflows/{wf_id}/states", json={"name": "CREATED", "is_initial": True}).json()["id"]

    step1 = client.post(
        f"/api/v1/workflows/{wf_id}/steps",
        json={
            "step_order": 1,
            "endpoint_id": endpoints["status"],
            "name": "Check Status",
            "request_template": {"query_params": {"order_id": "order-valid-1"}},
        },
    ).json()["id"]

    client.post(
        f"/api/v1/workflows/{wf_id}/transitions",
        json={"from_state_id": s1, "to_state_id": s1, "step_id": step1, "expected_behavior": "ALLOW"},
    )

    exec_1 = client.post(f"/api/v1/workflows/{wf_id}/execute").json()
    assert exec_1["triggered_by"] == "MANUAL"

    replay_resp = client.post(f"/api/v1/workflow-executions/{exec_1['id']}/replay")
    assert replay_resp.status_code == 200
    replay_data = replay_resp.json()
    assert replay_data["triggered_by"] == "REPLAY"
    assert replay_data["id"] != exec_1["id"]

    # Verify listing shows both executions
    all_execs = client.get(f"/api/v1/workflows/{wf_id}/executions").json()
    assert len(all_execs) == 2


def test_workflow_execution_credential_redaction_in_evidence(client: TestClient, db_session):
    """Ensure sensitive credentials applied during workflow steps are strictly redacted in evidence."""
    proj_id, endpoints = _setup_authorized_project(client, db_session, "Secret Redaction Project")

    # Create identity with sensitive token
    ident_resp = client.post(
        f"/api/v1/projects/{proj_id}/identities/",
        json={
            "name": "Privileged Agent",
            "auth_type": "bearer_token",
            "credential_value": "secret-super-token-9999",
            "credential_status": "configured",
        },
    )
    assert ident_resp.status_code == 201
    ident_id = ident_resp.json()["id"]

    wf_resp = client.post(
        f"/api/v1/projects/{proj_id}/workflows",
        json={"name": "Auth Redaction Workflow", "status": "ACTIVE"},
    )
    wf_id = wf_resp.json()["id"]

    s1 = client.post(f"/api/v1/workflows/{wf_id}/states", json={"name": "INITIAL", "is_initial": True}).json()["id"]

    step1 = client.post(
        f"/api/v1/workflows/{wf_id}/steps",
        json={
            "step_order": 1,
            "endpoint_id": endpoints["status"],
            "identity_id": ident_id,
            "name": "Authenticated Step",
            "request_template": {
                "headers": {"Authorization": "Bearer {{token}}"},
                "query_params": {"order_id": "order-valid-1"},
            },
        },
    ).json()["id"]

    client.post(
        f"/api/v1/workflows/{wf_id}/transitions",
        json={"from_state_id": s1, "to_state_id": s1, "step_id": step1, "expected_behavior": "ALLOW"},
    )

    exec_data = client.post(f"/api/v1/workflows/{wf_id}/execute").json()
    exec_id = exec_data["id"]

    # Retrieve execution details and verify evidence
    detail = client.get(f"/api/v1/workflow-executions/{exec_id}").json()
    step_exec = detail["step_executions"][0]
    auth_header = step_exec["request_summary"]["headers"].get("Authorization", "")
    assert "secret-super-token-9999" not in auth_header
    assert "[REDACTED]" in auth_header or "Bearer" in auth_header


def test_workflow_cascade_deletion_with_executions(client: TestClient, db_session):
    """Deleting a workflow cascades and cleans up its executions and step executions."""
    proj_id, endpoints = _setup_authorized_project(client, db_session, "Cascade Project")

    wf_resp = client.post(
        f"/api/v1/projects/{proj_id}/workflows",
        json={"name": "Cascade Workflow", "status": "ACTIVE"},
    )
    wf_id = wf_resp.json()["id"]

    s1 = client.post(f"/api/v1/workflows/{wf_id}/states", json={"name": "INITIAL", "is_initial": True}).json()["id"]

    step1 = client.post(
        f"/api/v1/workflows/{wf_id}/steps",
        json={
            "step_order": 1,
            "endpoint_id": endpoints["status"],
            "name": "Check Status",
            "request_template": {"query_params": {"order_id": "order-valid-1"}},
        },
    ).json()["id"]

    client.post(
        f"/api/v1/workflows/{wf_id}/transitions",
        json={"from_state_id": s1, "to_state_id": s1, "step_id": step1, "expected_behavior": "ALLOW"},
    )

    exec_data = client.post(f"/api/v1/workflows/{wf_id}/execute").json()
    exec_id = exec_data["id"]

    # Verify execution exists
    get_exec = client.get(f"/api/v1/workflow-executions/{exec_id}")
    assert get_exec.status_code == 200

    # Delete workflow
    del_wf = client.delete(f"/api/v1/workflows/{wf_id}")
    assert del_wf.status_code == 200

    # Verify execution no longer exists
    get_exec_after = client.get(f"/api/v1/workflow-executions/{exec_id}")
    assert get_exec_after.status_code == 404
