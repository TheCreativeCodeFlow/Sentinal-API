import pytest
from fastapi.testclient import TestClient

from app.models import (
    API,
    Endpoint,
    WorkflowExecution,
    WorkflowStepExecution,
    WorkflowAttackScenario,
    WorkflowAttackStep,
)

# Prevent pytest from collecting test execution/scenario models as test classes
WorkflowExecution.__test__ = False
WorkflowStepExecution.__test__ = False
WorkflowAttackScenario.__test__ = False
WorkflowAttackStep.__test__ = False


@pytest.fixture(autouse=True)
def reset_demo_orders(client: TestClient):
    """Reset demo orders before and after each test."""
    client.get("/demo-target/workflow/reset")
    yield
    client.get("/demo-target/workflow/reset")


def _setup_authorized_project(client: TestClient) -> int:
    res = client.post("/api/v1/projects/", json={"name": "Stage 7.3 Test Project", "base_url": "http://testserver"})
    assert res.status_code == 201
    project_id = res.json()["id"]

    auth_res = client.put(
        f"/api/v1/projects/{project_id}",
        json={"authorization_status": "authorized"},
    )
    assert auth_res.status_code == 200
    return project_id


def _setup_test_identities(client: TestClient, project_id: int):
    # Role
    r_res = client.post(
        f"/api/v1/projects/{project_id}/roles/",
        json={"name": "Customer", "description": "Customer Role"},
    )
    role_id = r_res.json()["id"]

    # Identity Alice
    alice_res = client.post(
        f"/api/v1/projects/{project_id}/identities/",
        json={
            "name": "Alice Victim",
            "auth_type": "bearer_token",
            "credential_value": "user_alice_001",
            "role_id": role_id,
        },
    )
    alice_id = alice_res.json()["id"]

    # Identity Bob
    bob_res = client.post(
        f"/api/v1/projects/{project_id}/identities/",
        json={
            "name": "Bob Attacker",
            "auth_type": "bearer_token",
            "credential_value": "user_bob_002",
            "role_id": role_id,
        },
    )
    bob_id = bob_res.json()["id"]

    return alice_id, bob_id


def _setup_order_endpoints(db_session, project_id: int):
    api = API(
        project_id=project_id,
        name="Orders API",
        version="v1",
        format="openapi3",
        url="http://testserver",
    )
    db_session.add(api)
    db_session.commit()
    db_session.refresh(api)

    ep_checkout = Endpoint(
        api_id=api.id,
        method="GET",
        path="/demo-target/workflow/orders/{order_id}/checkout",
        summary="Checkout Order",
    )
    ep_pay = Endpoint(
        api_id=api.id,
        method="GET",
        path="/demo-target/workflow/orders/{order_id}/pay",
        summary="Pay Order",
    )
    ep_claim = Endpoint(
        api_id=api.id,
        method="GET",
        path="/demo-target/workflow/orders/{order_id}/claim",
        summary="Claim Order Access",
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
    db_session.add_all([ep_checkout, ep_pay, ep_claim, ep_refund, ep_error])
    db_session.commit()
    db_session.refresh(ep_checkout)
    db_session.refresh(ep_pay)
    db_session.refresh(ep_claim)
    db_session.refresh(ep_refund)
    db_session.refresh(ep_error)

    return {
        "checkout": ep_checkout.id,
        "pay": ep_pay.id,
        "claim": ep_claim.id,
        "refund": ep_refund.id,
        "error": ep_error.id,
    }


def _create_full_active_workflow(
    client: TestClient, project_id: int, endpoints: dict, alice_id: str, bob_id: str, order_id_param: str
):
    wf_res = client.post(
        f"/api/v1/projects/{project_id}/workflows",
        json={"name": f"Order Flow {order_id_param}", "status": "ACTIVE"},
    )
    assert wf_res.status_code == 201
    wf_id = wf_res.json()["id"]

    # States: CREATED (Initial), CHECKED_OUT, PAID, REFUNDED (Terminal)
    s_created = client.post(
        f"/api/v1/workflows/{wf_id}/states",
        json={"name": "CREATED", "is_initial": True, "is_terminal": False},
    ).json()["id"]

    s_checked_out = client.post(
        f"/api/v1/workflows/{wf_id}/states",
        json={"name": "CHECKED_OUT", "is_initial": False, "is_terminal": False},
    ).json()["id"]

    s_paid = client.post(
        f"/api/v1/workflows/{wf_id}/states",
        json={"name": "PAID", "is_initial": False, "is_terminal": False},
    ).json()["id"]

    s_refunded = client.post(
        f"/api/v1/workflows/{wf_id}/states",
        json={"name": "REFUNDED", "is_initial": False, "is_terminal": True},
    ).json()["id"]

    # Steps: Step 1 (Checkout), Step 2 (Pay)
    template = {"path_params": {"order_id": order_id_param}}

    st_1 = client.post(
        f"/api/v1/workflows/{wf_id}/steps",
        json={
            "step_order": 1,
            "endpoint_id": endpoints["checkout"],
            "identity_id": alice_id,
            "http_method": "GET",
            "name": "Checkout Step",
            "request_template": template,
            "expected_status_codes": [200],
        },
    ).json()["id"]

    st_2 = client.post(
        f"/api/v1/workflows/{wf_id}/steps",
        json={
            "step_order": 2,
            "endpoint_id": endpoints["pay"],
            "identity_id": alice_id,
            "http_method": "GET",
            "name": "Payment Step",
            "request_template": template,
            "expected_status_codes": [200],
        },
    ).json()["id"]

    # Valid transitions: CREATED -> CHECKED_OUT (Step 1), CHECKED_OUT -> PAID (Step 2)
    client.post(
        f"/api/v1/workflows/{wf_id}/transitions",
        json={
            "from_state_id": s_created,
            "to_state_id": s_checked_out,
            "step_id": st_1,
            "expected_behavior": "ALLOW",
        },
    )
    client.post(
        f"/api/v1/workflows/{wf_id}/transitions",
        json={
            "from_state_id": s_checked_out,
            "to_state_id": s_paid,
            "step_id": st_2,
            "expected_behavior": "ALLOW",
        },
    )

    # Invalid transition explicitly marked DENY: CREATED -> REFUNDED
    client.post(
        f"/api/v1/workflows/{wf_id}/transitions",
        json={
            "from_state_id": s_created,
            "to_state_id": s_refunded,
            "step_id": None,
            "expected_behavior": "DENY",
            "description": "Cannot refund un-checked-out order directly",
        },
    )

    return {
        "workflow_id": wf_id,
        "states": {"CREATED": s_created, "CHECKED_OUT": s_checked_out, "PAID": s_paid, "REFUNDED": s_refunded},
        "steps": {"checkout": st_1, "pay": st_2},
    }


def test_attack_scenario_generation_all_types(client: TestClient, db_session):
    """Test generating all 6 adversarial scenario types from an active workflow."""
    p_id = _setup_authorized_project(client)
    alice_id, bob_id = _setup_test_identities(client, p_id)
    eps = _setup_order_endpoints(db_session, p_id)
    wf_data = _create_full_active_workflow(client, p_id, eps, alice_id, bob_id, "order-valid-1")
    wf_id = wf_data["workflow_id"]

    # Generate attack scenarios
    res = client.post(f"/api/v1/workflows/{wf_id}/generate-attack-scenarios")
    assert res.status_code == 200
    data = res.json()
    assert data["generated_count"] >= 5

    # Check scenarios list
    list_res = client.get(f"/api/v1/workflows/{wf_id}/attack-scenarios")
    assert list_res.status_code == 200
    scenarios = list_res.json()
    types_present = {s["scenario_type"] for s in scenarios}

    assert "INVALID_STATE_TRANSITION" in types_present
    assert "STEP_REPLAY" in types_present
    assert "STEP_SKIP" in types_present
    assert "STEP_REORDER" in types_present
    assert "IDENTITY_SWITCH" in types_present
    assert "CROSS_IDENTITY_CONTINUATION" in types_present

    # Verify steps inside scenarios
    for sc in scenarios:
        assert len(sc["steps"]) >= 1
        for step in sc["steps"]:
            assert step["action"] in ("EXECUTE", "SKIP", "REPLAY", "SWITCH_IDENTITY")
            assert step["position"] >= 1


def test_attack_scenario_deduplication(client: TestClient, db_session):
    """Test that generating scenarios multiple times deduplicates and avoids creating redundant rows."""
    p_id = _setup_authorized_project(client)
    alice_id, bob_id = _setup_test_identities(client, p_id)
    eps = _setup_order_endpoints(db_session, p_id)
    wf_data = _create_full_active_workflow(client, p_id, eps, alice_id, bob_id, "order-valid-1")
    wf_id = wf_data["workflow_id"]

    res1 = client.post(f"/api/v1/workflows/{wf_id}/generate-attack-scenarios")
    assert res1.status_code == 200
    count1 = res1.json()["generated_count"]

    res2 = client.post(f"/api/v1/workflows/{wf_id}/generate-attack-scenarios")
    assert res2.status_code == 200

    list_res = client.get(f"/api/v1/workflows/{wf_id}/attack-scenarios")
    assert len(list_res.json()) == count1


def test_attack_scenario_unauthorized_project_rejection(client: TestClient):
    """Test that generating or executing scenarios on unauthorized projects is rejected."""
    # Create project in pending status
    p_res = client.post("/api/v1/projects/", json={"name": "Pending Project"})
    p_id = p_res.json()["id"]

    wf_res = client.post(
        f"/api/v1/projects/{p_id}/workflows",
        json={"name": "Pending WF", "status": "ACTIVE"},
    )
    wf_id = wf_res.json()["id"]

    # Generation rejected
    gen_res = client.post(f"/api/v1/workflows/{wf_id}/generate-attack-scenarios")
    assert gen_res.status_code == 400
    assert "authorized" in gen_res.json()["detail"].lower()


def test_attack_scenario_inactive_workflow_rejection(client: TestClient):
    """Test that draft or disabled workflows reject scenario generation and execution."""
    p_id = _setup_authorized_project(client)
    wf_res = client.post(
        f"/api/v1/projects/{p_id}/workflows",
        json={"name": "Draft WF", "status": "DRAFT"},
    )
    wf_id = wf_res.json()["id"]

    gen_res = client.post(f"/api/v1/workflows/{wf_id}/generate-attack-scenarios")
    assert gen_res.status_code == 400
    assert "active" in gen_res.json()["detail"].lower()


def test_attack_scenario_step_skipping_vulnerable_confirmed(client: TestClient, db_session):
    """Test executing a STEP_SKIP scenario on a vulnerable endpoint detects WORKFLOW_STEP_SKIPPING finding."""
    p_id = _setup_authorized_project(client)
    alice_id, bob_id = _setup_test_identities(client, p_id)
    eps = _setup_order_endpoints(db_session, p_id)
    wf_data = _create_full_active_workflow(client, p_id, eps, alice_id, bob_id, "order-skip-vuln")
    wf_id = wf_data["workflow_id"]

    client.post(f"/api/v1/workflows/{wf_id}/generate-attack-scenarios")
    list_res = client.get(f"/api/v1/workflows/{wf_id}/attack-scenarios")
    skip_scenario = next(s for s in list_res.json() if s["scenario_type"] == "STEP_SKIP")

    # Execute
    exec_res = client.post(f"/api/v1/workflow-attack-scenarios/{skip_scenario['id']}/execute")
    assert exec_res.status_code == 200
    exec_data = exec_res.json()

    assert exec_data["status"] == "COMPLETED"
    assert exec_data["result"] == "CONFIRMED"
    assert len(exec_data["findings"]) >= 1

    finding = exec_data["findings"][0]
    assert finding["type"] == "WORKFLOW_STEP_SKIPPING"
    assert finding["severity"] == "HIGH"

    # Verify evidence chain
    step_execs = exec_data["step_executions"]
    assert len(step_execs) == 2
    assert step_execs[0]["action"] == "SKIP"
    assert step_execs[0]["status"] == "PASS"
    assert step_execs[1]["action"] == "EXECUTE"
    assert step_execs[1]["status"] == "CONFIRMED"


def test_attack_scenario_step_skipping_protected_pass(client: TestClient, db_session):
    """Test executing a STEP_SKIP scenario on a protected endpoint correctly passes (rejected by target)."""
    p_id = _setup_authorized_project(client)
    alice_id, bob_id = _setup_test_identities(client, p_id)
    eps = _setup_order_endpoints(db_session, p_id)
    wf_data = _create_full_active_workflow(client, p_id, eps, alice_id, bob_id, "order-skip-prot")
    wf_id = wf_data["workflow_id"]

    client.post(f"/api/v1/workflows/{wf_id}/generate-attack-scenarios")
    list_res = client.get(f"/api/v1/workflows/{wf_id}/attack-scenarios")
    skip_scenario = next(s for s in list_res.json() if s["scenario_type"] == "STEP_SKIP")

    # Execute
    exec_res = client.post(f"/api/v1/workflow-attack-scenarios/{skip_scenario['id']}/execute")
    assert exec_res.status_code == 200
    exec_data = exec_res.json()

    assert exec_data["status"] == "COMPLETED"
    assert exec_data["result"] == "PASS"
    assert len(exec_data["findings"]) == 0


def test_attack_scenario_step_replay_vulnerable_confirmed(client: TestClient, db_session):
    """Test executing a STEP_REPLAY scenario on a vulnerable endpoint detects WORKFLOW_STEP_REPLAY finding."""
    p_id = _setup_authorized_project(client)
    alice_id, bob_id = _setup_test_identities(client, p_id)
    eps = _setup_order_endpoints(db_session, p_id)
    wf_data = _create_full_active_workflow(client, p_id, eps, alice_id, bob_id, "order-replay-vuln")
    wf_id = wf_data["workflow_id"]

    client.post(f"/api/v1/workflows/{wf_id}/generate-attack-scenarios")
    list_res = client.get(f"/api/v1/workflows/{wf_id}/attack-scenarios")
    # Find replay scenario for step 2 (Payment step)
    replay_scenario = next(
        s for s in list_res.json()
        if s["scenario_type"] == "STEP_REPLAY" and "Payment" in s["name"]
    )

    exec_res = client.post(f"/api/v1/workflow-attack-scenarios/{replay_scenario['id']}/execute")
    assert exec_res.status_code == 200
    exec_data = exec_res.json()

    assert exec_data["result"] == "CONFIRMED"
    assert any(f["type"] == "WORKFLOW_STEP_REPLAY" for f in exec_data["findings"])


def test_attack_scenario_step_replay_protected_pass(client: TestClient, db_session):
    """Test executing a STEP_REPLAY scenario on a protected endpoint correctly passes."""
    p_id = _setup_authorized_project(client)
    alice_id, bob_id = _setup_test_identities(client, p_id)
    eps = _setup_order_endpoints(db_session, p_id)
    wf_data = _create_full_active_workflow(client, p_id, eps, alice_id, bob_id, "order-replay-prot")
    wf_id = wf_data["workflow_id"]

    client.post(f"/api/v1/workflows/{wf_id}/generate-attack-scenarios")
    list_res = client.get(f"/api/v1/workflows/{wf_id}/attack-scenarios")
    replay_scenario = next(
        s for s in list_res.json()
        if s["scenario_type"] == "STEP_REPLAY" and "Payment" in s["name"]
    )

    exec_res = client.post(f"/api/v1/workflow-attack-scenarios/{replay_scenario['id']}/execute")
    assert exec_res.status_code == 200
    exec_data = exec_res.json()

    assert exec_data["result"] == "PASS"
    assert len(exec_data["findings"]) == 0


def test_attack_scenario_identity_switch_vulnerable_confirmed(client: TestClient, db_session):
    """Test executing an IDENTITY_SWITCH scenario detects WORKFLOW_IDENTITY_SWITCH finding."""
    p_id = _setup_authorized_project(client)
    alice_id, bob_id = _setup_test_identities(client, p_id)
    eps = _setup_order_endpoints(db_session, p_id)
    wf_data = _create_full_active_workflow(client, p_id, eps, alice_id, bob_id, "order-id-switch-vuln")
    wf_id = wf_data["workflow_id"]

    client.post(f"/api/v1/workflows/{wf_id}/generate-attack-scenarios")
    list_res = client.get(f"/api/v1/workflows/{wf_id}/attack-scenarios")
    switch_sc = next(s for s in list_res.json() if s["scenario_type"] == "IDENTITY_SWITCH")

    exec_res = client.post(f"/api/v1/workflow-attack-scenarios/{switch_sc['id']}/execute")
    assert exec_res.status_code == 200
    exec_data = exec_res.json()

    assert exec_data["result"] == "CONFIRMED"
    assert any(f["type"] == "WORKFLOW_IDENTITY_SWITCH" for f in exec_data["findings"])


def test_attack_scenario_cross_identity_protected_pass(client: TestClient, db_session):
    """Test executing a CROSS_IDENTITY scenario against protected orders is rejected and passes."""
    p_id = _setup_authorized_project(client)
    alice_id, bob_id = _setup_test_identities(client, p_id)
    eps = _setup_order_endpoints(db_session, p_id)

    # Workflow using claim endpoint
    wf_res = client.post(
        f"/api/v1/projects/{p_id}/workflows",
        json={"name": "Claim Flow", "status": "ACTIVE"},
    )
    wf_id = wf_res.json()["id"]

    s_created = client.post(
        f"/api/v1/workflows/{wf_id}/states",
        json={"name": "CREATED", "is_initial": True, "is_terminal": False},
    ).json()["id"]

    client.post(
        f"/api/v1/workflows/{wf_id}/steps",
        json={
            "step_order": 1,
            "endpoint_id": eps["claim"],
            "identity_id": alice_id,
            "http_method": "GET",
            "name": "Claim Step",
            "request_template": {"path_params": {"order_id": "order-id-switch-prot"}},
            "expected_status_codes": [200],
        },
    )

    client.post(f"/api/v1/workflows/{wf_id}/generate-attack-scenarios")
    list_res = client.get(f"/api/v1/workflows/{wf_id}/attack-scenarios")
    cross_sc = next(s for s in list_res.json() if s["scenario_type"] == "CROSS_IDENTITY_CONTINUATION")

    exec_res = client.post(f"/api/v1/workflow-attack-scenarios/{cross_sc['id']}/execute")
    assert exec_res.status_code == 200
    exec_data = exec_res.json()

    # Bob's attempt on protected order was correctly rejected with 403
    assert exec_data["result"] == "PASS"
    assert len(exec_data["findings"]) == 0


def test_attack_scenario_invalid_state_transition_confirmed(client: TestClient, db_session):
    """Test executing an INVALID_STATE_TRANSITION scenario confirms invalid state transition."""
    p_id = _setup_authorized_project(client)
    alice_id, bob_id = _setup_test_identities(client, p_id)
    eps = _setup_order_endpoints(db_session, p_id)

    # Create workflow with order-vuln-1 where refund endpoint allows invalid refund from CREATED
    wf_res = client.post(
        f"/api/v1/projects/{p_id}/workflows",
        json={"name": "Vulnerable Refund Flow", "status": "ACTIVE"},
    )
    wf_id = wf_res.json()["id"]

    s_created = client.post(
        f"/api/v1/workflows/{wf_id}/states",
        json={"name": "CREATED", "is_initial": True, "is_terminal": False},
    ).json()["id"]
    s_refunded = client.post(
        f"/api/v1/workflows/{wf_id}/states",
        json={"name": "REFUNDED", "is_initial": False, "is_terminal": True},
    ).json()["id"]

    st_refund = client.post(
        f"/api/v1/workflows/{wf_id}/steps",
        json={
            "step_order": 1,
            "endpoint_id": eps["refund"],
            "identity_id": alice_id,
            "http_method": "GET",
            "name": "Refund Step",
            "request_template": {"path_params": {"order_id": "order-vuln-1"}},
            "expected_status_codes": [200],
        },
    ).json()["id"]

    # Explicit DENY transition
    client.post(
        f"/api/v1/workflows/{wf_id}/transitions",
        json={
            "from_state_id": s_created,
            "to_state_id": s_refunded,
            "step_id": st_refund,
            "expected_behavior": "DENY",
        },
    )

    client.post(f"/api/v1/workflows/{wf_id}/generate-attack-scenarios")
    list_res = client.get(f"/api/v1/workflows/{wf_id}/attack-scenarios")
    trans_sc = next(s for s in list_res.json() if s["scenario_type"] == "INVALID_STATE_TRANSITION")

    exec_res = client.post(f"/api/v1/workflow-attack-scenarios/{trans_sc['id']}/execute")
    assert exec_res.status_code == 200
    exec_data = exec_res.json()

    assert exec_data["result"] == "CONFIRMED"
    assert any(f["type"] == "INVALID_STATE_TRANSITION" for f in exec_data["findings"])


def test_attack_scenario_replay_endpoint(client: TestClient, db_session):
    """Test replaying an existing attack scenario execution."""
    p_id = _setup_authorized_project(client)
    alice_id, bob_id = _setup_test_identities(client, p_id)
    eps = _setup_order_endpoints(db_session, p_id)
    wf_data = _create_full_active_workflow(client, p_id, eps, alice_id, bob_id, "order-skip-vuln")
    wf_id = wf_data["workflow_id"]

    client.post(f"/api/v1/workflows/{wf_id}/generate-attack-scenarios")
    list_res = client.get(f"/api/v1/workflows/{wf_id}/attack-scenarios")
    skip_scenario = next(s for s in list_res.json() if s["scenario_type"] == "STEP_SKIP")

    # Initial execution
    client.post(f"/api/v1/workflow-attack-scenarios/{skip_scenario['id']}/execute")

    # Replay
    replay_res = client.post(f"/api/v1/workflow-attack-scenarios/{skip_scenario['id']}/replay")
    assert replay_res.status_code == 200
    replay_data = replay_res.json()
    assert replay_data["triggered_by"] == "REPLAY"

    # List executions
    execs_res = client.get(f"/api/v1/workflow-attack-scenarios/{skip_scenario['id']}/executions")
    assert execs_res.status_code == 200
    assert len(execs_res.json()) >= 2


def test_attack_scenario_evidence_chain_and_redaction(client: TestClient, db_session):
    """Test that attack evidence chain contains all steps and redacts credentials."""
    p_id = _setup_authorized_project(client)
    alice_id, bob_id = _setup_test_identities(client, p_id)
    eps = _setup_order_endpoints(db_session, p_id)
    wf_data = _create_full_active_workflow(client, p_id, eps, alice_id, bob_id, "order-skip-vuln")
    wf_id = wf_data["workflow_id"]

    client.post(f"/api/v1/workflows/{wf_id}/generate-attack-scenarios")
    list_res = client.get(f"/api/v1/workflows/{wf_id}/attack-scenarios")
    skip_scenario = next(s for s in list_res.json() if s["scenario_type"] == "STEP_SKIP")

    exec_res = client.post(f"/api/v1/workflow-attack-scenarios/{skip_scenario['id']}/execute")
    assert exec_res.status_code == 200
    exec_data = exec_res.json()

    finding_id = exec_data["findings"][0]["id"]
    finding_res = client.get(f"/api/v1/findings/{finding_id}")
    assert finding_res.status_code == 200
    finding_detail = finding_res.json()

    evidence = finding_detail["evidence"]
    assert evidence is not None
    assert "user_alice_001" not in (evidence["redacted_request"] or "")
    assert "user_alice_001" not in (evidence["redacted_response"] or "")
    req_meta = evidence["request_metadata"]
    assert "attack_sequence_chain" in req_meta
    assert len(req_meta["attack_sequence_chain"]) == 2
    assert req_meta["violating_step_position"] == 2


def test_attack_scenario_finding_deduplication(client: TestClient, db_session):
    """Test that executing the same attack scenario multiple times deduplicates open findings."""
    p_id = _setup_authorized_project(client)
    alice_id, bob_id = _setup_test_identities(client, p_id)
    eps = _setup_order_endpoints(db_session, p_id)
    wf_data = _create_full_active_workflow(client, p_id, eps, alice_id, bob_id, "order-skip-vuln")
    wf_id = wf_data["workflow_id"]

    client.post(f"/api/v1/workflows/{wf_id}/generate-attack-scenarios")
    list_res = client.get(f"/api/v1/workflows/{wf_id}/attack-scenarios")
    skip_scenario = next(s for s in list_res.json() if s["scenario_type"] == "STEP_SKIP")

    # Run 1
    client.post(f"/api/v1/workflow-attack-scenarios/{skip_scenario['id']}/execute")
    # Run 2
    client.post(f"/api/v1/workflow-attack-scenarios/{skip_scenario['id']}/execute")

    findings_res = client.get(f"/api/v1/projects/{p_id}/findings")
    assert findings_res.status_code == 200
    skip_findings = [f for f in findings_res.json() if f["type"] == "WORKFLOW_STEP_SKIPPING"]
    assert len(skip_findings) == 1
