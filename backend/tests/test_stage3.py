import pytest
from fastapi.testclient import TestClient
from app.models import Project, API, Endpoint, Role, Identity, Resource, ResourceOwnership, SecurityTest, TestExecution, Finding, Evidence

# Prevent pytest from treating TestExecution model as a test case class
TestExecution.__test__ = False


def create_authorized_project_setup(client: TestClient, db_session):
    """Helper to set up an authorized project with API, endpoint, identities, and resources."""
    # 1. Project with authorization_status = 'authorized'
    proj_res = client.post(
        "/api/v1/projects/",
        json={
            "name": "BOLA Target Project",
            "description": "Authorized target for BOLA engine testing",
            "environment": "staging",
            "base_url": "http://testserver",
            "authorization_status": "authorized",
        },
    )
    assert proj_res.status_code == 201
    proj_id = proj_res.json()["id"]

    # 2. Resource (Orders)
    res_res = client.post(
        f"/api/v1/projects/{proj_id}/resources/",
        json={
            "name": "Order",
            "description": "Customer order domain resource",
            "resource_type": "entity",
        },
    )
    assert res_res.status_code == 201
    resource_id = res_res.json()["id"]

    # 3. API & Endpoints created in db_session
    api = API(
        project_id=proj_id,
        name="Order Service",
        version="1.0",
        format="openapi3",
        status="active",
        url="http://testserver",
    )
    db_session.add(api)
    db_session.commit()
    db_session.refresh(api)

    vuln_ep = Endpoint(
        api_id=api.id,
        resource_id=resource_id,
        method="GET",
        path="/demo-target/orders/{order_id}",
        summary="Vulnerable Order Lookup",
    )
    prot_ep = Endpoint(
        api_id=api.id,
        resource_id=resource_id,
        method="GET",
        path="/demo-target/protected-orders/{order_id}",
        summary="Protected Order Lookup",
    )
    db_session.add_all([vuln_ep, prot_ep])
    db_session.commit()
    db_session.refresh(vuln_ep)
    db_session.refresh(prot_ep)

    # 4. Attacker Identity (Bob)
    bob_res = client.post(
        f"/api/v1/projects/{proj_id}/identities/",
        json={
            "name": "Bob Attacker",
            "auth_type": "bearer_token",
            "environment": "staging",
            "credential_value": "demo-token-bob",
        },
    )
    assert bob_res.status_code == 201
    bob_id = bob_res.json()["id"]

    # 5. Victim Identity (Alice)
    alice_res = client.post(
        f"/api/v1/projects/{proj_id}/identities/",
        json={
            "name": "Alice Victim",
            "auth_type": "bearer_token",
            "environment": "staging",
            "credential_value": "demo-token-alice",
        },
    )
    assert alice_res.status_code == 201
    alice_id = alice_res.json()["id"]

    # 6. Ownership records
    client.post(
        f"/api/v1/resources/{resource_id}/ownerships/",
        json={
            "identity_id": alice_id,
            "resource_instance_id": "order_alice_101",
            "ownership_type": "owner",
        },
    )
    client.post(
        f"/api/v1/resources/{resource_id}/ownerships/",
        json={
            "identity_id": bob_id,
            "resource_instance_id": "order_bob_202",
            "ownership_type": "owner",
        },
    )

    return {
        "project_id": proj_id,
        "resource_id": resource_id,
        "api_id": api.id,
        "vuln_ep_id": vuln_ep.id,
        "prot_ep_id": prot_ep.id,
        "bob_id": bob_id,
        "alice_id": alice_id,
    }


def test_unauthorized_target_rejection(client: TestClient, db_session):
    """Verify security tests are strictly rejected if the project is not authorized."""
    # Project with default authorization_status = 'pending'
    proj_res = client.post(
        "/api/v1/projects/",
        json={"name": "Pending Project", "authorization_status": "pending"},
    )
    assert proj_res.status_code == 201
    proj_id = proj_res.json()["id"]

    api = API(project_id=proj_id, name="Pending API", format="openapi3", status="active")
    db_session.add(api)
    db_session.commit()
    db_session.refresh(api)

    res_res = client.post(
        f"/api/v1/projects/{proj_id}/resources/",
        json={"name": "Resource 1"},
    )
    resource_id = res_res.json()["id"]

    ep = Endpoint(api_id=api.id, resource_id=resource_id, method="GET", path="/test/{id}")
    db_session.add(ep)
    db_session.commit()
    db_session.refresh(ep)

    bob_res = client.post(
        f"/api/v1/projects/{proj_id}/identities/",
        json={"name": "Bob", "credential_value": "secret-123"},
    )
    bob_id = bob_res.json()["id"]

    # Attempt to create BOLA test in unauthorized project
    test_res = client.post(
        f"/api/v1/projects/{proj_id}/security-tests/",
        json={
            "endpoint_id": ep.id,
            "attacker_identity_id": bob_id,
            "victim_resource_id": resource_id,
            "victim_resource_instance_id": "inst-1",
        },
    )
    assert test_res.status_code == 400
    assert "not been authorized" in test_res.json()["detail"]


def test_cross_project_validation(client: TestClient, db_session):
    """Verify all entities must belong to the exact same project."""
    setup_a = create_authorized_project_setup(client, db_session)

    # Project B
    proj_b = client.post(
        "/api/v1/projects/",
        json={"name": "Project B", "authorization_status": "authorized"},
    ).json()["id"]
    foreign_bob = client.post(
        f"/api/v1/projects/{proj_b}/identities/",
        json={"name": "Foreign Bob", "credential_value": "tok-b"},
    ).json()["id"]

    # Attempt to create test in Project A with attacker from Project B
    res = client.post(
        f"/api/v1/projects/{setup_a['project_id']}/security-tests/",
        json={
            "endpoint_id": setup_a["vuln_ep_id"],
            "attacker_identity_id": foreign_bob,
            "victim_resource_id": setup_a["resource_id"],
            "victim_resource_instance_id": "order_alice_101",
        },
    )
    assert res.status_code == 400
    assert "different project" in res.json()["detail"]


def test_invalid_configurations_rejected(client: TestClient, db_session):
    """Verify validation rules: safe HTTP methods, associated resources, and credentials."""
    setup = create_authorized_project_setup(client, db_session)
    proj_id = setup["project_id"]

    # 1. Unsafe method (POST)
    post_ep = Endpoint(api_id=setup["api_id"], resource_id=setup["resource_id"], method="POST", path="/orders")
    db_session.add(post_ep)
    db_session.commit()
    db_session.refresh(post_ep)

    res_post = client.post(
        f"/api/v1/projects/{proj_id}/security-tests/",
        json={
            "endpoint_id": post_ep.id,
            "attacker_identity_id": setup["bob_id"],
            "victim_resource_id": setup["resource_id"],
            "victim_resource_instance_id": "order_alice_101",
        },
    )
    assert res_post.status_code == 400
    assert "Only safe HTTP methods" in res_post.json()["detail"]

    # 2. Endpoint without associated resource
    no_res_ep = Endpoint(api_id=setup["api_id"], method="GET", path="/health")
    db_session.add(no_res_ep)
    db_session.commit()
    db_session.refresh(no_res_ep)

    res_no_res = client.post(
        f"/api/v1/projects/{proj_id}/security-tests/",
        json={
            "endpoint_id": no_res_ep.id,
            "attacker_identity_id": setup["bob_id"],
            "victim_resource_instance_id": "order_alice_101",
        },
    )
    assert res_no_res.status_code == 400
    assert "associated with a domain resource" in res_no_res.json()["detail"]

    # 3. Attacker without credentials
    unauth_ident_id = client.post(
        f"/api/v1/projects/{proj_id}/identities/",
        json={"name": "No Auth User", "credential_status": "unconfigured"},
    ).json()["id"]

    res_unauth = client.post(
        f"/api/v1/projects/{proj_id}/security-tests/",
        json={
            "endpoint_id": setup["vuln_ep_id"],
            "attacker_identity_id": unauth_ident_id,
            "victim_resource_id": setup["resource_id"],
            "victim_resource_instance_id": "order_alice_101",
        },
    )
    assert res_unauth.status_code == 400
    assert "must have configured authentication" in res_unauth.json()["detail"]


def test_bola_pass_case(client: TestClient, db_session):
    """Verify testing against a correctly protected endpoint results in PASS."""
    setup = create_authorized_project_setup(client, db_session)
    proj_id = setup["project_id"]

    # Create test targeting protected endpoint
    create_res = client.post(
        f"/api/v1/projects/{proj_id}/security-tests/",
        json={
            "endpoint_id": setup["prot_ep_id"],
            "attacker_identity_id": setup["bob_id"],
            "victim_identity_id": setup["alice_id"],
            "victim_resource_id": setup["resource_id"],
            "victim_resource_instance_id": "order_alice_101",
            "attacker_resource_instance_id": "order_bob_202",
        },
    )
    assert create_res.status_code == 201
    test_id = create_res.json()["id"]

    # Execute test
    exec_res = client.post(f"/api/v1/security-tests/{test_id}/execute")
    assert exec_res.status_code == 200
    data = exec_res.json()

    assert data["status"] == "COMPLETED"
    assert data["result"] == "PASS"
    assert data["http_status"] == 403
    assert "properly denied" in data["result_reason"]
    assert data["evidence"] is not None
    assert data["evidence"]["reproducibility_status"] == "REPRODUCIBLE"

    # Verify no findings created for PASS
    findings_res = client.get(f"/api/v1/projects/{proj_id}/findings/")
    assert findings_res.status_code == 200
    assert len(findings_res.json()) == 0


def test_bola_confirmed_case(client: TestClient, db_session):
    """Verify testing against an intentionally vulnerable endpoint results in CONFIRMED BOLA finding."""
    setup = create_authorized_project_setup(client, db_session)
    proj_id = setup["project_id"]

    # Create test targeting vulnerable endpoint
    create_res = client.post(
        f"/api/v1/projects/{proj_id}/security-tests/",
        json={
            "endpoint_id": setup["vuln_ep_id"],
            "attacker_identity_id": setup["bob_id"],
            "victim_identity_id": setup["alice_id"],
            "victim_resource_id": setup["resource_id"],
            "victim_resource_instance_id": "order_alice_101",
            "attacker_resource_instance_id": "order_bob_202",
        },
    )
    assert create_res.status_code == 201
    test_id = create_res.json()["id"]

    # Execute test
    exec_res = client.post(f"/api/v1/security-tests/{test_id}/execute")
    assert exec_res.status_code == 200
    data = exec_res.json()

    assert data["status"] == "COMPLETED"
    assert data["result"] == "CONFIRMED"
    assert data["http_status"] == 200
    assert "order_alice_101" in data["result_reason"]

    # Verify finding was automatically created
    findings_res = client.get(f"/api/v1/projects/{proj_id}/findings/")
    assert findings_res.status_code == 200
    findings = findings_res.json()
    assert len(findings) == 1

    finding = findings[0]
    assert finding["type"] == "BOLA"
    assert finding["severity"] == "HIGH"
    assert finding["title"] == "Broken Object Level Authorization"
    assert finding["status"] == "OPEN"
    assert "order_alice_101" in finding["description"]

    # Verify finding detail endpoint
    finding_id = finding["id"]
    detail_res = client.get(f"/api/v1/findings/{finding_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["evidence"] is not None
    assert detail["remediation"] is not None
    assert "Enforce server-side object-level authorization" in detail["remediation"]


def test_bola_inconclusive_case(client: TestClient, db_session):
    """Verify that a server error 500 produces an INCONCLUSIVE result."""
    setup = create_authorized_project_setup(client, db_session)
    proj_id = setup["project_id"]

    err_ep = Endpoint(
        api_id=setup["api_id"],
        resource_id=setup["resource_id"],
        method="GET",
        path="/demo-target/error-orders/{order_id}",
        summary="Error Order Lookup",
    )
    db_session.add(err_ep)
    db_session.commit()
    db_session.refresh(err_ep)

    create_res = client.post(
        f"/api/v1/projects/{proj_id}/security-tests/",
        json={
            "endpoint_id": err_ep.id,
            "attacker_identity_id": setup["bob_id"],
            "victim_resource_id": setup["resource_id"],
            "victim_resource_instance_id": "order_alice_101",
        },
    )
    test_id = create_res.json()["id"]

    exec_res = client.post(f"/api/v1/security-tests/{test_id}/execute")
    assert exec_res.status_code == 200
    data = exec_res.json()

    assert data["result"] == "INCONCLUSIVE"
    assert data["http_status"] == 500
    assert data["error_category"] == "server_error"

    # No finding generated for inconclusive
    findings = client.get(f"/api/v1/projects/{proj_id}/findings/").json()
    assert len(findings) == 0


def test_credential_redaction_and_secret_leakage_prevention(client: TestClient, db_session):
    """Verify raw tokens and credentials are NEVER exposed in execution or evidence responses."""
    setup = create_authorized_project_setup(client, db_session)
    proj_id = setup["project_id"]

    create_res = client.post(
        f"/api/v1/projects/{proj_id}/security-tests/",
        json={
            "endpoint_id": setup["vuln_ep_id"],
            "attacker_identity_id": setup["bob_id"],
            "victim_identity_id": setup["alice_id"],
            "victim_resource_id": setup["resource_id"],
            "victim_resource_instance_id": "order_alice_101",
        },
    )
    test_id = create_res.json()["id"]

    exec_res = client.post(f"/api/v1/security-tests/{test_id}/execute")
    assert exec_res.status_code == 200

    raw_exec_text = exec_res.text
    # Neither Bob's nor Alice's token should ever be in the output
    assert "demo-token-bob" not in raw_exec_text
    assert "demo-token-alice" not in raw_exec_text

    # Check evidence directly
    exec_id = exec_res.json()["id"]
    exec_detail = client.get(f"/api/v1/executions/{exec_id}").json()
    req_meta = exec_detail["evidence"]["request_metadata"]
    assert req_meta["headers"]["Authorization"] == "[REDACTED]"
    assert req_meta["headers"]["X-Correlation-ID"] is not None


def test_replay_test_flow(client: TestClient, db_session):
    """Verify the Replay Test action executes the security test again for the same target."""
    setup = create_authorized_project_setup(client, db_session)
    proj_id = setup["project_id"]

    test_res = client.post(
        f"/api/v1/projects/{proj_id}/security-tests/",
        json={
            "endpoint_id": setup["vuln_ep_id"],
            "attacker_identity_id": setup["bob_id"],
            "victim_resource_id": setup["resource_id"],
            "victim_resource_instance_id": "order_alice_101",
        },
    )
    test_id = test_res.json()["id"]

    # Initial execution
    client.post(f"/api/v1/security-tests/{test_id}/execute")
    findings = client.get(f"/api/v1/projects/{proj_id}/findings/").json()
    assert len(findings) == 1
    finding_id = findings[0]["id"]

    # Replay test
    replay_res = client.post(f"/api/v1/findings/{finding_id}/replay")
    assert replay_res.status_code == 200
    replay_data = replay_res.json()
    assert replay_data["result"] == "CONFIRMED"
    assert replay_data["status"] == "COMPLETED"

    # Verify executions count is now 2
    executions = client.get(f"/api/v1/security-tests/{test_id}/executions").json()
    assert len(executions) == 2
