import pytest
from fastapi.testclient import TestClient
from app.models import (
    Project,
    API,
    Endpoint,
    Role,
    Identity,
    SecurityTest,
    TestExecution,
    Finding,
    Evidence,
    AuthorizationMatrixRule,
    EndpointAuthorizationPolicy,
)
from app.services.security_engine.response_analyzer import ResponseAnalyzer

# Avoid pytest trying to collect TestExecution class as a test suite
TestExecution.__test__ = False


def create_authorized_bfla_project(client: TestClient, db_session) -> dict:
    """Helper to create an authorized testing project with endpoints and roles."""
    resp = client.post("/api/v1/projects/", json={
        "name": "BFLA Target API",
        "description": "Project for Authorization Boundary Engine verification",
        "environment": "staging",
        "base_url": "http://testserver",
        "authorization_status": "authorized",
    })
    assert resp.status_code == 201
    project = resp.json()
    proj_id = project["id"]

    # Create API & Endpoints
    api = API(
        project_id=proj_id,
        name="Admin Management API",
        version="v1",
        format="openapi3",
        status="active",
        url="http://testserver/demo-target",
    )
    db_session.add(api)
    db_session.commit()
    db_session.refresh(api)

    ep_vuln = Endpoint(
        api_id=api.id,
        method="GET",
        path="/demo-target/admin/system-stats",
        summary="Vulnerable Admin Stats",
    )
    ep_prot = Endpoint(
        api_id=api.id,
        method="GET",
        path="/demo-target/admin/protected-system-stats",
        summary="Protected Admin Stats",
    )
    ep_err = Endpoint(
        api_id=api.id,
        method="GET",
        path="/demo-target/admin/error-stats",
        summary="Server Error Admin Stats",
    )
    db_session.add_all([ep_vuln, ep_prot, ep_err])
    db_session.commit()
    db_session.refresh(ep_vuln)
    db_session.refresh(ep_prot)
    db_session.refresh(ep_err)

    # Create roles: User and Admin
    role_user_resp = client.post(f"/api/v1/projects/{project['id']}/roles/", json={
        "name": "User",
        "description": "Standard low-privilege user",
    })
    assert role_user_resp.status_code == 201
    role_user = role_user_resp.json()

    role_admin_resp = client.post(f"/api/v1/projects/{project['id']}/roles/", json={
        "name": "Admin",
        "description": "Privileged administrator",
    })
    assert role_admin_resp.status_code == 201
    role_admin = role_admin_resp.json()

    # Create identities
    ident_bob_resp = client.post(f"/api/v1/projects/{project['id']}/identities/", json={
        "name": "Bob Attacker",
        "role_id": role_user["id"],
        "auth_type": "bearer_token",
        "credential_value": "demo-token-bob",
    })
    assert ident_bob_resp.status_code == 201
    ident_bob = ident_bob_resp.json()

    ident_admin_resp = client.post(f"/api/v1/projects/{project['id']}/identities/", json={
        "name": "Charlie Admin",
        "role_id": role_admin["id"],
        "auth_type": "bearer_token",
        "credential_value": "demo-token-admin",
    })
    assert ident_admin_resp.status_code == 201
    ident_admin = ident_admin_resp.json()

    return {
        "project": project,
        "api": {"id": api.id, "name": api.name},
        "ep_vuln": {"id": ep_vuln.id, "path": ep_vuln.path, "method": ep_vuln.method},
        "ep_prot": {"id": ep_prot.id, "path": ep_prot.path, "method": ep_prot.method},
        "ep_err": {"id": ep_err.id, "path": ep_err.path, "method": ep_err.method},
        "role_user": role_user,
        "role_admin": role_admin,
        "ident_bob": ident_bob,
        "ident_admin": ident_admin,
    }


def test_authorization_matrix_crud(client: TestClient, db_session):
    """Test creating, reading, updating, and deleting authorization matrix rules."""
    ctx = create_authorized_bfla_project(client, db_session)
    proj_id = ctx["project"]["id"]
    ep_id = ctx["ep_vuln"]["id"]
    role_user_id = ctx["role_user"]["id"]
    role_admin_id = ctx["role_admin"]["id"]

    # 1. Create rule: User -> GET ep_vuln -> DENY
    rule_resp = client.post(f"/api/v1/projects/{proj_id}/authorization-matrix/rules", json={
        "endpoint_id": ep_id,
        "role_id": role_user_id,
        "http_method": "GET",
        "expected_access": "DENY",
    })
    assert rule_resp.status_code == 200
    rule = rule_resp.json()
    assert rule["expected_access"] == "DENY"
    assert rule["endpoint_id"] == ep_id
    assert rule["role_id"] == role_user_id

    # 2. Get Matrix View
    matrix_resp = client.get(f"/api/v1/projects/{proj_id}/authorization-matrix")
    assert matrix_resp.status_code == 200
    matrix_data = matrix_resp.json()
    assert matrix_data["project_id"] == proj_id
    assert len(matrix_data["roles"]) == 2
    assert len(matrix_data["endpoints"]) == 3

    # Check cell for ep_vuln and User role
    row = next(r for r in matrix_data["endpoints"] if r["endpoint_id"] == ep_id)
    assert row["cells"][role_user_id]["expected_access"] == "DENY"
    assert row["cells"][role_user_id]["test_status"] == "NOT TESTED"

    # 3. Bulk update: Admin -> ALLOW
    bulk_resp = client.put(f"/api/v1/projects/{proj_id}/authorization-matrix/rules", json=[
        {
            "endpoint_id": ep_id,
            "role_id": role_admin_id,
            "http_method": "GET",
            "expected_access": "ALLOW",
        }
    ])
    assert bulk_resp.status_code == 200

    # 4. Delete rule
    del_resp = client.delete(f"/api/v1/authorization-matrix/rules/{rule['id']}")
    assert del_resp.status_code == 204


def test_policy_validation_and_matrix_sync(client: TestClient, db_session):
    """Test endpoint authorization policy creation, update, and matrix reflection."""
    ctx = create_authorized_bfla_project(client, db_session)
    proj_id = ctx["project"]["id"]
    ep_id = ctx["ep_prot"]["id"]
    role_user_id = ctx["role_user"]["id"]
    role_admin_id = ctx["role_admin"]["id"]

    # 1. Get default policy
    pol_resp = client.get(f"/api/v1/endpoints/{ep_id}/policy")
    assert pol_resp.status_code == 200
    assert pol_resp.json()["authentication_required"] is True

    # 2. Update policy: allow Admin, deny User
    upd_resp = client.put(f"/api/v1/endpoints/{ep_id}/policy", json={
        "authentication_required": True,
        "notes": "Admin role strictly required for system statistics",
        "allowed_role_ids": [role_admin_id],
        "denied_role_ids": [role_user_id],
    })
    assert upd_resp.status_code == 200
    pol_data = upd_resp.json()
    assert len(pol_data["allowed_roles"]) == 1
    assert len(pol_data["denied_roles"]) == 1

    # 3. Verify matrix automatically reflects policy-derived expected access
    matrix_resp = client.get(f"/api/v1/projects/{proj_id}/authorization-matrix")
    assert matrix_resp.status_code == 200
    row = next(r for r in matrix_resp.json()["endpoints"] if r["endpoint_id"] == ep_id)
    assert row["cells"][role_admin_id]["expected_access"] == "ALLOW"
    assert row["cells"][role_user_id]["expected_access"] == "DENY"


def test_cross_project_isolation(client: TestClient, db_session):
    """Validate cross-project foreign key and policy integrity."""
    ctx1 = create_authorized_bfla_project(client, db_session)
    # Create second project
    p2_resp = client.post("/api/v1/projects/", json={"name": "Project Two", "authorization_status": "authorized"})
    p2 = p2_resp.json()

    # Try to add rule in Project 2 targeting endpoint from Project 1
    bad_rule = client.post(f"/api/v1/projects/{p2['id']}/authorization-matrix/rules", json={
        "endpoint_id": ctx1["ep_vuln"]["id"],
        "expected_access": "DENY",
    })
    assert bad_rule.status_code == 400
    assert "different project" in bad_rule.json()["detail"]

    # Try to set policy in Project 1 with a role belonging to Project 2
    r2_resp = client.post(f"/api/v1/projects/{p2['id']}/roles/", json={"name": "P2 Role"})
    r2 = r2_resp.json()

    bad_policy = client.put(f"/api/v1/endpoints/{ctx1['ep_vuln']['id']}/policy", json={
        "allowed_role_ids": [r2["id"]],
    })
    assert bad_policy.status_code == 400


def test_response_signature_generation():
    """Verify ResponseAnalyzer normalizes JSON, detects sensitive keys, and stable IDs."""
    sig = ResponseAnalyzer.analyze(
        status_code=200,
        headers={"content-type": "application/json; charset=utf-8"},
        body='{"id": 99, "user_id": "c1f73b64-8ab3-4c91-a5d2-f67f2c8d2a10", "secret_token": "hidden123", "role": "admin", "items": [{"name": "widget"}]}',
    )
    assert sig.status_code == 200
    assert sig.is_json is True
    assert sig.is_empty is False
    assert not sig.is_auth_failure
    # Normalized structure preserves types, not values
    assert sig.normalized_structure["id"] == "integer"
    assert sig.normalized_structure["secret_token"] == "string"
    assert sig.normalized_structure["items"] == [{"name": "string"}]
    # Identifiers extracted
    assert "99" in sig.detected_identifiers
    assert "c1f73b64-8ab3-4c91-a5d2-f67f2c8d2a10" in sig.detected_identifiers
    # Sensitive fields detected
    assert "secret_token" in sig.sensitive_fields_detected
    assert "role" in sig.sensitive_fields_detected

    # Test application-level denial in 200 OK
    sig_denied = ResponseAnalyzer.analyze(
        status_code=200,
        headers={"content-type": "application/json"},
        body='{"error": "Unauthorized: Access denied to administrative resource"}',
    )
    assert sig_denied.is_auth_failure is True
    res, reason, _ = ResponseAnalyzer.evaluate_access(sig_denied, "DENY")
    assert res == "PASS"


def test_bfla_pass_case(client: TestClient, db_session):
    """Test BFLA pass case: Bob (User role) attempts access to protected admin endpoint -> HTTP 403."""
    ctx = create_authorized_bfla_project(client, db_session)
    proj_id = ctx["project"]["id"]
    ep_id = ctx["ep_prot"]["id"]  # /demo-target/admin/protected-system-stats
    ident_bob_id = ctx["ident_bob"]["id"]

    # 1. Create BFLA test with expected_access='DENY'
    test_resp = client.post(f"/api/v1/projects/{proj_id}/security-tests/", json={
        "endpoint_id": ep_id,
        "test_type": "BFLA",
        "attacker_identity_id": ident_bob_id,
        "expected_access": "DENY",
    })
    assert test_resp.status_code == 201
    test_data = test_resp.json()
    assert test_data["test_type"] == "BFLA"
    assert test_data["expected_access"] == "DENY"

    # 2. Execute test
    exec_resp = client.post(f"/api/v1/security-tests/{test_data['id']}/execute")
    assert exec_resp.status_code == 200
    exec_data = exec_resp.json()
    assert exec_data["status"] == "COMPLETED"
    assert exec_data["result"] == "PASS"
    assert exec_data["http_status"] == 403

    # 3. Verify no finding is created
    findings_resp = client.get(f"/api/v1/projects/{proj_id}/findings/")
    assert findings_resp.status_code == 200
    assert len(findings_resp.json()) == 0


def test_bfla_confirmed_case(client: TestClient, db_session):
    """Test BFLA confirmed case: Bob (User role) accesses vulnerable admin endpoint -> HTTP 200 with admin data."""
    ctx = create_authorized_bfla_project(client, db_session)
    proj_id = ctx["project"]["id"]
    ep_id = ctx["ep_vuln"]["id"]  # /demo-target/admin/system-stats
    ident_bob_id = ctx["ident_bob"]["id"]

    # 1. Create BFLA test
    test_resp = client.post(f"/api/v1/projects/{proj_id}/security-tests/", json={
        "endpoint_id": ep_id,
        "test_type": "BFLA",
        "attacker_identity_id": ident_bob_id,
        "expected_access": "DENY",
    })
    assert test_resp.status_code == 201
    test_data = test_resp.json()

    # 2. Execute test
    exec_resp = client.post(f"/api/v1/security-tests/{test_data['id']}/execute")
    assert exec_resp.status_code == 200
    exec_data = exec_resp.json()
    assert exec_data["status"] == "COMPLETED"
    assert exec_data["result"] == "CONFIRMED"
    assert exec_data["http_status"] == 200

    # 3. Verify finding is generated with BFLA metadata
    findings_resp = client.get(f"/api/v1/projects/{proj_id}/findings/")
    assert findings_resp.status_code == 200
    findings = findings_resp.json()
    assert len(findings) == 1
    finding = findings[0]
    assert finding["type"] == "BFLA"
    assert finding["severity"] == "HIGH"
    assert finding["confidence"] == "HIGH"
    assert finding["expected_authorization"] == "DENY"
    assert "granted access" in finding["description"].lower()

    # 4. Check detailed finding endpoint
    det_resp = client.get(f"/api/v1/findings/{finding['id']}")
    assert det_resp.status_code == 200
    detail = det_resp.json()
    assert detail["evidence"] is not None
    assert detail["evidence"]["response_metadata"]["response_signature"]["status_code"] == 200


def test_duplicate_finding_prevention(client: TestClient, db_session):
    """Re-executing a confirmed test updates the existing finding instead of duplicating it."""
    ctx = create_authorized_bfla_project(client, db_session)
    proj_id = ctx["project"]["id"]
    ep_id = ctx["ep_vuln"]["id"]
    ident_bob_id = ctx["ident_bob"]["id"]

    test_resp = client.post(f"/api/v1/projects/{proj_id}/security-tests/", json={
        "endpoint_id": ep_id,
        "test_type": "BFLA",
        "attacker_identity_id": ident_bob_id,
        "expected_access": "DENY",
    })
    test_data = test_resp.json()

    # Run 1
    exec1 = client.post(f"/api/v1/security-tests/{test_data['id']}/execute").json()
    assert exec1["result"] == "CONFIRMED"

    findings1 = client.get(f"/api/v1/projects/{proj_id}/findings/").json()
    assert len(findings1) == 1
    finding_id = findings1[0]["id"]

    # Run 2 (re-execution of confirmed condition)
    exec2 = client.post(f"/api/v1/security-tests/{test_data['id']}/execute").json()
    assert exec2["result"] == "CONFIRMED"

    findings2 = client.get(f"/api/v1/projects/{proj_id}/findings/").json()
    assert len(findings2) == 1, "Duplicate finding was incorrectly created"
    assert findings2[0]["id"] == finding_id, "Existing finding ID should be preserved"
    assert findings2[0]["execution_id"] == exec2["id"], "Finding execution ID should be updated to latest execution"


def test_bfla_inconclusive_case(client: TestClient, db_session):
    """Test BFLA inconclusive case: endpoint returns HTTP 500 server error."""
    ctx = create_authorized_bfla_project(client, db_session)
    proj_id = ctx["project"]["id"]
    ep_id = ctx["ep_err"]["id"]
    ident_bob_id = ctx["ident_bob"]["id"]

    test_resp = client.post(f"/api/v1/projects/{proj_id}/security-tests/", json={
        "endpoint_id": ep_id,
        "test_type": "BFLA",
        "attacker_identity_id": ident_bob_id,
        "expected_access": "DENY",
    })
    test_data = test_resp.json()

    exec_resp = client.post(f"/api/v1/security-tests/{test_data['id']}/execute")
    assert exec_resp.status_code == 200
    exec_data = exec_resp.json()
    assert exec_data["status"] == "COMPLETED"
    assert exec_data["result"] == "INCONCLUSIVE"
    assert exec_data["http_status"] == 500
    assert exec_data["error_category"] == "server_error"

    # No finding generated
    findings = client.get(f"/api/v1/projects/{proj_id}/findings/").json()
    assert len(findings) == 0


def test_bfla_generator_flow(client: TestClient, db_session):
    """Test automatic controlled BFLA test generation."""
    ctx = create_authorized_bfla_project(client, db_session)
    proj_id = ctx["project"]["id"]

    # Generate tests
    gen_resp = client.post(f"/api/v1/projects/{proj_id}/generate-bfla-tests", json={
        "target_all_safe_endpoints": True,
    })
    assert gen_resp.status_code == 200
    gen_data = gen_resp.json()
    assert gen_data["generated_count"] >= 1
    assert len(gen_data["tests"]) >= 1

    # Running generator again skips existing tests
    gen_resp2 = client.post(f"/api/v1/projects/{proj_id}/generate-bfla-tests", json={
        "target_all_safe_endpoints": True,
    })
    assert gen_resp2.status_code == 200
    assert gen_resp2.json()["generated_count"] == 0
    assert gen_resp2.json()["skipped_count"] >= 1


def test_credential_redaction_in_bfla_evidence(client: TestClient, db_session):
    """Verify secrets are redacted in evidence for BFLA tests."""
    ctx = create_authorized_bfla_project(client, db_session)
    proj_id = ctx["project"]["id"]
    ep_id = ctx["ep_vuln"]["id"]
    ident_bob_id = ctx["ident_bob"]["id"]

    test_resp = client.post(f"/api/v1/projects/{proj_id}/security-tests/", json={
        "endpoint_id": ep_id,
        "test_type": "BFLA",
        "attacker_identity_id": ident_bob_id,
        "expected_access": "DENY",
    })
    test_id = test_resp.json()["id"]

    exec_resp = client.post(f"/api/v1/security-tests/{test_id}/execute")
    exec_id = exec_resp.json()["id"]

    # Inspect execution evidence
    exec_detail = client.get(f"/api/v1/executions/{exec_id}").json()
    ev = exec_detail["evidence"]
    assert ev is not None

    raw_ev_str = str(ev)
    assert "demo-token-bob" not in raw_ev_str, "Raw bearer token leaked in stored evidence!"
    assert "[REDACTED]" in raw_ev_str


def test_replay_bfla_finding(client: TestClient, db_session):
    """Test replaying a confirmed BFLA finding."""
    ctx = create_authorized_bfla_project(client, db_session)
    proj_id = ctx["project"]["id"]
    ep_id = ctx["ep_vuln"]["id"]
    ident_bob_id = ctx["ident_bob"]["id"]

    test = client.post(f"/api/v1/projects/{proj_id}/security-tests/", json={
        "endpoint_id": ep_id,
        "test_type": "BFLA",
        "attacker_identity_id": ident_bob_id,
        "expected_access": "DENY",
    }).json()

    # Execute to confirm finding
    client.post(f"/api/v1/security-tests/{test['id']}/execute")
    finding = client.get(f"/api/v1/projects/{proj_id}/findings/").json()[0]

    # Replay
    replay_resp = client.post(f"/api/v1/findings/{finding['id']}/replay")
    assert replay_resp.status_code == 200
    rep_data = replay_resp.json()
    assert rep_data["status"] == "COMPLETED"
    assert rep_data["result"] == "CONFIRMED"
