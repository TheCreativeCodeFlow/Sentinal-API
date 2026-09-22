import pytest
import json
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
    AuthenticationPolicy,
)

# Avoid pytest trying to collect TestExecution class as a test suite
TestExecution.__test__ = False


def create_authorized_auth_project(client: TestClient, db_session) -> dict:
    """Helper to create an authorized testing project with endpoints for authentication tests."""
    resp = client.post("/api/v1/projects/", json={
        "name": "Auth Security Target API",
        "description": "Project for Authentication Security Engine verification",
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
        name="Auth Test Target API",
        version="v1",
        format="openapi3",
        status="active",
        url="http://testserver/demo-target",
    )
    db_session.add(api)
    db_session.commit()
    db_session.refresh(api)

    ep_protected = Endpoint(
        api_id=api.id,
        method="GET",
        path="/demo-target/auth/protected",
        summary="Secure Protected Endpoint",
    )
    ep_vulnerable = Endpoint(
        api_id=api.id,
        method="GET",
        path="/demo-target/auth/vulnerable",
        summary="Authentication Bypass Vulnerable",
    )
    ep_soft_deny = Endpoint(
        api_id=api.id,
        method="GET",
        path="/demo-target/auth/soft-deny",
        summary="Soft Denial Endpoint",
    )
    ep_error = Endpoint(
        api_id=api.id,
        method="GET",
        path="/demo-target/auth/error",
        summary="Malformed Auth Crash Endpoint",
    )
    ep_generic_err = Endpoint(
        api_id=api.id,
        method="GET",
        path="/demo-target/auth/server-error",
        summary="Generic Error Endpoint",
    )
    db_session.add_all([ep_protected, ep_vulnerable, ep_soft_deny, ep_error, ep_generic_err])
    db_session.commit()

    # Create default role & identity
    role = Role(
        project_id=proj_id,
        name="StandardUser",
        description="Standard authenticated user",
    )
    db_session.add(role)
    db_session.commit()
    db_session.refresh(role)

    ident = Identity(
        project_id=proj_id,
        role_id=role.id,
        name="Alice Valid",
        auth_type="bearer_token",
        credential_value="demo-token-alice",
        environment="staging",
    )
    db_session.add(ident)
    db_session.commit()
    db_session.refresh(ident)

    return {
        "project": project,
        "api": api,
        "ep_protected": ep_protected,
        "ep_vulnerable": ep_vulnerable,
        "ep_soft_deny": ep_soft_deny,
        "ep_error": ep_error,
        "ep_generic_err": ep_generic_err,
        "role": role,
        "identity": ident,
    }


def test_auth_policy_crud_and_persistence(client: TestClient, db_session):
    """Test retrieving default policy and updating/persisting custom AuthenticationPolicy."""
    ctx = create_authorized_auth_project(client, db_session)
    ep_id = ctx["ep_protected"].id

    # 1. GET default policy
    resp = client.get(f"/api/v1/endpoints/{ep_id}/auth-policy")
    assert resp.status_code == 200
    data = resp.json()
    assert data["endpoint_id"] == ep_id
    assert data["authentication_required"] is True
    assert data["authentication_scheme"] == "bearer_token"
    assert data["expected_denial_status"] == 401

    # 2. PUT custom policy
    update_resp = client.put(f"/api/v1/endpoints/{ep_id}/auth-policy", json={
        "authentication_required": True,
        "authentication_scheme": "api_key",
        "expected_denial_status": 403,
        "notes": "Custom API Key authentication requirement",
    })
    assert update_resp.status_code == 200
    updated_data = update_resp.json()
    assert updated_data["authentication_scheme"] == "api_key"
    assert updated_data["expected_denial_status"] == 403
    assert updated_data["notes"] == "Custom API Key authentication requirement"

    # 3. GET verify persistence
    get_resp = client.get(f"/api/v1/endpoints/{ep_id}/auth-policy")
    assert get_resp.status_code == 200
    persisted = get_resp.json()
    assert persisted["authentication_scheme"] == "api_key"
    assert persisted["expected_denial_status"] == 403


def test_auth_missing_pass_and_confirmed(client: TestClient, db_session):
    """
    Test AUTH_MISSING:
    - PASS on secure endpoint (rejection with 401)
    - CONFIRMED on vulnerable endpoint (bypassed with 200 OK + data)
    """
    ctx = create_authorized_auth_project(client, db_session)
    proj_id = ctx["project"]["id"]

    # 1. Secure endpoint test (PASS)
    test_pass = client.post(f"/api/v1/projects/{proj_id}/security-tests/", json={
        "endpoint_id": ctx["ep_protected"].id,
        "test_type": "AUTH_MISSING",
        "attacker_identity_id": ctx["identity"].id,
    })
    assert test_pass.status_code == 201
    test_pass_id = test_pass.json()["id"]

    exec_pass = client.post(f"/api/v1/security-tests/{test_pass_id}/execute")
    assert exec_pass.status_code == 200
    exec_data = exec_pass.json()
    assert exec_data["status"] == "COMPLETED"
    assert exec_data["result"] == "PASS"
    assert exec_data["http_status"] == 401

    # Verify no finding generated
    findings_resp = client.get(f"/api/v1/projects/{proj_id}/findings")
    assert len(findings_resp.json()) == 0

    # 2. Vulnerable endpoint test (CONFIRMED)
    test_vuln = client.post(f"/api/v1/projects/{proj_id}/security-tests/", json={
        "endpoint_id": ctx["ep_vulnerable"].id,
        "test_type": "AUTH_MISSING",
        "attacker_identity_id": ctx["identity"].id,
    })
    assert test_vuln.status_code == 201
    test_vuln_id = test_vuln.json()["id"]

    exec_vuln = client.post(f"/api/v1/security-tests/{test_vuln_id}/execute")
    assert exec_vuln.status_code == 200
    vuln_data = exec_vuln.json()
    assert vuln_data["status"] == "COMPLETED"
    assert vuln_data["result"] == "CONFIRMED"
    assert vuln_data["http_status"] == 200

    # Verify finding generated
    findings = client.get(f"/api/v1/projects/{proj_id}/findings?category=AUTHENTICATION").json()
    assert len(findings) == 1
    assert findings[0]["type"] == "AUTHENTICATION_BYPASS"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["authentication_mechanism"] == "bearer_token"


def test_auth_invalid_pass_and_confirmed(client: TestClient, db_session):
    """
    Test AUTH_INVALID:
    - PASS on secure endpoint (rejection with 401)
    - CONFIRMED on vulnerable endpoint (accepted with 200 OK)
    """
    ctx = create_authorized_auth_project(client, db_session)
    proj_id = ctx["project"]["id"]

    # 1. PASS on secure endpoint
    sec_test = client.post(f"/api/v1/projects/{proj_id}/security-tests/", json={
        "endpoint_id": ctx["ep_protected"].id,
        "test_type": "AUTH_INVALID",
        "attacker_identity_id": ctx["identity"].id,
    }).json()

    exec_resp = client.post(f"/api/v1/security-tests/{sec_test['id']}/execute").json()
    assert exec_resp["result"] == "PASS"
    assert exec_resp["http_status"] == 401

    # 2. CONFIRMED on vulnerable endpoint
    vuln_test = client.post(f"/api/v1/projects/{proj_id}/security-tests/", json={
        "endpoint_id": ctx["ep_vulnerable"].id,
        "test_type": "AUTH_INVALID",
        "attacker_identity_id": ctx["identity"].id,
    }).json()

    exec_vuln = client.post(f"/api/v1/security-tests/{vuln_test['id']}/execute").json()
    assert exec_vuln["result"] == "CONFIRMED"
    assert exec_vuln["http_status"] == 200

    findings = client.get(f"/api/v1/projects/{proj_id}/findings?type_filter=AUTHENTICATION").json()
    assert len(findings) == 1
    assert findings[0]["type"] == "INVALID_AUTH_ACCEPTED"


def test_auth_malformed_handling_and_500_crash(client: TestClient, db_session):
    """
    Test AUTH_MALFORMED:
    - PASS on secure endpoint (returns 401 or 400 properly)
    - CONFIRMED on crash endpoint (crashes with HTTP 500 -> MALFORMED_AUTH_HANDLING)
    """
    ctx = create_authorized_auth_project(client, db_session)
    proj_id = ctx["project"]["id"]

    # 1. Secure endpoint handles malformed auth safely (PASS)
    sec_test = client.post(f"/api/v1/projects/{proj_id}/security-tests/", json={
        "endpoint_id": ctx["ep_protected"].id,
        "test_type": "AUTH_MALFORMED",
        "attacker_identity_id": ctx["identity"].id,
    }).json()

    exec_resp = client.post(f"/api/v1/security-tests/{sec_test['id']}/execute").json()
    assert exec_resp["result"] == "PASS"

    # 2. Crashing endpoint raises HTTP 500 on malformed input (CONFIRMED MALFORMED_AUTH_HANDLING)
    crash_test = client.post(f"/api/v1/projects/{proj_id}/security-tests/", json={
        "endpoint_id": ctx["ep_error"].id,
        "test_type": "AUTH_MALFORMED",
        "attacker_identity_id": ctx["identity"].id,
    }).json()

    exec_crash = client.post(f"/api/v1/security-tests/{crash_test['id']}/execute").json()
    assert exec_crash["result"] == "CONFIRMED"
    assert exec_crash["http_status"] == 500

    findings = client.get(f"/api/v1/projects/{proj_id}/findings").json()
    assert len(findings) == 1
    assert findings[0]["type"] == "MALFORMED_AUTH_HANDLING"


def test_auth_expired_pass_and_confirmed(client: TestClient, db_session):
    """
    Test AUTH_EXPIRED:
    - PASS on secure endpoint (rejects expired credential with 401)
    - CONFIRMED on vulnerable endpoint (accepts expired credential with 200 OK)
    """
    ctx = create_authorized_auth_project(client, db_session)
    proj_id = ctx["project"]["id"]

    # 1. Secure endpoint rejects expired token (PASS)
    sec_test = client.post(f"/api/v1/projects/{proj_id}/security-tests/", json={
        "endpoint_id": ctx["ep_protected"].id,
        "test_type": "AUTH_EXPIRED",
        "attacker_identity_id": ctx["identity"].id,
    }).json()

    exec_sec = client.post(f"/api/v1/security-tests/{sec_test['id']}/execute").json()
    assert exec_sec["result"] == "PASS"
    assert exec_sec["http_status"] == 401

    # 2. Vulnerable endpoint accepts expired token (CONFIRMED)
    vuln_test = client.post(f"/api/v1/projects/{proj_id}/security-tests/", json={
        "endpoint_id": ctx["ep_vulnerable"].id,
        "test_type": "AUTH_EXPIRED",
        "attacker_identity_id": ctx["identity"].id,
    }).json()

    exec_vuln = client.post(f"/api/v1/security-tests/{vuln_test['id']}/execute").json()
    assert exec_vuln["result"] == "CONFIRMED"
    assert exec_vuln["http_status"] == 200

    findings = client.get(f"/api/v1/projects/{proj_id}/findings").json()
    assert len(findings) == 1
    assert findings[0]["type"] == "EXPIRED_AUTH_ACCEPTED"


def test_auth_scheme_inconsistency(client: TestClient, db_session):
    """
    Test AUTH_SCHEME:
    - PASS on secure endpoint (rejects wrong scheme with 401)
    - CONFIRMED on vulnerable endpoint (accepts wrong scheme with 200 OK)
    """
    ctx = create_authorized_auth_project(client, db_session)
    proj_id = ctx["project"]["id"]

    # 1. Secure endpoint rejects wrong scheme (PASS)
    sec_test = client.post(f"/api/v1/projects/{proj_id}/security-tests/", json={
        "endpoint_id": ctx["ep_protected"].id,
        "test_type": "AUTH_SCHEME",
        "attacker_identity_id": ctx["identity"].id,
    }).json()

    exec_sec = client.post(f"/api/v1/security-tests/{sec_test['id']}/execute").json()
    assert exec_sec["result"] == "PASS"

    # 2. Vulnerable endpoint accepts wrong scheme (CONFIRMED)
    vuln_test = client.post(f"/api/v1/projects/{proj_id}/security-tests/", json={
        "endpoint_id": ctx["ep_vulnerable"].id,
        "test_type": "AUTH_SCHEME",
        "attacker_identity_id": ctx["identity"].id,
    }).json()

    exec_vuln = client.post(f"/api/v1/security-tests/{vuln_test['id']}/execute").json()
    assert exec_vuln["result"] == "CONFIRMED"

    findings = client.get(f"/api/v1/projects/{proj_id}/findings").json()
    assert len(findings) == 1
    assert findings[0]["type"] == "AUTHENTICATION_INCONSISTENCY"


def test_soft_denial_detection(client: TestClient, db_session):
    """
    Test soft-denial detection:
    Response is HTTP 200 OK with {"error": "Unauthorized", "authenticated": false}.
    ResponseAnalyzer must identify this as a denial (PASS) and NOT produce a false-positive bypass.
    """
    ctx = create_authorized_auth_project(client, db_session)
    proj_id = ctx["project"]["id"]

    soft_deny_test = client.post(f"/api/v1/projects/{proj_id}/security-tests/", json={
        "endpoint_id": ctx["ep_soft_deny"].id,
        "test_type": "AUTH_MISSING",
        "attacker_identity_id": ctx["identity"].id,
    }).json()

    exec_resp = client.post(f"/api/v1/security-tests/{soft_deny_test['id']}/execute").json()
    # Must be PASS because soft denial was detected
    assert exec_resp["result"] == "PASS"
    assert "application level" in exec_resp["result_reason"].lower()

    # Zero findings should be generated
    findings = client.get(f"/api/v1/projects/{proj_id}/findings").json()
    assert len(findings) == 0


def test_server_error_inconclusive_for_non_malformed(client: TestClient, db_session):
    """
    Test that generic HTTP 500 server errors on non-malformed tests (e.g. AUTH_MISSING)
    are properly classified as INCONCLUSIVE with error_category 'server_error'.
    """
    ctx = create_authorized_auth_project(client, db_session)
    proj_id = ctx["project"]["id"]

    err_test = client.post(f"/api/v1/projects/{proj_id}/security-tests/", json={
        "endpoint_id": ctx["ep_generic_err"].id,
        "test_type": "AUTH_MISSING",
        "attacker_identity_id": ctx["identity"].id,
    }).json()

    exec_resp = client.post(f"/api/v1/security-tests/{err_test['id']}/execute").json()
    assert exec_resp["result"] == "INCONCLUSIVE"
    assert exec_resp["error_category"] == "server_error"

    findings = client.get(f"/api/v1/projects/{proj_id}/findings").json()
    assert len(findings) == 0


def test_auth_test_generator_flow(client: TestClient, db_session):
    """
    Test AuthenticationTestGenerator:
    - Generates 5 auth test types for each safe endpoint
    - Subsequent run skips duplicates
    """
    ctx = create_authorized_auth_project(client, db_session)
    proj_id = ctx["project"]["id"]

    gen_resp = client.post(f"/api/v1/projects/{proj_id}/generate-auth-tests")
    assert gen_resp.status_code == 200
    gen_data = gen_resp.json()
    # 5 safe GET endpoints * 5 test types = 25 tests
    assert gen_data["generated_count"] == 25
    assert gen_data["skipped_count"] == 0

    # Second run should skip all existing tests
    gen_resp_2 = client.post(f"/api/v1/projects/{proj_id}/generate-auth-tests")
    assert gen_resp_2.status_code == 200
    gen_data_2 = gen_resp_2.json()
    assert gen_data_2["generated_count"] == 0
    assert gen_data_2["skipped_count"] == 25


def test_finding_deduplication(client: TestClient, db_session):
    """
    Test finding deduplication:
    Running the same vulnerable authentication test multiple times must NOT
    create duplicate OPEN finding records.
    """
    ctx = create_authorized_auth_project(client, db_session)
    proj_id = ctx["project"]["id"]

    test_obj = client.post(f"/api/v1/projects/{proj_id}/security-tests/", json={
        "endpoint_id": ctx["ep_vulnerable"].id,
        "test_type": "AUTH_MISSING",
        "attacker_identity_id": ctx["identity"].id,
    }).json()

    # Execution 1
    exec1 = client.post(f"/api/v1/security-tests/{test_obj['id']}/execute").json()
    assert exec1["result"] == "CONFIRMED"

    findings1 = client.get(f"/api/v1/projects/{proj_id}/findings").json()
    assert len(findings1) == 1
    initial_finding_id = findings1[0]["id"]

    # Execution 2
    exec2 = client.post(f"/api/v1/security-tests/{test_obj['id']}/execute").json()
    assert exec2["result"] == "CONFIRMED"

    findings2 = client.get(f"/api/v1/projects/{proj_id}/findings").json()
    assert len(findings2) == 1
    assert findings2[0]["id"] == initial_finding_id


def test_cross_project_isolation(client: TestClient, db_session):
    """Test that authentication tests, policies, and findings are isolated between projects."""
    ctx_a = create_authorized_auth_project(client, db_session)
    proj_a = ctx_a["project"]["id"]

    # Project B
    resp_b = client.post("/api/v1/projects/", json={
        "name": "Project B",
        "environment": "staging",
        "authorization_status": "authorized",
    }).json()
    proj_b = resp_b["id"]

    # Attempt to configure test in Project B using Project A endpoint -> rejected
    cross_test = client.post(f"/api/v1/projects/{proj_b}/security-tests/", json={
        "endpoint_id": ctx_a["ep_protected"].id,
        "test_type": "AUTH_MISSING",
    })
    assert cross_test.status_code == 400
    assert "belongs to a different project" in cross_test.json()["detail"].lower()


def test_credential_redaction_in_auth_evidence(client: TestClient, db_session):
    """Verify that credentials and tokens are redacted from stored evidence."""
    ctx = create_authorized_auth_project(client, db_session)
    proj_id = ctx["project"]["id"]

    test_obj = client.post(f"/api/v1/projects/{proj_id}/security-tests/", json={
        "endpoint_id": ctx["ep_protected"].id,
        "test_type": "AUTH_INVALID",
        "attacker_identity_id": ctx["identity"].id,
    }).json()

    exec_resp = client.post(f"/api/v1/security-tests/{test_obj['id']}/execute").json()
    exec_id = exec_resp["id"]

    evidence_obj = db_session.query(Evidence).filter(Evidence.execution_id == exec_id).first()
    assert evidence_obj is not None

    # Check that raw authorization headers are masked
    assert "invalid-token-forged-9999" not in str(evidence_obj.redacted_request)
    assert "[REDACTED]" in str(evidence_obj.redacted_request)


def test_replay_auth_finding(client: TestClient, db_session):
    """Test replaying an existing authentication finding."""
    ctx = create_authorized_auth_project(client, db_session)
    proj_id = ctx["project"]["id"]

    test_obj = client.post(f"/api/v1/projects/{proj_id}/security-tests/", json={
        "endpoint_id": ctx["ep_vulnerable"].id,
        "test_type": "AUTH_MISSING",
        "attacker_identity_id": ctx["identity"].id,
    }).json()

    client.post(f"/api/v1/security-tests/{test_obj['id']}/execute")
    findings = client.get(f"/api/v1/projects/{proj_id}/findings").json()
    assert len(findings) == 1
    finding_id = findings[0]["id"]

    # Replay finding
    replay_resp = client.post(f"/api/v1/findings/{finding_id}/replay")
    assert replay_resp.status_code == 200
    replay_data = replay_resp.json()
    assert replay_data["status"] == "COMPLETED"
    assert replay_data["result"] == "CONFIRMED"
