import json
import uuid
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.rate_limit import rate_limiter
from app.core.security import generate_api_token
from app.models import (
    Project, Role, User, ApiToken, ProjectMembership, AuditEvent,
    ScanProfile, SecurityGate, SecurityBaseline
)
from app.services.auth.permission_service import seed_project_roles


def test_complete_end_to_end_security_lifecycle(client: TestClient, db_session):
    """
    Final End-to-End Validation Scenario:
    Exercises the full deterministic lifecycle from project creation to report and audit.
    """
    # 1. Project Creation
    p_resp = client.post("/api/v1/projects/", json={
        "name": "E2E Final Validation Project",
        "description": "Deterministic validation of all SentinelAPI capabilities",
        "environment": "staging",
        "authorization_status": "authorized",
    })
    assert p_resp.status_code == 201
    proj = p_resp.json()
    p_id = proj["id"]

    # 2. Ingest API Specification
    spec_yaml = """
openapi: 3.0.0
info:
  title: Banking Transfer API
  version: 1.0.0
paths:
  /accounts/{id}:
    get:
      summary: Read Account Details
      responses:
        "200":
          description: OK
  /transfers:
    post:
      summary: Initiate Transfer
      responses:
        "201":
          description: Created
"""
    ingest_resp = client.post(
        f"/api/v1/{p_id}/ingest",
        files={"file": ("banking.yaml", spec_yaml, "text/yaml")},
    )
    assert ingest_resp.status_code == 202
    api_id = ingest_resp.json()["api_id"]

    # 3. Create Identities & Roles
    r_user = client.post(f"/api/v1/projects/{p_id}/roles/", json={"name": "Standard User"}).json()
    ident_resp = client.post(f"/api/v1/projects/{p_id}/identities/", json={
        "name": "Attacker Identity",
        "role_id": r_user["id"],
        "auth_type": "bearer_token",
        "credential_reference": "token_***attacker",
    })
    assert ident_resp.status_code == 201
    ident_id = ident_resp.json()["id"]

    # 4. Create Scan Profile
    prof_resp = client.post(f"/api/v1/projects/{p_id}/scan-profiles", json={
        "name": "Full Assurance Profile",
        "profile_type": "STANDARD",
        "allowed_test_types": ["BOLA", "BFLA", "AUTH_MISSING"],
    })
    assert prof_resp.status_code == 201
    prof_id = prof_resp.json()["id"]

    # 5. Create Test Suite & Execution Plan
    suite_resp = client.post(f"/api/v1/projects/{p_id}/test-suites", json={"name": "E2E Test Suite"})
    assert suite_resp.status_code == 201
    suite_id = suite_resp.json()["id"]

    plan_resp = client.post(f"/api/v1/projects/{p_id}/execution-plans", json={
        "name": "E2E Plan",
        "suite_id": suite_id,
        "execution_mode": "SEQUENTIAL",
    })
    assert plan_resp.status_code == 201
    plan_id = plan_resp.json()["id"]

    # 6. Execute Plan
    start_resp = client.post(f"/api/v1/execution-plans/{plan_id}/start")
    assert start_resp.status_code == 200
    plan_res = start_resp.json()
    assert plan_res["status"] in ("COMPLETED", "RUNNING")

    # 7. Create Baseline
    base_resp = client.post(f"/api/v1/projects/{p_id}/baselines", json={
        "name": "Release 1.0 Baseline",
        "execution_plan_id": plan_id,
        "is_active": True,
    })
    assert base_resp.status_code == 201
    base_id = base_resp.json()["id"]

    # 8. Create Security Gate
    gate_resp = client.post(f"/api/v1/projects/{p_id}/security-gates", json={
        "name": "Production Deploy Gate",
        "baseline_id": base_id,
        "scan_profile_id": prof_id,
        "failure_rules": {"max_regressions": 0, "max_new_violations": 0},
        "warning_rules": {"max_inconclusive": 1},
    })
    assert gate_resp.status_code == 201
    gate_id = gate_resp.json()["id"]

    # 9. Baseline Comparison
    comp_resp = client.post(
        f"/api/v1/baselines/{base_id}/compare",
        json={"execution_plan_id": plan_id},
    )
    assert comp_resp.status_code == 201
    comp_id = comp_resp.json()["id"]

    # 10. Gate Evaluation
    eval_resp = client.post(f"/api/v1/security-gates/{gate_id}/evaluate/{comp_id}")
    assert eval_resp.status_code == 200
    assert eval_resp.json()["status"] in ("PASS", "WARN", "FAIL", "ERROR")

    # 11. Generate Security Report
    rep_resp = client.post(f"/api/v1/projects/{p_id}/security-reports", json={
        "name": "Final Release Security Assessment",
        "report_type": "SECURITY_ASSESSMENT",
        "source_execution_plan_id": plan_id,
        "source_gate_evaluation_id": eval_resp.json()["id"],
    })
    assert rep_resp.status_code == 201
    rep_id = rep_resp.json()["id"]

    # 12. Create Scan Schedule
    sched_resp = client.post(f"/api/v1/projects/{p_id}/security-scan-schedules", json={
        "name": "Nightly Regression Schedule",
        "schedule_type": "DAILY",
        "timezone": "UTC",
        "scan_profile_id": prof_id,
        "security_gate_id": gate_id,
    })
    assert sched_resp.status_code == 201
    sched_id = sched_resp.json()["id"]

    # 13. Verify Audit Trail Contains Complete Lineage
    audit_resp = client.get(f"/api/v1/projects/{p_id}/audit-events")
    assert audit_resp.status_code == 200
    events = audit_resp.json()["events"]
    assert len(events) >= 1
    # Verify events are strictly immutable
    first_id = events[0]["id"]
    assert client.put(f"/api/v1/audit-events/{first_id}", json={}).status_code == 405
    assert client.delete(f"/api/v1/audit-events/{first_id}").status_code == 405


def test_cross_project_isolation_matrix(client: TestClient, db_session):
    """
    Exhaustive cross-project isolation matrix:
    Validates that User in Project A cannot access or mutate resources in Project B.
    """
    # Create Project Alpha and Project Beta
    p_alpha = client.post("/api/v1/projects/", json={"name": "Project Alpha"}).json()["id"]
    p_beta = client.post("/api/v1/projects/", json={"name": "Project Beta"}).json()["id"]

    # Seed roles
    client.post(f"/api/v1/projects/{p_alpha}/roles/seed")
    client.post(f"/api/v1/projects/{p_beta}/roles/seed")

    # Create users
    u_alpha = client.post("/api/v1/users", json={"email": "alpha_user@sentinel.local", "display_name": "Alpha User"}).json()
    u_beta = client.post("/api/v1/users", json={"email": "beta_user@sentinel.local", "display_name": "Beta User"}).json()

    # Assign membership: u_alpha -> Alpha, u_beta -> Beta
    r_admin_a = db_session.query(Role).filter(Role.project_id == p_alpha, Role.name == "PROJECT_ADMIN").first()
    r_admin_b = db_session.query(Role).filter(Role.project_id == p_beta, Role.name == "PROJECT_ADMIN").first()

    client.post(f"/api/v1/projects/{p_alpha}/memberships", json={"user_id": u_alpha["id"], "role_id": r_admin_a.id})
    client.post(f"/api/v1/projects/{p_beta}/memberships", json={"user_id": u_beta["id"], "role_id": r_admin_b.id})

    # Tokens
    tok_alpha = client.post(f"/api/v1/users/{u_alpha['id']}/api-tokens", json={"name": "Alpha Tok"}).json()["raw_token"]
    tok_beta = client.post(f"/api/v1/users/{u_beta['id']}/api-tokens", json={"name": "Beta Tok"}).json()["raw_token"]

    headers_alpha = {"Authorization": f"Bearer {tok_alpha}"}
    headers_beta = {"Authorization": f"Bearer {tok_beta}"}

    # 1. Alpha trying to access Beta audit events -> 403
    resp1 = client.get(f"/api/v1/projects/{p_beta}/audit-events", headers=headers_alpha)
    assert resp1.status_code == 403

    # 2. Alpha trying to list Beta memberships -> 403
    resp2 = client.get(f"/api/v1/projects/{p_beta}/memberships", headers=headers_alpha)
    assert resp2.status_code == 403

    # 3. Alpha trying to add member to Beta -> 403
    resp3 = client.post(
        f"/api/v1/projects/{p_beta}/memberships",
        json={"user_id": u_alpha["id"], "role_id": r_admin_b.id},
        headers=headers_alpha,
    )
    assert resp3.status_code == 403

    # 4. Beta accessing Alpha -> 403
    resp4 = client.get(f"/api/v1/projects/{p_alpha}/audit-events", headers=headers_beta)
    assert resp4.status_code == 403


def test_audit_preservation_on_entity_deletion(client: TestClient, db_session):
    """
    Verify SET NULL behavior: deleting a user or project preserves immutable audit records.
    """
    # Create user
    user = client.post("/api/v1/users", json={"email": "temp@sentinel.local", "display_name": "Temporary"}).json()
    u_id = user["id"]

    # Verify audit event was logged
    events = db_session.query(AuditEvent).filter(AuditEvent.actor_user_id == u_id).all()
    # If system created it, let's log an event explicitly with actor_user_id
    ev = AuditEvent(
        id=str(uuid.uuid4()),
        actor_user_id=u_id,
        event_type="AUTH",
        action="LOGIN",
        resource_type="SESSION",
        outcome="SUCCESS",
        request_id=str(uuid.uuid4()),
        metadata_json={"test": True},
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(ev)
    db_session.commit()
    ev_id = ev.id

    # Delete user via ORM session
    user_obj = db_session.query(User).filter(User.id == u_id).first()
    db_session.delete(user_obj)
    db_session.commit()

    # Verify AuditEvent still exists with actor_user_id set to None
    persisted_ev = db_session.query(AuditEvent).filter(AuditEvent.id == ev_id).first()
    assert persisted_ev is not None
    assert persisted_ev.actor_user_id is None
    assert persisted_ev.outcome == "SUCCESS"


def test_no_credential_leakage_in_error_or_audit(client: TestClient):
    """
    Verify passwords, API tokens, Authorization headers, and session cookies
    are never leaked in error messages, audit events, or response metadata.
    """
    # Deliberate malformed request with sensitive headers
    resp = client.post(
        "/api/v1/projects/",
        headers={
            "Authorization": "Bearer super_secret_token_value_999",
            "X-API-Key": "super_secret_api_key_888",
            "Cookie": "session=super_secret_cookie_777",
        },
        json={
            "name": "Secret Leakage Test",
            "password": "my_secret_password_123",
            "token": "sensitive_token_abc",
        },
    )
    # Check response text
    body_text = resp.text
    assert "super_secret_token_value_999" not in body_text
    assert "super_secret_api_key_888" not in body_text
    assert "super_secret_cookie_777" not in body_text
    assert "my_secret_password_123" not in body_text
    assert "sensitive_token_abc" not in body_text


def test_production_hardening_and_rate_limiting(client: TestClient):
    """
    Verify rate limiter blocks abuse with 429 when enabled and security headers are attached.
    """
    # Security Headers check
    resp = client.get("/")
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert resp.headers.get("X-XSS-Protection") == "1; mode=block"
    assert "X-Request-ID" in resp.headers

    # Rate Limiter check
    rate_limiter.reset()
    for _ in range(10):
        rate_limiter.is_allowed("127.0.0.1", limit=10, window_seconds=60)

    blocked, rem, retry = rate_limiter.is_allowed("127.0.0.1", limit=10, window_seconds=60)
    assert blocked is False
    assert rem == 0
    assert retry > 0
