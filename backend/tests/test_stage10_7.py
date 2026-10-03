import uuid
from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.rate_limit import rate_limiter
from app.core.security import generate_api_token, hash_token, verify_token_hash
from app.models import ApiToken, AuditEvent, ProjectMembership, Role, User
from app.services.auth.audit_service import sanitize_metadata
from app.services.auth.permission_service import seed_permissions, seed_project_roles


def test_crypto_token_generation_and_hashing():
    """Verify cryptographic token generation, hashing, and constant-time verification."""
    raw, prefix, thash = generate_api_token()
    assert raw.startswith("sent_")
    assert len(raw) > 20
    assert prefix == raw[:12]
    assert verify_token_hash(raw, thash) is True
    assert verify_token_hash("wrong_token", thash) is False


def test_metadata_recursive_sanitization():
    """Verify sensitive fields in metadata are recursively redacted."""
    raw_data = {
        "user_email": "user@example.com",
        "nested": {
            "api_key": "secret_key_123",
            "password": "my_password",
            "token": "tok_abc",
            "safe_field": 42,
        },
        "list_items": [
            {"cookie": "session=123", "action": "login"},
            "plain_text",
        ]
    }
    sanitized = sanitize_metadata(raw_data)
    assert sanitized["user_email"] == "user@example.com"
    assert sanitized["nested"]["safe_field"] == 42
    assert sanitized["nested"]["api_key"] == "[REDACTED]"
    assert sanitized["nested"]["password"] == "[REDACTED]"
    assert sanitized["nested"]["token"] == "[REDACTED]"
    assert sanitized["list_items"][0]["cookie"] == "[REDACTED]"
    assert sanitized["list_items"][0]["action"] == "login"
    assert sanitized["list_items"][1] == "plain_text"


def test_user_and_token_crud(client: TestClient, db_session):
    """Test user creation, listing, token generation, token listing, and revocation."""
    # 1. Create user
    user_resp = client.post("/api/v1/users", json={
        "email": "analyst@sentinel.local",
        "display_name": "Security Analyst",
    })
    assert user_resp.status_code == 201
    user = user_resp.json()
    user_id = user["id"]
    assert user["email"] == "analyst@sentinel.local"
    assert user["display_name"] == "Security Analyst"

    # Duplicate email rejected
    dup_resp = client.post("/api/v1/users", json={
        "email": "analyst@sentinel.local",
        "display_name": "Duplicate Analyst",
    })
    assert dup_resp.status_code == 409

    # 2. Create API token for user
    tok_resp = client.post(f"/api/v1/users/{user_id}/api-tokens", json={
        "name": "CI Token",
        "expires_in_days": 30,
    })
    assert tok_resp.status_code == 201
    tok_data = tok_resp.json()
    assert "raw_token" in tok_data
    assert tok_data["raw_token"].startswith("sent_")
    assert tok_data["name"] == "CI Token"
    raw_token = tok_data["raw_token"]
    token_id = tok_data["id"]

    # 3. List tokens for user
    list_tok_resp = client.get(f"/api/v1/users/{user_id}/api-tokens")
    assert list_tok_resp.status_code == 200
    assert list_tok_resp.json()["count"] == 1

    # 4. Authenticate using Bearer token
    verify_resp = client.get(
        "/api/v1/auth/verify",
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert verify_resp.status_code == 200
    verify_data = verify_resp.json()
    assert verify_data["authenticated"] is True
    assert verify_data["user"]["id"] == user_id
    assert verify_data["user"]["email"] == "analyst@sentinel.local"

    # 5. Check token status
    status_resp = client.get(
        "/api/v1/auth/token-status",
        headers={"X-API-Key": raw_token},
    )
    assert status_resp.status_code == 200
    status_data = status_resp.json()
    assert status_data["valid"] is True
    assert status_data["status"] == "ACTIVE"
    assert status_data["days_until_expiration"] is not None

    # 6. Revoke token
    del_tok = client.delete(
        f"/api/v1/api-tokens/{token_id}",
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert del_tok.status_code == 200

    # 7. Revoked token rejected
    revoked_resp = client.get(
        "/api/v1/auth/verify",
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert revoked_resp.status_code == 401


def test_expired_token_rejected(client: TestClient, db_session):
    """Verify expired token is rejected with 401."""
    # Create user
    user = User(
        id=str(uuid.uuid4()),
        email="expired@sentinel.local",
        display_name="Expired User",
        status="ACTIVE",
    )
    db_session.add(user)
    db_session.commit()

    # Create expired token
    raw, prefix, thash = generate_api_token()
    tok = ApiToken(
        id=str(uuid.uuid4()),
        user_id=user.id,
        token_hash=thash,
        token_prefix=prefix,
        name="Expired Token",
        status="ACTIVE",
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
    )
    db_session.add(tok)
    db_session.commit()

    resp = client.get(
        "/api/v1/auth/verify",
        headers={"Authorization": f"Bearer {raw}"},
    )
    assert resp.status_code == 401
    assert "Invalid or expired API token" in resp.json()["detail"]


def test_project_membership_and_rbac_permissions(client: TestClient, db_session):
    """Test project roles, membership assignments, and permission boundaries."""
    # 1. Create a project
    proj_resp = client.post("/api/v1/projects/", json={
        "name": "RBAC Project",
        "description": "RBAC Test",
        "environment": "staging",
    })
    assert proj_resp.status_code == 201
    project_id = proj_resp.json()["id"]

    # 2. Seed default roles for this project
    seed_resp = client.post(f"/api/v1/projects/{project_id}/roles/seed")
    assert seed_resp.status_code == 200

    # 3. Create users: viewer and analyst
    u_viewer = client.post("/api/v1/users", json={"email": "viewer@example.com", "display_name": "Viewer"}).json()
    u_analyst = client.post("/api/v1/users", json={"email": "analyst@example.com", "display_name": "Analyst"}).json()

    # 4. Get role IDs
    roles = db_session.query(Role).filter(Role.project_id == project_id).all()
    roles_map = {r.name: r.id for r in roles}
    assert "VIEWER" in roles_map
    assert "SECURITY_ANALYST" in roles_map
    assert "PROJECT_ADMIN" in roles_map

    # 5. Assign memberships
    m_viewer = client.post(f"/api/v1/projects/{project_id}/memberships", json={
        "user_id": u_viewer["id"],
        "role_id": roles_map["VIEWER"],
    })
    assert m_viewer.status_code == 201

    m_analyst = client.post(f"/api/v1/projects/{project_id}/memberships", json={
        "user_id": u_analyst["id"],
        "role_id": roles_map["SECURITY_ANALYST"],
    })
    assert m_analyst.status_code == 201

    # 6. List memberships
    memberships = client.get(f"/api/v1/projects/{project_id}/memberships").json()
    assert memberships["count"] == 2

    # 7. Generate tokens for each user
    tok_v = client.post(f"/api/v1/users/{u_viewer['id']}/api-tokens", json={"name": "Viewer Tok"}).json()
    tok_a = client.post(f"/api/v1/users/{u_analyst['id']}/api-tokens", json={"name": "Analyst Tok"}).json()

    # Viewer can read audit events
    v_audit = client.get(
        f"/api/v1/projects/{project_id}/audit-events",
        headers={"Authorization": f"Bearer {tok_v['raw_token']}"},
    )
    assert v_audit.status_code == 200

    # Viewer cannot add memberships (requires project:admin)
    u_other = client.post("/api/v1/users", json={"email": "other@example.com", "display_name": "Other"}).json()
    v_forbidden = client.post(
        f"/api/v1/projects/{project_id}/memberships",
        json={"user_id": u_other["id"], "role_id": roles_map["VIEWER"]},
        headers={"Authorization": f"Bearer {tok_v['raw_token']}"},
    )
    assert v_forbidden.status_code == 403
    assert "Permission 'project:admin' required" in v_forbidden.json()["detail"]


def test_cross_project_isolation(client: TestClient, db_session):
    """Verify an authenticated user cannot access resources in another project."""
    # Create Project 1 and Project 2
    p1 = client.post("/api/v1/projects/", json={"name": "Project Alpha"}).json()["id"]
    p2 = client.post("/api/v1/projects/", json={"name": "Project Beta"}).json()["id"]

    client.post(f"/api/v1/projects/{p1}/roles/seed")
    client.post(f"/api/v1/projects/{p2}/roles/seed")

    user_alpha = client.post("/api/v1/users", json={"email": "alpha_member@example.com", "display_name": "Alpha Member"}).json()
    r_admin_p1 = db_session.query(Role).filter(Role.project_id == p1, Role.name == "PROJECT_ADMIN").first()

    # Add user to Project Alpha only
    client.post(f"/api/v1/projects/{p1}/memberships", json={
        "user_id": user_alpha["id"],
        "role_id": r_admin_p1.id,
    })

    tok = client.post(f"/api/v1/users/{user_alpha['id']}/api-tokens", json={"name": "Alpha Tok"}).json()
    raw_token = tok["raw_token"]

    # Access Project Alpha -> OK
    resp_alpha = client.get(
        f"/api/v1/projects/{p1}/audit-events",
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert resp_alpha.status_code == 200

    # Access Project Beta -> 403 Forbidden (no active membership)
    resp_beta = client.get(
        f"/api/v1/projects/{p2}/audit-events",
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert resp_beta.status_code == 403
    assert f"Access to project {p2} forbidden" in resp_beta.json()["detail"]


def test_immutable_audit_logging(client: TestClient, db_session):
    """Verify audit events are recorded, queryable, and immutable."""
    # Create project
    proj = client.post("/api/v1/projects/", json={"name": "Audited Project"}).json()
    p_id = proj["id"]

    # Query audit events
    audit_resp = client.get(f"/api/v1/projects/{p_id}/audit-events")
    assert audit_resp.status_code == 200
    events = audit_resp.json()["events"]
    assert len(events) >= 1
    create_evt = [e for e in events if e["action"] == "CREATE" and e["resource_type"] == "PROJECT"]
    assert len(create_evt) == 1
    assert create_evt[0]["outcome"] == "SUCCESS"
    evt_id = create_evt[0]["id"]

    # Verify single audit event retrieval
    single_resp = client.get(f"/api/v1/audit-events/{evt_id}")
    assert single_resp.status_code == 200
    assert single_resp.json()["id"] == evt_id

    # Verify audit events cannot be modified or deleted (no PUT/DELETE endpoints)
    put_resp = client.put(f"/api/v1/audit-events/{evt_id}", json={"action": "MODIFIED"})
    assert put_resp.status_code == 405

    del_resp = client.delete(f"/api/v1/audit-events/{evt_id}")
    assert del_resp.status_code == 405


def test_security_headers_and_correlation_id(client: TestClient):
    """Verify security headers and correlation request ID are present on all responses."""
    custom_req_id = str(uuid.uuid4())
    resp = client.get("/", headers={"X-Request-ID": custom_req_id})
    assert resp.status_code == 200
    assert resp.headers.get("X-Request-ID") == custom_req_id
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert resp.headers.get("X-XSS-Protection") == "1; mode=block"

    # Auto-generated request ID when not provided
    resp_auto = client.get("/")
    assert resp_auto.status_code == 200
    assert resp_auto.headers.get("X-Request-ID") is not None


def test_rate_limiter_mechanism():
    """Verify sliding-window in-memory rate limiter functionality."""
    rate_limiter.reset()
    key = "test_client_ip"
    
    # 5 allowed requests
    for _ in range(5):
        allowed, remaining, _ = rate_limiter.is_allowed(key, limit=5, window_seconds=10)
        assert allowed is True

    # 6th request blocked
    allowed, remaining, retry_after = rate_limiter.is_allowed(key, limit=5, window_seconds=10)
    assert allowed is False
    assert remaining == 0
    assert retry_after > 0


def test_production_config_validation(monkeypatch):
    """Verify production settings validator flags insecure configurations."""
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "DEBUG", True)
    monkeypatch.setattr(settings, "SENTINEL_API_TOKEN", "")
    monkeypatch.setattr(settings, "SENTINEL_ENFORCE_AUTH", False)

    issues = settings.validate_production_configuration()
    assert len(issues) >= 2
    assert any("DEBUG must be disabled" in issue for issue in issues)
    assert any("Authentication enforcement must be enabled" in issue for issue in issues)
