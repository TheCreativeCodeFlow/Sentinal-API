import pytest
import json
from fastapi.testclient import TestClient
from app.models import (
    Project,
    API,
    Endpoint,
    Role,
    Identity,
    Resource,
    ResourceOwnership,
    SecurityTest,
    TestExecution,
    Finding,
    Evidence,
    ResourceProperty,
    PropertyAuthorizationRule,
)

# Avoid pytest trying to collect TestExecution class as a test suite
TestExecution.__test__ = False


def create_authorized_property_project(client: TestClient, db_session) -> dict:
    """Helper to create an authorized testing project with endpoints, roles, and resources."""
    resp = client.post("/api/v1/projects/", json={
        "name": "Property Exposure Target API",
        "description": "Project for Property-Level Authorization Engine verification",
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
        name="User Management API",
        version="v1",
        format="openapi3",
        status="active",
        url="http://testserver/demo-target",
    )
    db_session.add(api)
    db_session.commit()
    db_session.refresh(api)

    # Endpoints from demo_target
    ep_vuln = Endpoint(
        api_id=api.id,
        method="GET",
        path="/demo-target/users/{user_id}",
        summary="Vulnerable User Profile",
    )
    ep_filtered = Endpoint(
        api_id=api.id,
        method="GET",
        path="/demo-target/filtered-users/{user_id}",
        summary="Filtered User Profile",
    )
    ep_err = Endpoint(
        api_id=api.id,
        method="GET",
        path="/demo-target/error-orders/{order_id}",
        summary="Error Endpoint",
    )
    db_session.add_all([ep_vuln, ep_filtered, ep_err])
    db_session.commit()
    db_session.refresh(ep_vuln)
    db_session.refresh(ep_filtered)
    db_session.refresh(ep_err)

    # Create Roles: User and Admin
    role_user_resp = client.post(f"/api/v1/projects/{proj_id}/roles/", json={
        "name": "User",
        "description": "Standard consumer role",
    })
    assert role_user_resp.status_code == 201
    role_user = role_user_resp.json()

    role_admin_resp = client.post(f"/api/v1/projects/{proj_id}/roles/", json={
        "name": "Admin",
        "description": "Administrator role",
    })
    assert role_admin_resp.status_code == 201
    role_admin = role_admin_resp.json()

    # Create Identities
    ident_bob_resp = client.post(f"/api/v1/projects/{proj_id}/identities/", json={
        "name": "Bob Attacker",
        "role_id": role_user["id"],
        "auth_type": "bearer_token",
        "credential_value": "demo-token-bob",
    })
    assert ident_bob_resp.status_code == 201
    ident_bob = ident_bob_resp.json()

    ident_admin_resp = client.post(f"/api/v1/projects/{proj_id}/identities/", json={
        "name": "Alice Admin",
        "role_id": role_admin["id"],
        "auth_type": "bearer_token",
        "credential_value": "demo-token-alice",
    })
    assert ident_admin_resp.status_code == 201
    ident_admin = ident_admin_resp.json()

    # Create Resource: UserProfile
    res_resp = client.post(f"/api/v1/projects/{proj_id}/resources/", json={
        "name": "UserProfile",
        "description": "User profile resource containing personal and internal data",
    })
    assert res_resp.status_code == 201
    resource = res_resp.json()

    # Link Resource to vulnerable and filtered endpoints
    client.post(f"/api/v1/endpoints/{ep_vuln.id}/resource", json={
        "resource_id": resource["id"]
    })
    client.post(f"/api/v1/endpoints/{ep_filtered.id}/resource", json={
        "resource_id": resource["id"]
    })
    client.post(f"/api/v1/endpoints/{ep_err.id}/resource", json={
        "resource_id": resource["id"]
    })

    # Create ownership record for instance targeting
    client.post("/api/v1/ownerships/", json={
        "resource_id": resource["id"],
        "identity_id": ident_bob["id"],
        "resource_instance_id": "user_bob_002",
        "ownership_type": "direct",
    })

    return {
        "project": project,
        "api": api,
        "endpoints": {
            "vuln": ep_vuln,
            "filtered": ep_filtered,
            "err": ep_err,
        },
        "roles": {
            "user": role_user,
            "admin": role_admin,
        },
        "identities": {
            "bob": ident_bob,
            "admin": ident_admin,
        },
        "resource": resource,
    }


def test_property_crud(client: TestClient, db_session):
    """Test creating, reading, updating, and deleting resource properties with validations."""
    setup = create_authorized_property_project(client, db_session)
    res_id = setup["resource"]["id"]

    # 1. Create properties with various sensitivities
    p1 = client.post(f"/api/v1/resources/{res_id}/properties", json={
        "name": "email",
        "data_type": "string",
        "sensitivity": "PUBLIC",
        "description": "User email address",
    })
    assert p1.status_code == 201
    prop1 = p1.json()
    assert prop1["name"] == "email"
    assert prop1["sensitivity"] == "PUBLIC"

    p2 = client.post(f"/api/v1/resources/{res_id}/properties", json={
        "name": "role",
        "data_type": "string",
        "sensitivity": "INTERNAL",
        "description": "User authorization role",
    })
    assert p2.status_code == 201

    p3 = client.post(f"/api/v1/resources/{res_id}/properties", json={
        "name": "internal_notes",
        "data_type": "string",
        "sensitivity": "SENSITIVE",
        "description": "Internal CRM notes",
    })
    assert p3.status_code == 201

    # 2. Reject duplicate property name
    p_dup = client.post(f"/api/v1/resources/{res_id}/properties", json={
        "name": "email",
        "data_type": "string",
        "sensitivity": "PUBLIC",
    })
    assert p_dup.status_code == 400
    assert "already exists" in p_dup.json()["detail"]

    # 3. Reject invalid sensitivity
    p_inv = client.post(f"/api/v1/resources/{res_id}/properties", json={
        "name": "badge_number",
        "sensitivity": "SUPER_SECRET_INVALID",
    })
    assert p_inv.status_code == 400
    assert "Invalid sensitivity" in p_inv.json()["detail"]

    # 4. List properties
    p_list = client.get(f"/api/v1/resources/{res_id}/properties")
    assert p_list.status_code == 200
    props = p_list.json()
    assert len(props) == 3
    names = [p["name"] for p in props]
    assert "email" in names
    assert "role" in names
    assert "internal_notes" in names

    # 5. Get single property
    p_get = client.get(f"/api/v1/properties/{prop1['id']}")
    assert p_get.status_code == 200
    assert p_get.json()["id"] == prop1["id"]

    # 6. Update property
    p_update = client.put(f"/api/v1/properties/{prop1['id']}", json={
        "description": "Updated email description",
        "sensitivity": "INTERNAL",
    })
    assert p_update.status_code == 200
    assert p_update.json()["description"] == "Updated email description"
    assert p_update.json()["sensitivity"] == "INTERNAL"

    # 7. Delete property
    p_del = client.delete(f"/api/v1/properties/{prop1['id']}")
    assert p_del.status_code == 200
    assert client.get(f"/api/v1/properties/{prop1['id']}").status_code == 404


def test_property_authorization_rules_and_matrix(client: TestClient, db_session):
    """Test configuring authorization rules per role and viewing/bulk updating the matrix."""
    setup = create_authorized_property_project(client, db_session)
    res_id = setup["resource"]["id"]
    role_user_id = setup["roles"]["user"]["id"]
    role_admin_id = setup["roles"]["admin"]["id"]

    # Create properties
    p_role = client.post(f"/api/v1/resources/{res_id}/properties", json={
        "name": "role",
        "data_type": "string",
        "sensitivity": "INTERNAL",
    }).json()

    p_notes = client.post(f"/api/v1/resources/{res_id}/properties", json={
        "name": "internal_notes",
        "data_type": "string",
        "sensitivity": "SENSITIVE",
    }).json()

    # Set individual rule: User cannot see internal_notes
    r1 = client.post(f"/api/v1/properties/{p_notes['id']}/rules", json={
        "role_id": role_user_id,
        "access": "DENY",
    })
    assert r1.status_code == 200
    assert r1.json()["access"] == "DENY"

    # Check matrix view
    mat_resp = client.get(f"/api/v1/resources/{res_id}/property-matrix")
    assert mat_resp.status_code == 200
    mat = mat_resp.json()
    assert mat["resource_id"] == res_id
    assert len(mat["roles"]) == 2
    assert len(mat["properties"]) == 2

    # Find notes row
    notes_row = next(r for r in mat["properties"] if r["name"] == "internal_notes")
    assert notes_row["rules"][role_user_id] == "DENY"
    assert notes_row["rules"][role_admin_id] == "UNKNOWN"

    # Bulk update matrix
    bulk_resp = client.put(f"/api/v1/resources/{res_id}/property-matrix/bulk", json={
        "rules": [
            {"property_id": p_role["id"], "role_id": role_user_id, "access": "DENY"},
            {"property_id": p_role["id"], "role_id": role_admin_id, "access": "ALLOW"},
            {"property_id": p_notes["id"], "role_id": role_admin_id, "access": "ALLOW"},
        ]
    })
    assert bulk_resp.status_code == 200
    updated_mat = bulk_resp.json()
    role_row = next(r for r in updated_mat["properties"] if r["name"] == "role")
    assert role_row["rules"][role_user_id] == "DENY"
    assert role_row["rules"][role_admin_id] == "ALLOW"


def test_property_discovery_endpoint(client: TestClient, db_session):
    """Test candidate property discovery from sample JSON and heuristic classification."""
    setup = create_authorized_property_project(client, db_session)
    res_id = setup["resource"]["id"]

    sample = json.dumps({
        "id": "usr_123",
        "username": "alice",
        "api_key": "sec_live_999",
        "salary": 125000,
        "profile": {
            "credit_card": "4111-2222-3333-4444",
            "internal_notes": "VIP partner",
            "bio": "Software Engineer",
        },
        "tags": ["staff", "admin"],
    })

    disc_resp = client.post(f"/api/v1/resources/{res_id}/discover-properties", json={
        "sample_json": sample,
    })
    assert disc_resp.status_code == 200
    discovered = disc_resp.json()
    assert discovered["total_discovered"] > 0
    paths = {p["path"]: p for p in discovered["discovered_properties"]}

    # Verify extracted paths
    assert "id" in paths
    assert "username" in paths
    assert "api_key" in paths
    assert "salary" in paths
    assert "profile.credit_card" in paths
    assert "profile.internal_notes" in paths
    assert "profile.bio" in paths

    # Verify sensitivity heuristics
    assert paths["api_key"]["suggested_sensitivity"] == "SECRET"
    assert paths["profile.credit_card"]["suggested_sensitivity"] == "SENSITIVE"
    assert paths["profile.internal_notes"]["suggested_sensitivity"] == "INTERNAL"
    assert paths["username"]["suggested_sensitivity"] == "PUBLIC"

    # Bulk create discovered properties
    to_create = [
        {"name": p["path"], "data_type": p["data_type"], "sensitivity": p["suggested_sensitivity"]}
        for p in discovered["discovered_properties"]
    ]
    bulk_add = client.post(f"/api/v1/resources/{res_id}/properties/bulk", json=to_create)
    assert bulk_add.status_code == 201
    assert len(bulk_add.json()) == len(to_create)


def test_property_exposure_confirmed(client: TestClient, db_session):
    """Test that returning a DENY property flags a CONFIRMED PROPERTY_EXPOSURE finding."""
    setup = create_authorized_property_project(client, db_session)
    proj_id = setup["project"]["id"]
    res_id = setup["resource"]["id"]
    ep_vuln = setup["endpoints"]["vuln"]
    ident_bob = setup["identities"]["bob"]
    role_user_id = setup["roles"]["user"]["id"]

    # Define properties: role and internal_notes are DENY for User
    p_role = client.post(f"/api/v1/resources/{res_id}/properties", json={
        "name": "role",
        "data_type": "string",
        "sensitivity": "INTERNAL",
    }).json()

    p_notes = client.post(f"/api/v1/resources/{res_id}/properties", json={
        "name": "internal_notes",
        "data_type": "string",
        "sensitivity": "SENSITIVE",
    }).json()

    client.put(f"/api/v1/resources/{res_id}/property-matrix/bulk", json={
        "rules": [
            {"property_id": p_role["id"], "role_id": role_user_id, "access": "DENY"},
            {"property_id": p_notes["id"], "role_id": role_user_id, "access": "DENY"},
        ]
    })

    # Create PROPERTY_EXPOSURE security test
    test_resp = client.post(f"/api/v1/projects/{proj_id}/security-tests/", json={
        "endpoint_id": ep_vuln.id,
        "test_type": "PROPERTY_EXPOSURE",
        "attacker_identity_id": ident_bob["id"],
        "victim_resource_id": res_id,
        "victim_resource_instance_id": "user_bob_002",
        "expected_access": "DENY",
    })
    assert test_resp.status_code == 201
    test_data = test_resp.json()
    assert test_data["test_type"] == "PROPERTY_EXPOSURE"

    # Execute test
    exec_resp = client.post(f"/api/v1/security-tests/{test_data['id']}/execute")
    assert exec_resp.status_code == 200
    execution = exec_resp.json()
    assert execution["status"] == "COMPLETED"
    assert execution["result"] == "CONFIRMED"
    assert "exposure confirmed" in execution["result_reason"].lower()
    assert "role" in execution["result_reason"]
    assert "internal_notes" in execution["result_reason"]

    # Verify Finding created
    f_resp = client.get(f"/api/v1/projects/{proj_id}/findings/?type_filter=PROPERTY_EXPOSURE")
    assert f_resp.status_code == 200
    findings = f_resp.json()
    assert len(findings) == 1
    finding = findings[0]
    assert finding["type"] == "PROPERTY_EXPOSURE"
    assert finding["severity"] == "HIGH"
    assert finding["status"] == "OPEN"
    assert finding["resource_id"] == res_id
    assert "role" in finding["exposed_properties"]
    assert "internal_notes" in finding["exposed_properties"]


def test_property_exposure_pass(client: TestClient, db_session):
    """Test that when protected properties are omitted by filtered endpoint, test passes."""
    setup = create_authorized_property_project(client, db_session)
    proj_id = setup["project"]["id"]
    res_id = setup["resource"]["id"]
    ep_filtered = setup["endpoints"]["filtered"]
    ident_bob = setup["identities"]["bob"]
    role_user_id = setup["roles"]["user"]["id"]

    # Define rules: role and internal_notes are DENY for User
    p_role = client.post(f"/api/v1/resources/{res_id}/properties", json={
        "name": "role",
        "data_type": "string",
        "sensitivity": "INTERNAL",
    }).json()
    p_notes = client.post(f"/api/v1/resources/{res_id}/properties", json={
        "name": "internal_notes",
        "data_type": "string",
        "sensitivity": "SENSITIVE",
    }).json()

    client.put(f"/api/v1/resources/{res_id}/property-matrix/bulk", json={
        "rules": [
            {"property_id": p_role["id"], "role_id": role_user_id, "access": "DENY"},
            {"property_id": p_notes["id"], "role_id": role_user_id, "access": "DENY"},
        ]
    })

    # Create and execute test against filtered endpoint
    test_resp = client.post(f"/api/v1/projects/{proj_id}/security-tests/", json={
        "endpoint_id": ep_filtered.id,
        "test_type": "PROPERTY_EXPOSURE",
        "attacker_identity_id": ident_bob["id"],
        "victim_resource_id": res_id,
        "victim_resource_instance_id": "user_bob_002",
        "expected_access": "DENY",
    })
    assert test_resp.status_code == 201

    exec_resp = client.post(f"/api/v1/security-tests/{test_resp.json()['id']}/execute")
    assert exec_resp.status_code == 200
    execution = exec_resp.json()
    assert execution["status"] == "COMPLETED"
    assert execution["result"] == "PASS"

    # Verify no finding is created
    f_resp = client.get(f"/api/v1/projects/{proj_id}/findings/?type_filter=PROPERTY_EXPOSURE")
    assert f_resp.status_code == 200
    assert len(f_resp.json()) == 0


def test_property_exposure_inconclusive(client: TestClient, db_session):
    """Test that server 500 error results in INCONCLUSIVE result."""
    setup = create_authorized_property_project(client, db_session)
    proj_id = setup["project"]["id"]
    res_id = setup["resource"]["id"]
    ep_err = setup["endpoints"]["err"]
    ident_bob = setup["identities"]["bob"]

    test_resp = client.post(f"/api/v1/projects/{proj_id}/security-tests/", json={
        "endpoint_id": ep_err.id,
        "test_type": "PROPERTY_EXPOSURE",
        "attacker_identity_id": ident_bob["id"],
        "victim_resource_id": res_id,
        "victim_resource_instance_id": "err_001",
        "expected_access": "DENY",
    })
    assert test_resp.status_code == 201

    exec_resp = client.post(f"/api/v1/security-tests/{test_resp.json()['id']}/execute")
    assert exec_resp.status_code == 200
    execution = exec_resp.json()
    assert execution["status"] == "COMPLETED"
    assert execution["result"] == "INCONCLUSIVE"
    assert execution["http_status"] == 500


def test_property_finding_deduplication(client: TestClient, db_session):
    """Test that re-executing a property exposure test updates the existing open finding without duplicating."""
    setup = create_authorized_property_project(client, db_session)
    proj_id = setup["project"]["id"]
    res_id = setup["resource"]["id"]
    ep_vuln = setup["endpoints"]["vuln"]
    ident_bob = setup["identities"]["bob"]
    role_user_id = setup["roles"]["user"]["id"]

    p_role = client.post(f"/api/v1/resources/{res_id}/properties", json={
        "name": "role",
        "sensitivity": "INTERNAL",
    }).json()

    client.post(f"/api/v1/properties/{p_role['id']}/rules", json={
        "role_id": role_user_id,
        "access": "DENY",
    })

    test_resp = client.post(f"/api/v1/projects/{proj_id}/security-tests/", json={
        "endpoint_id": ep_vuln.id,
        "test_type": "PROPERTY_EXPOSURE",
        "attacker_identity_id": ident_bob["id"],
        "victim_resource_id": res_id,
        "victim_resource_instance_id": "user_bob_002",
        "expected_access": "DENY",
    })
    test_id = test_resp.json()["id"]

    # Execution 1
    exec1 = client.post(f"/api/v1/security-tests/{test_id}/execute").json()
    assert exec1["result"] == "CONFIRMED"

    findings1 = client.get(f"/api/v1/projects/{proj_id}/findings/?type_filter=PROPERTY_EXPOSURE").json()
    assert len(findings1) == 1
    initial_finding_id = findings1[0]["id"]
    assert findings1[0]["execution_id"] == exec1["id"]

    # Execution 2
    exec2 = client.post(f"/api/v1/security-tests/{test_id}/execute").json()
    assert exec2["result"] == "CONFIRMED"

    findings2 = client.get(f"/api/v1/projects/{proj_id}/findings/?type_filter=PROPERTY_EXPOSURE").json()
    assert len(findings2) == 1
    assert findings2[0]["id"] == initial_finding_id
    assert findings2[0]["execution_id"] == exec2["id"]


def test_cross_project_isolation(client: TestClient, db_session):
    """Test that cross-project role and property references are strictly rejected."""
    setup = create_authorized_property_project(client, db_session)
    proj_a_id = setup["project"]["id"]
    res_a_id = setup["resource"]["id"]

    # Create Project B
    p_b = client.post("/api/v1/projects/", json={
        "name": "Project B",
        "environment": "staging",
        "authorization_status": "authorized",
    }).json()

    role_b = client.post(f"/api/v1/projects/{p_b['id']}/roles/", json={
        "name": "RoleInProjectB",
    }).json()

    prop_a = client.post(f"/api/v1/resources/{res_a_id}/properties", json={
        "name": "sensitive_data",
        "sensitivity": "SENSITIVE",
    }).json()

    # Attempt to assign Role from Project B to Property in Project A
    cross_rule = client.post(f"/api/v1/properties/{prop_a['id']}/rules", json={
        "role_id": role_b["id"],
        "access": "DENY",
    })
    assert cross_rule.status_code == 400
    assert "different project" in cross_rule.json()["detail"]


def test_credential_redaction_in_property_evidence(client: TestClient, db_session):
    """Test that credentials in property exposure evidence are securely redacted."""
    setup = create_authorized_property_project(client, db_session)
    proj_id = setup["project"]["id"]
    res_id = setup["resource"]["id"]
    ep_vuln = setup["endpoints"]["vuln"]
    ident_bob = setup["identities"]["bob"]
    role_user_id = setup["roles"]["user"]["id"]

    p_role = client.post(f"/api/v1/resources/{res_id}/properties", json={
        "name": "role",
        "sensitivity": "INTERNAL",
    }).json()
    client.post(f"/api/v1/properties/{p_role['id']}/rules", json={
        "role_id": role_user_id,
        "access": "DENY",
    })

    test_resp = client.post(f"/api/v1/projects/{proj_id}/security-tests/", json={
        "endpoint_id": ep_vuln.id,
        "test_type": "PROPERTY_EXPOSURE",
        "attacker_identity_id": ident_bob["id"],
        "victim_resource_id": res_id,
        "victim_resource_instance_id": "user_bob_002",
        "expected_access": "DENY",
    })
    test_id = test_resp.json()["id"]

    exec_resp = client.post(f"/api/v1/security-tests/{test_id}/execute")
    assert exec_resp.status_code == 200

    # Check evidence details
    ev_data = exec_resp.json()["evidence"]
    assert ev_data is not None
    # Ensure raw bearer token is not leaked
    assert "demo-token-bob" not in str(ev_data["request_metadata"])
    assert "demo-token-bob" not in str(ev_data["redacted_request"])
    assert "[REDACTED]" in str(ev_data["request_metadata"]) or "[REDACTED]" in str(ev_data["redacted_request"])


def test_replay_property_exposure_finding(client: TestClient, db_session):
    """Test that replaying a property exposure finding triggers PropertyExposureEngine."""
    setup = create_authorized_property_project(client, db_session)
    proj_id = setup["project"]["id"]
    res_id = setup["resource"]["id"]
    ep_vuln = setup["endpoints"]["vuln"]
    ident_bob = setup["identities"]["bob"]
    role_user_id = setup["roles"]["user"]["id"]

    p_role = client.post(f"/api/v1/resources/{res_id}/properties", json={
        "name": "role",
        "sensitivity": "INTERNAL",
    }).json()
    client.post(f"/api/v1/properties/{p_role['id']}/rules", json={
        "role_id": role_user_id,
        "access": "DENY",
    })

    test_resp = client.post(f"/api/v1/projects/{proj_id}/security-tests/", json={
        "endpoint_id": ep_vuln.id,
        "test_type": "PROPERTY_EXPOSURE",
        "attacker_identity_id": ident_bob["id"],
        "victim_resource_id": res_id,
        "victim_resource_instance_id": "user_bob_002",
        "expected_access": "DENY",
    })
    test_id = test_resp.json()["id"]

    client.post(f"/api/v1/security-tests/{test_id}/execute")

    findings = client.get(f"/api/v1/projects/{proj_id}/findings/?type_filter=PROPERTY_EXPOSURE").json()
    finding_id = findings[0]["id"]

    # Replay
    replay_resp = client.post(f"/api/v1/findings/{finding_id}/replay")
    assert replay_resp.status_code == 200
    rep_exec = replay_resp.json()
    assert rep_exec["status"] == "COMPLETED"
    assert rep_exec["result"] == "CONFIRMED"
