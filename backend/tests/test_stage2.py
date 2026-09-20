import pytest
from fastapi.testclient import TestClient


def create_test_project(client: TestClient, name: str = "Auth Project"):
    """Helper to create a project for Stage 2 testing."""
    resp = client.post(
        "/api/v1/projects/",
        json={
            "name": name,
            "description": "Project for testing Stage 2 auth modeling",
            "environment": "staging",
            "base_url": "https://api.test.local",
            "authorization_status": "active",
        },
    )
    assert resp.status_code == 201
    return resp.json()


# ==============================================================================
# Role Tests
# ==============================================================================
def test_role_crud_and_custom_roles(client: TestClient):
    """Test role creation, listing, retrieval, update, and deletion with custom roles."""
    project = create_test_project(client, "Role Project")
    project_id = project["id"]

    # 1. Create standard and custom roles
    roles_to_create = [
        {"name": "Anonymous", "description": "Unauthenticated access"},
        {"name": "User", "description": "Standard authenticated user"},
        {"name": "Admin", "description": "Administrator with full access"},
        {"name": "Security Auditor", "description": "Custom compliance and audit role"},
    ]

    created_roles = {}
    for role_data in roles_to_create:
        resp = client.post(f"/api/v1/projects/{project_id}/roles/", json=role_data)
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == role_data["name"]
        assert data["description"] == role_data["description"]
        assert "id" in data
        created_roles[role_data["name"]] = data

    # 2. Prevent duplicate role name within same project
    dup_resp = client.post(
        f"/api/v1/projects/{project_id}/roles/",
        json={"name": "Admin", "description": "Duplicate admin"},
    )
    assert dup_resp.status_code == 400

    # 3. List roles for project
    list_resp = client.get(f"/api/v1/projects/{project_id}/roles/")
    assert list_resp.status_code == 200
    roles_list = list_resp.json()
    assert len(roles_list) == 4
    role_names = [r["name"] for r in roles_list]
    assert "Anonymous" in role_names
    assert "User" in role_names
    assert "Admin" in role_names
    assert "Security Auditor" in role_names

    # 4. View single role detail
    admin_id = created_roles["Admin"]["id"]
    get_resp = client.get(f"/api/v1/roles/{admin_id}")
    assert get_resp.status_code == 200
    admin_detail = get_resp.json()
    assert admin_detail["name"] == "Admin"
    assert "members" in admin_detail
    assert isinstance(admin_detail["members"], list)

    # 5. Update role
    auditor_id = created_roles["Security Auditor"]["id"]
    update_resp = client.put(
        f"/api/v1/roles/{auditor_id}",
        json={"name": "Lead Auditor", "description": "Updated auditor description"},
    )
    assert update_resp.status_code == 200
    assert update_resp.json()["name"] == "Lead Auditor"
    assert update_resp.json()["description"] == "Updated auditor description"

    # 6. Delete role
    del_resp = client.delete(f"/api/v1/roles/{auditor_id}")
    assert del_resp.status_code == 204
    get_del = client.get(f"/api/v1/roles/{auditor_id}")
    assert get_del.status_code == 404


# ==============================================================================
# Identity Tests & Credential Security
# ==============================================================================
def test_identity_crud_and_credential_security(client: TestClient):
    """Test identity CRUD and ensure sensitive credentials are never exposed."""
    project = create_test_project(client, "Identity Project")
    project_id = project["id"]

    # Create a role to assign
    role_resp = client.post(
        f"/api/v1/projects/{project_id}/roles/",
        json={"name": "User", "description": "Regular user"},
    )
    role_id = role_resp.json()["id"]

    # 1. Create Identity with sensitive credential
    secret_token = "secret_raw_bearer_token_xyz987"
    identity_payload = {
        "name": "Alice Developer",
        "description": "Primary test user for staging",
        "role_id": role_id,
        "auth_type": "bearer_token",
        "environment": "staging",
        "credential_status": "configured",
        "credential_value": secret_token,
    }

    create_resp = client.post(
        f"/api/v1/projects/{project_id}/identities/",
        json=identity_payload,
    )
    assert create_resp.status_code == 201
    identity_data = create_resp.json()
    identity_id = identity_data["id"]

    # Verify fields
    assert identity_data["name"] == "Alice Developer"
    assert identity_data["role_id"] == role_id
    assert identity_data["role_name"] == "User"
    assert identity_data["auth_type"] == "bearer_token"
    assert identity_data["environment"] == "staging"

    # SECURITY VERIFICATION: raw secret must NOT be present in JSON response
    assert secret_token not in str(create_resp.content)
    assert "credential_value" not in identity_data
    # Credential reference is auto-masked
    assert identity_data["credential_reference"] == "token_***z987"

    # 2. Get single identity
    get_resp = client.get(f"/api/v1/identities/{identity_id}")
    assert get_resp.status_code == 200
    get_data = get_resp.json()
    assert secret_token not in str(get_resp.content)
    assert "credential_value" not in get_data
    assert get_data["role_name"] == "User"
    assert get_data["owned_resources_count"] == 0

    # 3. List identities with filtering
    list_resp = client.get(f"/api/v1/projects/{project_id}/identities/?auth_type=bearer_token")
    assert list_resp.status_code == 200
    identities = list_resp.json()
    assert len(identities) == 1
    assert secret_token not in str(list_resp.content)

    # 4. Duplicate name check
    dup_resp = client.post(
        f"/api/v1/projects/{project_id}/identities/",
        json={"name": "Alice Developer"},
    )
    assert dup_resp.status_code == 400

    # 5. Update identity
    update_resp = client.put(
        f"/api/v1/identities/{identity_id}",
        json={"name": "Alice Senior Dev", "environment": "production"},
    )
    assert update_resp.status_code == 200
    assert update_resp.json()["name"] == "Alice Senior Dev"
    assert update_resp.json()["environment"] == "production"

    # 6. Delete identity
    del_resp = client.delete(f"/api/v1/identities/{identity_id}")
    assert del_resp.status_code == 204
    assert client.get(f"/api/v1/identities/{identity_id}").status_code == 404


def test_role_assignment_and_membership(client: TestClient):
    """Test assigning/reassigning roles to identities and showing role membership."""
    project = create_test_project(client, "Membership Project")
    project_id = project["id"]

    # Create two roles
    user_role = client.post(
        f"/api/v1/projects/{project_id}/roles/",
        json={"name": "User"},
    ).json()
    admin_role = client.post(
        f"/api/v1/projects/{project_id}/roles/",
        json={"name": "Admin"},
    ).json()

    # Create identity with no role
    identity = client.post(
        f"/api/v1/projects/{project_id}/identities/",
        json={"name": "Bob Member", "role_id": None},
    ).json()
    assert identity["role_id"] is None
    assert identity["role_name"] is None

    # Assign user role via POST /roles/{role_id}/assign/{identity_id}
    assign_resp = client.post(
        f"/api/v1/roles/{user_role['id']}/assign/{identity['id']}"
    )
    assert assign_resp.status_code == 200
    assert assign_resp.json()["role_id"] == user_role["id"]
    assert assign_resp.json()["role_name"] == "User"

    # Verify role membership list
    members_resp = client.get(f"/api/v1/roles/{user_role['id']}/members")
    assert members_resp.status_code == 200
    members = members_resp.json()
    assert len(members) == 1
    assert members[0]["id"] == identity["id"]
    assert members[0]["name"] == "Bob Member"

    # Reassign to Admin role via PUT /identities/{identity_id}/role
    reassign_resp = client.put(
        f"/api/v1/identities/{identity['id']}/role",
        json={"role_id": admin_role["id"]},
    )
    assert reassign_resp.status_code == 200
    assert reassign_resp.json()["role_id"] == admin_role["id"]
    assert reassign_resp.json()["role_name"] == "Admin"

    # Previous role should have 0 members now
    old_role_members = client.get(f"/api/v1/roles/{user_role['id']}/members").json()
    assert len(old_role_members) == 0

    new_role_members = client.get(f"/api/v1/roles/{admin_role['id']}/members").json()
    assert len(new_role_members) == 1

    # Deleting a role unassigns identities without deleting them
    client.delete(f"/api/v1/roles/{admin_role['id']}")
    ident_after_role_del = client.get(f"/api/v1/identities/{identity['id']}").json()
    assert ident_after_role_del["role_id"] is None
    assert ident_after_role_del["role_name"] is None


# ==============================================================================
# Resource Modeling & Ownership Tests
# ==============================================================================
def test_resource_crud_and_ownership(client: TestClient):
    """Test creating API resources (User, Order, Payment, Product) and ownership records."""
    project = create_test_project(client, "Resource Project")
    project_id = project["id"]

    # 1. Create resources: User, Order, Payment, Product
    resource_definitions = [
        {"name": "User", "resource_type": "User", "description": "User account resource"},
        {"name": "Order", "resource_type": "Order", "description": "E-commerce order resource"},
        {"name": "Payment", "resource_type": "Payment", "description": "Payment transaction resource"},
        {"name": "Product", "resource_type": "Product", "description": "Catalog product resource"},
    ]

    resources = {}
    for r_def in resource_definitions:
        resp = client.post(f"/api/v1/projects/{project_id}/resources/", json=r_def)
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == r_def["name"]
        assert data["resource_type"] == r_def["resource_type"]
        resources[r_def["name"]] = data

    # 2. List resources
    list_resp = client.get(f"/api/v1/projects/{project_id}/resources/")
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 4

    # 3. Prevent duplicate resource name
    dup_resp = client.post(
        f"/api/v1/projects/{project_id}/resources/",
        json={"name": "Order"},
    )
    assert dup_resp.status_code == 400

    # 4. Create Identity to own resources
    user_identity = client.post(
        f"/api/v1/projects/{project_id}/identities/",
        json={"name": "Customer Charlie"},
    ).json()

    # 5. Create Ownership: Identity A -> owns -> Resource X
    order_id = resources["Order"]["id"]
    ownership_payload = {
        "identity_id": user_identity["id"],
        "resource_instance_id": "Order #123",
        "ownership_type": "owner",
        "description": "Primary order placement",
    }

    own_resp = client.post(
        f"/api/v1/resources/{order_id}/ownerships/",
        json=ownership_payload,
    )
    assert own_resp.status_code == 201
    own_data = own_resp.json()
    assert own_data["resource_id"] == order_id
    assert own_data["identity_id"] == user_identity["id"]
    assert own_data["resource_instance_id"] == "Order #123"
    assert own_data["identity_name"] == "Customer Charlie"
    assert own_data["resource_name"] == "Order"

    # 6. List ownerships for resource
    list_own = client.get(f"/api/v1/resources/{order_id}/ownerships/")
    assert list_own.status_code == 200
    assert len(list_own.json()) == 1

    # 7. View resource detail includes ownerships
    res_detail = client.get(f"/api/v1/resources/{order_id}").json()
    assert len(res_detail["ownerships"]) == 1
    assert res_detail["ownerships"][0]["resource_instance_id"] == "Order #123"

    # 8. Delete ownership
    ownership_id = own_data["id"]
    del_own = client.delete(f"/api/v1/ownerships/{ownership_id}")
    assert del_own.status_code == 204

    # Verify ownership is removed
    assert len(client.get(f"/api/v1/resources/{order_id}/ownerships/").json()) == 0


# ==============================================================================
# API Endpoint Association Tests
# ==============================================================================
def test_endpoint_resource_association(client: TestClient):
    """Test associating API endpoints with resources (e.g. GET /orders/{id} -> Order)."""
    project = create_test_project(client, "Endpoint Assoc Project")
    project_id = project["id"]

    # 1. Create resource: Order
    res_resp = client.post(
        f"/api/v1/projects/{project_id}/resources/",
        json={"name": "Order", "resource_type": "Order"},
    )
    order_resource_id = res_resp.json()["id"]

    # 2. Create endpoints via OpenAPI spec ingestion
    import json
    spec_yaml = """
openapi: 3.0.0
info:
  title: Store API
  version: 1.0.0
paths:
  /orders/{id}:
    get:
      summary: Get order by ID
      responses:
        "200":
          description: Order details
    delete:
      summary: Delete order by ID
      responses:
        "204":
          description: Order deleted
"""
    ingest_resp = client.post(
        f"/api/v1/{project_id}/ingest",
        files={"file": ("spec.yaml", spec_yaml, "text/yaml")},
    )
    assert ingest_resp.status_code == 202
    ingested_api_id = ingest_resp.json()["api_id"]

    # List endpoints for ingested API
    endpoints_resp = client.get(f"/api/v1/{ingested_api_id}/endpoints/")
    assert endpoints_resp.status_code == 200
    endpoints = endpoints_resp.json()
    assert len(endpoints) == 2

    get_ep = [ep for ep in endpoints if ep["method"] == "GET"][0]
    delete_ep = [ep for ep in endpoints if ep["method"] == "DELETE"][0]

    # 4. Associate GET /orders/{id} -> Order resource
    assoc_resp = client.put(
        f"/api/v1/endpoints/{get_ep['id']}/resource",
        json={"resource_id": order_resource_id},
    )
    assert assoc_resp.status_code == 200
    assoc_data = assoc_resp.json()
    assert assoc_data["resource_id"] == order_resource_id
    assert assoc_data["resource_name"] == "Order"

    # Associate DELETE /orders/{id} -> Order resource
    client.put(
        f"/api/v1/endpoints/{delete_ep['id']}/resource",
        json={"resource_id": order_resource_id},
    )

    # 5. Query endpoints for resource
    res_endpoints = client.get(f"/api/v1/resources/{order_resource_id}/endpoints").json()
    assert len(res_endpoints) == 2
    paths = [ep["path"] for ep in res_endpoints]
    assert "/orders/{id}" in paths

    # 6. Disassociate endpoint (set resource_id = None)
    disassoc_resp = client.put(
        f"/api/v1/endpoints/{get_ep['id']}/resource",
        json={"resource_id": None},
    )
    assert disassoc_resp.status_code == 200
    assert disassoc_resp.json()["resource_id"] is None
    assert disassoc_resp.json()["resource_name"] is None

    # Now resource should only have 1 associated endpoint
    res_endpoints_after = client.get(f"/api/v1/resources/{order_resource_id}/endpoints").json()
    assert len(res_endpoints_after) == 1


# ==============================================================================
# Full Authorization Model Graph Persistence Tests
# ==============================================================================
def test_authorization_model_persistence(client: TestClient):
    """Test full authorization model view (Identity -> Role -> Resources)."""
    project = create_test_project(client, "Full Auth Graph Project")
    project_id = project["id"]

    # 1. Create Roles
    admin_role = client.post(
        f"/api/v1/projects/{project_id}/roles/",
        json={"name": "ADMIN"},
    ).json()
    user_role = client.post(
        f"/api/v1/projects/{project_id}/roles/",
        json={"name": "USER"},
    ).json()

    # 2. Create Resources
    order_res = client.post(
        f"/api/v1/projects/{project_id}/resources/",
        json={"name": "Order", "resource_type": "Order"},
    ).json()
    user_res = client.post(
        f"/api/v1/projects/{project_id}/resources/",
        json={"name": "User", "resource_type": "User"},
    ).json()

    # 3. Create Identities
    # User A -> USER
    user_a = client.post(
        f"/api/v1/projects/{project_id}/identities/",
        json={
            "name": "User A",
            "role_id": user_role["id"],
            "auth_type": "bearer_token",
            "credential_reference": "token_***456",
        },
    ).json()

    # Admin Alice -> ADMIN
    admin_alice = client.post(
        f"/api/v1/projects/{project_id}/identities/",
        json={
            "name": "Admin Alice",
            "role_id": admin_role["id"],
            "auth_type": "api_key",
            "credential_reference": "key_***999",
        },
    ).json()

    # 4. Ownership: User A -> owns -> Order #123
    client.post(
        f"/api/v1/resources/{order_res['id']}/ownerships/",
        json={
            "identity_id": user_a["id"],
            "resource_instance_id": "Order #123",
            "ownership_type": "owner",
        },
    )

    # 5. Ingest endpoints and associate with Order
    spec_yaml = """
openapi: 3.0.0
info:
  title: Orders Service
  version: 1.0.0
paths:
  /orders/{id}:
    get:
      summary: Read order
      responses:
        "200":
          description: OK
"""
    ingest = client.post(
        f"/api/v1/{project_id}/ingest",
        files={"file": ("orders.yaml", spec_yaml, "text/yaml")},
    ).json()
    endpoints = client.get(f"/api/v1/{ingest['api_id']}/endpoints/").json()
    client.put(
        f"/api/v1/endpoints/{endpoints[0]['id']}/resource",
        json={"resource_id": order_res["id"]},
    )

    # 6. Fetch Authorization Model Graph: GET /projects/{project_id}/authorization-model
    auth_model_resp = client.get(f"/api/v1/projects/{project_id}/authorization-model")
    assert auth_model_resp.status_code == 200
    model = auth_model_resp.json()

    assert model["project_id"] == project_id
    assert model["total_identities"] == 2
    assert model["total_roles"] == 2
    assert model["total_resources"] == 2

    nodes = {n["identity_name"]: n for n in model["nodes"]}
    assert "User A" in nodes
    assert "Admin Alice" in nodes

    # Verify User A -> USER -> Order #123
    user_a_node = nodes["User A"]
    assert user_a_node["role_name"] == "USER"
    assert len(user_a_node["resources"]) == 1
    owned_order = user_a_node["resources"][0]
    assert owned_order["resource_name"] == "Order"
    assert owned_order["instance_id"] == "Order #123"
    assert "GET /orders/{id}" in owned_order["associated_endpoints"]

    # Verify Admin Alice -> ADMIN
    admin_node = nodes["Admin Alice"]
    assert admin_node["role_name"] == "ADMIN"
    assert len(admin_node["resources"]) == 0


# ==============================================================================
# Cross-Project Isolation & Validation Tests
# ==============================================================================
def test_cross_project_isolation_and_validation(client: TestClient):
    """Test validation and cross-project boundary enforcement."""
    p1 = create_test_project(client, "Project 1")["id"]
    p2 = create_test_project(client, "Project 2")["id"]

    # Create role in P1
    r1 = client.post(f"/api/v1/projects/{p1}/roles/", json={"name": "P1 Role"}).json()["id"]

    # Create identity in P2 with role from P1 -> must fail
    fail_create = client.post(
        f"/api/v1/projects/{p2}/identities/",
        json={"name": "P2 Identity", "role_id": r1},
    )
    assert fail_create.status_code == 400

    # Create identity in P2 without role
    i2 = client.post(f"/api/v1/projects/{p2}/identities/", json={"name": "P2 Identity"}).json()["id"]

    # Assign role from P1 to identity in P2 -> must fail
    fail_assign = client.post(f"/api/v1/roles/{r1}/assign/{i2}")
    assert fail_assign.status_code == 400

    # Create resource in P1
    res1 = client.post(f"/api/v1/projects/{p1}/resources/", json={"name": "P1 Resource"}).json()["id"]

    # Assign ownership of P1 resource to P2 identity -> must fail
    fail_ownership = client.post(
        f"/api/v1/resources/{res1}/ownerships/",
        json={"identity_id": i2},
    )
    assert fail_ownership.status_code == 400
