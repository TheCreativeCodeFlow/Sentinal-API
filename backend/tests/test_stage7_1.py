import pytest
from fastapi.testclient import TestClient


def setup_project(client: TestClient, name="Workflow Project"):
    resp = client.post("/api/v1/projects/", json={
        "name": name,
        "description": "Project for workflow testing",
        "environment": "staging",
        "authorization_status": "authorized"
    })
    assert resp.status_code == 201
    return resp.json()


def setup_api_and_endpoint(client: TestClient, project_id: int, method="GET", path="/api/v1/orders"):
    spec_yaml = f"""
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  {path}:
    {method.lower()}:
      summary: Endpoint summary
      responses:
        "200":
          description: OK
"""
    ingest_resp = client.post(
        f"/api/v1/{project_id}/ingest/",
        files={"file": ("spec.yaml", spec_yaml, "text/yaml")},
    )
    assert ingest_resp.status_code == 202
    data = ingest_resp.json()
    api_id = data["api_id"]
    endpoints = client.get(f"/api/v1/{api_id}/endpoints/").json()
    matching = [e for e in endpoints if e["path"] == path and e["method"].upper() == method.upper()]
    endpoint = matching[0] if matching else endpoints[0]
    return {"id": api_id}, endpoint


def setup_identity(client: TestClient, project_id: int, name="Customer Identity"):
    role_resp = client.post(f"/api/v1/projects/{project_id}/roles/", json={
        "name": f"role_{name}",
        "description": "Test role"
    })
    assert role_resp.status_code == 201
    role_id = role_resp.json()["id"]

    ident_resp = client.post(f"/api/v1/projects/{project_id}/identities/", json={
        "name": name,
        "auth_type": "bearer_token",
        "role_id": role_id
    })
    assert ident_resp.status_code == 201
    return ident_resp.json()


def test_workflow_crud_and_status_validation(client: TestClient):
    proj = setup_project(client, "WF CRUD Project")
    proj_id = proj["id"]

    # 1. Create workflow
    create_resp = client.post(f"/api/v1/projects/{proj_id}/workflows", json={
        "name": "Checkout Flow",
        "description": "Standard checkout order process",
        "status": "DRAFT"
    })
    assert create_resp.status_code == 201
    wf = create_resp.json()
    wf_id = wf["id"]
    assert wf["name"] == "Checkout Flow"
    assert wf["status"] == "DRAFT"
    assert wf["project_id"] == proj_id

    # 2. Duplicate name in same project rejected
    dup_resp = client.post(f"/api/v1/projects/{proj_id}/workflows", json={
        "name": "Checkout Flow",
        "description": "Duplicate flow",
        "status": "DRAFT"
    })
    assert dup_resp.status_code == 400
    assert "already exists" in dup_resp.json()["detail"]

    # 3. Same name in different project allowed
    proj2 = setup_project(client, "WF CRUD Project 2")
    p2_resp = client.post(f"/api/v1/projects/{proj2['id']}/workflows", json={
        "name": "Checkout Flow",
        "description": "Flow in proj 2",
        "status": "DRAFT"
    })
    assert p2_resp.status_code == 201

    # 4. Invalid status rejected
    bad_status_resp = client.post(f"/api/v1/projects/{proj_id}/workflows", json={
        "name": "Bad Flow",
        "status": "INVALID_STATUS"
    })
    assert bad_status_resp.status_code == 400

    # 5. List workflows
    list_resp = client.get(f"/api/v1/projects/{proj_id}/workflows")
    assert list_resp.status_code == 200
    wfs = list_resp.json()
    assert len(wfs) == 1
    assert wfs[0]["id"] == wf_id

    # 6. Update workflow
    update_resp = client.patch(f"/api/v1/workflows/{wf_id}", json={
        "name": "Checkout Flow V2",
        "status": "ACTIVE",
        "description": "Updated checkout description"
    })
    assert update_resp.status_code == 200
    assert update_resp.json()["name"] == "Checkout Flow V2"
    assert update_resp.json()["status"] == "ACTIVE"

    # 7. Get workflow details
    detail_resp = client.get(f"/api/v1/workflows/{wf_id}")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["name"] == "Checkout Flow V2"
    assert detail["steps"] == []
    assert detail["states"] == []
    assert detail["transitions"] == []

    # 8. Delete workflow
    del_resp = client.delete(f"/api/v1/workflows/{wf_id}")
    assert del_resp.status_code == 200

    # Verify 404 after deletion
    assert client.get(f"/api/v1/workflows/{wf_id}").status_code == 404


def test_workflow_step_crud_and_method_restriction(client: TestClient):
    proj = setup_project(client, "WF Steps Project")
    proj_id = proj["id"]
    _, ep = setup_api_and_endpoint(client, proj_id, "GET", "/api/v1/cart")
    ident = setup_identity(client, proj_id, "Buyer")

    wf_resp = client.post(f"/api/v1/projects/{proj_id}/workflows", json={
        "name": "Cart Workflow",
        "status": "DRAFT"
    })
    wf_id = wf_resp.json()["id"]

    # 1. Allowed HTTP method: GET
    step1_resp = client.post(f"/api/v1/workflows/{wf_id}/steps", json={
        "step_order": 1,
        "endpoint_id": ep["id"],
        "identity_id": ident["id"],
        "http_method": "GET",
        "name": "Fetch Cart",
        "description": "Fetch customer cart contents",
        "expected_status_codes": [200]
    })
    assert step1_resp.status_code == 201
    step1 = step1_resp.json()
    assert step1["step_order"] == 1
    assert step1["http_method"] == "GET"
    assert step1["endpoint_path"] == "/api/v1/cart"
    assert step1["identity_name"] == "Buyer"

    # 2. Allowed HTTP method: HEAD
    step2_resp = client.post(f"/api/v1/workflows/{wf_id}/steps", json={
        "step_order": 2,
        "endpoint_id": ep["id"],
        "identity_id": ident["id"],
        "http_method": "HEAD",
        "name": "Check Cart Headers",
        "expected_status_codes": [200]
    })
    assert step2_resp.status_code == 201
    assert step2_resp.json()["http_method"] == "HEAD"

    # 3. Disallowed HTTP methods rejected: POST, PUT, DELETE, PATCH
    for disallowed_method in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"]:
        bad_method_resp = client.post(f"/api/v1/workflows/{wf_id}/steps", json={
            "step_order": 3,
            "endpoint_id": ep["id"],
            "http_method": disallowed_method,
            "name": f"Test {disallowed_method}"
        })
        assert bad_method_resp.status_code == 400
        assert "Only safe HTTP methods (GET, HEAD) are allowed" in bad_method_resp.json()["detail"]

    # 4. Duplicate step_order rejected
    dup_order_resp = client.post(f"/api/v1/workflows/{wf_id}/steps", json={
        "step_order": 1,
        "endpoint_id": ep["id"],
        "http_method": "GET",
        "name": "Duplicate Step Order 1"
    })
    assert dup_order_resp.status_code == 400
    assert "already exists in this workflow" in dup_order_resp.json()["detail"]

    # 5. List steps
    steps_list = client.get(f"/api/v1/workflows/{wf_id}/steps").json()
    assert len(steps_list) == 2
    assert steps_list[0]["step_order"] == 1
    assert steps_list[1]["step_order"] == 2

    # 6. Update step - patch to unsafe method rejected
    bad_patch = client.patch(f"/api/v1/workflows/{wf_id}/steps/{step1['id']}", json={
        "http_method": "POST"
    })
    assert bad_patch.status_code == 400

    # 7. Update step - safe update
    patch_resp = client.patch(f"/api/v1/workflow-steps/{step1['id']}", json={
        "name": "Updated Step Name",
        "expected_status_codes": [200, 204]
    })
    assert patch_resp.status_code == 200
    assert patch_resp.json()["name"] == "Updated Step Name"
    assert patch_resp.json()["expected_status_codes"] == [200, 204]

    # 8. Delete step
    del_resp = client.delete(f"/api/v1/workflow-steps/{step1['id']}")
    assert del_resp.status_code == 200
    assert client.get(f"/api/v1/workflow-steps/{step1['id']}").status_code == 404


def test_workflow_step_credential_rejection(client: TestClient):
    proj = setup_project(client, "WF Credential Project")
    proj_id = proj["id"]
    _, ep = setup_api_and_endpoint(client, proj_id, "GET", "/api/v1/profile")

    wf = client.post(f"/api/v1/projects/{proj_id}/workflows", json={
        "name": "Profile Flow"
    }).json()
    wf_id = wf["id"]

    # 1. Raw Bearer secret rejected
    raw_bearer_resp = client.post(f"/api/v1/workflows/{wf_id}/steps", json={
        "step_order": 1,
        "endpoint_id": ep["id"],
        "http_method": "GET",
        "name": "Raw Bearer Step",
        "request_template": {
            "headers": {
                "Authorization": "Bearer raw_super_secret_token_value_abc"
            }
        }
    })
    assert raw_bearer_resp.status_code == 400
    assert "Raw credentials or secrets are not allowed" in raw_bearer_resp.json()["detail"]

    # 2. Raw password field rejected
    raw_pwd_resp = client.post(f"/api/v1/workflows/{wf_id}/steps", json={
        "step_order": 1,
        "endpoint_id": ep["id"],
        "http_method": "GET",
        "name": "Raw Password Step",
        "request_template": {
            "body": {
                "password": "ClearTextPassword123!"
            }
        }
    })
    assert raw_pwd_resp.status_code == 400

    # 3. Raw api_key rejected
    raw_key_resp = client.post(f"/api/v1/workflows/{wf_id}/steps", json={
        "step_order": 1,
        "endpoint_id": ep["id"],
        "http_method": "GET",
        "name": "Raw Api Key Step",
        "request_template": {
            "headers": {
                "x-api-key": "secret_api_key_live_xyz"
            }
        }
    })
    assert raw_key_resp.status_code == 400

    # 4. Placeholders allowed
    placeholder_resp = client.post(f"/api/v1/workflows/{wf_id}/steps", json={
        "step_order": 1,
        "endpoint_id": ep["id"],
        "http_method": "GET",
        "name": "Placeholder Step",
        "request_template": {
            "headers": {
                "Authorization": "Bearer {{token}}",
                "x-api-key": "{{api_key}}"
            },
            "body": {
                "password": "{{identity_password}}"
            }
        }
    })
    assert placeholder_resp.status_code == 201

    # 5. [REDACTED] string allowed
    redacted_resp = client.post(f"/api/v1/workflows/{wf_id}/steps", json={
        "step_order": 2,
        "endpoint_id": ep["id"],
        "http_method": "GET",
        "name": "Redacted Step",
        "request_template": {
            "headers": {
                "Authorization": "[REDACTED]"
            }
        }
    })
    assert redacted_resp.status_code == 201


def test_workflow_state_crud_and_uniqueness(client: TestClient):
    proj = setup_project(client, "WF States Project")
    proj_id = proj["id"]
    wf = client.post(f"/api/v1/projects/{proj_id}/workflows", json={
        "name": "Order Lifecycle"
    }).json()
    wf_id = wf["id"]

    # 1. Create Initial State
    s1_resp = client.post(f"/api/v1/workflows/{wf_id}/states", json={
        "name": "CREATED",
        "description": "Order has been created",
        "is_initial": True,
        "is_terminal": False
    })
    assert s1_resp.status_code == 201
    s1 = s1_resp.json()
    assert s1["name"] == "CREATED"
    assert s1["is_initial"] is True
    assert s1["is_terminal"] is False

    # 2. Create Terminal State
    s2_resp = client.post(f"/api/v1/workflows/{wf_id}/states", json={
        "name": "COMPLETED",
        "description": "Order has reached final state",
        "is_initial": False,
        "is_terminal": True
    })
    assert s2_resp.status_code == 201

    # 3. Duplicate state name in same workflow rejected
    dup_resp = client.post(f"/api/v1/workflows/{wf_id}/states", json={
        "name": "CREATED"
    })
    assert dup_resp.status_code == 400
    assert "already exists in this workflow" in dup_resp.json()["detail"]

    # 4. List states
    states = client.get(f"/api/v1/workflows/{wf_id}/states").json()
    assert len(states) == 2

    # 5. Update state
    patch_resp = client.patch(f"/api/v1/workflow-states/{s1['id']}", json={
        "description": "Updated created description",
        "is_initial": True
    })
    assert patch_resp.status_code == 200
    assert patch_resp.json()["description"] == "Updated created description"

    # 6. Delete state
    del_resp = client.delete(f"/api/v1/workflow-states/{s1['id']}")
    assert del_resp.status_code == 200
    assert client.get(f"/api/v1/workflow-states/{s1['id']}").status_code == 404


def test_workflow_transition_crud_and_validation(client: TestClient):
    proj = setup_project(client, "WF Transitions Project")
    proj_id = proj["id"]
    _, ep = setup_api_and_endpoint(client, proj_id, "GET", "/api/v1/orders/status")

    wf = client.post(f"/api/v1/projects/{proj_id}/workflows", json={
        "name": "State Transitions Flow"
    }).json()
    wf_id = wf["id"]

    step = client.post(f"/api/v1/workflows/{wf_id}/steps", json={
        "step_order": 1,
        "endpoint_id": ep["id"],
        "http_method": "GET",
        "name": "Check Status"
    }).json()

    s1 = client.post(f"/api/v1/workflows/{wf_id}/states", json={"name": "PENDING", "is_initial": True}).json()
    s2 = client.post(f"/api/v1/workflows/{wf_id}/states", json={"name": "CONFIRMED"}).json()
    s3 = client.post(f"/api/v1/workflows/{wf_id}/states", json={"name": "CANCELLED", "is_terminal": True}).json()

    # 1. Create valid ALLOW transition
    t1_resp = client.post(f"/api/v1/workflows/{wf_id}/transitions", json={
        "from_state_id": s1["id"],
        "to_state_id": s2["id"],
        "step_id": step["id"],
        "expected_behavior": "ALLOW",
        "description": "Pending to Confirmed transition"
    })
    assert t1_resp.status_code == 201
    t1 = t1_resp.json()
    assert t1["expected_behavior"] == "ALLOW"
    assert t1["from_state_name"] == "PENDING"
    assert t1["to_state_name"] == "CONFIRMED"
    assert t1["step_name"] == "Check Status"

    # 2. Create valid DENY transition
    t2_resp = client.post(f"/api/v1/workflows/{wf_id}/transitions", json={
        "from_state_id": s3["id"],
        "to_state_id": s2["id"],
        "step_id": step["id"],
        "expected_behavior": "DENY",
        "description": "Cancelled to Confirmed should be denied"
    })
    assert t2_resp.status_code == 201
    assert t2_resp.json()["expected_behavior"] == "DENY"

    # 3. Duplicate transition rejected
    dup_resp = client.post(f"/api/v1/workflows/{wf_id}/transitions", json={
        "from_state_id": s1["id"],
        "to_state_id": s2["id"],
        "step_id": step["id"],
        "expected_behavior": "ALLOW"
    })
    assert dup_resp.status_code == 400
    assert "already exists" in dup_resp.json()["detail"]

    # 4. Invalid expected_behavior rejected
    bad_beh_resp = client.post(f"/api/v1/workflows/{wf_id}/transitions", json={
        "from_state_id": s1["id"],
        "to_state_id": s3["id"],
        "expected_behavior": "MAYBE"
    })
    assert bad_beh_resp.status_code == 400

    # 5. List transitions
    trans_list = client.get(f"/api/v1/workflows/{wf_id}/transitions").json()
    assert len(trans_list) == 2

    # 6. Update transition
    patch_resp = client.patch(f"/api/v1/workflow-transitions/{t1['id']}", json={
        "description": "Updated transition description",
        "expected_behavior": "ALLOW"
    })
    assert patch_resp.status_code == 200
    assert patch_resp.json()["description"] == "Updated transition description"

    # 7. Delete transition
    del_resp = client.delete(f"/api/v1/workflow-transitions/{t1['id']}")
    assert del_resp.status_code == 200
    assert client.get(f"/api/v1/workflow-transitions/{t1['id']}").status_code == 404


def test_cross_project_isolation_and_cross_workflow_validation(client: TestClient):
    proj1 = setup_project(client, "Cross Proj 1")
    proj2 = setup_project(client, "Cross Proj 2")

    _, ep1 = setup_api_and_endpoint(client, proj1["id"], "GET", "/api/v1/p1/data")
    _, ep2 = setup_api_and_endpoint(client, proj2["id"], "GET", "/api/v1/p2/data")

    ident1 = setup_identity(client, proj1["id"], "Ident P1")
    ident2 = setup_identity(client, proj2["id"], "Ident P2")

    wf1 = client.post(f"/api/v1/projects/{proj1['id']}/workflows", json={"name": "WF 1"}).json()
    wf2 = client.post(f"/api/v1/projects/{proj2['id']}/workflows", json={"name": "WF 2"}).json()

    s1_wf1 = client.post(f"/api/v1/workflows/{wf1['id']}/states", json={"name": "State WF1"}).json()
    s2_wf2 = client.post(f"/api/v1/workflows/{wf2['id']}/states", json={"name": "State WF2"}).json()

    # 1. Step in WF1 cannot reference Endpoint from Proj 2
    bad_ep_resp = client.post(f"/api/v1/workflows/{wf1['id']}/steps", json={
        "step_order": 1,
        "endpoint_id": ep2["id"],
        "http_method": "GET",
        "name": "Step with cross ep"
    })
    assert bad_ep_resp.status_code == 400
    assert "Endpoint does not belong to the same project" in bad_ep_resp.json()["detail"]

    # 2. Step in WF1 cannot reference Identity from Proj 2
    bad_ident_resp = client.post(f"/api/v1/workflows/{wf1['id']}/steps", json={
        "step_order": 1,
        "endpoint_id": ep1["id"],
        "identity_id": ident2["id"],
        "http_method": "GET",
        "name": "Step with cross ident"
    })
    assert bad_ident_resp.status_code == 400
    assert "Identity does not belong to the same project" in bad_ident_resp.json()["detail"]

    # 3. Transition in WF1 cannot reference from_state from WF2
    bad_from_resp = client.post(f"/api/v1/workflows/{wf1['id']}/transitions", json={
        "from_state_id": s2_wf2["id"],
        "to_state_id": s1_wf1["id"],
        "expected_behavior": "ALLOW"
    })
    assert bad_from_resp.status_code == 400
    assert "From state does not belong to this workflow" in bad_from_resp.json()["detail"]

    # 4. Transition in WF1 cannot reference to_state from WF2
    bad_to_resp = client.post(f"/api/v1/workflows/{wf1['id']}/transitions", json={
        "from_state_id": s1_wf1["id"],
        "to_state_id": s2_wf2["id"],
        "expected_behavior": "ALLOW"
    })
    assert bad_to_resp.status_code == 400
    assert "To state does not belong to this workflow" in bad_to_resp.json()["detail"]


def test_workflow_cascade_deletion(client: TestClient):
    proj = setup_project(client, "Cascade Proj")
    proj_id = proj["id"]
    _, ep = setup_api_and_endpoint(client, proj_id, "GET", "/api/v1/test")

    wf = client.post(f"/api/v1/projects/{proj_id}/workflows", json={"name": "Cascade Flow"}).json()
    wf_id = wf["id"]

    step = client.post(f"/api/v1/workflows/{wf_id}/steps", json={
        "step_order": 1,
        "endpoint_id": ep["id"],
        "http_method": "GET",
        "name": "Step 1"
    }).json()

    s1 = client.post(f"/api/v1/workflows/{wf_id}/states", json={"name": "S1"}).json()
    s2 = client.post(f"/api/v1/workflows/{wf_id}/states", json={"name": "S2"}).json()

    trans = client.post(f"/api/v1/workflows/{wf_id}/transitions", json={
        "from_state_id": s1["id"],
        "to_state_id": s2["id"],
        "step_id": step["id"],
        "expected_behavior": "ALLOW"
    }).json()

    # Check workflow detail counts
    detail = client.get(f"/api/v1/workflows/{wf_id}").json()
    assert len(detail["steps"]) == 1
    assert len(detail["states"]) == 2
    assert len(detail["transitions"]) == 1

    # Delete workflow
    del_resp = client.delete(f"/api/v1/workflows/{wf_id}")
    assert del_resp.status_code == 200

    # Ensure all child entities are removed
    assert client.get(f"/api/v1/workflow-steps/{step['id']}").status_code == 404
    assert client.get(f"/api/v1/workflow-states/{s1['id']}").status_code == 404
    assert client.get(f"/api/v1/workflow-states/{s2['id']}").status_code == 404
    assert client.get(f"/api/v1/workflow-transitions/{trans['id']}").status_code == 404
