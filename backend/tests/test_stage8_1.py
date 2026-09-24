"""
Stage 8.1 Test Suite: Deterministic Finding Correlation & Attack Graph Foundation
Author: SentinelAPI Security Architecture Team

Validates deterministic correlation engine rules, graph reproducibility, project isolation,
and confirms no target API requests are executed during correlation.
"""

import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from app.models import (
    Project,
    API,
    Endpoint,
    Role,
    Identity,
    Resource,
    Workflow,
    WorkflowExecution,
    SecurityTest,
    TestExecution,
    Finding,
    AttackGraph,
    AttackGraphNode,
    AttackGraphEdge,
    FindingCorrelation,
)
from app.services.security_engine.correlation_engine import CorrelationEngine

# Prevent pytest from treating model classes as test case classes
AttackGraph.__test__ = False
AttackGraphNode.__test__ = False
AttackGraphEdge.__test__ = False
FindingCorrelation.__test__ = False
TestExecution.__test__ = False


def create_base_test_setup(client: TestClient, db_session, proj_name="Stage 8.1 Test Project"):
    """Helper to set up an authorized project with API, endpoint, role, identity, and resource."""
    proj = Project(
        name=proj_name,
        description="Authorized test target for correlation engine",
        environment="staging",
        base_url="http://testserver",
        authorization_status="authorized",
    )
    db_session.add(proj)
    db_session.commit()
    db_session.refresh(proj)

    api = API(
        project_id=proj.id,
        name="Core API",
        version="1.0",
        format="openapi3",
        status="active",
        url="http://testserver",
    )
    db_session.add(api)
    db_session.commit()
    db_session.refresh(api)

    resource = Resource(
        project_id=proj.id,
        api_id=api.id,
        name="AccountResource",
        resource_type="entity",
    )
    db_session.add(resource)
    db_session.commit()
    db_session.refresh(resource)

    role = Role(
        project_id=proj.id,
        name="AuditorRole",
        description="Auditor role for testing",
    )
    db_session.add(role)
    db_session.commit()
    db_session.refresh(role)

    identity = Identity(
        project_id=proj.id,
        role_id=role.id,
        name="AttackerUser",
        auth_type="bearer",
    )
    db_session.add(identity)
    db_session.commit()
    db_session.refresh(identity)

    endpoint = Endpoint(
        api_id=api.id,
        resource_id=resource.id,
        method="GET",
        path=f"/api/accounts-{proj.id}/{{account_id}}",
        summary="Lookup Account",
    )
    db_session.add(endpoint)
    db_session.commit()
    db_session.refresh(endpoint)

    return {
        "project": proj,
        "api": api,
        "resource": resource,
        "role": role,
        "identity": identity,
        "endpoint": endpoint,
    }


def test_same_identity_correlation(client: TestClient, db_session):
    """Two findings sharing the same attacker_identity_id produce SAME_IDENTITY correlation."""
    setup = create_base_test_setup(client, db_session)
    proj = setup["project"]
    ident = setup["identity"]

    f1 = Finding(
        project_id=proj.id,
        attacker_identity_id=ident.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="BOLA Vulnerability on Endpoint A",
        description="Unauthorized object access using identity",
        remediation="Enforce object-level access controls",
    )
    f2 = Finding(
        project_id=proj.id,
        attacker_identity_id=ident.id,
        type="BFLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="BFLA Vulnerability on Endpoint B",
        description="Function level access bypass using identity",
        remediation="Enforce role checks",
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    engine = CorrelationEngine(db=db_session)
    result = engine.run_correlation(project_id=proj.id)

    assert result["confirmed_findings_count"] == 2
    assert result["correlations_count"] >= 1
    rel_types = [c.relationship_type for c in result["correlations"]]
    assert "SAME_IDENTITY" in rel_types


def test_same_endpoint_correlation(client: TestClient, db_session):
    """Two findings sharing the same endpoint_id produce SAME_ENDPOINT correlation."""
    setup = create_base_test_setup(client, db_session)
    proj = setup["project"]
    ep = setup["endpoint"]

    f1 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="BOLA on Accounts Endpoint",
        description="IDOR detected",
        remediation="Validate user ownership",
    )
    f2 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        type="AUTH_MISSING",
        severity="CRITICAL",
        confidence="HIGH",
        status="OPEN",
        title="Unauthenticated Access on Accounts Endpoint",
        description="Endpoint allows requests without token",
        remediation="Enforce authentication",
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    engine = CorrelationEngine(db=db_session)
    result = engine.run_correlation(project_id=proj.id)

    rel_types = [c.relationship_type for c in result["correlations"]]
    assert "SAME_ENDPOINT" in rel_types


def test_same_resource_correlation(client: TestClient, db_session):
    """Two findings referencing the same resource_id produce SAME_RESOURCE correlation."""
    setup = create_base_test_setup(client, db_session)
    proj = setup["project"]
    res = setup["resource"]

    f1 = Finding(
        project_id=proj.id,
        resource_id=res.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="BOLA on Resource",
        description="Access violation",
        remediation="Check resource ownership",
    )
    f2 = Finding(
        project_id=proj.id,
        resource_id=res.id,
        type="PROPERTY_EXPOSURE",
        severity="MEDIUM",
        confidence="HIGH",
        status="OPEN",
        title="Property Exposure on Resource",
        description="Sensitive property returned",
        exposed_properties="ssn, salary",
        remediation="Filter response properties",
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    engine = CorrelationEngine(db=db_session)
    result = engine.run_correlation(project_id=proj.id)

    rel_types = [c.relationship_type for c in result["correlations"]]
    assert "SAME_RESOURCE" in rel_types


def test_same_workflow_correlation(client: TestClient, db_session):
    """Two findings sharing the same workflow_id produce SAME_WORKFLOW correlation."""
    setup = create_base_test_setup(client, db_session)
    proj = setup["project"]

    wf = Workflow(
        project_id=proj.id,
        name="Checkout Workflow",
        status="ACTIVE",
    )
    db_session.add(wf)
    db_session.commit()
    db_session.refresh(wf)

    f1 = Finding(
        project_id=proj.id,
        workflow_id=wf.id,
        type="WORKFLOW_BYPASS",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Checkout Step Skip Allowed",
        description="Step 2 skipped",
        remediation="Enforce step sequencing",
    )
    f2 = Finding(
        project_id=proj.id,
        workflow_id=wf.id,
        type="STEP_REPLAY_ACCEPTED",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Payment Replay Permitted",
        description="Duplicate charge allowed",
        remediation="Enforce idempotent state",
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    engine = CorrelationEngine(db=db_session)
    result = engine.run_correlation(project_id=proj.id)

    rel_types = [c.relationship_type for c in result["correlations"]]
    assert "SAME_WORKFLOW" in rel_types


def test_same_execution_correlation(client: TestClient, db_session):
    """Two findings sharing the same workflow_execution_id produce SAME_EXECUTION correlation."""
    setup = create_base_test_setup(client, db_session)
    proj = setup["project"]

    wf = Workflow(project_id=proj.id, name="Order Flow", status="ACTIVE")
    db_session.add(wf)
    db_session.commit()
    db_session.refresh(wf)

    wf_exec = WorkflowExecution(
        workflow_id=wf.id,
        status="COMPLETED",
        result="CONFIRMED",
        triggered_by="MANUAL",
    )
    db_session.add(wf_exec)
    db_session.commit()
    db_session.refresh(wf_exec)

    f1 = Finding(
        project_id=proj.id,
        workflow_id=wf.id,
        workflow_execution_id=wf_exec.id,
        type="INVALID_STATE_TRANSITION",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Transition from DRAFT to COMPLETED allowed",
        description="State machine bypass",
        remediation="Validate current state",
    )
    f2 = Finding(
        project_id=proj.id,
        workflow_id=wf.id,
        workflow_execution_id=wf_exec.id,
        type="UNAUTHORIZED_STATE_TRANSITION",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Terminal State Rewind Permitted",
        description="State mutated after terminal",
        remediation="Freeze terminal states",
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    engine = CorrelationEngine(db=db_session)
    result = engine.run_correlation(project_id=proj.id)

    rel_types = [c.relationship_type for c in result["correlations"]]
    assert "SAME_EXECUTION" in rel_types


def test_auth_to_authorization_correlation(client: TestClient, db_session):
    """Authentication finding and authorization finding referencing same endpoint and identity yield AUTH_TO_AUTHORIZATION."""
    setup = create_base_test_setup(client, db_session)
    proj = setup["project"]
    ep = setup["endpoint"]
    ident = setup["identity"]

    auth_finding = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident.id,
        type="AUTH_INVALID",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Invalid Token Accepted",
        description="Target accepts expired/invalid token",
        remediation="Verify JWT signature and expiry",
    )
    authz_finding = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident.id,
        type="BFLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Admin Endpoint Exposed to Regular Identity",
        description="Function level authorization bypass",
        remediation="Enforce role check",
    )
    db_session.add_all([auth_finding, authz_finding])
    db_session.commit()

    engine = CorrelationEngine(db=db_session)
    result = engine.run_correlation(project_id=proj.id)

    rel_types = [c.relationship_type for c in result["correlations"]]
    assert "AUTH_TO_AUTHORIZATION" in rel_types


def test_authorization_to_workflow_correlation(client: TestClient, db_session):
    """Authorization finding and workflow finding with shared context yield AUTHORIZATION_TO_WORKFLOW."""
    setup = create_base_test_setup(client, db_session)
    proj = setup["project"]
    ident = setup["identity"]
    res = setup["resource"]

    wf = Workflow(project_id=proj.id, name="Claim Processing Flow", status="ACTIVE")
    db_session.add(wf)
    db_session.commit()
    db_session.refresh(wf)

    authz_finding = Finding(
        project_id=proj.id,
        attacker_identity_id=ident.id,
        resource_id=res.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="BOLA on Claim Resource",
        description="Attacker can access victim claim",
        remediation="Validate claim ownership",
    )
    wf_finding = Finding(
        project_id=proj.id,
        workflow_id=wf.id,
        attacker_identity_id=ident.id,
        resource_id=res.id,
        type="IDENTITY_SESSION_POISONING",
        severity="CRITICAL",
        confidence="HIGH",
        status="OPEN",
        title="Workflow Identity Tampering",
        description="Identity switch allowed mid-workflow",
        remediation="Bind session to workflow context",
    )
    db_session.add_all([authz_finding, wf_finding])
    db_session.commit()

    engine = CorrelationEngine(db=db_session)
    result = engine.run_correlation(project_id=proj.id)

    rel_types = [c.relationship_type for c in result["correlations"]]
    assert "AUTHORIZATION_TO_WORKFLOW" in rel_types


def test_property_exposure_chain_correlation(client: TestClient, db_session):
    """Property exposure finding referencing the same resource as authorization/workflow finding yields PROPERTY_EXPOSURE_CHAIN."""
    setup = create_base_test_setup(client, db_session)
    proj = setup["project"]
    res = setup["resource"]

    prop_finding = Finding(
        project_id=proj.id,
        resource_id=res.id,
        type="EXCESSIVE_DATA_EXPOSURE",
        severity="MEDIUM",
        confidence="HIGH",
        status="OPEN",
        title="Excessive Data Exposed on Account",
        description="PII fields returned",
        exposed_properties="account_balance, routing_number",
        remediation="Apply response DTO filters",
    )
    authz_finding = Finding(
        project_id=proj.id,
        resource_id=res.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="BOLA on Account Lookup",
        description="Arbitrary account retrieval allowed",
        remediation="Check user-account relation",
    )
    db_session.add_all([prop_finding, authz_finding])
    db_session.commit()

    engine = CorrelationEngine(db=db_session)
    result = engine.run_correlation(project_id=proj.id)

    rel_types = [c.relationship_type for c in result["correlations"]]
    assert "PROPERTY_EXPOSURE_CHAIN" in rel_types


def test_same_project_isolation(client: TestClient, db_session):
    """Findings from different projects are NEVER correlated."""
    setup1 = create_base_test_setup(client, db_session, proj_name="Project 1")
    setup2 = create_base_test_setup(client, db_session, proj_name="Project 2")

    # Both findings happen to reference the same endpoint ID or title, but different projects
    f1 = Finding(
        project_id=setup1["project"].id,
        endpoint_id=setup1["endpoint"].id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Finding in Project 1",
        description="Isolated finding",
        remediation="None",
    )
    f2 = Finding(
        project_id=setup2["project"].id,
        endpoint_id=setup2["endpoint"].id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Finding in Project 2",
        description="Isolated finding",
        remediation="None",
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    engine = CorrelationEngine(db=db_session)
    res1 = engine.run_correlation(project_id=setup1["project"].id)
    res2 = engine.run_correlation(project_id=setup2["project"].id)

    # In setup 1 there is only 1 confirmed finding, so 0 correlations
    assert res1["confirmed_findings_count"] == 1
    assert res1["correlations_count"] == 0

    assert res2["confirmed_findings_count"] == 1
    assert res2["correlations_count"] == 0

    # Ensure correlations in DB belong only to their respective project
    all_corrs = db_session.query(FindingCorrelation).all()
    for c in all_corrs:
        assert c.project_id in (setup1["project"].id, setup2["project"].id)


def test_no_correlation_for_unrelated_findings(client: TestClient, db_session):
    """Findings in the same project with completely disjoint context have 0 correlations."""
    setup = create_base_test_setup(client, db_session)
    proj = setup["project"]
    api = setup["api"]

    # Endpoint 1
    ep1 = Endpoint(api_id=api.id, method="GET", path="/users")
    # Endpoint 2
    ep2 = Endpoint(api_id=api.id, method="GET", path="/health")
    db_session.add_all([ep1, ep2])
    db_session.commit()

    f1 = Finding(
        project_id=proj.id,
        endpoint_id=ep1.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Finding on Users",
        description="Unrelated",
        remediation="Fix users",
    )
    f2 = Finding(
        project_id=proj.id,
        endpoint_id=ep2.id,
        type="SECURITY_HEADER_MISSING",
        severity="LOW",
        confidence="HIGH",
        status="OPEN",
        title="Missing Header on Health",
        description="Unrelated",
        remediation="Add header",
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    engine = CorrelationEngine(db=db_session)
    result = engine.run_correlation(project_id=proj.id)

    assert result["confirmed_findings_count"] == 2
    assert result["correlations_count"] == 0


def test_no_correlation_for_inconclusive_findings(client: TestClient, db_session):
    """Findings with INCONCLUSIVE or ERROR result are excluded from correlation and graph."""
    setup = create_base_test_setup(client, db_session)
    proj = setup["project"]
    ep = setup["endpoint"]
    ident = setup["identity"]

    sec_test = SecurityTest(
        project_id=proj.id,
        endpoint_id=ep.id,
        test_type="BOLA",
        attacker_identity_id=ident.id,
        status="completed",
    )
    db_session.add(sec_test)
    db_session.commit()

    inconclusive_exec = TestExecution(
        security_test_id=sec_test.id,
        status="COMPLETED",
        result="INCONCLUSIVE",
        result_reason="500 Server Error encountered",
    )
    db_session.add(inconclusive_exec)
    db_session.commit()

    # Confirmed finding
    f_confirmed = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Confirmed BOLA",
        description="Real confirmed vulnerability",
        remediation="Fix it",
    )
    # Inconclusive finding
    f_inconclusive = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident.id,
        execution_id=inconclusive_exec.id,
        type="BOLA",
        severity="HIGH",
        confidence="LOW",
        status="INCONCLUSIVE",
        title="Inconclusive BOLA",
        description="Not verified",
        remediation="Investigate",
    )
    db_session.add_all([f_confirmed, f_inconclusive])
    db_session.commit()

    engine = CorrelationEngine(db=db_session)
    result = engine.run_correlation(project_id=proj.id)

    # Only 1 confirmed finding should be evaluated, so 0 correlations
    assert result["confirmed_findings_count"] == 1
    assert result["correlations_count"] == 0

    # Ensure inconclusive finding is NOT in graph nodes
    graph = result["graph"]
    node_finding_ids = [n.finding_id for n in graph.nodes if n.finding_id]
    assert f_confirmed.id in node_finding_ids
    assert f_inconclusive.id not in node_finding_ids


def test_duplicate_correlation_prevention(client: TestClient, db_session):
    """Running correlation multiple times does not produce duplicate correlations."""
    setup = create_base_test_setup(client, db_session)
    proj = setup["project"]
    ident = setup["identity"]

    f1 = Finding(
        project_id=proj.id,
        attacker_identity_id=ident.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Finding 1",
        description="First",
        remediation="Fix",
    )
    f2 = Finding(
        project_id=proj.id,
        attacker_identity_id=ident.id,
        type="BFLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Finding 2",
        description="Second",
        remediation="Fix",
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    engine = CorrelationEngine(db=db_session)

    # Run 1
    res1 = engine.run_correlation(project_id=proj.id)
    initial_corrs = res1["correlations_count"]
    initial_new = res1["new_correlations_count"]
    assert initial_corrs >= 1
    assert initial_new == initial_corrs

    # Run 2
    res2 = engine.run_correlation(project_id=proj.id)
    assert res2["correlations_count"] == initial_corrs
    assert res2["new_correlations_count"] == 0  # 0 new correlations added!


def test_deterministic_graph_reconstruction(client: TestClient, db_session):
    """Graph construction is 100% deterministic and reproducible on repeated runs."""
    setup = create_base_test_setup(client, db_session)
    proj = setup["project"]
    ep = setup["endpoint"]
    ident = setup["identity"]
    res = setup["resource"]

    f1 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident.id,
        resource_id=res.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Deterministic Finding A",
        description="IDOR on Account",
        remediation="Fix",
    )
    f2 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident.id,
        resource_id=res.id,
        type="BFLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Deterministic Finding B",
        description="Function bypass on Account",
        remediation="Fix",
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    engine = CorrelationEngine(db=db_session)

    # First run
    run1 = engine.run_correlation(project_id=proj.id)
    node_count_1 = run1["node_count"]
    edge_count_1 = run1["edge_count"]
    nodes_1 = sorted([n.label for n in run1["graph"].nodes])

    # Second run
    run2 = engine.run_correlation(project_id=proj.id)
    node_count_2 = run2["node_count"]
    edge_count_2 = run2["edge_count"]
    nodes_2 = sorted([n.label for n in run2["graph"].nodes])

    assert node_count_1 == node_count_2
    assert edge_count_1 == edge_count_2
    assert nodes_1 == nodes_2


def test_no_target_api_execution_during_correlation(client: TestClient, db_session):
    """Ensure that the correlation engine never initiates HTTP requests."""
    setup = create_base_test_setup(client, db_session)
    proj = setup["project"]

    f1 = Finding(
        project_id=proj.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Finding 1",
        description="Test",
        remediation="Fix",
    )
    db_session.add(f1)
    db_session.commit()

    # Mock httpx.AsyncClient or any HTTP request mechanisms
    with patch("httpx.AsyncClient.request") as mock_http:
        res = client.post(f"/api/v1/projects/{proj.id}/correlation/run")
        assert res.status_code == 200
        mock_http.assert_not_called()


def test_correlation_rest_api_endpoints(client: TestClient, db_session):
    """Test REST API endpoints for correlations and attack graphs."""
    setup = create_base_test_setup(client, db_session)
    proj = setup["project"]
    ident = setup["identity"]
    ep = setup["endpoint"]

    f1 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="API Test Finding 1",
        description="Desc",
        remediation="Rem",
    )
    f2 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident.id,
        type="BFLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="API Test Finding 2",
        description="Desc",
        remediation="Rem",
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    # 1. POST run correlation
    run_res = client.post(f"/api/v1/projects/{proj.id}/correlation/run")
    assert run_res.status_code == 200
    run_data = run_res.json()
    assert run_data["project_id"] == proj.id
    assert run_data["confirmed_findings_count"] == 2
    assert run_data["node_count"] > 0
    assert run_data["edge_count"] > 0
    graph_id = run_data["graph_id"]

    # 2. GET correlations for project
    corr_res = client.get(f"/api/v1/projects/{proj.id}/correlations")
    assert corr_res.status_code == 200
    corrs = corr_res.json()
    assert len(corrs) >= 1

    # 3. GET attack-graphs for project
    graphs_res = client.get(f"/api/v1/projects/{proj.id}/attack-graphs")
    assert graphs_res.status_code == 200
    graphs = graphs_res.json()
    assert len(graphs) >= 1
    assert graphs[0]["id"] == graph_id

    # 4. GET attack graph detail
    graph_detail_res = client.get(f"/api/v1/attack-graphs/{graph_id}")
    assert graph_detail_res.status_code == 200
    detail = graph_detail_res.json()
    assert "nodes" in detail
    assert "edges" in detail
    assert len(detail["nodes"]) > 0

    # 5. GET attack graph nodes
    nodes_res = client.get(f"/api/v1/attack-graphs/{graph_id}/nodes")
    assert nodes_res.status_code == 200
    nodes = nodes_res.json()
    assert len(nodes) == len(detail["nodes"])

    # 6. GET attack graph edges
    edges_res = client.get(f"/api/v1/attack-graphs/{graph_id}/edges")
    assert edges_res.status_code == 200
    edges = edges_res.json()
    assert len(edges) == len(detail["edges"])
