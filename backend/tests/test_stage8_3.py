"""
Stage 8.3 Test Suite: Deterministic Security Impact Analysis
Author: SentinelAPI Security Architecture Team

Validates deterministic evaluation of security boundaries (AUTH, AUTHORIZATION,
IDENTITY, RESOURCE, WORKFLOW, PROPERTY), sensitive data reached, cross-identity/resource
traversal, terminal impact classification, deterministic rebuild, exclusion of inconclusive/error
findings, cross-project isolation, and zero target API execution.
"""

import pytest
import json
from unittest.mock import patch
from fastapi.testclient import TestClient
from app.models import (
    Project,
    API,
    Endpoint,
    Role,
    Identity,
    Resource,
    ResourceProperty,
    ResourceOwnership,
    Workflow,
    Finding,
    AttackGraph,
    AttackGraphNode,
    AttackGraphEdge,
    AttackPath,
    AttackPathStep,
    SecurityImpact,
    TestExecution,
)
from app.services.security_engine.correlation_engine import CorrelationEngine
from app.services.security_engine.attack_path_engine import AttackPathEngine
from app.services.security_engine.impact_engine import ImpactEngine

# Prevent pytest from treating model classes as test suites
AttackGraph.__test__ = False
AttackGraphNode.__test__ = False
AttackGraphEdge.__test__ = False
AttackPath.__test__ = False
AttackPathStep.__test__ = False
SecurityImpact.__test__ = False
TestExecution.__test__ = False


def create_base_test_setup(client: TestClient, db_session, proj_name="Stage 8.3 Test Project"):
    """Helper to set up an authorized project with API, endpoint, role, identity, and resource."""
    proj = Project(
        name=proj_name,
        description="Authorized test target for impact engine",
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


def test_authentication_boundary_detection(client: TestClient, db_session):
    """1. Authentication boundary and initial access detection."""
    setup = create_base_test_setup(client, db_session, proj_name="Auth Boundary Project")
    proj = setup["project"]
    ident = setup["identity"]
    ep = setup["endpoint"]

    f = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident.id,
        type="AUTH_MISSING",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Missing Authentication",
        description="Endpoint accepts unauthenticated requests",
        remediation="Enforce authentication",
    )
    db_session.add(f)
    db_session.commit()

    engine = ImpactEngine(db_session)
    result = engine.run_impact_analysis(proj.id)

    assert result["impacts_count"] == 1
    impact = result["impacts"][0]
    assert impact.authentication_boundary_crossed is True
    assert impact.initial_access is True
    assert impact.authorization_boundary_crossed is False
    assert "authentication boundary" in impact.explanation.lower()


def test_authorization_boundary_detection(client: TestClient, db_session):
    """2. Authorization and resource boundary detection."""
    setup = create_base_test_setup(client, db_session, proj_name="Authz Boundary Project")
    proj = setup["project"]
    ident = setup["identity"]
    ep = setup["endpoint"]
    res = setup["resource"]

    f = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        resource_id=res.id,
        attacker_identity_id=ident.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="BOLA on Account Endpoint",
        description="User can access unauthorized accounts",
        remediation="Enforce object-level access controls",
    )
    db_session.add(f)
    db_session.commit()

    engine = ImpactEngine(db_session)
    result = engine.run_impact_analysis(proj.id)

    assert result["impacts_count"] == 1
    impact = result["impacts"][0]
    assert impact.authorization_boundary_crossed is True
    assert impact.resource_boundary_crossed is True
    assert impact.authentication_boundary_crossed is False
    assert impact.terminal_impact == "RESOURCE_ACCESS"


def test_identity_boundary_detection(client: TestClient, db_session):
    """3. Identity boundary detection via resource ownership / victim identity."""
    setup = create_base_test_setup(client, db_session, proj_name="Identity Boundary Project")
    proj = setup["project"]
    attacker = setup["identity"]
    ep = setup["endpoint"]
    res = setup["resource"]

    # Victim identity who owns resource instance 999
    victim = Identity(
        project_id=proj.id,
        name="VictimUser",
        auth_type="bearer",
    )
    db_session.add(victim)
    db_session.commit()

    ownership = ResourceOwnership(
        resource_id=res.id,
        identity_id=victim.id,
        resource_instance_id="acc-999",
        ownership_type="PRIMARY_OWNER",
    )
    db_session.add(ownership)
    db_session.commit()

    f = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        resource_id=res.id,
        attacker_identity_id=attacker.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Cross-Identity Access to Account",
        description="Attacker accesses Victim resource acc-999",
        remediation="Check user ownership",
    )
    db_session.add(f)
    db_session.commit()

    engine = ImpactEngine(db_session)
    result = engine.run_impact_analysis(proj.id)

    impact = result["impacts"][0]
    assert impact.identity_boundary_crossed is True
    assert impact.cross_identity_impact is True
    assert impact.terminal_impact == "CROSS_IDENTITY_ACCESS"


def test_resource_boundary_detection(client: TestClient, db_session):
    """4. Resource boundary detection."""
    setup = create_base_test_setup(client, db_session, proj_name="Resource Boundary Project")
    proj = setup["project"]
    ident = setup["identity"]
    ep = setup["endpoint"]
    res = setup["resource"]

    f = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        resource_id=res.id,
        attacker_identity_id=ident.id,
        type="BFLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="BFLA on Admin Action",
        description="Unprivileged role performed admin operation",
        remediation="Restrict role permissions",
    )
    db_session.add(f)
    db_session.commit()

    engine = ImpactEngine(db_session)
    eval_res = engine.evaluate_finding_impact(f)

    assert eval_res["resource_boundary_crossed"] is True
    assert eval_res["authorization_boundary_crossed"] is True


def test_workflow_boundary_detection(client: TestClient, db_session):
    """5. Workflow boundary detection."""
    setup = create_base_test_setup(client, db_session, proj_name="Workflow Boundary Project")
    proj = setup["project"]
    ident = setup["identity"]
    ep = setup["endpoint"]

    wf = Workflow(
        project_id=proj.id,
        name="Checkout Flow",
        description="Order checkout process",
        status="ACTIVE",
    )
    db_session.add(wf)
    db_session.commit()

    f = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        workflow_id=wf.id,
        attacker_identity_id=ident.id,
        type="INVALID_STATE_TRANSITION",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Invalid State Transition in Checkout",
        description="Payment step skipped directly to fulfillment",
        remediation="Enforce server-side workflow state validation",
    )
    db_session.add(f)
    db_session.commit()

    engine = ImpactEngine(db_session)
    eval_res = engine.evaluate_finding_impact(f)

    assert eval_res["workflow_boundary_crossed"] is True
    assert eval_res["terminal_impact"] == "PRIVILEGED_WORKFLOW_ACCESS"


def test_property_boundary_detection(client: TestClient, db_session):
    """6. Property boundary detection."""
    setup = create_base_test_setup(client, db_session, proj_name="Property Boundary Project")
    proj = setup["project"]
    ident = setup["identity"]
    ep = setup["endpoint"]
    res = setup["resource"]

    f = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        resource_id=res.id,
        attacker_identity_id=ident.id,
        type="PROPERTY_EXPOSURE",
        severity="MEDIUM",
        confidence="HIGH",
        status="OPEN",
        title="Exposed Internal Field",
        description="Internal account metadata exposed",
        exposed_properties=json.dumps(["internal_code"]),
        remediation="Filter response properties",
    )
    db_session.add(f)
    db_session.commit()

    engine = ImpactEngine(db_session)
    eval_res = engine.evaluate_finding_impact(f)

    assert eval_res["property_boundary_crossed"] is True


def test_sensitive_property_detection(client: TestClient, db_session):
    """7. Sensitive property detection (PII)."""
    setup = create_base_test_setup(client, db_session, proj_name="Sensitive Property Project")
    proj = setup["project"]
    ident = setup["identity"]
    ep = setup["endpoint"]
    res = setup["resource"]

    prop = ResourceProperty(
        resource_id=res.id,
        name="ssn",
        sensitivity="SENSITIVE",
        data_type="string",
    )
    db_session.add(prop)
    db_session.commit()

    f = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        resource_id=res.id,
        attacker_identity_id=ident.id,
        type="PROPERTY_EXPOSURE",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="PII Data Exposed",
        description="Customer SSN returned in response",
        exposed_properties=json.dumps(["ssn"]),
        remediation="Remove SSN from public serializer",
    )
    db_session.add(f)
    db_session.commit()

    engine = ImpactEngine(db_session)
    eval_res = engine.evaluate_finding_impact(f)

    assert eval_res["property_boundary_crossed"] is True
    assert eval_res["sensitive_data_reached"] is True
    assert eval_res["terminal_impact"] == "SENSITIVE_PROPERTY_EXPOSURE"
    assert any("ssn" in p for p in eval_res["sensitive_properties_reached"])


def test_secret_property_detection(client: TestClient, db_session):
    """8. Secret property detection (SECRET)."""
    setup = create_base_test_setup(client, db_session, proj_name="Secret Property Project")
    proj = setup["project"]
    ident = setup["identity"]
    ep = setup["endpoint"]
    res = setup["resource"]

    prop = ResourceProperty(
        resource_id=res.id,
        name="api_secret_key",
        sensitivity="SECRET",
        data_type="string",
    )
    db_session.add(prop)
    db_session.commit()

    f = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        resource_id=res.id,
        attacker_identity_id=ident.id,
        type="PROPERTY_EXPOSURE",
        severity="CRITICAL",
        confidence="HIGH",
        status="OPEN",
        title="Secret API Key Exposed",
        description="Private API secret key returned in JSON",
        exposed_properties=json.dumps(["api_secret_key"]),
        remediation="Never expose secret credentials",
    )
    db_session.add(f)
    db_session.commit()

    engine = ImpactEngine(db_session)
    eval_res = engine.evaluate_finding_impact(f)

    assert eval_res["property_boundary_crossed"] is True
    assert eval_res["sensitive_data_reached"] is True
    assert eval_res["terminal_impact"] == "SENSITIVE_PROPERTY_EXPOSURE"
    assert any("api_secret_key (SECRET)" in p for p in eval_res["sensitive_properties_reached"])


def test_cross_identity_impact(client: TestClient, db_session):
    """9. Cross-identity impact detection in attack path."""
    setup = create_base_test_setup(client, db_session, proj_name="Cross Identity Path Project")
    proj = setup["project"]
    ident1 = setup["identity"]
    ep = setup["endpoint"]

    ident2 = Identity(
        project_id=proj.id,
        name="SecondUser",
        auth_type="bearer",
    )
    db_session.add(ident2)
    db_session.commit()

    f1 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident1.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="BOLA Finding",
        description="First finding",
        remediation="Check user access",
    )
    f2 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident2.id,
        type="INVALID_STATE_TRANSITION",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="State finding",
        description="Second finding with different identity",
        remediation="Check workflow identity binding",
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    engine = ImpactEngine(db_session)
    eval_res = engine.evaluate_findings_impact([f1, f2], is_path=True)

    assert eval_res["cross_identity_impact"] is True
    assert eval_res["identity_boundary_crossed"] is True
    assert len(eval_res["identities_involved"]) == 2


def test_cross_resource_impact(client: TestClient, db_session):
    """10. Cross-resource impact detection when multiple resources are traversed."""
    setup = create_base_test_setup(client, db_session, proj_name="Cross Resource Project")
    proj = setup["project"]
    api = setup["api"]
    res1 = setup["resource"]
    ident = setup["identity"]
    ep1 = setup["endpoint"]

    res2 = Resource(
        project_id=proj.id,
        api_id=api.id,
        name="OrderResource",
        resource_type="entity",
    )
    db_session.add(res2)
    db_session.commit()

    ep2 = Endpoint(
        api_id=api.id,
        resource_id=res2.id,
        method="GET",
        path=f"/api/orders-{proj.id}/{{order_id}}",
        summary="Lookup Order",
    )
    db_session.add(ep2)
    db_session.commit()

    f1 = Finding(
        project_id=proj.id,
        endpoint_id=ep1.id,
        resource_id=res1.id,
        attacker_identity_id=ident.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="BOLA on Accounts",
        description="Access account",
        remediation="Check object permissions",
    )
    f2 = Finding(
        project_id=proj.id,
        endpoint_id=ep2.id,
        resource_id=res2.id,
        attacker_identity_id=ident.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="BOLA on Orders",
        description="Access order",
        remediation="Check object permissions",
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    engine = ImpactEngine(db_session)
    eval_res = engine.evaluate_findings_impact([f1, f2], is_path=True)

    assert eval_res["cross_resource_impact"] is True
    assert len(eval_res["resources_involved"]) == 2


def test_terminal_impact_selection(client: TestClient, db_session):
    """11. Deterministic terminal impact mapping rules."""
    setup = create_base_test_setup(client, db_session, proj_name="Terminal Impact Project")
    proj = setup["project"]
    ident = setup["identity"]
    ep = setup["endpoint"]
    res = setup["resource"]

    engine = ImpactEngine(db_session)

    # 1. Pure Resource Access
    f_res = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        resource_id=res.id,
        attacker_identity_id=ident.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Simple BOLA",
        description="Access resource",
        remediation="Check resource access",
    )
    eval_res = engine.evaluate_finding_impact(f_res)
    assert eval_res["terminal_impact"] == "RESOURCE_ACCESS"

    # 2. Privileged Workflow Access
    wf = Workflow(project_id=proj.id, name="Admin WF", status="ACTIVE")
    db_session.add(wf)
    db_session.commit()

    f_wf = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        workflow_id=wf.id,
        attacker_identity_id=ident.id,
        type="STEP_SKIP",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Workflow Skip",
        description="Skip step",
        remediation="Enforce step completion",
    )
    eval_res = engine.evaluate_finding_impact(f_wf)
    assert eval_res["terminal_impact"] == "PRIVILEGED_WORKFLOW_ACCESS"


def test_multi_boundary_paths(client: TestClient, db_session):
    """12. Multi-boundary attack path resulting in MULTI_BOUNDARY_ACCESS."""
    setup = create_base_test_setup(client, db_session, proj_name="Multi Boundary Project")
    proj = setup["project"]
    ident = setup["identity"]
    ep = setup["endpoint"]
    res = setup["resource"]

    # Add sensitive property
    prop = ResourceProperty(
        resource_id=res.id,
        name="credit_card",
        sensitivity="SENSITIVE",
        data_type="string",
    )
    db_session.add(prop)

    # Add workflow
    wf = Workflow(project_id=proj.id, name="Transfer WF", status="ACTIVE")
    db_session.add(wf)
    db_session.commit()

    # Finding 1: Workflow transition
    f1 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        workflow_id=wf.id,
        attacker_identity_id=ident.id,
        type="INVALID_STATE_TRANSITION",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="State Transition",
        description="Invalid state transition",
        remediation="Validate workflow transitions",
    )
    # Finding 2: Sensitive property exposure
    f2 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        resource_id=res.id,
        attacker_identity_id=ident.id,
        type="PROPERTY_EXPOSURE",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="CC Exposed",
        description="Credit card revealed",
        exposed_properties=json.dumps(["credit_card"]),
        remediation="Mask card numbers",
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    engine = ImpactEngine(db_session)
    eval_res = engine.evaluate_findings_impact([f1, f2], is_path=True)

    assert eval_res["workflow_boundary_crossed"] is True
    assert eval_res["property_boundary_crossed"] is True
    assert eval_res["sensitive_data_reached"] is True
    assert eval_res["terminal_impact"] == "MULTI_BOUNDARY_ACCESS"


def test_unrelated_findings(client: TestClient, db_session):
    """13. Unrelated or non-violating findings result in terminal impact NONE."""
    setup = create_base_test_setup(client, db_session, proj_name="No Impact Project")
    proj = setup["project"]

    engine = ImpactEngine(db_session)
    result = engine.run_impact_analysis(proj.id)

    assert result["impacts_count"] == 0


def test_inconclusive_findings_excluded(client: TestClient, db_session):
    """14. INCONCLUSIVE findings are strictly excluded from impact analysis."""
    setup = create_base_test_setup(client, db_session, proj_name="Inconclusive Project")
    proj = setup["project"]
    ident = setup["identity"]
    ep = setup["endpoint"]
    res = setup["resource"]

    f = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        resource_id=res.id,
        attacker_identity_id=ident.id,
        type="BOLA",
        severity="HIGH",
        confidence="LOW",
        status="INCONCLUSIVE",
        title="Inconclusive BOLA",
        description="Could not confirm access",
        remediation="Verify manually",
    )
    db_session.add(f)
    db_session.commit()

    engine = ImpactEngine(db_session)
    assert engine.is_confirmed(f) is False

    result = engine.run_impact_analysis(proj.id)
    assert result["impacts_count"] == 0


def test_error_findings_excluded(client: TestClient, db_session):
    """15. ERROR findings are strictly excluded from impact analysis."""
    setup = create_base_test_setup(client, db_session, proj_name="Error Finding Project")
    proj = setup["project"]
    ident = setup["identity"]
    ep = setup["endpoint"]
    res = setup["resource"]

    f = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        resource_id=res.id,
        attacker_identity_id=ident.id,
        type="BOLA",
        severity="HIGH",
        confidence="LOW",
        status="ERROR",
        title="Failed Test Execution",
        description="Test execution errored",
        remediation="Check server logs",
    )
    db_session.add(f)
    db_session.commit()

    engine = ImpactEngine(db_session)
    assert engine.is_confirmed(f) is False

    result = engine.run_impact_analysis(proj.id)
    assert result["impacts_count"] == 0


def test_cross_project_isolation(client: TestClient, db_session):
    """16. Impact analysis isolates findings and paths strictly within project boundary."""
    setup_a = create_base_test_setup(client, db_session, proj_name="Project Alpha")
    setup_b = create_base_test_setup(client, db_session, proj_name="Project Beta")

    proj_a = setup_a["project"]
    proj_b = setup_b["project"]

    f_a = Finding(
        project_id=proj_a.id,
        endpoint_id=setup_a["endpoint"].id,
        resource_id=setup_a["resource"].id,
        attacker_identity_id=setup_a["identity"].id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Project A BOLA",
        description="BOLA in Alpha",
        remediation="Fix in Alpha",
    )
    db_session.add(f_a)
    db_session.commit()

    engine = ImpactEngine(db_session)
    res_b = engine.run_impact_analysis(proj_b.id)
    assert res_b["impacts_count"] == 0

    res_a = engine.run_impact_analysis(proj_a.id)
    assert res_a["impacts_count"] == 1
    assert res_a["impacts"][0].project_id == proj_a.id


def test_deterministic_rebuild(client: TestClient, db_session):
    """17. Deterministic rebuild recalculates impact when underlying status changes."""
    setup = create_base_test_setup(client, db_session, proj_name="Rebuild Project")
    proj = setup["project"]
    ident = setup["identity"]
    ep = setup["endpoint"]
    res = setup["resource"]

    f = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        resource_id=res.id,
        attacker_identity_id=ident.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="BOLA Finding",
        description="Active BOLA",
        remediation="Fix BOLA",
    )
    db_session.add(f)
    db_session.commit()

    engine = ImpactEngine(db_session)
    result = engine.run_impact_analysis(proj.id)
    impact = result["impacts"][0]
    assert impact.terminal_impact == "RESOURCE_ACCESS"

    # Now mark the finding as FALSE_POSITIVE (no longer confirmed)
    f.status = "FALSE_POSITIVE"
    db_session.commit()

    rebuilt = engine.rebuild_security_impact(impact.id)
    assert rebuilt.terminal_impact == "NONE"
    assert "no longer confirmed" in rebuilt.explanation.lower()


def test_zero_target_api_execution(client: TestClient, db_session):
    """18. Verify impact analysis executes zero HTTP requests against target APIs."""
    setup = create_base_test_setup(client, db_session, proj_name="Zero Network Project")
    proj = setup["project"]
    ident = setup["identity"]
    ep = setup["endpoint"]
    res = setup["resource"]

    f = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        resource_id=res.id,
        attacker_identity_id=ident.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="BOLA Finding",
        description="Active BOLA",
        remediation="Fix BOLA",
    )
    db_session.add(f)
    db_session.commit()

    with patch("httpx.Client.send") as mock_send, patch("httpx.AsyncClient.send") as mock_async_send:
        engine = ImpactEngine(db_session)
        result = engine.run_impact_analysis(proj.id)
        assert result["impacts_count"] == 1
        impact = result["impacts"][0]
        engine.rebuild_security_impact(impact.id)

        assert mock_send.call_count == 0
        assert mock_async_send.call_count == 0


def test_security_impact_rest_api_endpoints(client: TestClient, db_session):
    """19. REST API endpoints for Stage 8.3 Security Impact Analysis."""
    setup = create_base_test_setup(client, db_session, proj_name="Impact REST API Project")
    proj = setup["project"]
    ident = setup["identity"]
    ep = setup["endpoint"]
    res = setup["resource"]

    f = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        resource_id=res.id,
        attacker_identity_id=ident.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="REST BOLA Finding",
        description="Active BOLA for REST test",
        remediation="Enforce object level authorization",
    )
    db_session.add(f)
    db_session.commit()

    # 1. POST /api/v1/projects/{project_id}/impact-analysis/run
    resp = client.post(f"/api/v1/projects/{proj.id}/impact-analysis/run")
    assert resp.status_code == 200
    data = resp.json()
    assert data["project_id"] == proj.id
    assert data["impacts_count"] == 1
    impact_id = data["impacts"][0]["id"]
    assert data["impacts"][0]["terminal_impact"] == "RESOURCE_ACCESS"
    assert "RESOURCE" in data["impacts"][0]["boundaries_crossed"]
    assert "AUTHORIZATION" in data["impacts"][0]["boundaries_crossed"]

    # 2. GET /api/v1/projects/{project_id}/security-impacts
    resp = client.get(f"/api/v1/projects/{proj.id}/security-impacts")
    assert resp.status_code == 200
    impacts = resp.json()
    assert len(impacts) == 1
    assert impacts[0]["id"] == impact_id

    # 3. GET /api/v1/security-impacts/{impact_id}
    resp = client.get(f"/api/v1/security-impacts/{impact_id}")
    assert resp.status_code == 200
    detail = resp.json()
    assert detail["id"] == impact_id
    assert detail["terminal_impact"] == "RESOURCE_ACCESS"

    # 4. POST /api/v1/security-impacts/{impact_id}/rebuild
    resp = client.post(f"/api/v1/security-impacts/{impact_id}/rebuild")
    assert resp.status_code == 200
    rebuilt = resp.json()
    assert rebuilt["id"] == impact_id
    assert rebuilt["terminal_impact"] == "RESOURCE_ACCESS"
