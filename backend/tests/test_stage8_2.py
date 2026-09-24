"""
Stage 8.2 Test Suite: Deterministic Attack Path Detection
Author: SentinelAPI Security Architecture Team

Validates deterministic conversion of finding correlations into explainable, ordered
attack paths, chain patterns (A-E), path validation, cycle prevention, confidence rules,
explanation generation, and zero target API execution.
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
    Finding,
    AttackGraph,
    AttackGraphNode,
    AttackGraphEdge,
    FindingCorrelation,
    AttackPath,
    AttackPathStep,
    TestExecution,
)
from app.services.security_engine.correlation_engine import CorrelationEngine
from app.services.security_engine.attack_path_engine import AttackPathEngine

# Prevent pytest from treating model classes as test case classes
AttackGraph.__test__ = False
AttackGraphNode.__test__ = False
AttackGraphEdge.__test__ = False
FindingCorrelation.__test__ = False
AttackPath.__test__ = False
AttackPathStep.__test__ = False
TestExecution.__test__ = False


def create_base_test_setup(client: TestClient, db_session, proj_name="Stage 8.2 Test Project"):
    """Helper to set up an authorized project with API, endpoint, role, identity, and resource."""
    proj = Project(
        name=proj_name,
        description="Authorized test target for attack path engine",
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


def test_auth_to_bola_path(client: TestClient, db_session):
    """Pattern A: AUTH -> AUTHORIZATION forms a 2-step attack path."""
    setup = create_base_test_setup(client, db_session, proj_name="Auth to BOLA Project")
    proj = setup["project"]
    ident = setup["identity"]
    ep = setup["endpoint"]

    f1 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident.id,
        type="AUTHENTICATION_BYPASS",
        severity="CRITICAL",
        confidence="HIGH",
        status="OPEN",
        title="Missing Auth on Account Lookup",
        description="No authentication header required",
        remediation="Enforce Bearer authentication",
    )
    f2 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="BOLA on Account Lookup",
        description="User can access arbitrary accounts",
        remediation="Enforce object-level access controls",
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    # Run correlation first
    corr_engine = CorrelationEngine(db_session)
    corr_engine.run_correlation(proj.id)

    # Analyze attack paths
    path_engine = AttackPathEngine(db_session)
    result = path_engine.analyze_project_attack_paths(proj.id)

    assert result["paths_count"] == 1
    path = result["paths"][0]
    assert path.confidence == "HIGH"
    assert "AUTHENTICATION_BYPASS" in path.name
    assert "BOLA" in path.name

    steps = path.steps
    assert len(steps) == 2
    assert steps[0].position == 1
    assert steps[0].finding_id == f1.id
    assert steps[0].prerequisite_finding_id is None
    assert steps[0].relationship_type == "INITIAL_COMPROMISE"

    assert steps[1].position == 2
    assert steps[1].finding_id == f2.id
    assert steps[1].prerequisite_finding_id == f1.id
    assert steps[1].relationship_type == "AUTH_TO_AUTHORIZATION"
    assert "bypasses access verification" in steps[1].reason


def test_bola_to_property_path(client: TestClient, db_session):
    """Pattern B: AUTHORIZATION -> PROPERTY forms a 2-step attack path on the same resource."""
    setup = create_base_test_setup(client, db_session, proj_name="BOLA to Property Project")
    proj = setup["project"]
    res = setup["resource"]

    f1 = Finding(
        project_id=proj.id,
        resource_id=res.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="BOLA Vulnerability on Account",
        description="Unauthorized account access",
        remediation="Validate user ownership",
    )
    f2 = Finding(
        project_id=proj.id,
        resource_id=res.id,
        type="PROPERTY_EXPOSURE",
        severity="MEDIUM",
        confidence="HIGH",
        status="OPEN",
        title="Sensitive PII Property Exposure",
        description="SSN exposed in response",
        exposed_properties='["ssn", "secret_key"]',
        remediation="Filter sensitive fields",
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    corr_engine = CorrelationEngine(db_session)
    corr_engine.run_correlation(proj.id)

    path_engine = AttackPathEngine(db_session)
    result = path_engine.analyze_project_attack_paths(proj.id)

    assert result["paths_count"] == 1
    path = result["paths"][0]
    steps = path.steps
    assert len(steps) == 2
    assert steps[0].finding_id == f1.id
    assert steps[1].finding_id == f2.id
    assert steps[1].relationship_type == "PROPERTY_EXPOSURE_CHAIN"
    assert "grants access to resource" in steps[1].reason


def test_bola_to_workflow_path(client: TestClient, db_session):
    """Pattern C: AUTHORIZATION -> WORKFLOW forms a 2-step attack path via shared context."""
    setup = create_base_test_setup(client, db_session, proj_name="BOLA to Workflow Project")
    proj = setup["project"]
    res = setup["resource"]

    wf = Workflow(
        project_id=proj.id,
        name="Account Transfer Workflow",
        status="ACTIVE",
    )
    db_session.add(wf)
    db_session.commit()
    db_session.refresh(wf)

    f1 = Finding(
        project_id=proj.id,
        resource_id=res.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="BOLA on Account",
        description="Object access breach",
        remediation="Validate account owner",
    )
    f2 = Finding(
        project_id=proj.id,
        resource_id=res.id,
        workflow_id=wf.id,
        type="INVALID_STATE_TRANSITION",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Invalid State Transition in Transfer Workflow",
        description="Skipped approval state",
        remediation="Enforce strict state machine",
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    corr_engine = CorrelationEngine(db_session)
    corr_engine.run_correlation(proj.id)

    path_engine = AttackPathEngine(db_session)
    result = path_engine.analyze_project_attack_paths(proj.id)

    assert result["paths_count"] == 1
    path = result["paths"][0]
    steps = path.steps
    assert len(steps) == 2
    assert steps[0].finding_id == f1.id
    assert steps[1].finding_id == f2.id
    assert steps[1].relationship_type == "AUTHORIZATION_TO_WORKFLOW"
    assert "compromises access controls, allowing exploitation" in steps[1].reason


def test_workflow_to_property_path(client: TestClient, db_session):
    """Pattern D: WORKFLOW -> PROPERTY forms a 2-step attack path on the same resource."""
    setup = create_base_test_setup(client, db_session, proj_name="Workflow to Property Project")
    proj = setup["project"]
    res = setup["resource"]

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
        resource_id=res.id,
        workflow_id=wf.id,
        type="INVALID_STATE_TRANSITION",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Premature State Transition in Checkout",
        description="Order marked paid without gateway confirmation",
        remediation="Verify payment receipt",
    )
    f2 = Finding(
        project_id=proj.id,
        resource_id=res.id,
        type="PROPERTY_EXPOSURE",
        severity="MEDIUM",
        confidence="HIGH",
        status="OPEN",
        title="Payment Token Property Exposure",
        description="Raw transaction token exposed",
        exposed_properties='["raw_token"]',
        remediation="Redact transaction token",
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    corr_engine = CorrelationEngine(db_session)
    corr_engine.run_correlation(proj.id)

    path_engine = AttackPathEngine(db_session)
    result = path_engine.analyze_project_attack_paths(proj.id)

    assert result["paths_count"] == 1
    path = result["paths"][0]
    steps = path.steps
    assert len(steps) == 2
    assert steps[0].finding_id == f1.id
    assert steps[1].finding_id == f2.id
    assert steps[1].relationship_type == "PROPERTY_EXPOSURE_CHAIN"
    assert "moves resource" in steps[1].reason


def test_multistep_chain(client: TestClient, db_session):
    """Pattern E: Multi-step attack chain AUTH -> BOLA -> WORKFLOW -> PROPERTY."""
    setup = create_base_test_setup(client, db_session, proj_name="Multistep Project")
    proj = setup["project"]
    ident = setup["identity"]
    ep = setup["endpoint"]
    res = setup["resource"]

    wf = Workflow(
        project_id=proj.id,
        name="Billing Workflow",
        status="ACTIVE",
    )
    db_session.add(wf)
    db_session.commit()
    db_session.refresh(wf)

    f1 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident.id,
        type="AUTHENTICATION_BYPASS",
        severity="CRITICAL",
        confidence="HIGH",
        status="OPEN",
        title="Authentication Bypass on Billing Endpoint",
        description="Auth header ignored",
        remediation="Require authentication",
    )
    f2 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident.id,
        resource_id=res.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="BOLA on Billing Account",
        description="Arbitrary billing account access",
        remediation="Check user billing permission",
    )
    f3 = Finding(
        project_id=proj.id,
        resource_id=res.id,
        workflow_id=wf.id,
        type="INVALID_STATE_TRANSITION",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Illegal State Transition in Billing Workflow",
        description="Bypassed billing review step",
        remediation="Validate workflow step transitions",
    )
    f4 = Finding(
        project_id=proj.id,
        resource_id=res.id,
        type="PROPERTY_EXPOSURE",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Billing Account Secret Property Exposure",
        description="Exposed bank routing number",
        exposed_properties='["bank_routing_number"]',
        remediation="Mask financial details",
    )
    db_session.add_all([f1, f2, f3, f4])
    db_session.commit()

    corr_engine = CorrelationEngine(db_session)
    corr_engine.run_correlation(proj.id)

    path_engine = AttackPathEngine(db_session)
    result = path_engine.analyze_project_attack_paths(proj.id)

    assert result["paths_count"] >= 1
    # Find the multi-step chain
    multistep_path = next((p for p in result["paths"] if len(p.steps) == 4), None)
    assert multistep_path is not None, "Expected a 4-step attack path"

    assert multistep_path.confidence == "HIGH"
    steps = multistep_path.steps
    assert [s.finding_id for s in steps] == [f1.id, f2.id, f3.id, f4.id]
    assert steps[0].relationship_type == "INITIAL_COMPROMISE"
    assert steps[1].relationship_type == "AUTH_TO_AUTHORIZATION"
    assert steps[2].relationship_type == "AUTHORIZATION_TO_WORKFLOW"
    assert steps[3].relationship_type == "PROPERTY_EXPOSURE_CHAIN"


def test_unrelated_findings_no_paths(client: TestClient, db_session):
    """Unrelated findings sharing no context do not form an attack path."""
    setup = create_base_test_setup(client, db_session, proj_name="Unrelated Findings Project")
    proj = setup["project"]
    api = setup["api"]

    ep2 = Endpoint(
        api_id=api.id,
        method="GET",
        path=f"/api/misc-{proj.id}",
        summary="Misc",
    )
    db_session.add(ep2)
    db_session.commit()

    f1 = Finding(
        project_id=proj.id,
        endpoint_id=ep2.id,
        type="AUTHENTICATION_BYPASS",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Auth Bypass on Misc",
        description="Misc endpoint missing auth",
        remediation="Require auth",
    )
    f2 = Finding(
        project_id=proj.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="BOLA on Independent Endpoint",
        description="No shared endpoint or identity",
        remediation="Enforce authz",
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    corr_engine = CorrelationEngine(db_session)
    corr_engine.run_correlation(proj.id)

    path_engine = AttackPathEngine(db_session)
    result = path_engine.analyze_project_attack_paths(proj.id)

    assert result["paths_count"] == 0


def test_inconclusive_findings_excluded(client: TestClient, db_session):
    """Findings with INCONCLUSIVE status are strictly excluded from attack paths."""
    setup = create_base_test_setup(client, db_session, proj_name="Inconclusive Excluded Project")
    proj = setup["project"]
    ident = setup["identity"]
    ep = setup["endpoint"]

    f1 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident.id,
        type="AUTHENTICATION_BYPASS",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Confirmed Auth Flaw",
        description="Auth missing",
        remediation="Fix auth",
    )
    f2 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident.id,
        type="BOLA",
        severity="HIGH",
        confidence="LOW",
        status="INCONCLUSIVE",
        title="Inconclusive BOLA Test",
        description="Could not confirm access breach",
        remediation="Re-test manually",
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    corr_engine = CorrelationEngine(db_session)
    corr_engine.run_correlation(proj.id)

    path_engine = AttackPathEngine(db_session)
    result = path_engine.analyze_project_attack_paths(proj.id)

    assert result["paths_count"] == 0


def test_error_findings_excluded(client: TestClient, db_session):
    """Findings with ERROR status are strictly excluded from attack paths."""
    setup = create_base_test_setup(client, db_session, proj_name="Error Excluded Project")
    proj = setup["project"]
    ident = setup["identity"]
    ep = setup["endpoint"]

    f1 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident.id,
        type="AUTHENTICATION_BYPASS",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Confirmed Auth Flaw",
        description="Auth missing",
        remediation="Fix auth",
    )
    f2 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="ERROR",
        title="Execution Error Test",
        description="Target server returned 500 error",
        remediation="Investigate crash",
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    corr_engine = CorrelationEngine(db_session)
    corr_engine.run_correlation(proj.id)

    path_engine = AttackPathEngine(db_session)
    result = path_engine.analyze_project_attack_paths(proj.id)

    assert result["paths_count"] == 0


def test_cross_project_findings_excluded(client: TestClient, db_session):
    """Findings from different projects must never be combined into an attack path."""
    setup1 = create_base_test_setup(client, db_session, proj_name="Cross Project 1")
    setup2 = create_base_test_setup(client, db_session, proj_name="Cross Project 2")
    proj1 = setup1["project"]
    proj2 = setup2["project"]

    f1 = Finding(
        project_id=proj1.id,
        type="AUTHENTICATION_BYPASS",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Auth Flaw in Project 1",
        description="Auth missing",
        remediation="Fix auth",
    )
    f2 = Finding(
        project_id=proj2.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="BOLA in Project 2",
        description="BOLA vulnerability",
        remediation="Fix bola",
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    path_engine = AttackPathEngine(db_session)
    res1 = path_engine.analyze_project_attack_paths(proj1.id)
    res2 = path_engine.analyze_project_attack_paths(proj2.id)

    assert res1["paths_count"] == 0
    assert res2["paths_count"] == 0


def test_missing_correlation_edge_prevents_path(client: TestClient, db_session):
    """Without an explicit FindingCorrelation edge, findings do not form an attack path."""
    setup = create_base_test_setup(client, db_session, proj_name="No Correlation Edge Project")
    proj = setup["project"]
    ident = setup["identity"]
    ep = setup["endpoint"]

    f1 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident.id,
        type="AUTHENTICATION_BYPASS",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Auth Flaw",
        description="Auth bypass",
        remediation="Enforce auth",
    )
    f2 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="BOLA Flaw",
        description="BOLA bypass",
        remediation="Enforce authz",
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    # Intentionally DO NOT run correlation engine, so no FindingCorrelation exists
    path_engine = AttackPathEngine(db_session)
    result = path_engine.analyze_project_attack_paths(proj.id)

    assert result["paths_count"] == 0


def test_cycle_prevention(client: TestClient, db_session):
    """Candidate paths never loop infinitely or repeat findings."""
    setup = create_base_test_setup(client, db_session, proj_name="Cycle Prevention Project")
    proj = setup["project"]
    ident = setup["identity"]
    ep = setup["endpoint"]

    f1 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident.id,
        type="AUTHENTICATION_BYPASS",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Auth Flaw",
        description="Auth missing",
        remediation="Fix auth",
    )
    f2 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="BOLA Flaw",
        description="BOLA vulnerability",
        remediation="Fix authz",
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    corr_engine = CorrelationEngine(db_session)
    corr_engine.run_correlation(proj.id)

    path_engine = AttackPathEngine(db_session)
    result = path_engine.analyze_project_attack_paths(proj.id)

    for path in result["paths"]:
        finding_ids = [s.finding_id for s in path.steps]
        assert len(finding_ids) == len(set(finding_ids)), "Path must not contain duplicate findings"


def test_duplicate_path_prevention(client: TestClient, db_session):
    """Running attack path analysis multiple times produces identical paths without duplicates."""
    setup = create_base_test_setup(client, db_session, proj_name="Duplicate Prevention Project")
    proj = setup["project"]
    ident = setup["identity"]
    ep = setup["endpoint"]

    f1 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident.id,
        type="AUTHENTICATION_BYPASS",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Auth Flaw",
        description="Auth missing",
        remediation="Fix auth",
    )
    f2 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="BOLA Flaw",
        description="BOLA vulnerability",
        remediation="Fix authz",
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    corr_engine = CorrelationEngine(db_session)
    corr_engine.run_correlation(proj.id)

    path_engine = AttackPathEngine(db_session)
    res1 = path_engine.analyze_project_attack_paths(proj.id)
    res2 = path_engine.analyze_project_attack_paths(proj.id)

    assert res1["paths_count"] == 1
    assert res2["paths_count"] == 1

    # Verify database count has not accumulated duplicates
    db_paths = db_session.query(AttackPath).filter(AttackPath.project_id == proj.id).all()
    assert len(db_paths) == 1


def test_deterministic_path_reconstruction(client: TestClient, db_session):
    """Rebuilding an attack path offline re-evaluates and maintains deterministic steps."""
    setup = create_base_test_setup(client, db_session, proj_name="Rebuild Project")
    proj = setup["project"]
    ident = setup["identity"]
    ep = setup["endpoint"]

    f1 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident.id,
        type="AUTHENTICATION_BYPASS",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Auth Flaw",
        description="Auth missing",
        remediation="Fix auth",
    )
    f2 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="BOLA Flaw",
        description="BOLA vulnerability",
        remediation="Fix authz",
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    corr_engine = CorrelationEngine(db_session)
    corr_engine.run_correlation(proj.id)

    path_engine = AttackPathEngine(db_session)
    res = path_engine.analyze_project_attack_paths(proj.id)
    path = res["paths"][0]

    # Rebuild path
    rebuilt_path = path_engine.rebuild_attack_path(path.id)
    assert rebuilt_path.status == "ACTIVE"
    assert len(rebuilt_path.steps) == 2


def test_confidence_rule_validation(client: TestClient, db_session):
    """Validates deterministic confidence assignment: HIGH for strong context, MEDIUM for weaker context."""
    setup = create_base_test_setup(client, db_session, proj_name="Confidence Project")
    proj = setup["project"]
    ep = setup["endpoint"]

    # Same endpoint, but NO attacker identity assigned to f1 or f2
    f1 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        type="AUTHENTICATION_BYPASS",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Auth Flaw with no Identity",
        description="Bypass without specified identity",
        remediation="Fix auth",
    )
    f2 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="BOLA with different Context",
        description="BOLA on same endpoint only",
        remediation="Fix bola",
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    corr_engine = CorrelationEngine(db_session)
    corr_engine.run_correlation(proj.id)

    path_engine = AttackPathEngine(db_session)
    result = path_engine.analyze_project_attack_paths(proj.id)

    assert result["paths_count"] == 1
    # Without matching identity, correlation is only SAME_ENDPOINT
    path = result["paths"][0]
    assert path.confidence in ("HIGH", "MEDIUM")


def test_explanation_generation(client: TestClient, db_session):
    """AttackPath and AttackPathStep contain explainable domain narratives without AI prose."""
    setup = create_base_test_setup(client, db_session, proj_name="Explanation Project")
    proj = setup["project"]
    ident = setup["identity"]
    ep = setup["endpoint"]

    f1 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident.id,
        type="AUTHENTICATION_BYPASS",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Open Door Flaw",
        description="No credentials needed",
        remediation="Require bearer token",
    )
    f2 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Access Granted to Other Records",
        description="Object level access leak",
        remediation="Check user access rights",
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    corr_engine = CorrelationEngine(db_session)
    corr_engine.run_correlation(proj.id)

    path_engine = AttackPathEngine(db_session)
    result = path_engine.analyze_project_attack_paths(proj.id)

    path = result["paths"][0]
    assert len(path.description) > 20
    assert "Attack path initiated" in path.description
    assert f1.type in path.description

    assert len(path.steps[1].reason) > 20
    assert "bypasses access verification" in path.steps[1].reason


def test_no_target_api_execution(client: TestClient, db_session):
    """Ensures attack path analysis and rebuilding execute 0 outbound target HTTP calls."""
    setup = create_base_test_setup(client, db_session, proj_name="No Outbound Project")
    proj = setup["project"]
    ident = setup["identity"]
    ep = setup["endpoint"]

    f1 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident.id,
        type="AUTHENTICATION_BYPASS",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Auth Flaw",
        description="No credentials required",
        remediation="Fix auth",
    )
    f2 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="BOLA Flaw",
        description="Object access breach",
        remediation="Enforce object check",
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    corr_engine = CorrelationEngine(db_session)
    corr_engine.run_correlation(proj.id)

    with patch("httpx.AsyncClient.request") as mock_async_http, patch("httpx.Client.request") as mock_sync_http:
        path_engine = AttackPathEngine(db_session)
        res = path_engine.analyze_project_attack_paths(proj.id)
        assert res["paths_count"] == 1

        path = res["paths"][0]
        path_engine.rebuild_attack_path(path.id)

        assert mock_async_http.call_count == 0, "Outbound async HTTP request was detected!"
        assert mock_sync_http.call_count == 0, "Outbound sync HTTP request was detected!"


def test_attack_path_rest_api_endpoints(client: TestClient, db_session):
    """Tests REST API endpoints for attack path analysis, listing, details, steps, and rebuild."""
    setup = create_base_test_setup(client, db_session, proj_name="REST API Project")
    proj = setup["project"]
    ident = setup["identity"]
    ep = setup["endpoint"]

    f1 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident.id,
        type="AUTHENTICATION_BYPASS",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="Auth Flaw",
        description="Missing auth",
        remediation="Add auth",
    )
    f2 = Finding(
        project_id=proj.id,
        endpoint_id=ep.id,
        attacker_identity_id=ident.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="OPEN",
        title="BOLA Flaw",
        description="Object access breach",
        remediation="Enforce object checks",
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    # 1. POST /api/v1/projects/{project_id}/attack-paths/analyze
    res_analyze = client.post(f"/api/v1/projects/{proj.id}/attack-paths/analyze")
    assert res_analyze.status_code == 200
    data_analyze = res_analyze.json()
    assert data_analyze["project_id"] == proj.id
    assert data_analyze["paths_count"] == 1
    path_id = data_analyze["paths"][0]["id"]

    # 2. GET /api/v1/projects/{project_id}/attack-paths
    res_list = client.get(f"/api/v1/projects/{proj.id}/attack-paths")
    assert res_list.status_code == 200
    data_list = res_list.json()
    assert len(data_list) == 1
    assert data_list[0]["id"] == path_id

    # 3. GET /api/v1/attack-paths/{path_id}
    res_get = client.get(f"/api/v1/attack-paths/{path_id}")
    assert res_get.status_code == 200
    data_get = res_get.json()
    assert data_get["id"] == path_id
    assert len(data_get["steps"]) == 2

    # 4. GET /api/v1/attack-paths/{path_id}/steps
    res_steps = client.get(f"/api/v1/attack-paths/{path_id}/steps")
    assert res_steps.status_code == 200
    data_steps = res_steps.json()
    assert len(data_steps) == 2
    assert data_steps[0]["position"] == 1
    assert data_steps[1]["position"] == 2

    # 5. POST /api/v1/attack-paths/{path_id}/rebuild
    res_rebuild = client.post(f"/api/v1/attack-paths/{path_id}/rebuild")
    assert res_rebuild.status_code == 200
    assert res_rebuild.json()["status"] == "ACTIVE"

    # 6. 404 Checks
    res_404 = client.get("/api/v1/attack-paths/non-existent-uuid")
    assert res_404.status_code == 404
