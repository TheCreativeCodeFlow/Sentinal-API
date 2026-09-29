"""
Stage 9.3: Security Investigation Workspace Tests
Author: SentinelAPI Security Architecture Team

Comprehensive test suite verifying:
- Investigation CRUD operations
- Creation from confirmed finding
- Strict rejection of unconfirmed/inconclusive/error findings
- Automatic context discovery across the full lineage:
  Finding -> Evidence -> Related Findings -> Attack Graph -> Attack Path ->
  Security Impact -> AI Analyses -> AI Hypotheses -> Converted SecurityTests -> Workflow Executions
- Duplicate item prevention and deterministic position ordering
- Project isolation and cross-project rejection
- Timeline construction with verified provenance categories (VERIFIED, DETERMINISTIC, AI, HUMAN, ENGINE)
- Sanitized context with zero credential exposure
- Zero target HTTP execution
"""

import pytest
import uuid
from fastapi.testclient import TestClient
from unittest.mock import patch

from app.models import (
    Project,
    API,
    Endpoint,
    Role,
    Identity,
    Resource,
    SecurityTest,
    TestExecution,
    Finding,
    Evidence,
    Workflow,
    WorkflowStep,
    WorkflowExecution,
    AttackGraph,
    AttackGraphNode,
    AttackPath,
    AttackPathStep,
    SecurityImpact,
    AIAnalysis,
    AIHypothesis,
    AIHypothesisReview,
    FindingCorrelation,
    SecurityInvestigation,
    InvestigationItem,
)
from app.services.security_engine.investigation_service import InvestigationService


def test_investigation_crud(client: TestClient, db_session):
    """Verify standard CRUD lifecycle for an investigation."""
    proj = Project(name=f"Inv-CRUD-{uuid.uuid4().hex[:6]}", authorization_status="authorized")
    db_session.add(proj)
    db_session.commit()

    # 1. Create
    resp = client.post(
        f"/api/v1/projects/{proj.id}/investigations",
        json={"title": "Manual Investigation", "description": "Investigating potential risk"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["title"] == "Manual Investigation"
    assert data["status"] == "OPEN"
    inv_id = data["id"]

    # 2. Get by ID
    get_res = client.get(f"/api/v1/investigations/{inv_id}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == inv_id

    # 3. List
    list_res = client.get(f"/api/v1/projects/{proj.id}/investigations")
    assert list_res.status_code == 200
    assert list_res.json()["count"] >= 1

    # 4. Patch / Resolve
    patch_res = client.patch(
        f"/api/v1/investigations/{inv_id}",
        json={"status": "RESOLVED", "title": "Resolved Investigation"},
    )
    assert patch_res.status_code == 200
    pdata = patch_res.json()
    assert pdata["status"] == "RESOLVED"
    assert pdata["resolved_at"] is not None


def test_create_investigation_from_confirmed_finding(client: TestClient, db_session):
    """Verify creating an investigation from a confirmed finding."""
    proj = Project(name=f"Inv-Finding-{uuid.uuid4().hex[:6]}", authorization_status="authorized")
    db_session.add(proj)
    db_session.commit()

    finding = Finding(
        project_id=proj.id,
        type="BOLA",
        severity="HIGH",
        confidence="HIGH",
        status="CONFIRMED",
        title="BOLA on Orders",
        description="Tenant A accessed Tenant B order",
        remediation="Enforce authorization checks",
    )
    db_session.add(finding)
    db_session.commit()

    resp = client.post(
        f"/api/v1/projects/{proj.id}/investigations/from-finding/{finding.id}"
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["primary_finding_id"] == finding.id
    assert "BOLA on Orders" in data["title"]
    assert data["item_count"] >= 1


def test_create_investigation_rejects_unconfirmed_finding(client: TestClient, db_session):
    """Verify that unconfirmed (OPEN, INCONCLUSIVE, ERROR) findings cannot initiate investigations."""
    proj = Project(name=f"Inv-Reject-{uuid.uuid4().hex[:6]}", authorization_status="authorized")
    db_session.add(proj)
    db_session.commit()

    # OPEN finding (not marked confirmed)
    open_finding = Finding(
        project_id=proj.id,
        type="BOLA",
        severity="HIGH",
        status="OPEN",
        title="Unconfirmed finding",
        description="desc",
        remediation="rem",
    )
    db_session.add(open_finding)

    # INCONCLUSIVE finding
    inconclusive_finding = Finding(
        project_id=proj.id,
        type="BFLA",
        severity="MEDIUM",
        status="INCONCLUSIVE",
        title="Inconclusive test result",
        description="desc",
        remediation="rem",
    )
    db_session.add(inconclusive_finding)
    db_session.commit()

    # Should reject OPEN
    r1 = client.post(f"/api/v1/projects/{proj.id}/investigations/from-finding/{open_finding.id}")
    assert r1.status_code == 400
    assert "CONFIRMED" in r1.json()["detail"]

    # Should reject INCONCLUSIVE
    r2 = client.post(f"/api/v1/projects/{proj.id}/investigations/from-finding/{inconclusive_finding.id}")
    assert r2.status_code == 400
    assert "CONFIRMED" in r2.json()["detail"]


def test_prevent_duplicate_investigation_for_same_finding(client: TestClient, db_session):
    """Verify that creating from finding returns existing investigation rather than duplicate."""
    proj = Project(name=f"Inv-Dedup-{uuid.uuid4().hex[:6]}", authorization_status="authorized")
    db_session.add(proj)
    db_session.commit()

    finding = Finding(
        project_id=proj.id,
        type="BOLA",
        status="CONFIRMED",
        title="Duplicate Test Finding",
        description="desc",
        remediation="rem",
    )
    db_session.add(finding)
    db_session.commit()

    # First call
    r1 = client.post(f"/api/v1/projects/{proj.id}/investigations/from-finding/{finding.id}")
    assert r1.status_code == 201
    id1 = r1.json()["id"]

    # Second call without force_new -> returns existing
    r2 = client.post(f"/api/v1/projects/{proj.id}/investigations/from-finding/{finding.id}")
    assert r2.status_code == 201
    assert r2.json()["id"] == id1


def test_automatic_context_discovery_full_lineage(client: TestClient, db_session):
    """
    Verify complete automatic discovery of:
    Evidence, Related Findings, Attack Graph, Attack Path, Security Impact,
    AI Analyses, AI Hypotheses, Converted SecurityTests, and Workflow Executions.
    """
    proj = Project(name=f"Inv-Lineage-{uuid.uuid4().hex[:6]}", authorization_status="authorized")
    db_session.add(proj)
    db_session.commit()

    # 1. Primary finding + Evidence
    f1 = Finding(
        project_id=proj.id,
        type="AUTH_MISSING",
        status="CONFIRMED",
        title="Unauthenticated Endpoint",
        description="Public access without token",
        remediation="Add auth policy",
    )
    db_session.add(f1)
    db_session.commit()

    ev1 = Evidence(
        finding_id=f1.id,
        expected_behavior="401 Unauthorized",
        actual_behavior="200 OK",
        redacted_request="GET /api/v1/test HTTP/1.1\nHost: example.com",
        redacted_response='{"status": "ok"}',
    )
    db_session.add(ev1)

    # 2. Related finding via FindingCorrelation
    f2 = Finding(
        project_id=proj.id,
        type="BOLA",
        status="CONFIRMED",
        title="BOLA on Invoices",
        description="IDOR allows accessing others invoices",
        remediation="Check ownership",
    )
    db_session.add(f2)
    db_session.commit()

    corr = FindingCorrelation(
        project_id=proj.id,
        finding_a_id=f1.id,
        finding_b_id=f2.id,
        relationship_type="SHARED_ENDPOINT",
        confidence="HIGH",
        reason="Both vulnerabilities exist on the billing service",
    )
    db_session.add(corr)

    # 3. Attack Graph & Node
    graph = AttackGraph(project_id=proj.id, name="Billing Attack Graph")
    db_session.add(graph)
    db_session.commit()

    node = AttackGraphNode(graph_id=graph.id, finding_id=f1.id, node_type="FINDING", label="Unauthenticated Entry")
    db_session.add(node)

    # 4. Attack Path & Step
    path = AttackPath(project_id=proj.id, attack_graph_id=graph.id, name="Unauth to BOLA Chain")
    db_session.add(path)
    db_session.commit()

    step = AttackPathStep(attack_path_id=path.id, finding_id=f1.id, position=1, relationship_type="ENTRY_POINT", reason="First step")
    db_session.add(step)

    # 5. Security Impact
    impact = SecurityImpact(
        project_id=proj.id,
        finding_id=f1.id,
        attack_path_id=path.id,
        terminal_impact="CROSS_IDENTITY_ACCESS",
        explanation="Permits cross-tenant data exfiltration",
    )
    db_session.add(impact)

    # 6. AI Analysis
    analysis = AIAnalysis(
        project_id=proj.id,
        finding_id=f1.id,
        analysis_type="FINDING_EXPLANATION",
        status="COMPLETED",
        model_provider="mock",
        model_name="test-model",
        input_context={"finding": f1.title},
        output={"summary": "Detailed AI narrative"},
    )
    db_session.add(analysis)
    db_session.commit()

    # 7. AI Hypothesis + Converted SecurityTest
    api_obj = API(project_id=proj.id, name="Lineage API", url="https://api.lineage.com")
    db_session.add(api_obj)
    db_session.commit()
    ep_obj = Endpoint(api_id=api_obj.id, method="GET", path=f"/api/v1/lineage-{uuid.uuid4().hex[:4]}")
    db_session.add(ep_obj)
    db_session.commit()
    st = SecurityTest(project_id=proj.id, endpoint_id=ep_obj.id, test_type="BOLA", status="COMPLETED")
    db_session.add(st)
    db_session.commit()

    hypo = AIHypothesis(
        project_id=proj.id,
        ai_analysis_id=analysis.id,
        finding_id=f1.id,
        hypothesis="BOLA test on invoices after unauth access",
        reason="Lateral movement candidate",
        suggested_test_type="BOLA",
        status="CONVERTED",
        security_test_id=st.id,
    )
    db_session.add(hypo)

    # 8. Workflow Execution
    wf = Workflow(project_id=proj.id, name="Billing Workflow")
    db_session.add(wf)
    db_session.commit()

    wf_exec = WorkflowExecution(workflow_id=wf.id, status="COMPLETED", result="FAIL")
    db_session.add(wf_exec)
    db_session.commit()
    f1.workflow_execution_id = wf_exec.id
    db_session.commit()

    # Trigger investigation creation
    res = client.post(f"/api/v1/projects/{proj.id}/investigations/from-finding/{f1.id}")
    assert res.status_code == 201
    inv_id = res.json()["id"]

    # Verify context aggregation
    ctx_res = client.get(f"/api/v1/investigations/{inv_id}/context")
    assert ctx_res.status_code == 200
    ctx = ctx_res.json()

    assert ctx["summary_counts"]["findings"] >= 2  # f1 and f2
    assert ctx["summary_counts"]["evidence"] >= 1
    assert ctx["summary_counts"]["attack_graphs"] >= 1
    assert ctx["summary_counts"]["attack_paths"] >= 1
    assert ctx["summary_counts"]["security_impacts"] >= 1
    assert ctx["summary_counts"]["ai_analyses"] >= 1
    assert ctx["summary_counts"]["ai_hypotheses"] >= 1
    assert ctx["summary_counts"]["security_tests"] >= 1
    assert ctx["summary_counts"]["workflow_executions"] >= 1


def test_duplicate_item_prevention(client: TestClient, db_session):
    """Verify that attaching the same item twice is prevented."""
    proj = Project(name=f"Inv-DupItem-{uuid.uuid4().hex[:6]}", authorization_status="authorized")
    db_session.add(proj)
    db_session.commit()

    inv = SecurityInvestigation(project_id=proj.id, title="Test Inv")
    db_session.add(inv)

    finding = Finding(project_id=proj.id, type="BOLA", status="CONFIRMED", title="Test Finding", description="d", remediation="r")
    db_session.add(finding)
    db_session.commit()

    # First attach
    r1 = client.post(
        f"/api/v1/investigations/{inv.id}/items",
        json={"item_type": "FINDING", "item_id": finding.id},
    )
    assert r1.status_code == 201

    # Second attach should fail
    r2 = client.post(
        f"/api/v1/investigations/{inv.id}/items",
        json={"item_type": "FINDING", "item_id": finding.id},
    )
    assert r2.status_code == 400
    assert "already attached" in r2.json()["detail"]


def test_investigation_ordering(client: TestClient, db_session):
    """Verify sequential, deterministic ordering of investigation items."""
    proj = Project(name=f"Inv-Ordering-{uuid.uuid4().hex[:6]}", authorization_status="authorized")
    db_session.add(proj)
    db_session.commit()

    inv = SecurityInvestigation(project_id=proj.id, title="Order Test Inv")
    db_session.add(inv)

    f1 = Finding(project_id=proj.id, type="BOLA", status="CONFIRMED", title="F1", description="d", remediation="r")
    f2 = Finding(project_id=proj.id, type="BOLA", status="CONFIRMED", title="F2", description="d", remediation="r")
    f3 = Finding(project_id=proj.id, type="BOLA", status="CONFIRMED", title="F3", description="d", remediation="r")
    db_session.add_all([f1, f2, f3])
    db_session.commit()

    client.post(f"/api/v1/investigations/{inv.id}/items", json={"item_type": "FINDING", "item_id": f1.id})
    client.post(f"/api/v1/investigations/{inv.id}/items", json={"item_type": "FINDING", "item_id": f2.id})
    client.post(f"/api/v1/investigations/{inv.id}/items", json={"item_type": "FINDING", "item_id": f3.id})

    inv_res = client.get(f"/api/v1/investigations/{inv.id}")
    items = inv_res.json()["items"]
    assert len(items) == 3
    assert items[0]["position"] == 1
    assert items[1]["position"] == 2
    assert items[2]["position"] == 3


def test_project_isolation_and_cross_project_rejection(client: TestClient, db_session):
    """Verify strict project boundaries and rejection of cross-project references."""
    proj_a = Project(name=f"Inv-ProjA-{uuid.uuid4().hex[:6]}", authorization_status="authorized")
    proj_b = Project(name=f"Inv-ProjB-{uuid.uuid4().hex[:6]}", authorization_status="authorized")
    db_session.add_all([proj_a, proj_b])
    db_session.commit()

    finding_b = Finding(
        project_id=proj_b.id,
        type="BOLA",
        status="CONFIRMED",
        title="Project B Finding",
        description="desc",
        remediation="rem",
    )
    db_session.add(finding_b)
    db_session.commit()

    # Attempt to create investigation in Project A with finding from Project B
    r1 = client.post(
        f"/api/v1/projects/{proj_a.id}/investigations",
        json={"title": "Cross Project Inv", "primary_finding_id": finding_b.id},
    )
    assert r1.status_code == 400

    # Attempt to create from finding across project
    r2 = client.post(
        f"/api/v1/projects/{proj_a.id}/investigations/from-finding/{finding_b.id}"
    )
    assert r2.status_code == 400

    # Attempt to attach item across project
    inv_a = SecurityInvestigation(project_id=proj_a.id, title="Inv A")
    db_session.add(inv_a)
    db_session.commit()

    r3 = client.post(
        f"/api/v1/investigations/{inv_a.id}/items",
        json={"item_type": "FINDING", "item_id": finding_b.id},
    )
    assert r3.status_code == 400


def test_reject_inconclusive_or_error_finding_attachment(client: TestClient, db_session):
    """Verify that INCONCLUSIVE or ERROR findings cannot be attached as verified findings."""
    proj = Project(name=f"Inv-RejectAttach-{uuid.uuid4().hex[:6]}", authorization_status="authorized")
    db_session.add(proj)
    db_session.commit()

    inv = SecurityInvestigation(project_id=proj.id, title="Inv Valid Only")
    db_session.add(inv)

    err_finding = Finding(
        project_id=proj.id,
        type="BOLA",
        status="ERROR",
        title="Execution Error Finding",
        description="desc",
        remediation="rem",
    )
    db_session.add(err_finding)
    db_session.commit()

    res = client.post(
        f"/api/v1/investigations/{inv.id}/items",
        json={"item_type": "FINDING", "item_id": err_finding.id},
    )
    assert res.status_code == 400
    assert "ERROR" in res.json()["detail"]


def test_timeline_construction_and_provenance(client: TestClient, db_session):
    """
    Verify chronological timeline construction with strictly labeled provenance categories:
    VERIFIED, DETERMINISTIC, AI, HUMAN, ENGINE.
    """
    proj = Project(name=f"Inv-Timeline-{uuid.uuid4().hex[:6]}", authorization_status="authorized")
    db_session.add(proj)
    db_session.commit()

    finding = Finding(
        project_id=proj.id,
        type="BOLA",
        status="CONFIRMED",
        title="Verified Finding",
        description="desc",
        remediation="rem",
    )
    db_session.add(finding)
    db_session.commit()

    ev = Evidence(
        finding_id=finding.id,
        expected_behavior="401",
        actual_behavior="200",
    )
    db_session.add(ev)
    db_session.commit()

    graph = AttackGraph(project_id=proj.id, name="Test Graph")
    db_session.add(graph)
    db_session.commit()

    path = AttackPath(project_id=proj.id, attack_graph_id=graph.id, name="Test Path")
    db_session.add(path)
    db_session.commit()

    analysis = AIAnalysis(
        project_id=proj.id,
        finding_id=finding.id,
        analysis_type="FINDING_EXPLANATION",
        status="COMPLETED",
        model_provider="mock",
        model_name="test",
        input_context={},
    )
    db_session.add(analysis)
    db_session.commit()

    hypo = AIHypothesis(
        project_id=proj.id,
        ai_analysis_id=analysis.id,
        finding_id=finding.id,
        hypothesis="Hypothesis test",
        reason="Deduction",
        suggested_test_type="BOLA",
        status="APPROVED",
    )
    db_session.add(hypo)
    db_session.commit()

    review = AIHypothesisReview(
        hypothesis_id=hypo.id,
        action="APPROVED",
        reviewer_reference="sec_alice",
        reason="Validated hypothesis",
    )
    db_session.add(review)

    api_obj2 = API(project_id=proj.id, name="Timeline API", url="https://api.timeline.com")
    db_session.add(api_obj2)
    db_session.commit()
    ep_obj2 = Endpoint(api_id=api_obj2.id, method="GET", path=f"/api/v1/timeline-{uuid.uuid4().hex[:4]}")
    db_session.add(ep_obj2)
    db_session.commit()
    st = SecurityTest(project_id=proj.id, endpoint_id=ep_obj2.id, test_type="BOLA", status="COMPLETED")
    db_session.add(st)
    db_session.commit()

    texec = TestExecution(
        security_test_id=st.id,
        status="COMPLETED",
        result="FAIL",
    )
    db_session.add(texec)
    db_session.commit()

    # Create investigation
    inv = SecurityInvestigation(project_id=proj.id, title="Timeline Inv", primary_finding_id=finding.id)
    db_session.add(inv)
    db_session.commit()

    service = InvestigationService(db=db_session)
    service.attach_item(inv.id, "FINDING", finding.id)
    service.attach_item(inv.id, "EVIDENCE", ev.id)
    service.attach_item(inv.id, "ATTACK_GRAPH", graph.id)
    service.attach_item(inv.id, "ATTACK_PATH", path.id)
    service.attach_item(inv.id, "AI_ANALYSIS", analysis.id)
    service.attach_item(inv.id, "AI_HYPOTHESIS", hypo.id)
    service.attach_item(inv.id, "SECURITY_TEST", st.id)

    # Fetch timeline
    t_res = client.get(f"/api/v1/investigations/{inv.id}/timeline")
    assert t_res.status_code == 200
    events = t_res.json()["events"]
    assert len(events) >= 5

    categories = {e["category"] for e in events}
    # Verify presence of the core architectural source classifications
    assert "VERIFIED" in categories
    assert "DETERMINISTIC" in categories
    assert "AI" in categories
    assert "HUMAN" in categories
    assert "ENGINE" in categories


def test_create_from_attack_path(client: TestClient, db_session):
    """Verify creating an investigation centered on an attack path."""
    proj = Project(name=f"Inv-FromPath-{uuid.uuid4().hex[:6]}", authorization_status="authorized")
    db_session.add(proj)
    db_session.commit()

    graph = AttackGraph(project_id=proj.id, name="Path Centered Graph")
    db_session.add(graph)
    db_session.commit()

    path = AttackPath(project_id=proj.id, attack_graph_id=graph.id, name="Multi-step Auth Breach")
    db_session.add(path)
    db_session.commit()

    f = Finding(project_id=proj.id, type="BFLA", status="CONFIRMED", title="Admin Access", description="d", remediation="r")
    db_session.add(f)
    db_session.commit()

    step = AttackPathStep(attack_path_id=path.id, finding_id=f.id, position=1, relationship_type="INITIAL_ACCESS", reason="Step 1")
    db_session.add(step)
    db_session.commit()

    res = client.post(f"/api/v1/projects/{proj.id}/investigations/from-path/{path.id}")
    assert res.status_code == 201
    data = res.json()
    assert data["primary_attack_path_id"] == path.id
    assert "Multi-step Auth Breach" in data["title"]


def test_sanitized_investigation_context_no_leakage(client: TestClient, db_session):
    """Verify that investigation context strictly redacts sensitive headers and tokens."""
    proj = Project(name=f"Inv-Sanitize-{uuid.uuid4().hex[:6]}", authorization_status="authorized")
    db_session.add(proj)
    db_session.commit()

    finding = Finding(
        project_id=proj.id,
        type="BOLA",
        status="CONFIRMED",
        title="Sanitized Finding",
        description="Leaked Bearer SUPER_SECRET_TOKEN_XYZ123 in url",
        remediation="Sanitize output",
    )
    db_session.add(finding)
    db_session.commit()

    ev = Evidence(
        finding_id=finding.id,
        expected_behavior="401",
        actual_behavior="200",
        request_metadata='{"headers": {"Authorization": "Bearer RAW_TOKEN_ABCD", "Host": "example.com"}}',
        response_metadata='{"headers": {"Set-Cookie": "session_id=SECRET123"}}',
        redacted_request="GET /orders?token=RAW_TOKEN_ABCD HTTP/1.1",
        redacted_response='{"key": "RAW_KEY_SECRET"}',
    )
    db_session.add(ev)
    db_session.commit()

    res = client.post(f"/api/v1/projects/{proj.id}/investigations/from-finding/{finding.id}")
    inv_id = res.json()["id"]

    ctx_res = client.get(f"/api/v1/investigations/{inv_id}/context")
    assert ctx_res.status_code == 200
    ctx_str = ctx_res.text

    assert "RAW_TOKEN_ABCD" not in ctx_str
    assert "SECRET123" not in ctx_str
    assert "[REDACTED]" in ctx_str


def test_no_target_http_execution(client: TestClient, db_session):
    """Verify that investigation operations never issue target HTTP requests."""
    proj = Project(name=f"Inv-NoTraffic-{uuid.uuid4().hex[:6]}", authorization_status="authorized")
    db_session.add(proj)
    db_session.commit()

    finding = Finding(project_id=proj.id, type="BOLA", status="CONFIRMED", title="Test", description="d", remediation="r")
    db_session.add(finding)
    db_session.commit()

    with patch("app.services.security_engine.client.AsyncSecurityHttpClient.execute") as mock_exec, \
         patch("httpx.AsyncClient.request") as mock_httpx_async, \
         patch("urllib.request.urlopen") as mock_urllib:
        # Create
        c_res = client.post(f"/api/v1/projects/{proj.id}/investigations/from-finding/{finding.id}")
        assert c_res.status_code == 201
        inv_id = c_res.json()["id"]

        # Timeline
        client.get(f"/api/v1/investigations/{inv_id}/timeline")

        # Context
        client.get(f"/api/v1/investigations/{inv_id}/context")

        # Patch
        client.patch(f"/api/v1/investigations/{inv_id}", json={"status": "RESOLVED"})

        assert mock_exec.call_count == 0
        assert mock_httpx_async.call_count == 0
        assert mock_urllib.call_count == 0
