"""
Stage 9.2 Test Suite: Human-Approved AI Security Testing
Author: SentinelAPI Security Architecture Team

Validates:
1. Hypothesis creation and default security attributes (requires_human_review=True, PENDING_REVIEW)
2. Project isolation and cross-project boundary protection
3. Hypothesis validation on valid hypotheses
4. All supported test types accepted
5. Unsupported test types rejected
6. Destructive HTTP methods/commands rejected
7. Credential attacks (brute force, spray, stuffing) rejected
8. Token forging and signature manipulation rejected
9. Explicit human approval workflow and state transition
10. Explicit human rejection workflow with documented reason
11. Approval creates immutable AIHypothesisReview audit record
12. Rejection creates immutable AIHypothesisReview audit record
13. Cannot approve twice (idempotency/state guard)
14. Cannot reject twice (state guard)
15. Cannot convert unapproved hypothesis (PENDING_REVIEW or REJECTED)
16. Conversion produces correct deterministic SecurityTest with allowlisted fields
17. Conversion does NOT execute target HTTP requests
18. AI cannot modify Finding (severity, confidence, status unchanged)
19. AI cannot mark Finding confirmed
20. Project authorization must still be valid during approval
21. Replay/re-conversion isolation (cannot convert twice)
22. Cross-project isolation during validation and conversion
23. REST API endpoints (GET list, GET single, approve, reject, convert, audit)
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
    Finding,
    Evidence,
    AttackGraph,
    AttackPath,
    AttackPathStep,
    AIAnalysis,
    AIHypothesis,
    AIHypothesisReview,
    SecurityTest,
    TestExecution,
)
from app.services.ai import (
    HypothesisValidator,
    HypothesisValidationError,
    HypothesisReviewService,
    HypothesisReviewError,
    HypothesisConverter,
    HypothesisConversionError,
    AISecurityService,
    SUPPORTED_TEST_TYPES,
)

# Prevent pytest from treating classes named *Test or *Analysis as test suites
SecurityTest.__test__ = False
AIAnalysis.__test__ = False
AIHypothesis.__test__ = False
AIHypothesisReview.__test__ = False
AttackGraph.__test__ = False
AttackPath.__test__ = False
AttackPathStep.__test__ = False
TestExecution.__test__ = False


def create_stage9_2_test_setup(client: TestClient, db_session, proj_name="Stage 9.2 Test Project"):
    """Helper to set up an authorized project with API, endpoint, role, identity, resource, finding, path, and analysis."""
    proj = Project(
        name=proj_name,
        description="Authorized test target for human-approved testing",
        environment="staging",
        base_url="http://testserver",
        authorization_status="authorized",
    )
    db_session.add(proj)
    db_session.commit()
    db_session.refresh(proj)

    api = API(
        project_id=proj.id,
        name="Orders API",
        version="1.0",
        format="openapi3",
        status="active",
        url="http://testserver",
    )
    db_session.add(api)
    db_session.commit()
    db_session.refresh(api)

    slug = proj_name.lower().replace(" ", "_")
    endpoint = Endpoint(
        api_id=api.id,
        path=f"/api/v1/{slug}/orders/{{order_id}}",
        method="GET",
        summary="Retrieve order by ID",
    )
    db_session.add(endpoint)
    db_session.commit()
    db_session.refresh(endpoint)

    role = Role(
        project_id=proj.id,
        name="CustomerRole",
        description="Customer user role",
    )
    db_session.add(role)
    db_session.commit()
    db_session.refresh(role)

    alice = Identity(
        project_id=proj.id,
        role_id=role.id,
        name="AliceCustomer",
        auth_type="bearer",
    )
    bob = Identity(
        project_id=proj.id,
        role_id=role.id,
        name="BobCustomer",
        auth_type="bearer",
    )
    db_session.add(alice)
    db_session.add(bob)
    db_session.commit()
    db_session.refresh(alice)
    db_session.refresh(bob)

    resource = Resource(
        project_id=proj.id,
        api_id=api.id,
        name="OrderResource",
        resource_type="entity",
    )
    db_session.add(resource)
    db_session.commit()
    db_session.refresh(resource)

    finding = Finding(
        project_id=proj.id,
        endpoint_id=endpoint.id,
        attacker_identity_id=alice.id,
        resource_id=resource.id,
        type="BOLA",
        severity="HIGH",
        confidence="CONFIRMED",
        status="CONFIRMED",
        title="BOLA on Orders",
        description="Alice can access arbitrary orders.",
        actual_behavior="Returned HTTP 200 with victim order data.",
        remediation="Check user ownership on order query.",
    )
    db_session.add(finding)
    db_session.commit()
    db_session.refresh(finding)

    evidence = Evidence(
        finding_id=finding.id,
        response_metadata=json.dumps({"status_code": 200, "duration_ms": 30, "headers": {"Content-Type": "application/json"}}),
        redacted_response=json.dumps({"order_id": "999", "owner": "bob"}),
        expected_behavior="HTTP 403 required.",
        actual_behavior="HTTP 200 returned.",
    )
    db_session.add(evidence)
    db_session.commit()
    db_session.refresh(evidence)

    graph = AttackGraph(
        project_id=proj.id,
        name="Orders Attack Graph",
        status="ACTIVE",
    )
    db_session.add(graph)
    db_session.commit()
    db_session.refresh(graph)

    path = AttackPath(
        project_id=proj.id,
        attack_graph_id=graph.id,
        name="BOLA to Order Exposure",
        status="ACTIVE",
        confidence="HIGH",
    )
    db_session.add(path)
    db_session.commit()
    db_session.refresh(path)

    step = AttackPathStep(
        attack_path_id=path.id,
        position=1,
        finding_id=finding.id,
        relationship_type="INITIAL_ACCESS",
        reason="Exposes order data to unauthorized tenants.",
    )
    db_session.add(step)
    db_session.commit()

    analysis = AIAnalysis(
        project_id=proj.id,
        attack_path_id=path.id,
        analysis_type="ATTACK_HYPOTHESIS",
        status="COMPLETED",
        model_provider="mock",
        model_name="mock-reasoner",
        input_context={"context": "orders"},
        output={"hypotheses": []},
    )
    db_session.add(analysis)
    db_session.commit()
    db_session.refresh(analysis)

    return {
        "project": proj,
        "api": api,
        "endpoint": endpoint,
        "alice": alice,
        "bob": bob,
        "resource": resource,
        "finding": finding,
        "path": path,
        "analysis": analysis,
    }


# ==============================================================================
# TESTS
# ==============================================================================

def test_hypothesis_creation(client: TestClient, db_session):
    """1. Test hypothesis model creation with default security attributes."""
    data = create_stage9_2_test_setup(client, db_session)
    proj = data["project"]
    analysis = data["analysis"]
    path = data["path"]
    finding = data["finding"]

    hypo = AIHypothesis(
        project_id=proj.id,
        ai_analysis_id=analysis.id,
        attack_path_id=path.id,
        finding_id=finding.id,
        hypothesis="Test whether Alice can read Bob's invoice through /orders/{id}",
        reason="Observed BOLA pattern on orders endpoint.",
        suggested_test_type="BOLA",
        confidence="HIGH",
        requires_human_review=True,
        status="PENDING_REVIEW",
    )
    db_session.add(hypo)
    db_session.commit()
    db_session.refresh(hypo)

    assert hypo.id is not None
    assert hypo.requires_human_review is True
    assert hypo.status == "PENDING_REVIEW"
    assert hypo.reviewed_at is None
    assert hypo.reviewed_by is None
    assert hypo.security_test_id is None


def test_project_isolation(client: TestClient, db_session):
    """2. Test cross-project isolation: validator blocks mismatched project findings."""
    data1 = create_stage9_2_test_setup(client, db_session, "Project 1")
    data2 = create_stage9_2_test_setup(client, db_session, "Project 2")

    # Hypothesis in Project 1 incorrectly referencing Finding from Project 2
    hypo = AIHypothesis(
        project_id=data1["project"].id,
        ai_analysis_id=data1["analysis"].id,
        attack_path_id=data1["path"].id,
        finding_id=data2["finding"].id,  # Mismatched finding
        hypothesis="Cross project test hypothesis",
        reason="Testing boundary enforcement",
        suggested_test_type="BOLA",
        confidence="MEDIUM",
        requires_human_review=True,
        status="PENDING_REVIEW",
    )
    db_session.add(hypo)
    db_session.commit()

    validator = HypothesisValidator(db_session)
    with pytest.raises(HypothesisValidationError, match="Cross-project isolation breach"):
        validator.validate(hypo)


def test_hypothesis_validation(client: TestClient, db_session):
    """3. Test valid hypothesis successfully passes validator."""
    data = create_stage9_2_test_setup(client, db_session)
    hypo = AIHypothesis(
        project_id=data["project"].id,
        ai_analysis_id=data["analysis"].id,
        attack_path_id=data["path"].id,
        finding_id=data["finding"].id,
        hypothesis="Test whether secondary order invoice endpoint lacks authorization check.",
        reason="BOLA vulnerability observed on primary order endpoint.",
        suggested_test_type="BOLA",
        confidence="HIGH",
        requires_human_review=True,
        status="PENDING_REVIEW",
    )
    db_session.add(hypo)
    db_session.commit()

    validator = HypothesisValidator(db_session)
    assert validator.validate(hypo) is True


def test_supported_test_types(client: TestClient, db_session):
    """4. Test all allowlisted test types are accepted by validator."""
    data = create_stage9_2_test_setup(client, db_session)
    validator = HypothesisValidator(db_session)

    for test_type in SUPPORTED_TEST_TYPES:
        hypo = AIHypothesis(
            project_id=data["project"].id,
            ai_analysis_id=data["analysis"].id,
            hypothesis=f"Test hypothesis for {test_type}",
            reason="Security review verification",
            suggested_test_type=test_type,
            confidence="LOW",
            requires_human_review=True,
            status="PENDING_REVIEW",
        )
        assert validator.validate(hypo) is True


def test_unsupported_test_type_rejection(client: TestClient, db_session):
    """5. Test unsupported test types are rejected."""
    data = create_stage9_2_test_setup(client, db_session)
    validator = HypothesisValidator(db_session)

    hypo = AIHypothesis(
        project_id=data["project"].id,
        ai_analysis_id=data["analysis"].id,
        hypothesis="Test arbitrary vulnerability",
        reason="Security test",
        suggested_test_type="UNKNOWN_ARBITRARY_TYPE",
        confidence="LOW",
        requires_human_review=True,
        status="PENDING_REVIEW",
    )
    with pytest.raises(HypothesisValidationError, match="Unsupported test type"):
        validator.validate(hypo)


def test_destructive_method_rejection(client: TestClient, db_session):
    """6. Test destructive HTTP methods and commands are rejected."""
    data = create_stage9_2_test_setup(client, db_session)
    validator = HypothesisValidator(db_session)

    hypo = AIHypothesis(
        project_id=data["project"].id,
        ai_analysis_id=data["analysis"].id,
        hypothesis="Execute DELETE /orders/123 to purge records",
        reason="Testing destructive deletion",
        suggested_test_type="BOLA",
        confidence="MEDIUM",
        requires_human_review=True,
        status="PENDING_REVIEW",
    )
    with pytest.raises(HypothesisValidationError, match="destructive action or method"):
        validator.validate(hypo)


def test_credential_attack_rejection(client: TestClient, db_session):
    """7. Test credential attacks (brute force, spraying) are rejected."""
    data = create_stage9_2_test_setup(client, db_session)
    validator = HypothesisValidator(db_session)

    hypo = AIHypothesis(
        project_id=data["project"].id,
        ai_analysis_id=data["analysis"].id,
        hypothesis="Perform brute-force password guessing against login endpoint",
        reason="Testing password entropy",
        suggested_test_type="BFLA",
        confidence="MEDIUM",
        requires_human_review=True,
        status="PENDING_REVIEW",
    )
    with pytest.raises(HypothesisValidationError, match="prohibited credential attack"):
        validator.validate(hypo)


def test_token_forging_rejection(client: TestClient, db_session):
    """8. Test token forging and signature forgery are rejected."""
    data = create_stage9_2_test_setup(client, db_session)
    validator = HypothesisValidator(db_session)

    hypo = AIHypothesis(
        project_id=data["project"].id,
        ai_analysis_id=data["analysis"].id,
        hypothesis="Send fake jwt token with none algorithm to forge signature",
        reason="Testing signature validation",
        suggested_test_type="AUTH_INVALID",
        confidence="HIGH",
        requires_human_review=True,
        status="PENDING_REVIEW",
    )
    with pytest.raises(HypothesisValidationError, match="prohibited token forging"):
        validator.validate(hypo)


def test_approval(client: TestClient, db_session):
    """9. Test human approval transitions status to APPROVED and sets reviewer attributes."""
    data = create_stage9_2_test_setup(client, db_session)
    hypo = AIHypothesis(
        project_id=data["project"].id,
        ai_analysis_id=data["analysis"].id,
        hypothesis="Valid hypothesis for human review",
        reason="Security assessment",
        suggested_test_type="BOLA",
        confidence="HIGH",
        requires_human_review=True,
        status="PENDING_REVIEW",
    )
    db_session.add(hypo)
    db_session.commit()

    service = HypothesisReviewService(db_session)
    updated, review = service.approve_hypothesis(
        hypothesis_id=hypo.id,
        reviewer_reference="sec-engineer@company.com",
        reason="Approved for staging testing.",
    )

    assert updated.status == "APPROVED"
    assert updated.reviewed_by == "sec-engineer@company.com"
    assert updated.reviewed_at is not None
    assert review.action == "APPROVE"


def test_rejection(client: TestClient, db_session):
    """10. Test human rejection transitions status to REJECTED and records reason."""
    data = create_stage9_2_test_setup(client, db_session)
    hypo = AIHypothesis(
        project_id=data["project"].id,
        ai_analysis_id=data["analysis"].id,
        hypothesis="Plausible but out-of-scope hypothesis",
        reason="Security exploration",
        suggested_test_type="BOLA",
        confidence="LOW",
        requires_human_review=True,
        status="PENDING_REVIEW",
    )
    db_session.add(hypo)
    db_session.commit()

    service = HypothesisReviewService(db_session)
    updated, review = service.reject_hypothesis(
        hypothesis_id=hypo.id,
        reviewer_reference="auditor@company.com",
        reason="Out of scope for this audit cycle.",
    )

    assert updated.status == "REJECTED"
    assert updated.reviewed_by == "auditor@company.com"
    assert updated.rejection_reason == "Out of scope for this audit cycle."
    assert review.action == "REJECT"


def test_approval_audit_record(client: TestClient, db_session):
    """11. Test approval creates an immutable AIHypothesisReview audit record."""
    data = create_stage9_2_test_setup(client, db_session)
    hypo = AIHypothesis(
        project_id=data["project"].id,
        ai_analysis_id=data["analysis"].id,
        hypothesis="Audit record approval test",
        reason="Testing audit persistence",
        suggested_test_type="BOLA",
        status="PENDING_REVIEW",
    )
    db_session.add(hypo)
    db_session.commit()

    service = HypothesisReviewService(db_session)
    service.approve_hypothesis(hypo.id, "lead-analyst@corp.io", "Verified safe.")

    reviews = db_session.query(AIHypothesisReview).filter(AIHypothesisReview.hypothesis_id == hypo.id).all()
    assert len(reviews) == 1
    assert reviews[0].action == "APPROVE"
    assert reviews[0].reviewer_reference == "lead-analyst@corp.io"
    assert reviews[0].reason == "Verified safe."


def test_rejection_audit_record(client: TestClient, db_session):
    """12. Test rejection creates an immutable AIHypothesisReview audit record."""
    data = create_stage9_2_test_setup(client, db_session)
    hypo = AIHypothesis(
        project_id=data["project"].id,
        ai_analysis_id=data["analysis"].id,
        hypothesis="Audit record rejection test",
        reason="Testing rejection audit",
        suggested_test_type="BOLA",
        status="PENDING_REVIEW",
    )
    db_session.add(hypo)
    db_session.commit()

    service = HypothesisReviewService(db_session)
    service.reject_hypothesis(hypo.id, "qa-reviewer@corp.io", "Redundant test case.")

    reviews = db_session.query(AIHypothesisReview).filter(AIHypothesisReview.hypothesis_id == hypo.id).all()
    assert len(reviews) == 1
    assert reviews[0].action == "REJECT"
    assert reviews[0].reviewer_reference == "qa-reviewer@corp.io"
    assert reviews[0].reason == "Redundant test case."


def test_cannot_approve_twice(client: TestClient, db_session):
    """13. Test hypothesis cannot be approved twice."""
    data = create_stage9_2_test_setup(client, db_session)
    hypo = AIHypothesis(
        project_id=data["project"].id,
        ai_analysis_id=data["analysis"].id,
        hypothesis="Double approval test",
        reason="Testing state guard",
        suggested_test_type="BOLA",
        status="PENDING_REVIEW",
    )
    db_session.add(hypo)
    db_session.commit()

    service = HypothesisReviewService(db_session)
    service.approve_hypothesis(hypo.id, "reviewer1")

    with pytest.raises(HypothesisReviewError, match="Cannot approve hypothesis in 'APPROVED' status"):
        service.approve_hypothesis(hypo.id, "reviewer2")


def test_cannot_reject_twice(client: TestClient, db_session):
    """14. Test hypothesis cannot be rejected twice."""
    data = create_stage9_2_test_setup(client, db_session)
    hypo = AIHypothesis(
        project_id=data["project"].id,
        ai_analysis_id=data["analysis"].id,
        hypothesis="Double rejection test",
        reason="Testing state guard",
        suggested_test_type="BOLA",
        status="PENDING_REVIEW",
    )
    db_session.add(hypo)
    db_session.commit()

    service = HypothesisReviewService(db_session)
    service.reject_hypothesis(hypo.id, "reviewer1", "Reason 1")

    with pytest.raises(HypothesisReviewError, match="Cannot reject hypothesis in 'REJECTED' status"):
        service.reject_hypothesis(hypo.id, "reviewer2", "Reason 2")


def test_cannot_convert_unapproved_hypothesis(client: TestClient, db_session):
    """15. Test cannot convert a hypothesis that is still PENDING_REVIEW or REJECTED."""
    data = create_stage9_2_test_setup(client, db_session)
    converter = HypothesisConverter(db_session)

    # 1. PENDING_REVIEW
    hypo_pending = AIHypothesis(
        project_id=data["project"].id,
        ai_analysis_id=data["analysis"].id,
        hypothesis="Unapproved conversion test",
        reason="Testing conversion guard",
        suggested_test_type="BOLA",
        status="PENDING_REVIEW",
    )
    db_session.add(hypo_pending)
    db_session.commit()

    with pytest.raises(HypothesisConversionError, match="Only 'APPROVED' hypotheses can be converted"):
        converter.convert_hypothesis(hypo_pending.id)

    # 2. REJECTED
    hypo_pending.status = "REJECTED"
    db_session.commit()

    with pytest.raises(HypothesisConversionError, match="Only 'APPROVED' hypotheses can be converted"):
        converter.convert_hypothesis(hypo_pending.id)


def test_conversion_produces_correct_security_test(client: TestClient, db_session):
    """16. Test converting approved hypothesis produces valid SecurityTest and updates status."""
    data = create_stage9_2_test_setup(client, db_session)
    hypo = AIHypothesis(
        project_id=data["project"].id,
        ai_analysis_id=data["analysis"].id,
        finding_id=data["finding"].id,
        attack_path_id=data["path"].id,
        hypothesis="Test Alice accessing Bob's order",
        reason="Validated BOLA gap",
        suggested_test_type="BOLA",
        status="APPROVED",
        reviewed_by="security-lead",
    )
    db_session.add(hypo)
    db_session.commit()

    converter = HypothesisConverter(db_session)
    updated_hypo, sec_test = converter.convert_hypothesis(hypo.id, "operator@corp.com")

    assert updated_hypo.status == "CONVERTED"
    assert updated_hypo.security_test_id == sec_test.id
    assert sec_test.test_type == "BOLA"
    assert sec_test.project_id == data["project"].id
    assert sec_test.endpoint_id == data["endpoint"].id
    assert sec_test.attacker_identity_id == data["alice"].id
    assert sec_test.status == "configured"
    # Allowlisted configuration JSON check
    config = json.loads(sec_test.configuration)
    assert config["converted_from_ai_hypothesis"] is True
    assert config["hypothesis_id"] == hypo.id


def test_conversion_does_not_execute_http(client: TestClient, db_session):
    """17. Critical safety rule: Conversion strictly does NOT execute target HTTP requests."""
    data = create_stage9_2_test_setup(client, db_session)
    hypo = AIHypothesis(
        project_id=data["project"].id,
        ai_analysis_id=data["analysis"].id,
        finding_id=data["finding"].id,
        hypothesis="Zero traffic test",
        reason="Verify non-executable conversion",
        suggested_test_type="BOLA",
        status="APPROVED",
        reviewed_by="security-lead",
    )
    db_session.add(hypo)
    db_session.commit()

    converter = HypothesisConverter(db_session)
    with patch("httpx.Client.post") as mock_post, patch("httpx.Client.get") as mock_get:
        _, sec_test = converter.convert_hypothesis(hypo.id)
        mock_post.assert_not_called()
        mock_get.assert_not_called()

    # Confirms security test is created in 'configured' state, NOT 'completed'
    assert sec_test.status == "configured"


def test_ai_cannot_modify_finding(client: TestClient, db_session):
    """18. Safety rule: AI review and conversion lifecycle NEVER modifies Finding attributes."""
    data = create_stage9_2_test_setup(client, db_session)
    finding = data["finding"]

    initial_severity = finding.severity
    initial_confidence = finding.confidence
    initial_status = finding.status
    initial_type = finding.type

    # Run review and conversion
    hypo = AIHypothesis(
        project_id=data["project"].id,
        ai_analysis_id=data["analysis"].id,
        finding_id=finding.id,
        hypothesis="Finding immutability test",
        reason="Verify finding attributes remain untouched",
        suggested_test_type="BOLA",
        status="PENDING_REVIEW",
    )
    db_session.add(hypo)
    db_session.commit()

    review_svc = HypothesisReviewService(db_session)
    review_svc.approve_hypothesis(hypo.id, "auditor")

    converter = HypothesisConverter(db_session)
    converter.convert_hypothesis(hypo.id)

    db_session.expire_all()
    refreshed_finding = db_session.query(Finding).filter(Finding.id == finding.id).first()

    assert refreshed_finding.severity == initial_severity
    assert refreshed_finding.confidence == initial_confidence
    assert refreshed_finding.status == initial_status
    assert refreshed_finding.type == initial_type


def test_ai_cannot_mark_finding_confirmed(client: TestClient, db_session):
    """19. Safety rule: AI hypotheses cannot change unconfirmed findings to confirmed."""
    data = create_stage9_2_test_setup(client, db_session)
    finding = data["finding"]
    finding.status = "OPEN"
    finding.confidence = "HIGH"
    db_session.commit()

    hypo = AIHypothesis(
        project_id=data["project"].id,
        ai_analysis_id=data["analysis"].id,
        finding_id=finding.id,
        hypothesis="Test finding remains OPEN",
        reason="Testing lack of confirmation privilege",
        suggested_test_type="BOLA",
        status="PENDING_REVIEW",
    )
    db_session.add(hypo)
    db_session.commit()

    review_svc = HypothesisReviewService(db_session)
    review_svc.approve_hypothesis(hypo.id, "sec-user")

    converter = HypothesisConverter(db_session)
    converter.convert_hypothesis(hypo.id)

    db_session.expire_all()
    refreshed_finding = db_session.query(Finding).filter(Finding.id == finding.id).first()
    assert refreshed_finding.status == "OPEN"


def test_authorization_must_still_be_valid_during_approval(client: TestClient, db_session):
    """20. Project authorization must still be valid during approval."""
    data = create_stage9_2_test_setup(client, db_session)
    hypo = AIHypothesis(
        project_id=data["project"].id,
        ai_analysis_id=data["analysis"].id,
        hypothesis="Revoked project test",
        reason="Testing authorization revocation",
        suggested_test_type="BOLA",
        status="PENDING_REVIEW",
    )
    db_session.add(hypo)
    db_session.commit()

    # Revoke project authorization
    data["project"].authorization_status = "revoked"
    db_session.commit()

    service = HypothesisReviewService(db_session)
    with pytest.raises(HypothesisReviewError, match="authorization status is 'revoked'"):
        service.approve_hypothesis(hypo.id, "admin")


def test_replay_conversion_isolation(client: TestClient, db_session):
    """21. Replay prevention: A converted hypothesis cannot be converted a second time."""
    data = create_stage9_2_test_setup(client, db_session)
    hypo = AIHypothesis(
        project_id=data["project"].id,
        ai_analysis_id=data["analysis"].id,
        finding_id=data["finding"].id,
        hypothesis="Replay prevention test",
        reason="Testing single conversion invariant",
        suggested_test_type="BOLA",
        status="APPROVED",
        reviewed_by="admin",
    )
    db_session.add(hypo)
    db_session.commit()

    converter = HypothesisConverter(db_session)
    converter.convert_hypothesis(hypo.id)

    with pytest.raises(HypothesisConversionError, match="Cannot convert hypothesis in 'CONVERTED' status"):
        converter.convert_hypothesis(hypo.id)


def test_cross_project_isolation(client: TestClient, db_session):
    """22. Validator blocks hypotheses where required context references entities in another project."""
    data1 = create_stage9_2_test_setup(client, db_session, "Proj A")
    data2 = create_stage9_2_test_setup(client, db_session, "Proj B")

    hypo = AIHypothesis(
        project_id=data1["project"].id,
        ai_analysis_id=data1["analysis"].id,
        hypothesis="Cross project context test",
        reason="Testing context validation",
        suggested_test_type="BOLA",
        required_context={"endpoint_id": data2["endpoint"].id},  # Belongs to Proj B!
        status="PENDING_REVIEW",
    )
    db_session.add(hypo)
    db_session.commit()

    validator = HypothesisValidator(db_session)
    with pytest.raises(HypothesisValidationError, match="does not exist in project"):
        validator.validate(hypo)


def test_rest_api_hypotheses_endpoints(client: TestClient, db_session):
    """23. Test full REST API workflow for Stage 9.2: list, get, approve, reject, convert, audit."""
    data = create_stage9_2_test_setup(client, db_session)
    proj = data["project"]
    analysis = data["analysis"]
    finding = data["finding"]

    hypo1 = AIHypothesis(
        project_id=proj.id,
        ai_analysis_id=analysis.id,
        finding_id=finding.id,
        hypothesis="REST API hypothesis 1 (for approval & conversion)",
        reason="Observational BOLA pattern",
        suggested_test_type="BOLA",
        status="PENDING_REVIEW",
    )
    hypo2 = AIHypothesis(
        project_id=proj.id,
        ai_analysis_id=analysis.id,
        finding_id=finding.id,
        hypothesis="REST API hypothesis 2 (for rejection)",
        reason="Out of scope test",
        suggested_test_type="BOLA",
        status="PENDING_REVIEW",
    )
    db_session.add(hypo1)
    db_session.add(hypo2)
    db_session.commit()

    # 1. GET /projects/{project_id}/ai/hypotheses
    res_list = client.get(f"/api/v1/projects/{proj.id}/ai/hypotheses")
    assert res_list.status_code == 200
    list_data = res_list.json()
    assert list_data["count"] >= 2

    # 2. GET /ai/hypotheses/{hypothesis_id}
    res_get = client.get(f"/api/v1/ai/hypotheses/{hypo1.id}")
    assert res_get.status_code == 200
    assert res_get.json()["id"] == hypo1.id

    # 3. POST /ai/hypotheses/{hypothesis_id}/approve
    res_app = client.post(
        f"/api/v1/ai/hypotheses/{hypo1.id}/approve",
        json={"reviewer_reference": "lead-sec@corp.com", "reason": "Approved for staging test run."},
    )
    assert res_app.status_code == 200
    assert res_app.json()["status"] == "APPROVED"

    # Cannot approve twice via REST
    res_app_dup = client.post(
        f"/api/v1/ai/hypotheses/{hypo1.id}/approve",
        json={"reviewer_reference": "lead-sec@corp.com"},
    )
    assert res_app_dup.status_code == 400

    # 4. POST /ai/hypotheses/{hypothesis_id}/reject
    res_rej = client.post(
        f"/api/v1/ai/hypotheses/{hypo2.id}/reject",
        json={"reviewer_reference": "lead-sec@corp.com", "reason": "Deemed unnecessary by audit policy."},
    )
    assert res_rej.status_code == 200
    assert res_rej.json()["status"] == "REJECTED"

    # 5. POST /ai/hypotheses/{hypothesis_id}/convert
    res_conv = client.post(
        f"/api/v1/ai/hypotheses/{hypo1.id}/convert",
        json={"reviewer_reference": "ops-engineer@corp.com"},
    )
    assert res_conv.status_code == 200
    conv_data = res_conv.json()
    assert conv_data["hypothesis"]["status"] == "CONVERTED"
    assert "security_test_id" in conv_data
    sec_id = conv_data["security_test_id"]

    # 6. GET /ai/hypotheses/{hypothesis_id}/audit
    res_audit = client.get(f"/api/v1/ai/hypotheses/{hypo1.id}/audit")
    assert res_audit.status_code == 200
    audit_data = res_audit.json()
    assert len(audit_data["reviews"]) == 1
    assert audit_data["security_test"]["id"] == sec_id
    assert len(audit_data["lifecycle_stages"]) >= 3
