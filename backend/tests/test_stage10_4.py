"""
Stage 10.4: Security Reporting & Evidence Packages Test Suite
Author: SentinelAPI Security Architecture Team

Comprehensive automated test suite covering:
1. Report Lifecycle & Immutability:
   - Report creation (DRAFT)
   - Source validation (requires at least one valid source)
   - Cross-project source rejection
   - Draft updates and duplicate name rejection
   - Generation of immutable snapshot with deterministic SHA-256 checksum
   - Snapshot versioning upon regeneration (v1, v2)
   - Archival and rejection of modifications/regeneration on ARCHIVED reports
   - Deletion
2. Provenance Architecture:
   - VERIFIED: findings, evidence, remediation
   - DETERMINISTIC: executive summary, gate result, baseline comparison, attack paths, security impact, investigation
   - AI: AI analysis and hypotheses with explicit advisory disclaimer
   - HUMAN: human hypothesis reviews and rationale
   - ENGINE: execution plan and orchestrator metadata
3. Evidence Package & Manifest:
   - Deterministic manifest generation with object counts and SHA-256 checksums
   - Evidence package hierarchy (report.json, manifest.json, findings/, attack-paths/, impact/, evidence/, investigations/, ai/, human-review/, remediation/)
   - Strict credential & header redaction (no raw tokens, passwords, cookies)
4. Zero Target HTTP Calls:
   - Report generation executes purely deterministic data capture with zero target HTTP requests
5. REST API Endpoints:
   - Complete CRUD, generation, archival, json snapshot, manifest, and evidence package endpoints
"""

import pytest
import uuid
import json
from datetime import datetime, timezone
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.models import (
    Project,
    API,
    Endpoint,
    Resource,
    SecurityTest,
    TestExecution,
    Finding,
    Evidence,
    SecurityExecutionPlan,
    SecurityExecutionItem,
    ScanProfile,
    SecurityBaseline,
    SecurityBaselineControl,
    SecurityBaselineComparison,
    SecurityBaselineComparisonItem,
    SecurityGate,
    SecurityGateEvaluation,
    SecurityGateEvaluationItem,
    SecurityInvestigation,
    InvestigationItem,
    AttackGraph,
    AttackPath,
    AttackPathStep,
    SecurityImpact,
    AIAnalysis,
    AIHypothesis,
    AIHypothesisReview,
    SecurityReport,
    SecurityReportSnapshot,
)
from app.services.security_engine.report_service import (
    SecurityReportService,
    SecurityReportError,
    ReportNotFoundError,
    DuplicateReportError,
    InvalidReportSourceError,
    ArchivedReportError,
    CrossProjectViolationError,
)

# Pytest exclusions
SecurityReport.__test__ = False
SecurityReportSnapshot.__test__ = False
SecurityGate.__test__ = False
SecurityGateEvaluation.__test__ = False
SecurityGateEvaluationItem.__test__ = False
SecurityBaseline.__test__ = False
SecurityBaselineComparison.__test__ = False
SecurityExecutionPlan.__test__ = False


@pytest.fixture
def report_fixture(db_session):
    """Fixture providing full security entities across two isolated projects."""
    proj_a = Project(
        name=f"Project-Alpha-{uuid.uuid4().hex[:6]}",
        authorization_status="authorized",
        environment="staging",
        base_url="http://testserver",
    )
    proj_b = Project(
        name=f"Project-Beta-{uuid.uuid4().hex[:6]}",
        authorization_status="authorized",
        environment="staging",
        base_url="http://testserver",
    )
    db_session.add_all([proj_a, proj_b])
    db_session.commit()

    api_a = API(project_id=proj_a.id, name="Core API", version="1.0", format="openapi3", status="active", url="http://testserver")
    db_session.add(api_a)
    db_session.commit()

    ep_1 = Endpoint(api_id=api_a.id, method="GET", path="/api/v1/users/me", summary="Current User")
    ep_2 = Endpoint(api_id=api_a.id, method="GET", path="/api/v1/admin/records", summary="Admin Records")
    db_session.add_all([ep_1, ep_2])
    db_session.commit()

    res_user = Resource(project_id=proj_a.id, name="User Account")
    db_session.add(res_user)
    db_session.commit()

    test_1 = SecurityTest(project_id=proj_a.id, endpoint_id=ep_1.id, test_type="BOLA", status="configured")
    test_2 = SecurityTest(project_id=proj_a.id, endpoint_id=ep_2.id, test_type="BFLA", status="configured")
    db_session.add_all([test_1, test_2])
    db_session.commit()

    # Findings
    finding_1 = Finding(
        project_id=proj_a.id,
        security_test_id=test_1.id,
        endpoint_id=ep_1.id,
        resource_id=res_user.id,
        type="BOLA",
        status="CONFIRMED",
        severity="HIGH",
        confidence="HIGH",
        title="Unauthorized Object Access on /users/me",
        description="Victim user records accessed by attacker without authorization.",
        expected_authorization="DENY",
        actual_behavior="ALLOW (200 OK)",
        remediation="Validate user ownership before returning user records.",
    )
    db_session.add(finding_1)
    db_session.commit()

    # Evidence with sensitive headers to verify redaction
    evidence_1 = Evidence(
        finding_id=finding_1.id,
        expected_behavior="DENY (403 Forbidden)",
        actual_behavior="ALLOW (200 OK)",
        request_metadata=json.dumps({
            "method": "GET",
            "url": "http://testserver/api/v1/users/me?token=secret12345",
            "headers": {
                "Authorization": "Bearer sensitive_token_xyz",
                "Cookie": "session=secret_cookie_val",
                "User-Agent": "SentinelSecurityEngine/1.0",
            },
        }),
        response_metadata=json.dumps({
            "status_code": 200,
            "headers": {
                "Set-Cookie": "session=sensitive_leak",
                "Content-Type": "application/json",
            },
            "body": '{"user_id": 123, "api_key": "raw_secret_leak"}',
        }),
    )
    db_session.add(evidence_1)
    db_session.commit()

    # Attack Graph
    graph_a = AttackGraph(project_id=proj_a.id, name="Core Attack Graph")
    db_session.add(graph_a)
    db_session.commit()

    # Attack Path
    path_1 = AttackPath(
        project_id=proj_a.id,
        attack_graph_id=graph_a.id,
        name="BOLA Exfiltration Path",
        description="Exploits BOLA on user endpoint to access sensitive records.",
        confidence="HIGH",
    )
    db_session.add(path_1)
    db_session.commit()

    step_1 = AttackPathStep(
        attack_path_id=path_1.id,
        finding_id=finding_1.id,
        position=1,
        relationship_type="EXPLOITS",
        reason="Directly exposes data without authorization",
    )
    db_session.add(step_1)
    db_session.commit()

    # Security Impact
    impact_1 = SecurityImpact(
        project_id=proj_a.id,
        finding_id=finding_1.id,
        attack_path_id=path_1.id,
        initial_access=True,
        authorization_boundary_crossed=True,
        sensitive_data_reached=True,
        cross_identity_impact=True,
        terminal_impact="DATA_EXFILTRATION",
        explanation="Attackers can read arbitrary victim profile objects.",
    )
    db_session.add(impact_1)
    db_session.commit()

    # Execution Plan
    plan_a = SecurityExecutionPlan(
        project_id=proj_a.id,
        name="Sprint Security Audit Plan",
        status="COMPLETED",
        execution_mode="SEQUENTIAL",
        total_tests=2,
        completed_tests=2,
        confirmed_findings=1,
        inconclusive_tests=0,
        failed_tests=0,
    )
    # Plan for Project B (cross-project test)
    plan_b = SecurityExecutionPlan(
        project_id=proj_b.id,
        name="Project B Plan",
        status="COMPLETED",
        execution_mode="SEQUENTIAL",
    )
    db_session.add_all([plan_a, plan_b])
    db_session.commit()

    # Baseline & Gate Evaluation
    baseline_a = SecurityBaseline(
        project_id=proj_a.id,
        name="Production Baseline v1",
        version=1,
        status="ACTIVE",
    )
    profile_a = ScanProfile(
        project_id=proj_a.id,
        name="Deep Audit Profile",
        profile_type="DEEP",
        status="ACTIVE",
    )
    db_session.add_all([baseline_a, profile_a])
    db_session.commit()

    comp_a = SecurityBaselineComparison(
        baseline_id=baseline_a.id,
        execution_plan_id=plan_a.id,
        status="COMPLETED",
        summary={"regressions_count": 0, "new_violations_count": 1},
    )
    db_session.add(comp_a)
    db_session.commit()

    comp_item = SecurityBaselineComparisonItem(
        comparison_id=comp_a.id,
        security_test_id=test_1.id,
        finding_id=finding_1.id,
        result="NEW_VIOLATION",
        previous_behavior="PASS",
        current_behavior="CONFIRMED",
        explanation="New confirmed BOLA finding observed.",
    )
    db_session.add(comp_item)
    db_session.commit()

    gate_a = SecurityGate(
        project_id=proj_a.id,
        name="Sprint Gate",
        baseline_id=baseline_a.id,
        scan_profile_id=profile_a.id,
        status="ACTIVE",
        failure_rules={"max_regressions": 0, "max_new_violations": 0},
    )
    db_session.add(gate_a)
    db_session.commit()

    gate_eval_a = SecurityGateEvaluation(
        gate_id=gate_a.id,
        project_id=proj_a.id,
        baseline_comparison_id=comp_a.id,
        status="FAIL",
        failure_count=1,
        warning_count=0,
        confirmed_findings=1,
        regressions=0,
        new_violations=1,
        failed_tests=0,
        inconclusive_tests=0,
        error_tests=0,
        summary={"status": "FAIL", "exit_code": 1},
        evaluated_at=datetime.now(timezone.utc),
    )
    db_session.add(gate_eval_a)
    db_session.commit()

    # Investigation
    investigation_a = SecurityInvestigation(
        project_id=proj_a.id,
        title="Investigation into BOLA leak",
        description="Comprehensive investigation of tenant boundary breach.",
        status="OPEN",
        primary_finding_id=finding_1.id,
        primary_attack_path_id=path_1.id,
    )
    db_session.add(investigation_a)
    db_session.commit()

    inv_item = InvestigationItem(
        investigation_id=investigation_a.id,
        item_type="FINDING",
        item_id=finding_1.id,
        position=1,
    )
    db_session.add(inv_item)
    db_session.commit()

    # AI Analysis & Human Review
    ai_analysis_1 = AIAnalysis(
        project_id=proj_a.id,
        finding_id=finding_1.id,
        analysis_type="ROOT_CAUSE",
        model_provider="MOCK_PROVIDER",
        model_name="MOCK_MODEL",
        input_context={"finding_id": finding_1.id},
        output={"summary": "AI analysis suggests missing user authorization checks in handler."},
    )
    db_session.add(ai_analysis_1)
    db_session.commit()

    hypothesis_1 = AIHypothesis(
        project_id=proj_a.id,
        ai_analysis_id=ai_analysis_1.id,
        finding_id=finding_1.id,
        hypothesis="Attacker can access any user's private data",
        reason="No ID check",
        suggested_test_type="BOLA",
        status="APPROVED",
    )
    db_session.add(hypothesis_1)
    db_session.commit()

    human_review_1 = AIHypothesisReview(
        hypothesis_id=hypothesis_1.id,
        action="APPROVE",
        reviewer_reference="secops_lead@sentinel.local",
        reason="Confirmed validity of the BOLA path.",
    )
    db_session.add(human_review_1)
    db_session.commit()

    return {
        "proj_a": proj_a,
        "proj_b": proj_b,
        "plan_a": plan_a,
        "plan_b": plan_b,
        "gate_eval_a": gate_eval_a,
        "investigation_a": investigation_a,
        "finding_1": finding_1,
        "evidence_1": evidence_1,
        "path_1": path_1,
        "impact_1": impact_1,
        "ai_analysis_1": ai_analysis_1,
        "human_review_1": human_review_1,
    }


# =============================================================================
# 1. REPORT LIFECYCLE & IMMUTABILITY
# =============================================================================

def test_report_crud_and_uniqueness(db_session, report_fixture):
    """Test report creation, name uniqueness within project, updates, and deletion."""
    proj_a = report_fixture["proj_a"]
    proj_b = report_fixture["proj_b"]
    plan_a = report_fixture["plan_a"]
    gate_eval_a = report_fixture["gate_eval_a"]
    service = SecurityReportService(db=db_session)

    # 1. Create Report
    report = service.create_report(
        project_id=proj_a.id,
        name="Q3 Release Security Assessment",
        description="Comprehensive audit of Core API",
        report_type="SECURITY_ASSESSMENT",
        source_execution_plan_id=plan_a.id,
        source_gate_evaluation_id=gate_eval_a.id,
    )
    assert report.id is not None
    assert report.name == "Q3 Release Security Assessment"
    assert report.status == "DRAFT"
    assert report.version == 1

    # 2. Reject duplicate report name in same project
    with pytest.raises(DuplicateReportError):
        service.create_report(
            project_id=proj_a.id,
            name="Q3 Release Security Assessment",
            source_execution_plan_id=plan_a.id,
        )

    # 3. Allow same report name in a DIFFERENT project
    plan_b = report_fixture["plan_b"]
    report_b = service.create_report(
        project_id=proj_b.id,
        name="Q3 Release Security Assessment",
        source_execution_plan_id=plan_b.id,
    )
    assert report_b.id != report.id

    # 4. Cross-project isolation check
    with pytest.raises(CrossProjectViolationError):
        service.get_report(report_b.id, project_id=proj_a.id)

    # 5. Update draft report
    updated = service.update_report(
        report_id=report.id,
        project_id=proj_a.id,
        description="Updated description for Q3 release audit",
    )
    assert updated.description == "Updated description for Q3 release audit"

    # 6. Delete report
    deleted = service.delete_report(report.id, project_id=proj_a.id)
    assert deleted is True
    assert service.get_report(report.id) is None


def test_report_source_validation_and_cross_project_rejection(db_session, report_fixture):
    """Ensure at least one source is required and cross-project sources are rejected."""
    proj_a = report_fixture["proj_a"]
    plan_b = report_fixture["plan_b"]
    service = SecurityReportService(db=db_session)

    # Rejection: No source provided
    with pytest.raises(InvalidReportSourceError):
        service.create_report(
            project_id=proj_a.id,
            name="Empty Source Report",
        )

    # Rejection: Source from a different project
    with pytest.raises(CrossProjectViolationError):
        service.create_report(
            project_id=proj_a.id,
            name="Cross Project Source Report",
            source_execution_plan_id=plan_b.id,  # Belongs to proj_b!
        )


def test_report_generation_and_snapshot_versioning(db_session, report_fixture):
    """Test generating immutable snapshot, checksum computation, and deterministic versioning."""
    proj_a = report_fixture["proj_a"]
    plan_a = report_fixture["plan_a"]
    gate_eval_a = report_fixture["gate_eval_a"]
    service = SecurityReportService(db=db_session)

    report = service.create_report(
        project_id=proj_a.id,
        name="Versioned Audit Report",
        source_execution_plan_id=plan_a.id,
        source_gate_evaluation_id=gate_eval_a.id,
    )

    # First Generation -> Version 1
    snapshot_v1 = service.generate_report(report.id)
    assert snapshot_v1.version == 1
    assert snapshot_v1.checksum is not None
    assert len(snapshot_v1.checksum) == 64  # SHA-256
    assert report.status == "GENERATED"
    assert report.version == 1

    # Second Generation -> Version 2 (previous snapshot preserved)
    snapshot_v2 = service.generate_report(report.id)
    assert snapshot_v2.version == 2
    assert snapshot_v2.id != snapshot_v1.id
    assert report.version == 2

    # Verify both snapshots are intact and queryable
    snap_1_fetch = service.get_snapshot(report.id, version=1)
    snap_2_fetch = service.get_snapshot(report.id, version=2)
    assert snap_1_fetch.version == 1
    assert snap_2_fetch.version == 2


def test_archived_report_immutability(db_session, report_fixture):
    """Archived reports cannot be modified or regenerated."""
    proj_a = report_fixture["proj_a"]
    plan_a = report_fixture["plan_a"]
    service = SecurityReportService(db=db_session)

    report = service.create_report(
        project_id=proj_a.id,
        name="Archive Immutability Report",
        source_execution_plan_id=plan_a.id,
    )
    service.generate_report(report.id)

    # Archive report
    archived = service.archive_report(report.id)
    assert archived.status == "ARCHIVED"

    # Attempting to update must fail
    with pytest.raises(ArchivedReportError):
        service.update_report(report.id, name="Renamed After Archive")

    # Attempting to regenerate must fail
    with pytest.raises(ArchivedReportError):
        service.generate_report(report.id)


# =============================================================================
# 2. PROVENANCE CATEGORIES & DATA STRUCTURES
# =============================================================================

def test_report_provenance_and_content_sections(db_session, report_fixture):
    """Verify distinct provenance categories are explicitly preserved across sections."""
    proj_a = report_fixture["proj_a"]
    plan_a = report_fixture["plan_a"]
    gate_eval_a = report_fixture["gate_eval_a"]
    investigation_a = report_fixture["investigation_a"]
    service = SecurityReportService(db=db_session)

    report = service.create_report(
        project_id=proj_a.id,
        name="Provenance Audit Report",
        source_execution_plan_id=plan_a.id,
        source_gate_evaluation_id=gate_eval_a.id,
        source_investigation_id=investigation_a.id,
    )

    snapshot = service.generate_report(report.id)
    content = snapshot.report_json

    # Executive Summary: DETERMINISTIC
    assert content["executive_summary"]["provenance"] == "DETERMINISTIC"
    assert content["executive_summary"]["metrics"]["confirmed_findings"] >= 1

    # Scan Information: ENGINE
    assert content["scan_information"]["provenance"] == "ENGINE"
    assert content["scan_information"]["execution_plan_id"] == plan_a.id

    # Security Gate Result: DETERMINISTIC
    assert content["security_gate_result"]["provenance"] == "DETERMINISTIC"
    assert content["security_gate_result"]["status"] == "FAIL"

    # Verified Findings: VERIFIED
    assert len(content["verified_findings"]) >= 1
    for f in content["verified_findings"]:
        assert f["provenance"] == "VERIFIED"
        assert "finding_id" in f

    # Attack Paths: DETERMINISTIC
    assert len(content["attack_paths"]) >= 1
    assert content["attack_paths"][0]["provenance"] == "DETERMINISTIC"
    assert len(content["attack_paths"][0]["steps"]) >= 1

    # Security Impact: DETERMINISTIC
    assert len(content["security_impact"]) >= 1
    assert content["security_impact"][0]["provenance"] == "DETERMINISTIC"
    assert content["security_impact"][0]["sensitive_data_reached"] is True

    # Evidence: VERIFIED
    assert len(content["evidence"]) >= 1
    assert content["evidence"][0]["provenance"] == "VERIFIED"

    # Remediation: VERIFIED
    assert len(content["remediation"]) >= 1
    assert content["remediation"][0]["provenance"] == "VERIFIED"
    assert "remediation_guidance" in content["remediation"][0]

    # AI Analysis: AI with advisory disclaimer
    assert len(content["ai_analysis"]) >= 1
    assert content["ai_analysis"][0]["provenance"] == "AI"
    assert "AI ANALYSIS — NOT VERIFIED SECURITY FACT" in content["ai_analysis"][0]["disclaimer"]

    # Human Review: HUMAN
    assert len(content["human_review"]) >= 1
    assert content["human_review"][0]["provenance"] == "HUMAN"
    assert content["human_review"][0]["action"] == "APPROVE"


# =============================================================================
# 3. EVIDENCE & CREDENTIAL REDACTION GUARANTEE
# =============================================================================

def test_evidence_sanitization_and_credential_redaction(db_session, report_fixture):
    """Ensure report snapshots never persist raw credentials, cookies, or authorization tokens."""
    proj_a = report_fixture["proj_a"]
    plan_a = report_fixture["plan_a"]
    service = SecurityReportService(db=db_session)

    report = service.create_report(
        project_id=proj_a.id,
        name="Redaction Verification Report",
        source_execution_plan_id=plan_a.id,
    )

    snapshot = service.generate_report(report.id)
    raw_json_str = json.dumps(snapshot.report_json)

    # Verify sensitive token strings from evidence_1 are completely redacted
    assert "sensitive_token_xyz" not in raw_json_str
    assert "secret_cookie_val" not in raw_json_str
    assert "secret12345" not in raw_json_str
    assert "raw_secret_leak" not in raw_json_str
    assert "[REDACTED]" in raw_json_str


# =============================================================================
# 4. MANIFEST & EVIDENCE PACKAGE INTEGRITY
# =============================================================================

def test_manifest_and_evidence_package(db_session, report_fixture):
    """Verify package manifest and complete structured evidence package."""
    proj_a = report_fixture["proj_a"]
    plan_a = report_fixture["plan_a"]
    gate_eval_a = report_fixture["gate_eval_a"]
    service = SecurityReportService(db=db_session)

    report = service.create_report(
        project_id=proj_a.id,
        name="Manifest Package Report",
        source_execution_plan_id=plan_a.id,
        source_gate_evaluation_id=gate_eval_a.id,
    )
    service.generate_report(report.id)

    # 1. Fetch Manifest
    manifest = service.get_manifest(report.id)
    assert manifest["report_id"] == report.id
    assert manifest["report_version"] == 1
    assert manifest["schema_version"] == "1.0"
    assert manifest["integrity_status"] == "VERIFIED"
    assert manifest["object_counts"]["verified_findings"] >= 1
    assert "report.json" in manifest["checksums"]
    assert "package" in manifest["checksums"]

    # 2. Fetch Complete Evidence Package
    pkg = service.get_evidence_package(report.id)
    assert "manifest.json" in pkg
    assert "report.json" in pkg
    assert "findings/" in pkg
    assert "attack-paths/" in pkg
    assert "impact/" in pkg
    assert "evidence/" in pkg
    assert "ai/" in pkg
    assert "human-review/" in pkg
    assert "remediation/" in pkg


# =============================================================================
# 5. ZERO TARGET HTTP CALLS GUARANTEE
# =============================================================================

def test_zero_target_http_calls_during_report_generation(db_session, report_fixture):
    """Report generation must NEVER execute target HTTP requests."""
    proj_a = report_fixture["proj_a"]
    plan_a = report_fixture["plan_a"]
    service = SecurityReportService(db=db_session)

    report = service.create_report(
        project_id=proj_a.id,
        name="Zero HTTP Report",
        source_execution_plan_id=plan_a.id,
    )

    with patch("app.services.security_engine.client.AsyncSecurityHttpClient.execute") as mock_http:
        snapshot = service.generate_report(report.id)
        assert snapshot.checksum is not None
        mock_http.assert_not_called()


# =============================================================================
# 6. REST API INTEGRATION TESTS
# =============================================================================

def test_api_security_report_full_lifecycle(client: TestClient, db_session, report_fixture):
    """Test full CRUD, generation, json download, and manifest retrieval via REST API."""
    proj_a = report_fixture["proj_a"]
    plan_a = report_fixture["plan_a"]
    gate_eval_a = report_fixture["gate_eval_a"]

    # 1. Create Report via API
    resp = client.post(
        f"/api/v1/projects/{proj_a.id}/security-reports",
        json={
            "name": "API Report Test",
            "description": "Report created via REST API",
            "report_type": "SECURITY_ASSESSMENT",
            "source_execution_plan_id": plan_a.id,
            "source_gate_evaluation_id": gate_eval_a.id,
        },
    )
    assert resp.status_code == 201, resp.text
    report_data = resp.json()
    report_id = report_data["id"]
    assert report_data["name"] == "API Report Test"
    assert report_data["status"] == "DRAFT"

    # 2. List Reports
    resp_list = client.get(f"/api/v1/projects/{proj_a.id}/security-reports")
    assert resp_list.status_code == 200
    assert resp_list.json()["count"] >= 1

    # 3. Get Report Detail (Draft)
    resp_get = client.get(f"/api/v1/security-reports/{report_id}")
    assert resp_get.status_code == 200
    assert resp_get.json()["report"]["id"] == report_id

    # 4. Patch Report
    resp_patch = client.patch(
        f"/api/v1/security-reports/{report_id}",
        json={"description": "Updated description via API"},
    )
    assert resp_patch.status_code == 200
    assert resp_patch.json()["description"] == "Updated description via API"

    # 5. Generate Snapshot
    resp_gen = client.post(f"/api/v1/security-reports/{report_id}/generate")
    assert resp_gen.status_code == 200, resp_gen.text
    snap_data = resp_gen.json()
    assert snap_data["version"] == 1
    assert "checksum" in snap_data

    # 6. Get Immutable JSON Snapshot
    resp_json = client.get(f"/api/v1/security-reports/{report_id}/json")
    assert resp_json.status_code == 200
    json_body = resp_json.json()
    assert "executive_summary" in json_body
    assert "verified_findings" in json_body

    # 7. Get Manifest
    resp_manifest = client.get(f"/api/v1/security-reports/{report_id}/manifest")
    assert resp_manifest.status_code == 200
    manifest_data = resp_manifest.json()
    assert manifest_data["integrity_status"] == "VERIFIED"

    # 8. Get Evidence Package
    resp_pkg = client.get(f"/api/v1/security-reports/{report_id}/package")
    assert resp_pkg.status_code == 200
    pkg_data = resp_pkg.json()
    assert "manifest.json" in pkg_data
    assert "report.json" in pkg_data

    # 9. Archive Report
    resp_archive = client.post(f"/api/v1/security-reports/{report_id}/archive")
    assert resp_archive.status_code == 200
    assert resp_archive.json()["status"] == "ARCHIVED"

    # 10. Delete Report
    resp_del = client.delete(f"/api/v1/security-reports/{report_id}")
    assert resp_del.status_code == 200
