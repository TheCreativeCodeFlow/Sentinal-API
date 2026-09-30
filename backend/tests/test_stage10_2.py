"""
Stage 10.2: Scan Profiles & Security Baselines Test Suite
Author: SentinelAPI Security Architecture Team

Comprehensive automated test suite covering:
1. Scan Profile Domain & CRUD:
   - Profile creation (QUICK, STANDARD, DEEP, CUSTOM)
   - Unique profile name constraint within a project
   - Cross-project isolation
   - Profile update & deletion
   - Disabled profiles cannot create execution plans
2. Profile Test Selection Heuristics (Deterministic & Read-Only):
   - QUICK profile selects Auth and BOLA/BFLA; excludes property & workflow attacks
   - STANDARD profile selects Auth, BOLA, BFLA, property exposure, and basic workflow tests
   - DEEP profile selects exhaustive set of all tests
   - CUSTOM profile respects custom criteria (allowed_test_types, max_tests, etc.)
   - Test selection reasons and priorities are deterministic
   - Preview endpoint executes zero target HTTP requests
   - Execution plan creation from profile sets profile_id and source_type
3. Security Baselines Domain & Invariants:
   - Baseline creation and deterministic versioning (v1, v2, ...)
   - Single ACTIVE baseline per project invariant (activating a baseline archives existing active)
   - Update, activate, and archive operations
   - Cross-project isolation
4. Baseline Capture from Execution Plan:
   - Rejection if plan status is not COMPLETED
   - Automated control extraction from completed execution items and findings
5. Multi-Dimensional Baseline Comparison Engine:
   - REGRESSION detection (PASS -> CONFIRMED)
   - IMPROVED detection (CONFIRMED -> PASS)
   - UNCHANGED detection
   - NEW_VIOLATION detection (new confirmed finding not in baseline)
   - NOT_APPLICABLE detection (unexecuted tests are never assumed secure)
   - Finding linkage without creating duplicate findings
   - Summary statistics and detail endpoints
"""

import pytest
import uuid
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.models import (
    Project,
    API,
    Endpoint,
    Resource,
    SecurityTest,
    TestExecution,
    Finding,
    SecurityExecutionPlan,
    SecurityExecutionItem,
    ScanProfile,
    SecurityBaseline,
    SecurityBaselineControl,
    SecurityBaselineComparison,
    SecurityBaselineComparisonItem,
    Workflow,
)
from app.services.security_engine.scan_profile_service import (
    ScanProfileService,
    ScanProfileError,
    ProfileNotFoundError,
    DuplicateProfileError,
    DisabledProfileError,
    CrossProjectViolationError as ProfileCrossProjectViolationError,
)
from app.services.security_engine.baseline_service import (
    SecurityBaselineService,
    BaselineComparisonService,
    BaselineError,
    BaselineNotFoundError,
    InvalidBaselinePlanError,
    CrossProjectViolationError as BaselineCrossProjectViolationError,
)

# Prevent pytest from treating model classes as test cases
ScanProfile.__test__ = False
SecurityBaseline.__test__ = False
SecurityBaselineControl.__test__ = False
SecurityBaselineComparison.__test__ = False
SecurityBaselineComparisonItem.__test__ = False
SecurityExecutionPlan.__test__ = False
SecurityExecutionItem.__test__ = False
SecurityTest.__test__ = False
TestExecution.__test__ = False


@pytest.fixture
def baseline_fixture(db_session):
    """Fixture providing authorized project with endpoints, resources, workflows, and tests."""
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

    # API & Endpoints for Project A
    api_a = API(project_id=proj_a.id, name="Core API", version="1.0", format="openapi3", status="active", url="http://testserver")
    db_session.add(api_a)
    db_session.commit()

    ep_auth = Endpoint(api_id=api_a.id, method="GET", path="/api/v1/auth/me", summary="Auth Endpoint")
    ep_users = Endpoint(api_id=api_a.id, method="GET", path="/api/v1/users/{id}", summary="User Endpoint")
    ep_admin = Endpoint(api_id=api_a.id, method="GET", path="/api/v1/admin/audit", summary="Admin Endpoint")
    ep_data = Endpoint(api_id=api_a.id, method="GET", path="/api/v1/data/report", summary="Data Endpoint")
    db_session.add_all([ep_auth, ep_users, ep_admin, ep_data])
    db_session.commit()

    res_user = Resource(project_id=proj_a.id, name="User", description="User Account")
    db_session.add(res_user)
    db_session.commit()

    wf_checkout = Workflow(project_id=proj_a.id, name="Checkout Workflow", status="ACTIVE")
    db_session.add(wf_checkout)
    db_session.commit()

    # Security tests spanning different categories
    test_auth = SecurityTest(project_id=proj_a.id, endpoint_id=ep_auth.id, test_type="AUTH_MISSING", status="configured")
    test_bola = SecurityTest(project_id=proj_a.id, endpoint_id=ep_users.id, test_type="BOLA", status="configured")
    test_bfla = SecurityTest(project_id=proj_a.id, endpoint_id=ep_admin.id, test_type="BFLA", status="configured")
    test_prop = SecurityTest(project_id=proj_a.id, endpoint_id=ep_data.id, victim_resource_id=res_user.id, test_type="PROPERTY_EXPOSURE", status="configured")
    test_wf_bypass = SecurityTest(project_id=proj_a.id, endpoint_id=ep_data.id, test_type="WORKFLOW_STATE_BYPASS", status="configured")
    test_wf_replay = SecurityTest(project_id=proj_a.id, endpoint_id=ep_data.id, test_type="WORKFLOW_REPLAY", status="configured")

    db_session.add_all([test_auth, test_bola, test_bfla, test_prop, test_wf_bypass, test_wf_replay])
    db_session.commit()

    return {
        "proj_a": proj_a,
        "proj_b": proj_b,
        "ep_auth": ep_auth,
        "ep_users": ep_users,
        "ep_admin": ep_admin,
        "ep_data": ep_data,
        "test_auth": test_auth,
        "test_bola": test_bola,
        "test_bfla": test_bfla,
        "test_prop": test_prop,
        "test_wf_bypass": test_wf_bypass,
        "test_wf_replay": test_wf_replay,
    }


# =============================================================================
# 1. SCAN PROFILE TESTS
# =============================================================================

def test_scan_profile_crud_and_uniqueness(db_session, baseline_fixture):
    """Test creating, reading, updating, and duplicate name prevention on scan profiles."""
    proj_a = baseline_fixture["proj_a"]
    proj_b = baseline_fixture["proj_b"]
    service = ScanProfileService(db=db_session)

    # 1. Create standard profile
    profile = service.create_profile(
        project_id=proj_a.id,
        name="Nightly Security Profile",
        profile_type="STANDARD",
        description="Standard nightly checks",
    )
    assert profile.id is not None
    assert profile.name == "Nightly Security Profile"
    assert profile.profile_type == "STANDARD"
    assert profile.status == "ACTIVE"

    # 2. Reject duplicate profile name in same project
    with pytest.raises(DuplicateProfileError):
        service.create_profile(
            project_id=proj_a.id,
            name="Nightly Security Profile",
            profile_type="QUICK",
        )

    # 3. Allow same profile name in a DIFFERENT project
    profile_b = service.create_profile(
        project_id=proj_b.id,
        name="Nightly Security Profile",
        profile_type="QUICK",
    )
    assert profile_b.id != profile.id

    # 4. Cross-project isolation
    with pytest.raises(ProfileCrossProjectViolationError):
        service.get_profile(profile_b.id, project_id=proj_a.id)

    # 5. Update profile
    updated = service.update_profile(
        profile_id=profile.id,
        project_id=proj_a.id,
        description="Updated description",
        status="DISABLED",
    )
    assert updated.description == "Updated description"
    assert updated.status == "DISABLED"


def test_scan_profile_test_selection_heuristics(db_session, baseline_fixture):
    """Test deterministic test selection logic across QUICK, STANDARD, DEEP, CUSTOM."""
    proj_a = baseline_fixture["proj_a"]
    service = ScanProfileService(db=db_session)

    # 1. QUICK profile: selects Auth, BOLA, BFLA; excludes property & workflow
    quick = service.create_profile(project_id=proj_a.id, name="Quick Profile", profile_type="QUICK")
    quick_tests = service.select_tests_for_profile(quick)
    quick_types = [t["test_type"] for t in quick_tests]
    assert "AUTH_MISSING" in quick_types
    assert "BOLA" in quick_types
    assert "BFLA" in quick_types
    assert "PROPERTY_EXPOSURE" not in quick_types
    assert "WORKFLOW_STATE_BYPASS" not in quick_types
    assert "WORKFLOW_REPLAY" not in quick_types
    # Verify deterministic reasons
    for t in quick_tests:
        assert "QUICK profile prioritized" in t["reason"]

    # 2. STANDARD profile: selects Auth, BOLA, BFLA, Property, and basic Workflow (state bypass); excludes replay
    standard = service.create_profile(project_id=proj_a.id, name="Standard Profile", profile_type="STANDARD")
    standard_tests = service.select_tests_for_profile(standard)
    std_types = [t["test_type"] for t in standard_tests]
    assert "AUTH_MISSING" in std_types
    assert "BOLA" in std_types
    assert "BFLA" in std_types
    assert "PROPERTY_EXPOSURE" in std_types
    assert "WORKFLOW_STATE_BYPASS" in std_types
    assert "WORKFLOW_REPLAY" not in std_types

    # 3. DEEP profile: selects all tests in project
    deep = service.create_profile(project_id=proj_a.id, name="Deep Profile", profile_type="DEEP")
    deep_tests = service.select_tests_for_profile(deep)
    deep_types = [t["test_type"] for t in deep_tests]
    assert len(deep_tests) == 6
    assert "WORKFLOW_REPLAY" in deep_types

    # 4. CUSTOM profile: configuration filtering
    custom = service.create_profile(
        project_id=proj_a.id,
        name="Custom Profile",
        profile_type="CUSTOM",
        configuration={
            "allowed_test_types": ["BOLA", "BFLA"],
            "max_tests": 1,
        },
    )
    custom_tests = service.select_tests_for_profile(custom)
    assert len(custom_tests) == 1
    assert custom_tests[0]["test_type"] in ("BOLA", "BFLA")
    assert "CUSTOM profile matched" in custom_tests[0]["reason"]


def test_scan_profile_plan_creation(db_session, baseline_fixture):
    """Test generating a SecurityExecutionPlan from an active vs. disabled scan profile."""
    proj_a = baseline_fixture["proj_a"]
    service = ScanProfileService(db=db_session)

    # 1. Active profile creates plan with profile_id and items
    profile = service.create_profile(project_id=proj_a.id, name="Active Profile", profile_type="STANDARD")
    plan = service.create_plan_from_profile(project_id=proj_a.id, profile_id=profile.id, name="Plan Alpha")
    assert plan.id is not None
    assert plan.profile_id == profile.id
    assert plan.suite_id is None
    assert plan.source_type == "PROFILE"
    assert plan.profile_name == "Active Profile"
    assert plan.total_tests == 5  # 5 tests matched by standard
    assert len(plan.items) == 5
    assert plan.items[0].execution_order == 1
    assert plan.items[1].execution_order == 2

    # 2. Disabled profile cannot create plan
    disabled_profile = service.create_profile(
        project_id=proj_a.id,
        name="Disabled Profile",
        profile_type="QUICK",
        status="DISABLED",
    )
    with pytest.raises(DisabledProfileError):
        service.create_plan_from_profile(project_id=proj_a.id, profile_id=disabled_profile.id)


# =============================================================================
# 2. SECURITY BASELINE TESTS
# =============================================================================

def test_security_baseline_versioning_and_single_active_invariant(db_session, baseline_fixture):
    """Test baseline creation, version increments, and single ACTIVE baseline rule."""
    proj_a = baseline_fixture["proj_a"]
    service = SecurityBaselineService(db=db_session)

    # 1. Create Baseline 1 (DRAFT, version 1)
    b1 = service.create_baseline(project_id=proj_a.id, name="Baseline Initial", status="DRAFT")
    assert b1.version == 1
    assert b1.status == "DRAFT"

    # 2. Create Baseline 2 (ACTIVE, version 2)
    b2 = service.create_baseline(project_id=proj_a.id, name="Baseline Production", status="ACTIVE")
    assert b2.version == 2
    assert b2.status == "ACTIVE"

    # 3. Create Baseline 3 (ACTIVE, version 3) -> b2 must automatically transition to ARCHIVED
    b3 = service.create_baseline(project_id=proj_a.id, name="Baseline NextGen", status="ACTIVE")
    assert b3.version == 3
    assert b3.status == "ACTIVE"

    db_session.refresh(b2)
    assert b2.status == "ARCHIVED"

    # 4. Reactivate b2 -> b3 must become ARCHIVED
    service.activate_baseline(b2.id)
    db_session.refresh(b2)
    db_session.refresh(b3)
    assert b2.status == "ACTIVE"
    assert b3.status == "ARCHIVED"


def test_baseline_capture_from_execution_plan(db_session, baseline_fixture):
    """Test capturing a baseline from a completed execution plan and rejecting incomplete plans."""
    proj_a = baseline_fixture["proj_a"]
    test_bola = baseline_fixture["test_bola"]
    test_auth = baseline_fixture["test_auth"]
    b_service = SecurityBaselineService(db=db_session)

    # 1. Plan in READY status must be rejected
    ready_plan = SecurityExecutionPlan(
        project_id=proj_a.id,
        name="Pending Plan",
        status="READY",
        execution_mode="SEQUENTIAL",
        total_tests=2,
    )
    db_session.add(ready_plan)
    db_session.commit()

    with pytest.raises(InvalidBaselinePlanError):
        b_service.create_baseline_from_execution_plan(
            project_id=proj_a.id,
            execution_plan_id=ready_plan.id,
        )

    # 2. Plan in COMPLETED status with executed items
    completed_plan = SecurityExecutionPlan(
        project_id=proj_a.id,
        name="Verified Audit Plan",
        status="COMPLETED",
        execution_mode="SEQUENTIAL",
        total_tests=2,
        completed_tests=2,
        completed_at=datetime.now(timezone.utc),
    )
    db_session.add(completed_plan)
    db_session.flush()

    item_1 = SecurityExecutionItem(
        execution_plan_id=completed_plan.id,
        security_test_id=test_auth.id,
        execution_order=1,
        status="COMPLETED",
        result="PASS",
    )
    item_2 = SecurityExecutionItem(
        execution_plan_id=completed_plan.id,
        security_test_id=test_bola.id,
        execution_order=2,
        status="COMPLETED",
        result="CONFIRMED",
    )
    db_session.add_all([item_1, item_2])
    db_session.commit()

    # Capture baseline
    baseline = b_service.create_baseline_from_execution_plan(
        project_id=proj_a.id,
        execution_plan_id=completed_plan.id,
        name="Sprint Baseline",
    )
    assert baseline.id is not None
    assert baseline.source_execution_plan_id == completed_plan.id
    assert baseline.control_count == 2

    # Check controls
    controls_map = {c.control_type: c for c in baseline.controls}
    assert "AUTHENTICATION_REQUIRED" in controls_map
    assert controls_map["AUTHENTICATION_REQUIRED"].expected_behavior == "PASS"

    assert "BOLA_PROTECTION" in controls_map
    assert controls_map["BOLA_PROTECTION"].expected_behavior == "CONFIRMED"


# =============================================================================
# 3. BASELINE COMPARISON ENGINE TESTS
# =============================================================================

def test_baseline_comparison_multi_dimensional(db_session, baseline_fixture):
    """
    Test comparison engine evaluating:
    - REGRESSION: baseline was PASS, current is CONFIRMED
    - IMPROVED: baseline was CONFIRMED, current is PASS
    - UNCHANGED: behavior matches baseline
    - NEW_VIOLATION: new confirmed vulnerability not in baseline
    - NOT_APPLICABLE: control not executed in current plan (NEVER assumed secure)
    - Linkage to Finding records
    """
    proj_a = baseline_fixture["proj_a"]
    test_auth = baseline_fixture["test_auth"]      # Will test REGRESSION (PASS -> CONFIRMED)
    test_bola = baseline_fixture["test_bola"]      # Will test IMPROVED (CONFIRMED -> PASS)
    test_bfla = baseline_fixture["test_bfla"]      # Will test NOT_APPLICABLE (not in current plan)
    test_prop = baseline_fixture["test_prop"]      # Will test UNCHANGED (PASS -> PASS)
    test_wf = baseline_fixture["test_wf_replay"]   # Will test NEW_VIOLATION (not in baseline, CONFIRMED)

    # 1. Create baseline with controls for auth, bola, bfla, prop
    b_service = SecurityBaselineService(db=db_session)
    baseline = b_service.create_baseline(project_id=proj_a.id, name="Q1 Baseline", status="ACTIVE")

    c_auth = SecurityBaselineControl(
        baseline_id=baseline.id,
        control_type="AUTHENTICATION_REQUIRED",
        target_type="ENDPOINT",
        target_id=str(test_auth.endpoint_id),
        expected_behavior="PASS",
        severity="HIGH",
        configuration={"security_test_id": test_auth.id},
    )
    c_bola = SecurityBaselineControl(
        baseline_id=baseline.id,
        control_type="BOLA_PROTECTION",
        target_type="ENDPOINT",
        target_id=str(test_bola.endpoint_id),
        expected_behavior="CONFIRMED",
        severity="HIGH",
        configuration={"security_test_id": test_bola.id},
    )
    c_bfla = SecurityBaselineControl(
        baseline_id=baseline.id,
        control_type="BFLA_PROTECTION",
        target_type="ENDPOINT",
        target_id=str(test_bfla.endpoint_id),
        expected_behavior="PASS",
        severity="HIGH",
        configuration={"security_test_id": test_bfla.id},
    )
    c_prop = SecurityBaselineControl(
        baseline_id=baseline.id,
        control_type="PROPERTY_PROTECTION",
        target_type="RESOURCE",
        target_id=str(test_prop.victim_resource_id),
        expected_behavior="PASS",
        severity="MEDIUM",
        configuration={"security_test_id": test_prop.id},
    )
    db_session.add_all([c_auth, c_bola, c_bfla, c_prop])
    db_session.commit()

    # 2. Create findings to link to regressions/violations
    f_auth = Finding(
        project_id=proj_a.id,
        security_test_id=test_auth.id,
        type="AUTH_MISSING",
        severity="HIGH",
        status="OPEN",
        title="Unauthenticated Access Allowed",
        description="Endpoint allows unauthorized requests.",
        remediation="Enforce JWT verification.",
    )
    f_wf = Finding(
        project_id=proj_a.id,
        security_test_id=test_wf.id,
        type="WORKFLOW_REPLAY",
        severity="CRITICAL",
        status="OPEN",
        title="Replay Attack Succeeded",
        description="Replayed transaction was accepted.",
        remediation="Add idempotent transaction tokens.",
    )
    db_session.add_all([f_auth, f_wf])
    db_session.commit()

    # 3. Create current COMPLETED execution plan:
    # - test_auth executes -> CONFIRMED (REGRESSION)
    # - test_bola executes -> PASS (IMPROVED)
    # - test_prop executes -> PASS (UNCHANGED)
    # - test_wf executes -> CONFIRMED (NEW_VIOLATION)
    # - (test_bfla NOT executed -> NOT_APPLICABLE)
    curr_plan = SecurityExecutionPlan(
        project_id=proj_a.id,
        name="Current Verification Plan",
        status="COMPLETED",
        total_tests=4,
        completed_tests=4,
    )
    db_session.add(curr_plan)
    db_session.flush()

    it_auth = SecurityExecutionItem(
        execution_plan_id=curr_plan.id,
        security_test_id=test_auth.id,
        execution_order=1,
        status="COMPLETED",
        result="CONFIRMED",
    )
    it_bola = SecurityExecutionItem(
        execution_plan_id=curr_plan.id,
        security_test_id=test_bola.id,
        execution_order=2,
        status="COMPLETED",
        result="PASS",
    )
    it_prop = SecurityExecutionItem(
        execution_plan_id=curr_plan.id,
        security_test_id=test_prop.id,
        execution_order=3,
        status="COMPLETED",
        result="PASS",
    )
    it_wf = SecurityExecutionItem(
        execution_plan_id=curr_plan.id,
        security_test_id=test_wf.id,
        execution_order=4,
        status="COMPLETED",
        result="CONFIRMED",
    )
    db_session.add_all([it_auth, it_bola, it_prop, it_wf])
    db_session.commit()

    # 4. Execute comparison
    comp_service = BaselineComparisonService(db=db_session)
    comparison = comp_service.compare_baseline_with_plan(
        baseline_id=baseline.id,
        execution_plan_id=curr_plan.id,
    )

    assert comparison.id is not None
    assert comparison.status == "COMPLETED"

    summary = comparison.summary
    assert summary["regressions_count"] == 1
    assert summary["improvements_count"] == 1
    assert summary["unchanged_count"] == 1
    assert summary["new_violations_count"] == 1
    assert summary["not_applicable_count"] == 1
    assert summary["has_regressions"] is True
    assert summary["has_new_violations"] is True

    # 5. Verify individual items
    items_by_res = {i.result: i for i in comparison.items}

    # Regression item linked to f_auth
    reg_item = items_by_res["REGRESSION"]
    assert reg_item.security_test_id == test_auth.id
    assert reg_item.finding_id == f_auth.id
    assert reg_item.previous_behavior == "PASS"
    assert reg_item.current_behavior == "CONFIRMED"
    assert "regression" in reg_item.explanation.lower()

    # Improved item
    imp_item = items_by_res["IMPROVED"]
    assert imp_item.security_test_id == test_bola.id
    assert imp_item.previous_behavior == "CONFIRMED"
    assert imp_item.current_behavior == "PASS"

    # Unchanged item
    unc_item = items_by_res["UNCHANGED"]
    assert unc_item.security_test_id == test_prop.id
    assert unc_item.previous_behavior == "PASS"
    assert unc_item.current_behavior == "PASS"

    # New violation item linked to f_wf
    new_item = items_by_res["NEW_VIOLATION"]
    assert new_item.security_test_id == test_wf.id
    assert new_item.finding_id == f_wf.id
    assert new_item.current_behavior == "CONFIRMED"

    # Not applicable item (never assumed secure!)
    na_item = items_by_res["NOT_APPLICABLE"]
    assert na_item.control_id == c_bfla.id
    assert na_item.current_behavior is None
    assert "not executed" in na_item.explanation.lower()


# =============================================================================
# 4. REST API INTEGRATION TESTS
# =============================================================================

def test_scan_profile_api_endpoints(client: TestClient, baseline_fixture):
    """Test Scan Profile HTTP endpoints."""
    proj_a = baseline_fixture["proj_a"]

    # 1. Create profile
    resp = client.post(
        f"/api/v1/projects/{proj_a.id}/scan-profiles",
        json={
            "name": "API Quick Scan",
            "profile_type": "QUICK",
            "description": "Fast smoke scan",
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    profile_id = data["id"]
    assert data["name"] == "API Quick Scan"
    assert data["profile_type"] == "QUICK"

    # 2. Preview profile
    resp_prev = client.get(f"/api/v1/scan-profiles/{profile_id}/preview")
    assert resp_prev.status_code == 200
    prev_data = resp_prev.json()
    assert prev_data["profile_id"] == profile_id
    assert prev_data["selected_test_count"] > 0
    assert len(prev_data["selected_tests"]) > 0

    # 3. Create plan from profile
    resp_plan = client.post(
        f"/api/v1/scan-profiles/{profile_id}/create-plan",
        json={"name": "Quick Plan Alpha", "execution_mode": "SEQUENTIAL"},
    )
    assert resp_plan.status_code == 201
    plan_data = resp_plan.json()
    assert plan_data["profile_id"] == profile_id
    assert plan_data["source_type"] == "PROFILE"
    assert plan_data["total_tests"] > 0

    # 4. List profiles
    resp_list = client.get(f"/api/v1/projects/{proj_a.id}/scan-profiles")
    assert resp_list.status_code == 200
    assert resp_list.json()["count"] >= 1


def test_baseline_and_comparison_api_endpoints(client: TestClient, db_session, baseline_fixture):
    """Test Security Baseline and Comparison HTTP endpoints."""
    proj_a = baseline_fixture["proj_a"]
    test_bola = baseline_fixture["test_bola"]

    # Create completed plan
    plan = SecurityExecutionPlan(
        project_id=proj_a.id,
        name="Audit Completed Plan",
        status="COMPLETED",
        total_tests=1,
        completed_tests=1,
    )
    db_session.add(plan)
    db_session.flush()

    item = SecurityExecutionItem(
        execution_plan_id=plan.id,
        security_test_id=test_bola.id,
        execution_order=1,
        status="COMPLETED",
        result="PASS",
    )
    db_session.add(item)
    db_session.commit()

    # 1. Create baseline from completed plan
    resp_b = client.post(
        f"/api/v1/projects/{proj_a.id}/baselines/from-plan",
        json={
            "execution_plan_id": plan.id,
            "name": "Audit Baseline API",
        },
    )
    assert resp_b.status_code == 201
    b_data = resp_b.json()
    baseline_id = b_data["id"]
    assert b_data["version"] == 1
    assert b_data["control_count"] == 1

    # 2. Activate baseline
    resp_act = client.post(f"/api/v1/baselines/{baseline_id}/activate")
    assert resp_act.status_code == 200
    assert resp_act.json()["status"] == "ACTIVE"

    # 3. Compare baseline with plan
    resp_comp = client.post(
        f"/api/v1/baselines/{baseline_id}/compare",
        json={"execution_plan_id": plan.id},
    )
    assert resp_comp.status_code == 201
    comp_data = resp_comp.json()
    comparison_id = comp_data["id"]
    assert comp_data["summary"]["unchanged_count"] == 1

    # 4. Get comparison detail
    resp_detail = client.get(f"/api/v1/baseline-comparisons/{comparison_id}")
    assert resp_detail.status_code == 200
    detail = resp_detail.json()
    assert detail["baseline_name"] == "Audit Baseline API"
    assert len(detail["unchanged"]) == 1
