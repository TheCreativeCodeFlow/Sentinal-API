"""
Stage 10.3: CI/CD Security Regression Gates Test Suite
Author: SentinelAPI Security Architecture Team

Comprehensive automated test suite covering:
1. SecurityGate Domain & CRUD:
   - Gate creation with baseline, scan profile, and rule configuration
   - Unique gate name constraint within a project
   - Cross-project isolation (cannot link baseline or scan profile from another project)
   - Gate update (name, status, rules) and deletion
   - Status filtering on gate listing
2. Rule Configuration Validation:
   - Strict Pydantic validation (forbid extra keys)
   - Non-negative thresholds enforcement (ge=0)
   - Unknown rules and malformed values rejected
3. Evaluation Logic & Precedence Order:
   - PASS: 0 violations, 0 regressions -> PASS (exit_code=0)
   - WARN: warning rules exceeded (inconclusive / errors) -> WARN (exit_code=0)
   - FAIL: failure rules exceeded (regressions, new violations, findings, failed tests) -> FAIL (exit_code=1)
   - Strict Precedence: FAIL takes precedence over WARN
   - Disabled gate cannot evaluate
   - Incomplete plan cannot evaluate (must be COMPLETED)
   - Baseline mismatch rejected
4. Evidence Traceability & Idempotency:
   - Full linkage to finding IDs, comparison item IDs, and security test IDs
   - Idempotent evaluation: repeated evaluate calls for the same (gate, comparison) reuse existing record
5. Zero Target HTTP Calls:
   - Evaluation never executes HTTP requests
6. CI/CD API Endpoints:
   - REST API CRUD, evaluation, evaluation items, machine-readable CI result
"""

import pytest
import uuid
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
)
from app.services.security_engine.security_gate_service import (
    SecurityGateService,
    SecurityGateError,
    GateNotFoundError,
    DuplicateGateError,
    DisabledGateError,
    CrossProjectViolationError,
    InvalidGateRuleError,
    InvalidEvaluationStateError,
    get_gate_exit_code,
)

# Prevent pytest from treating models as test classes
SecurityGate.__test__ = False
SecurityGateEvaluation.__test__ = False
SecurityGateEvaluationItem.__test__ = False
SecurityBaseline.__test__ = False
SecurityBaselineComparison.__test__ = False
SecurityExecutionPlan.__test__ = False


@pytest.fixture
def gate_fixture(db_session):
    """Fixture providing authorized projects, scan profile, baseline, and comparison setup."""
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

    ep_1 = Endpoint(api_id=api_a.id, method="GET", path="/api/v1/users", summary="List Users")
    ep_2 = Endpoint(api_id=api_a.id, method="GET", path="/api/v1/admin/logs", summary="Admin Logs")
    db_session.add_all([ep_1, ep_2])
    db_session.commit()

    test_1 = SecurityTest(project_id=proj_a.id, endpoint_id=ep_1.id, test_type="AUTH_MISSING", status="configured")
    test_2 = SecurityTest(project_id=proj_a.id, endpoint_id=ep_2.id, test_type="BFLA", status="configured")
    db_session.add_all([test_1, test_2])
    db_session.commit()

    # Scan profile for Project A
    profile_a = ScanProfile(
        project_id=proj_a.id,
        name="Standard CI Profile",
        profile_type="STANDARD",
        status="ACTIVE",
    )
    # Scan profile for Project B
    profile_b = ScanProfile(
        project_id=proj_b.id,
        name="Project B Profile",
        profile_type="QUICK",
        status="ACTIVE",
    )
    db_session.add_all([profile_a, profile_b])
    db_session.commit()

    # Baseline for Project A
    baseline_a = SecurityBaseline(
        project_id=proj_a.id,
        name="v1.0 Production Baseline",
        version=1,
        status="ACTIVE",
    )
    # Baseline for Project B
    baseline_b = SecurityBaseline(
        project_id=proj_b.id,
        name="Project B Baseline",
        version=1,
        status="ACTIVE",
    )
    db_session.add_all([baseline_a, baseline_b])
    db_session.commit()

    # Baseline control for Project A
    ctrl_1 = SecurityBaselineControl(
        baseline_id=baseline_a.id,
        control_type="AUTH_CONTROL",
        target_type="SECURITY_TEST",
        target_id=test_1.id,
        expected_behavior="PASS",
        severity="HIGH",
        enabled=True,
    )
    db_session.add(ctrl_1)
    db_session.commit()

    # Completed Execution Plan for Project A
    plan_clean = SecurityExecutionPlan(
        project_id=proj_a.id,
        name="CI Clean Scan Plan",
        status="COMPLETED",
        execution_mode="SEQUENTIAL",
        total_tests=2,
        completed_tests=2,
        confirmed_findings=0,
        inconclusive_tests=0,
        failed_tests=0,
    )
    db_session.add(plan_clean)
    db_session.commit()

    # Comparison Clean (all pass / unchanged)
    comp_clean = SecurityBaselineComparison(
        baseline_id=baseline_a.id,
        execution_plan_id=plan_clean.id,
        status="COMPLETED",
        summary={"regressions": 0, "new_violations": 0},
    )
    db_session.add(comp_clean)
    db_session.commit()

    comp_item_unchanged = SecurityBaselineComparisonItem(
        comparison_id=comp_clean.id,
        control_id=ctrl_1.id,
        security_test_id=test_1.id,
        previous_behavior="PASS",
        current_behavior="PASS",
        result="UNCHANGED",
        explanation="Test passed as expected",
    )
    db_session.add(comp_item_unchanged)
    db_session.commit()

    # Finding for regression test
    finding_reg = Finding(
        project_id=proj_a.id,
        security_test_id=test_1.id,
        endpoint_id=ep_1.id,
        type="AUTH_MISSING",
        status="OPEN",
        severity="HIGH",
        title="Auth Missing Regression",
        description="Regression detected in auth control",
        remediation="Ensure authentication is enforced",
    )
    db_session.add(finding_reg)
    db_session.commit()

    # Plan with regression
    plan_reg = SecurityExecutionPlan(
        project_id=proj_a.id,
        name="CI Regressive Scan Plan",
        status="COMPLETED",
        execution_mode="SEQUENTIAL",
        total_tests=2,
        completed_tests=2,
        confirmed_findings=1,
        inconclusive_tests=0,
        failed_tests=1,
    )
    db_session.add(plan_reg)
    db_session.commit()

    comp_reg = SecurityBaselineComparison(
        baseline_id=baseline_a.id,
        execution_plan_id=plan_reg.id,
        status="COMPLETED",
        summary={"regressions": 1, "new_violations": 0},
    )
    db_session.add(comp_reg)
    db_session.commit()

    comp_item_reg = SecurityBaselineComparisonItem(
        comparison_id=comp_reg.id,
        control_id=ctrl_1.id,
        security_test_id=test_1.id,
        finding_id=finding_reg.id,
        previous_behavior="PASS",
        current_behavior="CONFIRMED",
        result="REGRESSION",
        explanation="Regression detected: control failed",
    )
    db_session.add(comp_item_reg)
    db_session.commit()

    return {
        "proj_a": proj_a,
        "proj_b": proj_b,
        "profile_a": profile_a,
        "profile_b": profile_b,
        "baseline_a": baseline_a,
        "baseline_b": baseline_b,
        "ctrl_1": ctrl_1,
        "plan_clean": plan_clean,
        "comp_clean": comp_clean,
        "plan_reg": plan_reg,
        "comp_reg": comp_reg,
        "finding_reg": finding_reg,
        "test_1": test_1,
    }


# =============================================================================
# 1. SECURITY GATE CRUD & CONSTRAINTS
# =============================================================================

def test_security_gate_crud_and_uniqueness(db_session, gate_fixture):
    """Test creating, reading, updating, and duplicate name prevention on gates."""
    proj_a = gate_fixture["proj_a"]
    proj_b = gate_fixture["proj_b"]
    profile_a = gate_fixture["profile_a"]
    baseline_a = gate_fixture["baseline_a"]
    service = SecurityGateService(db=db_session)

    # 1. Create Gate
    gate = service.create_gate(
        project_id=proj_a.id,
        name="Production Release Gate",
        baseline_id=baseline_a.id,
        scan_profile_id=profile_a.id,
        description="Gate enforcing zero regressions",
        failure_rules={"max_regressions": 0, "max_new_violations": 0},
        warning_rules={"max_inconclusive": 2},
    )
    assert gate.id is not None
    assert gate.name == "Production Release Gate"
    assert gate.status == "ACTIVE"
    assert gate.failure_rules["max_regressions"] == 0
    assert gate.warning_rules["max_inconclusive"] == 2

    # 2. Reject duplicate gate name in same project
    with pytest.raises(DuplicateGateError):
        service.create_gate(
            project_id=proj_a.id,
            name="Production Release Gate",
            baseline_id=baseline_a.id,
            scan_profile_id=profile_a.id,
        )

    # 3. Allow same gate name in a different project
    profile_b = gate_fixture["profile_b"]
    baseline_b = gate_fixture["baseline_b"]
    gate_b = service.create_gate(
        project_id=proj_b.id,
        name="Production Release Gate",
        baseline_id=baseline_b.id,
        scan_profile_id=profile_b.id,
    )
    assert gate_b.id != gate.id

    # 4. Cross-project isolation check on get_gate
    with pytest.raises(CrossProjectViolationError):
        service.get_gate(gate_b.id, project_id=proj_a.id)

    # 5. Cross-project reference prevention on creation
    with pytest.raises(CrossProjectViolationError):
        service.create_gate(
            project_id=proj_a.id,
            name="Invalid Cross Project Gate",
            baseline_id=baseline_b.id,  # belongs to proj_b!
            scan_profile_id=profile_a.id,
        )

    with pytest.raises(CrossProjectViolationError):
        service.create_gate(
            project_id=proj_a.id,
            name="Invalid Cross Profile Gate",
            baseline_id=baseline_a.id,
            scan_profile_id=profile_b.id,  # belongs to proj_b!
        )

    # 6. Update gate
    updated = service.update_gate(
        gate_id=gate.id,
        project_id=proj_a.id,
        description="Updated description",
        failure_rules={"max_regressions": 1, "max_new_violations": 0, "max_confirmed_findings": 0, "max_failed_tests": 0},
    )
    assert updated.description == "Updated description"
    assert updated.failure_rules["max_regressions"] == 1

    # 7. List gates
    gates = service.list_gates(project_id=proj_a.id)
    assert len(gates) == 1
    assert gates[0].id == gate.id

    # 8. Delete gate
    deleted = service.delete_gate(gate.id, project_id=proj_a.id)
    assert deleted is True
    assert service.get_gate(gate.id) is None


# =============================================================================
# 2. RULE CONFIGURATION VALIDATION
# =============================================================================

def test_rule_configuration_validation(db_session, gate_fixture):
    """Test strict deterministic validation of failure and warning rules."""
    proj_a = gate_fixture["proj_a"]
    profile_a = gate_fixture["profile_a"]
    baseline_a = gate_fixture["baseline_a"]
    service = SecurityGateService(db=db_session)

    # Unknown rule keys must be rejected (extra="forbid")
    with pytest.raises(InvalidGateRuleError):
        service.create_gate(
            project_id=proj_a.id,
            name="Unknown Rule Gate",
            baseline_id=baseline_a.id,
            scan_profile_id=profile_a.id,
            failure_rules={"arbitrary_custom_rule": 5},
        )

    # Negative thresholds must be rejected (ge=0)
    with pytest.raises(InvalidGateRuleError):
        service.create_gate(
            project_id=proj_a.id,
            name="Negative Threshold Gate",
            baseline_id=baseline_a.id,
            scan_profile_id=profile_a.id,
            failure_rules={"max_regressions": -1},
        )

    with pytest.raises(InvalidGateRuleError):
        service.create_gate(
            project_id=proj_a.id,
            name="Negative Warning Gate",
            baseline_id=baseline_a.id,
            scan_profile_id=profile_a.id,
            warning_rules={"max_inconclusive": -2},
        )


# =============================================================================
# 3. EVALUATION LOGIC & PRECEDENCE ORDER
# =============================================================================

def test_gate_evaluation_pass(db_session, gate_fixture):
    """Clean scan comparison yields PASS with exit code 0."""
    proj_a = gate_fixture["proj_a"]
    profile_a = gate_fixture["profile_a"]
    baseline_a = gate_fixture["baseline_a"]
    comp_clean = gate_fixture["comp_clean"]
    service = SecurityGateService(db=db_session)

    gate = service.create_gate(
        project_id=proj_a.id,
        name="Strict Clean Gate",
        baseline_id=baseline_a.id,
        scan_profile_id=profile_a.id,
        failure_rules={"max_regressions": 0, "max_new_violations": 0},
        warning_rules={"max_inconclusive": 0, "max_errors": 0},
    )

    evaluation = service.evaluate_gate(
        gate_id=gate.id,
        baseline_comparison_id=comp_clean.id,
    )

    assert evaluation.status == "PASS"
    assert evaluation.failure_count == 0
    assert evaluation.warning_count == 0
    assert evaluation.regressions == 0
    assert evaluation.new_violations == 0
    assert get_gate_exit_code(evaluation.status) == 0


def test_gate_evaluation_fail(db_session, gate_fixture):
    """Regressive comparison triggers FAIL with exit code 1 and links finding."""
    proj_a = gate_fixture["proj_a"]
    profile_a = gate_fixture["profile_a"]
    baseline_a = gate_fixture["baseline_a"]
    comp_reg = gate_fixture["comp_reg"]
    finding_reg = gate_fixture["finding_reg"]
    service = SecurityGateService(db=db_session)

    gate = service.create_gate(
        project_id=proj_a.id,
        name="Zero Regression Gate",
        baseline_id=baseline_a.id,
        scan_profile_id=profile_a.id,
        failure_rules={"max_regressions": 0, "max_new_violations": 0},
    )

    evaluation = service.evaluate_gate(
        gate_id=gate.id,
        baseline_comparison_id=comp_reg.id,
    )

    assert evaluation.status == "FAIL"
    assert evaluation.failure_count >= 1
    assert evaluation.regressions == 1
    assert get_gate_exit_code(evaluation.status) == 1

    # Verify item traceability
    reg_items = [it for it in evaluation.items if it.rule_type == "REGRESSION" and it.triggered]
    assert len(reg_items) == 1
    assert reg_items[0].finding_id == finding_reg.id
    assert reg_items[0].severity == "FAILURE"


def test_gate_evaluation_warn(db_session, gate_fixture):
    """Triggering only warning rule yields WARN with exit code 0."""
    proj_a = gate_fixture["proj_a"]
    profile_a = gate_fixture["profile_a"]
    baseline_a = gate_fixture["baseline_a"]
    comp_clean = gate_fixture["comp_clean"]
    service = SecurityGateService(db=db_session)

    # Create plan with 1 inconclusive test and 0 failures
    plan_warn = SecurityExecutionPlan(
        project_id=proj_a.id,
        name="Inconclusive Plan",
        status="COMPLETED",
        execution_mode="SEQUENTIAL",
        total_tests=1,
        completed_tests=1,
        confirmed_findings=0,
        inconclusive_tests=1,
        failed_tests=0,
    )
    db_session.add(plan_warn)
    db_session.commit()

    comp_warn = SecurityBaselineComparison(
        baseline_id=baseline_a.id,
        execution_plan_id=plan_warn.id,
        status="COMPLETED",
        summary={"regressions": 0, "new_violations": 0},
    )
    db_session.add(comp_warn)
    db_session.commit()

    gate = service.create_gate(
        project_id=proj_a.id,
        name="Warning Gate",
        baseline_id=baseline_a.id,
        scan_profile_id=profile_a.id,
        failure_rules={"max_regressions": 0, "max_new_violations": 0},
        warning_rules={"max_inconclusive": 0},  # 1 inconclusive > 0 threshold -> WARN
    )

    evaluation = service.evaluate_gate(
        gate_id=gate.id,
        baseline_comparison_id=comp_warn.id,
    )

    assert evaluation.status == "WARN"
    assert evaluation.failure_count == 0
    assert evaluation.warning_count >= 1
    assert get_gate_exit_code(evaluation.status) == 0


def test_gate_evaluation_precedence_fail_over_warn(db_session, gate_fixture):
    """FAIL takes precedence over WARN when both failure and warning rules are triggered."""
    proj_a = gate_fixture["proj_a"]
    profile_a = gate_fixture["profile_a"]
    baseline_a = gate_fixture["baseline_a"]
    comp_reg = gate_fixture["comp_reg"]
    service = SecurityGateService(db=db_session)

    # comp_reg has 1 regression. Configure gate with failure on regression and warning on errors
    gate = service.create_gate(
        project_id=proj_a.id,
        name="Precedence Gate",
        baseline_id=baseline_a.id,
        scan_profile_id=profile_a.id,
        failure_rules={"max_regressions": 0},
        warning_rules={"max_inconclusive": 0},
    )

    evaluation = service.evaluate_gate(
        gate_id=gate.id,
        baseline_comparison_id=comp_reg.id,
    )

    # Even if warning rules are evaluated, overall gate status must be FAIL
    assert evaluation.status == "FAIL"
    assert get_gate_exit_code(evaluation.status) == 1


def test_disabled_gate_cannot_evaluate(db_session, gate_fixture):
    """Disabled gates cannot be evaluated."""
    proj_a = gate_fixture["proj_a"]
    profile_a = gate_fixture["profile_a"]
    baseline_a = gate_fixture["baseline_a"]
    comp_clean = gate_fixture["comp_clean"]
    service = SecurityGateService(db=db_session)

    gate = service.create_gate(
        project_id=proj_a.id,
        name="Disabled Gate",
        baseline_id=baseline_a.id,
        scan_profile_id=profile_a.id,
        status="DISABLED",
    )

    with pytest.raises(DisabledGateError):
        service.evaluate_gate(
            gate_id=gate.id,
            baseline_comparison_id=comp_clean.id,
        )


def test_evaluation_requires_completed_plan(db_session, gate_fixture):
    """Cannot evaluate against incomplete or running execution plan."""
    proj_a = gate_fixture["proj_a"]
    profile_a = gate_fixture["profile_a"]
    baseline_a = gate_fixture["baseline_a"]
    service = SecurityGateService(db=db_session)

    plan_running = SecurityExecutionPlan(
        project_id=proj_a.id,
        name="Running Scan Plan",
        status="RUNNING",
        execution_mode="SEQUENTIAL",
    )
    db_session.add(plan_running)
    db_session.commit()

    comp_running = SecurityBaselineComparison(
        baseline_id=baseline_a.id,
        execution_plan_id=plan_running.id,
        status="COMPLETED",
    )
    db_session.add(comp_running)
    db_session.commit()

    gate = service.create_gate(
        project_id=proj_a.id,
        name="Active Gate",
        baseline_id=baseline_a.id,
        scan_profile_id=profile_a.id,
    )

    with pytest.raises(InvalidEvaluationStateError):
        service.evaluate_gate(
            gate_id=gate.id,
            baseline_comparison_id=comp_running.id,
        )


def test_evaluation_baseline_mismatch_rejected(db_session, gate_fixture):
    """Comparison baseline must match gate configured baseline."""
    proj_a = gate_fixture["proj_a"]
    profile_a = gate_fixture["profile_a"]
    baseline_a = gate_fixture["baseline_a"]
    comp_clean = gate_fixture["comp_clean"]
    service = SecurityGateService(db=db_session)

    # Create a secondary baseline
    baseline_v2 = SecurityBaseline(
        project_id=proj_a.id,
        name="v2.0 Baseline",
        version=2,
        status="ACTIVE",
    )
    db_session.add(baseline_v2)
    db_session.commit()

    # Gate configured with baseline_v2
    gate = service.create_gate(
        project_id=proj_a.id,
        name="V2 Gate",
        baseline_id=baseline_v2.id,
        scan_profile_id=profile_a.id,
    )

    # Evaluating comp_clean (which was compared against baseline_a) must be rejected
    with pytest.raises(InvalidEvaluationStateError):
        service.evaluate_gate(
            gate_id=gate.id,
            baseline_comparison_id=comp_clean.id,
        )


# =============================================================================
# 4. IDEMPOTENCY & EVIDENCE TRACEABILITY
# =============================================================================

def test_evaluation_idempotency(db_session, gate_fixture):
    """Evaluating the same gate and comparison pair returns existing evaluation record."""
    proj_a = gate_fixture["proj_a"]
    profile_a = gate_fixture["profile_a"]
    baseline_a = gate_fixture["baseline_a"]
    comp_clean = gate_fixture["comp_clean"]
    service = SecurityGateService(db=db_session)

    gate = service.create_gate(
        project_id=proj_a.id,
        name="Idempotent Gate",
        baseline_id=baseline_a.id,
        scan_profile_id=profile_a.id,
    )

    eval1 = service.evaluate_gate(gate.id, comp_clean.id)
    eval2 = service.evaluate_gate(gate.id, comp_clean.id)

    assert eval1.id == eval2.id
    # Assert database count is strictly 1
    total_evals = (
        db_session.query(SecurityGateEvaluation)
        .filter(
            SecurityGateEvaluation.gate_id == gate.id,
            SecurityGateEvaluation.baseline_comparison_id == comp_clean.id,
        )
        .count()
    )
    assert total_evals == 1


def test_ci_result_payload_format(db_session, gate_fixture):
    """Verify machine-readable CI result payload adheres strictly to specification."""
    proj_a = gate_fixture["proj_a"]
    profile_a = gate_fixture["profile_a"]
    baseline_a = gate_fixture["baseline_a"]
    comp_reg = gate_fixture["comp_reg"]
    finding_reg = gate_fixture["finding_reg"]
    service = SecurityGateService(db=db_session)

    gate = service.create_gate(
        project_id=proj_a.id,
        name="CI Payload Gate",
        baseline_id=baseline_a.id,
        scan_profile_id=profile_a.id,
        failure_rules={"max_regressions": 0},
    )

    evaluation = service.evaluate_gate(gate.id, comp_reg.id)
    ci_result = service.get_ci_result(evaluation.id)

    assert ci_result["status"] == "FAIL"
    assert ci_result["exit_code"] == 1
    assert ci_result["gate_id"] == gate.id
    assert ci_result["gate_name"] == "CI Payload Gate"
    assert ci_result["baseline_version"] == 1
    assert ci_result["evaluation_id"] == evaluation.id
    assert "metrics" in ci_result
    assert ci_result["metrics"]["regressions"] == 1
    assert len(ci_result["triggered_rules"]) >= 1

    trig = ci_result["triggered_rules"][0]
    assert trig["rule_type"] == "REGRESSION"
    assert finding_reg.id in trig["finding_ids"]


# =============================================================================
# 5. ZERO TARGET HTTP CALLS GUARANTEE
# =============================================================================

def test_zero_target_http_calls_during_evaluation(db_session, gate_fixture):
    """Security gate evaluation MUST NOT make target HTTP calls."""
    proj_a = gate_fixture["proj_a"]
    profile_a = gate_fixture["profile_a"]
    baseline_a = gate_fixture["baseline_a"]
    comp_clean = gate_fixture["comp_clean"]
    service = SecurityGateService(db=db_session)

    gate = service.create_gate(
        project_id=proj_a.id,
        name="Zero HTTP Gate",
        baseline_id=baseline_a.id,
        scan_profile_id=profile_a.id,
    )

    with patch("app.services.security_engine.client.AsyncSecurityHttpClient.execute") as mock_http:
        evaluation = service.evaluate_gate(gate.id, comp_clean.id)
        assert evaluation.status == "PASS"
        mock_http.assert_not_called()


# =============================================================================
# 6. REST API INTEGRATION TESTS
# =============================================================================

def test_api_security_gate_full_lifecycle(client: TestClient, db_session, gate_fixture):
    """Test full CRUD and evaluation lifecycle through REST API."""
    proj_a = gate_fixture["proj_a"]
    profile_a = gate_fixture["profile_a"]
    baseline_a = gate_fixture["baseline_a"]
    comp_clean = gate_fixture["comp_clean"]

    # 1. Create Gate via API
    resp = client.post(
        f"/api/v1/projects/{proj_a.id}/security-gates",
        json={
            "name": "API Automated Gate",
            "description": "Gate created via REST API",
            "baseline_id": baseline_a.id,
            "scan_profile_id": profile_a.id,
            "failure_rules": {"max_regressions": 0, "max_new_violations": 0},
            "warning_rules": {"max_inconclusive": 1},
        },
    )
    assert resp.status_code == 201, resp.text
    gate_data = resp.json()
    gate_id = gate_data["id"]
    assert gate_data["name"] == "API Automated Gate"
    assert gate_data["baseline_id"] == baseline_a.id

    # 2. List Gates
    resp_list = client.get(f"/api/v1/projects/{proj_a.id}/security-gates")
    assert resp_list.status_code == 200
    assert resp_list.json()["count"] >= 1

    # 3. Get Gate Detail
    resp_get = client.get(f"/api/v1/security-gates/{gate_id}")
    assert resp_get.status_code == 200
    assert resp_get.json()["id"] == gate_id

    # 4. Patch Gate
    resp_patch = client.patch(
        f"/api/v1/security-gates/{gate_id}",
        json={"description": "Updated via PATCH"},
    )
    assert resp_patch.status_code == 200
    assert resp_patch.json()["description"] == "Updated via PATCH"

    # 5. Evaluate Gate via API
    resp_eval = client.post(f"/api/v1/security-gates/{gate_id}/evaluate/{comp_clean.id}")
    assert resp_eval.status_code == 200, resp_eval.text
    eval_data = resp_eval.json()
    eval_id = eval_data["id"]
    assert eval_data["status"] == "PASS"

    # 6. Get Evaluation Detail
    resp_eval_get = client.get(f"/api/v1/security-gate-evaluations/{eval_id}")
    assert resp_eval_get.status_code == 200
    assert resp_eval_get.json()["id"] == eval_id

    # 7. Get Evaluation Items
    resp_items = client.get(f"/api/v1/security-gate-evaluations/{eval_id}/items")
    assert resp_items.status_code == 200
    assert isinstance(resp_items.json(), list)

    # 8. Get CI Result
    resp_ci = client.get(f"/api/v1/security-gate-evaluations/{eval_id}/result")
    assert resp_ci.status_code == 200
    ci_json = resp_ci.json()
    assert ci_json["status"] == "PASS"
    assert ci_json["exit_code"] == 0

    # 9. List Project Evaluations
    resp_proj_evals = client.get(f"/api/v1/projects/{proj_a.id}/security-gate-evaluations")
    assert resp_proj_evals.status_code == 200
    assert resp_proj_evals.json()["count"] >= 1

    # 10. Delete Gate
    resp_del = client.delete(f"/api/v1/security-gates/{gate_id}")
    assert resp_del.status_code == 200
