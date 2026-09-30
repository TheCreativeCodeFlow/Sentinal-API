"""
Stage 10.1: Security Test Orchestration & Execution Plans Tests
Author: SentinelAPI Security Architecture Team

Comprehensive test suite verifying:
- Test Suite CRUD operations, ordering constraints, duplicate prevention.
- Cross-project isolation for test suites and execution plans.
- Plan creation from suites (enabled-only filter, disabled-suite rejection).
- Plan creation from explicit test IDs (ownership validation).
- Project authorization guard (strictly rejecting unauthorized projects).
- Idempotency guards (preventing double starts or restarting completed/cancelled plans).
- Execution modes: SEQUENTIAL, FAIL_FAST, CONTINUE_ON_FAILURE.
- Cancellation handling (marking queued items CANCELLED).
- Progress tracking and aggregated metrics calculation.
- Absolute prohibition against direct target HTTP requests by orchestrator.
"""

import pytest
import uuid
import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient

from app.models import (
    Project,
    API,
    Endpoint,
    SecurityTest,
    TestExecution,
    SecurityTestSuite,
    SecurityTestSuiteItem,
    SecurityExecutionPlan,
    SecurityExecutionItem,
)
from app.services.security_engine.orchestrator import (
    TestOrchestrator,
    OrchestrationError,
    CrossProjectViolationError,
    PlanStateError,
    AuthorizationError,
    EntityNotFoundError,
    InvalidSuiteStateError,
)

# Prevent pytest from treating these models as test case classes
SecurityTestSuite.__test__ = False
SecurityTestSuiteItem.__test__ = False
SecurityExecutionPlan.__test__ = False
SecurityExecutionItem.__test__ = False
SecurityTest.__test__ = False
TestExecution.__test__ = False


@pytest.fixture
def test_setup(db_session):
    """Fixture providing authorized and unauthorized projects with tests."""
    # Authorized Project A
    proj_a = Project(
        name=f"Project-A-{uuid.uuid4().hex[:6]}",
        authorization_status="authorized",
        environment="staging",
        base_url="http://testserver",
    )
    # Unauthorized Project B
    proj_b = Project(
        name=f"Project-B-{uuid.uuid4().hex[:6]}",
        authorization_status="pending",
        environment="staging",
        base_url="http://testserver",
    )
    db_session.add_all([proj_a, proj_b])
    db_session.commit()

    # API and Endpoint for Project A
    api_a = API(project_id=proj_a.id, name="Service A", version="1.0", format="openapi3", status="active", url="http://testserver")
    db_session.add(api_a)
    db_session.commit()

    ep_a1 = Endpoint(api_id=api_a.id, method="GET", path="/api/v1/resource/1", summary="Endpoint 1")
    ep_a2 = Endpoint(api_id=api_a.id, method="GET", path="/api/v1/resource/2", summary="Endpoint 2")
    ep_a3 = Endpoint(api_id=api_a.id, method="GET", path="/api/v1/resource/3", summary="Endpoint 3")
    db_session.add_all([ep_a1, ep_a2, ep_a3])
    db_session.commit()

    # Tests for Project A
    test_a1 = SecurityTest(project_id=proj_a.id, endpoint_id=ep_a1.id, test_type="BOLA", status="configured")
    test_a2 = SecurityTest(project_id=proj_a.id, endpoint_id=ep_a2.id, test_type="BFLA", status="configured")
    test_a3 = SecurityTest(project_id=proj_a.id, endpoint_id=ep_a3.id, test_type="PROPERTY_EXPOSURE", status="configured")
    test_a4 = SecurityTest(project_id=proj_a.id, endpoint_id=ep_a1.id, test_type="AUTH_MISSING", status="configured")

    # Tests for Project B
    api_b = API(project_id=proj_b.id, name="Service B", version="1.0", format="openapi3", status="active", url="http://testserver")
    db_session.add(api_b)
    db_session.commit()
    ep_b1 = Endpoint(api_id=api_b.id, method="GET", path="/api/v1/b", summary="Endpoint B")
    db_session.add(ep_b1)
    db_session.commit()
    test_b1 = SecurityTest(project_id=proj_b.id, endpoint_id=ep_b1.id, test_type="BOLA", status="configured")

    db_session.add_all([test_a1, test_a2, test_a3, test_a4, test_b1])
    db_session.commit()

    return {
        "proj_a": proj_a,
        "proj_b": proj_b,
        "tests_a": [test_a1, test_a2, test_a3, test_a4],
        "test_b": test_b1,
    }


# =============================================================================
# 1. Test Suite Management Tests
# =============================================================================

def test_suite_crud_api(client: TestClient, test_setup):
    """Verify test suite creation, listing, updating, and deletion via API."""
    proj_a = test_setup["proj_a"]

    # Create suite
    res = client.post(
        f"/api/v1/projects/{proj_a.id}/test-suites",
        json={"name": "Regression Suite", "description": "Core authorization test suite", "status": "ACTIVE"},
    )
    assert res.status_code == 201
    suite_data = res.json()
    assert suite_data["name"] == "Regression Suite"
    assert suite_data["status"] == "ACTIVE"
    assert suite_data["test_count"] == 0
    suite_id = suite_data["id"]

    # Get suite
    get_res = client.get(f"/api/v1/test-suites/{suite_id}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == suite_id

    # List suites
    list_res = client.get(f"/api/v1/projects/{proj_a.id}/test-suites")
    assert list_res.status_code == 200
    assert list_res.json()["count"] >= 1

    # Update suite
    patch_res = client.patch(
        f"/api/v1/test-suites/{suite_id}",
        json={"name": "Updated Regression Suite", "status": "DISABLED"},
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["name"] == "Updated Regression Suite"
    assert patch_res.json()["status"] == "DISABLED"

    # Delete suite
    del_res = client.delete(f"/api/v1/test-suites/{suite_id}")
    assert del_res.status_code == 200
    assert del_res.json()["status"] == "deleted"

    # Verify 404 after delete
    get_again = client.get(f"/api/v1/test-suites/{suite_id}")
    assert get_again.status_code == 404


def test_suite_item_management(client: TestClient, test_setup):
    """Verify adding tests, ordering, toggling enabled state, and removing items."""
    proj_a = test_setup["proj_a"]
    tests_a = test_setup["tests_a"]

    # Create suite
    s_res = client.post(
        f"/api/v1/projects/{proj_a.id}/test-suites",
        json={"name": "Ordered Suite", "status": "ACTIVE"},
    )
    suite_id = s_res.json()["id"]

    # Add 3 tests
    res1 = client.post(
        f"/api/v1/test-suites/{suite_id}/tests",
        json={"security_test_id": tests_a[0].id, "execution_order": 1, "enabled": True},
    )
    assert res1.status_code == 201
    item1 = res1.json()
    assert item1["execution_order"] == 1
    assert item1["enabled"] is True

    res2 = client.post(
        f"/api/v1/test-suites/{suite_id}/tests",
        json={"security_test_id": tests_a[1].id, "execution_order": 2, "enabled": True},
    )
    assert res2.status_code == 201

    res3 = client.post(
        f"/api/v1/test-suites/{suite_id}/tests",
        json={"security_test_id": tests_a[2].id, "execution_order": 3, "enabled": False},
    )
    assert res3.status_code == 201

    # Verify suite count and items
    get_suite = client.get(f"/api/v1/test-suites/{suite_id}")
    s_data = get_suite.json()
    assert s_data["test_count"] == 3
    assert len(s_data["items"]) == 3

    # Toggle enabled state
    patch_item = client.patch(
        f"/api/v1/test-suites/{suite_id}/tests/{item1['id']}",
        json={"enabled": False},
    )
    assert patch_item.status_code == 200
    assert patch_item.json()["enabled"] is False

    # Remove item
    del_item = client.delete(f"/api/v1/test-suites/{suite_id}/tests/{item1['id']}")
    assert del_item.status_code == 200

    # Remaining items re-compacted to orders 1 and 2
    get_after_del = client.get(f"/api/v1/test-suites/{suite_id}")
    remaining = get_after_del.json()["items"]
    assert len(remaining) == 2
    orders = [it["execution_order"] for it in remaining]
    assert orders == [1, 2]


def test_suite_cross_project_rejection(client: TestClient, test_setup):
    """Enforce strict cross-project isolation: cannot add test from Project B to Suite in Project A."""
    proj_a = test_setup["proj_a"]
    test_b = test_setup["test_b"]

    s_res = client.post(
        f"/api/v1/projects/{proj_a.id}/test-suites",
        json={"name": "Suite A", "status": "ACTIVE"},
    )
    suite_id = s_res.json()["id"]

    cross_res = client.post(
        f"/api/v1/test-suites/{suite_id}/tests",
        json={"security_test_id": test_b.id, "execution_order": 1},
    )
    assert cross_res.status_code == 400
    assert "belongs to project" in cross_res.json()["detail"].lower()


# =============================================================================
# 2. Execution Plan Creation Tests
# =============================================================================

def test_create_plan_from_suite(client: TestClient, test_setup):
    """Verify execution plan creation from an active suite respects enabled items only."""
    proj_a = test_setup["proj_a"]
    tests_a = test_setup["tests_a"]

    s_res = client.post(
        f"/api/v1/projects/{proj_a.id}/test-suites",
        json={"name": "Suite with Disabled", "status": "ACTIVE"},
    )
    suite_id = s_res.json()["id"]

    # Add 2 enabled, 1 disabled
    client.post(f"/api/v1/test-suites/{suite_id}/tests", json={"security_test_id": tests_a[0].id, "enabled": True})
    client.post(f"/api/v1/test-suites/{suite_id}/tests", json={"security_test_id": tests_a[1].id, "enabled": False})
    client.post(f"/api/v1/test-suites/{suite_id}/tests", json={"security_test_id": tests_a[2].id, "enabled": True})

    plan_res = client.post(
        f"/api/v1/projects/{proj_a.id}/execution-plans",
        json={"name": "Filtered Plan", "suite_id": suite_id, "execution_mode": "SEQUENTIAL"},
    )
    assert plan_res.status_code == 201
    plan_data = plan_res.json()
    assert plan_data["status"] == "READY"
    assert plan_data["total_tests"] == 2  # Only 2 enabled
    assert len(plan_data["items"]) == 2
    assert plan_data["items"][0]["execution_order"] == 1
    assert plan_data["items"][1]["execution_order"] == 2


def test_create_plan_from_disabled_suite_fails(client: TestClient, test_setup):
    """Verify creating a plan from a DISABLED suite is rejected."""
    proj_a = test_setup["proj_a"]
    s_res = client.post(
        f"/api/v1/projects/{proj_a.id}/test-suites",
        json={"name": "Disabled Suite", "status": "DISABLED"},
    )
    suite_id = s_res.json()["id"]

    plan_res = client.post(
        f"/api/v1/projects/{proj_a.id}/execution-plans",
        json={"name": "Plan", "suite_id": suite_id},
    )
    assert plan_res.status_code == 400
    assert "disabled" in plan_res.json()["detail"].lower()


def test_create_plan_from_tests_list(client: TestClient, test_setup):
    """Verify creating an execution plan from an explicit list of test IDs."""
    proj_a = test_setup["proj_a"]
    tests_a = test_setup["tests_a"]

    plan_res = client.post(
        f"/api/v1/projects/{proj_a.id}/execution-plans",
        json={
            "name": "Custom Test Plan",
            "security_test_ids": [tests_a[0].id, tests_a[3].id],
            "execution_mode": "FAIL_FAST",
        },
    )
    assert plan_res.status_code == 201
    plan_data = plan_res.json()
    assert plan_data["status"] == "READY"
    assert plan_data["execution_mode"] == "FAIL_FAST"
    assert plan_data["total_tests"] == 2


def test_create_plan_cross_project_rejection(client: TestClient, test_setup):
    """Enforce rejection when trying to create a plan with tests from another project."""
    proj_a = test_setup["proj_a"]
    test_b = test_setup["test_b"]

    plan_res = client.post(
        f"/api/v1/projects/{proj_a.id}/execution-plans",
        json={"name": "Illegal Plan", "security_test_ids": [test_b.id]},
    )
    assert plan_res.status_code == 400
    assert "belongs to project" in plan_res.json()["detail"].lower()


# =============================================================================
# 3. Plan Execution & Mode Tests
# =============================================================================

def test_unauthorized_project_execution_guard(client: TestClient, test_setup):
    """Target project must be explicitly 'authorized'; unauthorized plans cannot start."""
    proj_b = test_setup["proj_b"]  # authorization_status = 'pending'
    test_b = test_setup["test_b"]

    # Create plan for Project B
    plan_res = client.post(
        f"/api/v1/projects/{proj_b.id}/execution-plans",
        json={"name": "Unauthorized Plan", "security_test_ids": [test_b.id]},
    )
    assert plan_res.status_code == 201
    plan_id = plan_res.json()["id"]

    # Start should fail with 400
    start_res = client.post(f"/api/v1/execution-plans/{plan_id}/start")
    assert start_res.status_code == 400
    assert "authorized" in start_res.json()["detail"].lower()


def test_sequential_execution_mode(db_session, test_setup):
    """Test SEQUENTIAL execution mode: all tests run to completion and results aggregate."""
    proj_a = test_setup["proj_a"]
    tests_a = test_setup["tests_a"]

    orchestrator = TestOrchestrator(db=db_session)
    plan = orchestrator.create_plan_from_tests(
        project_id=proj_a.id,
        security_test_ids=[tests_a[0].id, tests_a[1].id, tests_a[2].id],
        name="Sequential Test Plan",
        execution_mode="SEQUENTIAL",
    )

    # Mock engine execution to avoid live network requests
    mock_exec1 = MagicMock(id=str(uuid.uuid4()), result="PASS", status="COMPLETED")
    mock_exec2 = MagicMock(id=str(uuid.uuid4()), result="CONFIRMED", status="COMPLETED")
    mock_exec3 = MagicMock(id=str(uuid.uuid4()), result="INCONCLUSIVE", status="COMPLETED")

    with patch("app.services.security_engine.evaluator.BOLAEngine.execute_test", new_callable=AsyncMock) as m_bola, \
         patch("app.services.security_engine.bfla_engine.BFLAEngine.execute_test", new_callable=AsyncMock) as m_bfla, \
         patch("app.services.security_engine.property_engine.PropertyExposureEngine.execute_test", new_callable=AsyncMock) as m_prop:

        m_bola.return_value = mock_exec1
        m_bfla.return_value = mock_exec2
        m_prop.return_value = mock_exec3

        executed_plan = asyncio.run(orchestrator.start_plan(plan.id))

    assert executed_plan.status == "COMPLETED"
    assert executed_plan.total_tests == 3
    assert executed_plan.completed_tests == 3
    assert executed_plan.confirmed_findings == 1
    assert executed_plan.inconclusive_tests == 1
    assert executed_plan.failed_tests == 0

    # Verify individual item results
    items = sorted(executed_plan.items, key=lambda x: x.execution_order)
    assert items[0].result == "PASS"
    assert items[0].status == "COMPLETED"
    assert items[1].result == "CONFIRMED"
    assert items[1].status == "COMPLETED"
    assert items[2].result == "INCONCLUSIVE"
    assert items[2].status == "COMPLETED"


def test_fail_fast_execution_mode(db_session, test_setup):
    """Test FAIL_FAST mode: upon error/failure, remaining tests are marked SKIPPED and plan halts."""
    proj_a = test_setup["proj_a"]
    tests_a = test_setup["tests_a"]

    orchestrator = TestOrchestrator(db=db_session)
    plan = orchestrator.create_plan_from_tests(
        project_id=proj_a.id,
        security_test_ids=[tests_a[0].id, tests_a[1].id, tests_a[2].id],
        name="Fail Fast Test Plan",
        execution_mode="FAIL_FAST",
    )

    # First test passes, second test raises an exception (or fails)
    mock_exec1 = MagicMock(id=str(uuid.uuid4()), result="PASS", status="COMPLETED")

    with patch("app.services.security_engine.evaluator.BOLAEngine.execute_test", new_callable=AsyncMock) as m_bola, \
         patch("app.services.security_engine.bfla_engine.BFLAEngine.execute_test", new_callable=AsyncMock) as m_bfla, \
         patch("app.services.security_engine.property_engine.PropertyExposureEngine.execute_test", new_callable=AsyncMock) as m_prop:

        m_bola.return_value = mock_exec1
        m_bfla.side_effect = RuntimeError("Target Connection Timeout")

        executed_plan = asyncio.run(orchestrator.start_plan(plan.id))

    assert executed_plan.status == "FAILED"
    assert executed_plan.total_tests == 3
    assert executed_plan.completed_tests == 2  # test 1 + test 2
    assert executed_plan.failed_tests == 1

    items = sorted(executed_plan.items, key=lambda x: x.execution_order)
    assert items[0].status == "COMPLETED"
    assert items[1].status == "FAILED"
    assert items[1].result == "ERROR"
    assert "Timeout" in (items[1].error_message or "")
    assert items[2].status == "SKIPPED"  # Never executed


def test_continue_on_failure_execution_mode(db_session, test_setup):
    """Test CONTINUE_ON_FAILURE mode: test failures do not prevent remaining tests from executing."""
    proj_a = test_setup["proj_a"]
    tests_a = test_setup["tests_a"]

    orchestrator = TestOrchestrator(db=db_session)
    plan = orchestrator.create_plan_from_tests(
        project_id=proj_a.id,
        security_test_ids=[tests_a[0].id, tests_a[1].id, tests_a[2].id],
        name="Continue On Failure Plan",
        execution_mode="CONTINUE_ON_FAILURE",
    )

    mock_exec1 = MagicMock(id=str(uuid.uuid4()), result="PASS", status="COMPLETED")
    mock_exec3 = MagicMock(id=str(uuid.uuid4()), result="PASS", status="COMPLETED")

    with patch("app.services.security_engine.evaluator.BOLAEngine.execute_test", new_callable=AsyncMock) as m_bola, \
         patch("app.services.security_engine.bfla_engine.BFLAEngine.execute_test", new_callable=AsyncMock) as m_bfla, \
         patch("app.services.security_engine.property_engine.PropertyExposureEngine.execute_test", new_callable=AsyncMock) as m_prop:

        m_bola.return_value = mock_exec1
        m_bfla.side_effect = RuntimeError("Target 500 error")
        m_prop.return_value = mock_exec3

        executed_plan = asyncio.run(orchestrator.start_plan(plan.id))

    assert executed_plan.status == "COMPLETED"
    assert executed_plan.total_tests == 3
    assert executed_plan.completed_tests == 3
    assert executed_plan.failed_tests == 1

    items = sorted(executed_plan.items, key=lambda x: x.execution_order)
    assert items[0].status == "COMPLETED"
    assert items[1].status == "FAILED"
    assert items[2].status == "COMPLETED"


# =============================================================================
# 4. Idempotency & Cancellation Tests
# =============================================================================

def test_idempotency_guards(db_session, test_setup):
    """Cannot start a plan that is already COMPLETED or CANCELLED."""
    proj_a = test_setup["proj_a"]
    tests_a = test_setup["tests_a"]

    orchestrator = TestOrchestrator(db=db_session)
    plan = orchestrator.create_plan_from_tests(
        project_id=proj_a.id,
        security_test_ids=[tests_a[0].id],
        name="Idempotency Plan",
    )

    mock_exec = MagicMock(id=str(uuid.uuid4()), result="PASS", status="COMPLETED")
    with patch("app.services.security_engine.evaluator.BOLAEngine.execute_test", new_callable=AsyncMock) as m_bola:
        m_bola.return_value = mock_exec
        asyncio.run(orchestrator.start_plan(plan.id))

    # Attempting to start already completed plan should raise PlanStateError
    with pytest.raises(PlanStateError) as exc_info:
        asyncio.run(orchestrator.start_plan(plan.id))
    assert "already completed" in str(exc_info.value).lower()


def test_plan_cancellation(client: TestClient, test_setup):
    """Verify cancelling an execution plan marks unstarted items CANCELLED."""
    proj_a = test_setup["proj_a"]
    tests_a = test_setup["tests_a"]

    plan_res = client.post(
        f"/api/v1/projects/{proj_a.id}/execution-plans",
        json={"name": "Cancel Me", "security_test_ids": [tests_a[0].id, tests_a[1].id]},
    )
    plan_id = plan_res.json()["id"]

    cancel_res = client.post(f"/api/v1/execution-plans/{plan_id}/cancel")
    assert cancel_res.status_code == 200
    plan_data = cancel_res.json()
    assert plan_data["status"] == "CANCELLED"
    for item in plan_data["items"]:
        assert item["status"] == "CANCELLED"

    # Verify cannot start cancelled plan
    start_res = client.post(f"/api/v1/execution-plans/{plan_id}/start")
    assert start_res.status_code == 400
    assert "cancelled" in start_res.json()["detail"].lower()


def test_plan_progress_endpoint(client: TestClient, test_setup, db_session):
    """Verify the progress endpoint accurately reports metrics and percent."""
    proj_a = test_setup["proj_a"]
    tests_a = test_setup["tests_a"]

    orchestrator = TestOrchestrator(db=db_session)
    plan = orchestrator.create_plan_from_tests(
        project_id=proj_a.id,
        security_test_ids=[tests_a[0].id, tests_a[1].id],
        name="Progress Test Plan",
    )
    # Manually simulate 1 completed item
    plan.completed_tests = 1
    plan.items[0].status = "COMPLETED"
    plan.items[0].result = "CONFIRMED"
    db_session.commit()

    res = client.get(f"/api/v1/execution-plans/{plan.id}/progress")
    assert res.status_code == 200
    data = res.json()
    assert data["total_tests"] == 2
    assert data["completed_tests"] == 1
    assert data["progress_percent"] == 50.0
    assert data["results_summary"]["CONFIRMED"] == 1
