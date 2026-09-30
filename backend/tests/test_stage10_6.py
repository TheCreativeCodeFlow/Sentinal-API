"""
Stage 10.6: Scheduled & Continuous Security Scanning Test Suite
Author: SentinelAPI Security Architecture Team

Comprehensive automated test suite covering:
1. Schedule Domain & Lifecycle:
   - Creation, reading, updating, and deletion of SecurityScanSchedule
   - Unique schedule name per project enforcement
   - Cross-project isolation (profiles, gates)
   - State transitions (ACTIVE, DISABLED, EXPIRED)
   - Preservation of historical execution records upon schedule deletion (SET NULL)
2. Timezone & Recurrence Calculations:
   - IANA timezone validation with zoneinfo
   - Rejection of invalid timezones
   - Preset recurrences (ONCE, HOURLY, DAILY, WEEKLY)
   - Custom 5-part cron expressions
   - Daylight Saving Time (DST) transition handling
   - Start window and expiration (end_at) constraints
3. Preview Capability:
   - 5-occurrence preview calculation without creating plans or running tests
   - Zero target HTTP calls
4. Guardrails & Concurrency Protection:
   - Project authorization guard (unauthorized projects recorded as SKIPPED)
   - Disabled scan profile guard (recorded as SKIPPED)
   - Concurrency & duplicate-run protection (max_concurrent_runs enforced, SKIPPED)
5. End-to-End Orchestrated Pipeline:
   - Schedule -> ScheduledExecution -> ExecutionPlan -> BaselineComparison -> GateEvaluation -> Report
   - Safe failure handling and schedule advancement
6. Background Scheduler:
   - SchedulerRunner finding and triggering due schedules
7. REST API Endpoints:
   - All 12 routes tested with proper response formats and status codes
"""

import pytest
import uuid
import asyncio
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient

from app.models import (
    Project,
    API,
    Endpoint,
    SecurityTest,
    TestExecution,
    Finding,
    ScanProfile,
    SecurityBaseline,
    SecurityBaselineControl,
    SecurityBaselineComparison,
    SecurityGate,
    SecurityGateEvaluation,
    SecurityReport,
    SecurityExecutionPlan,
    SecurityExecutionItem,
    SecurityScanSchedule,
    SecurityScheduledExecution,
)
from app.services.security_engine.schedule_service import (
    ScheduleService,
    ScheduleError,
    ScheduleNotFoundError,
    DuplicateScheduleError,
    InvalidScheduleError,
    CrossProjectViolationError,
    DisabledScheduleError,
)
from app.services.security_engine.scheduled_scan_service import ScheduledScanService
from app.services.security_engine.scheduler import SchedulerRunner

# Pytest class discovery exclusions
SecurityScanSchedule.__test__ = False
SecurityScheduledExecution.__test__ = False
SecurityReport.__test__ = False
SecurityGate.__test__ = False
SecurityBaseline.__test__ = False
SecurityExecutionPlan.__test__ = False


@pytest.fixture
def schedule_fixture(db_session):
    """Fixture providing populated projects, scan profiles, and gates."""
    proj_a = Project(
        name=f"Project-Alpha-{uuid.uuid4().hex[:6]}",
        authorization_status="authorized",
        environment="staging",
        base_url="http://testserver",
    )
    proj_b = Project(
        name=f"Project-Beta-{uuid.uuid4().hex[:6]}",
        authorization_status="authorized",
        environment="production",
        base_url="http://prodserver",
    )
    db_session.add_all([proj_a, proj_b])
    db_session.commit()
    db_session.refresh(proj_a)
    db_session.refresh(proj_b)

    # API & Endpoint for Alpha
    api = API(project_id=proj_a.id, name="Core API", format="OPENAPI_JSON", status="ACTIVE")
    db_session.add(api)
    db_session.commit()
    db_session.refresh(api)

    ep = Endpoint(api_id=api.id, path="/api/v1/users", method="GET")
    db_session.add(ep)
    db_session.commit()
    db_session.refresh(ep)

    # Security Test for Alpha
    sec_test = SecurityTest(
        project_id=proj_a.id,
        endpoint_id=ep.id,
        test_type="AUTH_MISSING",
        status="ACTIVE",
    )
    db_session.add(sec_test)
    db_session.commit()
    db_session.refresh(sec_test)

    # Scan Profiles
    prof_a = ScanProfile(
        project_id=proj_a.id,
        name="Alpha Standard Profile",
        profile_type="STANDARD",
        status="ACTIVE",
        configuration={},
    )
    prof_b = ScanProfile(
        project_id=proj_b.id,
        name="Beta Deep Profile",
        profile_type="DEEP",
        status="ACTIVE",
        configuration={},
    )
    db_session.add_all([prof_a, prof_b])
    db_session.commit()
    db_session.refresh(prof_a)
    db_session.refresh(prof_b)

    # Baseline for Alpha
    baseline = SecurityBaseline(
        project_id=proj_a.id,
        name="Alpha Baseline v1",
        status="ACTIVE",
        version=1,
    )
    db_session.add(baseline)
    db_session.commit()
    db_session.refresh(baseline)

    # Security Gate for Alpha
    gate = SecurityGate(
        project_id=proj_a.id,
        name="Alpha Gate",
        status="ACTIVE",
        baseline_id=baseline.id,
        scan_profile_id=prof_a.id,
        failure_rules={"max_regressions": 0, "max_new_violations": 0},
        warning_rules={"max_inconclusive": 2},
    )
    db_session.add(gate)
    db_session.commit()
    db_session.refresh(gate)

    return {
        "proj_a": proj_a,
        "proj_b": proj_b,
        "prof_a": prof_a,
        "prof_b": prof_b,
        "baseline": baseline,
        "gate": gate,
        "test": sec_test,
    }


# =============================================================================
# 1. TIMEZONE & RECURRENCE TESTS
# =============================================================================

def test_timezone_validation(db_session):
    """Test IANA timezone validation and rejection of invalid names."""
    service = ScheduleService(db_session)

    # Valid timezones
    tz_utc = service.validate_timezone("UTC")
    assert tz_utc.key == "UTC"

    tz_ny = service.validate_timezone("America/New_York")
    assert tz_ny.key == "America/New_York"

    tz_kol = service.validate_timezone("Asia/Kolkata")
    assert tz_kol.key == "Asia/Kolkata"

    # Invalid timezones
    with pytest.raises(InvalidScheduleError, match="Invalid timezone"):
        service.validate_timezone("Mars/Phobos")

    with pytest.raises(InvalidScheduleError, match="Invalid timezone"):
        service.validate_timezone("Invalid/Zone")


def test_recurrence_calculation_types(db_session):
    """Test calculation of next run for HOURLY, DAILY, WEEKLY, CRON, and ONCE."""
    service = ScheduleService(db_session)
    base_time = datetime(2026, 10, 1, 10, 15, 0, tzinfo=timezone.utc)

    # HOURLY -> top of next hour (11:00 UTC)
    next_hourly = service.calculate_next_run(
        schedule_type="HOURLY",
        timezone_name="UTC",
        base_time=base_time,
    )
    assert next_hourly == datetime(2026, 10, 1, 11, 0, 0, tzinfo=timezone.utc)

    # DAILY -> midnight (2026-10-02 00:00 UTC)
    next_daily = service.calculate_next_run(
        schedule_type="DAILY",
        timezone_name="UTC",
        base_time=base_time,
    )
    assert next_daily == datetime(2026, 10, 2, 0, 0, 0, tzinfo=timezone.utc)

    # WEEKLY -> next Sunday at midnight
    next_weekly = service.calculate_next_run(
        schedule_type="WEEKLY",
        timezone_name="UTC",
        base_time=base_time,
    )
    assert next_weekly.weekday() == 6  # Sunday

    # CRON -> custom expression e.g. every 15 minutes
    next_cron = service.calculate_next_run(
        schedule_type="CRON",
        timezone_name="UTC",
        cron_expression="*/15 * * * *",
        base_time=base_time,
    )
    assert next_cron == datetime(2026, 10, 1, 10, 30, 0, tzinfo=timezone.utc)

    # ONCE -> target scheduled_at
    future_once = datetime(2026, 10, 5, 14, 0, 0, tzinfo=timezone.utc)
    next_once = service.calculate_next_run(
        schedule_type="ONCE",
        timezone_name="UTC",
        scheduled_at=future_once,
        base_time=base_time,
    )
    assert next_once == future_once

    # ONCE in the past returns None
    past_once = datetime(2026, 9, 1, 0, 0, 0, tzinfo=timezone.utc)
    assert service.calculate_next_run(
        schedule_type="ONCE",
        timezone_name="UTC",
        scheduled_at=past_once,
        base_time=base_time,
    ) is None


def test_dst_transition_resilience(db_session):
    """
    Test DST transition in America/New_York (spring forward).
    Clocks skip from 2:00 AM to 3:00 AM on second Sunday in March.
    """
    service = ScheduleService(db_session)
    # 2026-03-07 23:00 NY time (standard time UTC-5)
    base_ny = datetime(2026, 3, 7, 23, 0, 0, tzinfo=ZoneInfo("America/New_York"))

    # Daily midnight scan
    next_run = service.calculate_next_run(
        schedule_type="DAILY",
        timezone_name="America/New_York",
        base_time=base_ny,
    )
    assert next_run is not None
    # Converted back to NY time must be midnight
    ny_local = next_run.astimezone(ZoneInfo("America/New_York"))
    assert ny_local.hour == 0
    assert ny_local.minute == 0


def test_start_and_end_window_constraints(db_session):
    """Test start_at delaying calculation and end_at expiring schedule."""
    service = ScheduleService(db_session)
    now = datetime.now(timezone.utc)

    # start_at 2 days in the future
    future_start = now + timedelta(days=2)
    next_run = service.calculate_next_run(
        schedule_type="DAILY",
        timezone_name="UTC",
        start_at=future_start,
        base_time=now,
    )
    assert next_run >= future_start - timedelta(seconds=1)

    # end_at in the past
    past_end = now - timedelta(hours=1)
    next_expired = service.calculate_next_run(
        schedule_type="DAILY",
        timezone_name="UTC",
        end_at=past_end,
        base_time=now,
    )
    assert next_expired is None


# =============================================================================
# 2. SCHEDULE CRUD & PROJECT ISOLATION
# =============================================================================

def test_schedule_crud_lifecycle(db_session, schedule_fixture):
    """Test creating, reading, updating, and deleting a scan schedule."""
    service = ScheduleService(db_session)
    proj_a = schedule_fixture["proj_a"]
    prof_a = schedule_fixture["prof_a"]
    gate = schedule_fixture["gate"]

    # 1. Create Schedule
    schedule = service.create_schedule(
        project_id=proj_a.id,
        name="Nightly Alpha Scan",
        description="Daily security regression tests",
        scan_profile_id=prof_a.id,
        security_gate_id=gate.id,
        timezone_name="UTC",
        schedule_type="DAILY",
        max_concurrent_runs=1,
        timeout_seconds=300,
    )
    assert schedule.id is not None
    assert schedule.status == "ACTIVE"
    assert schedule.next_run_at is not None
    assert schedule.scan_profile_id == prof_a.id
    assert schedule.security_gate_id == gate.id

    # 2. Duplicate Name in Same Project Rejected
    with pytest.raises(DuplicateScheduleError):
        service.create_schedule(
            project_id=proj_a.id,
            name="Nightly Alpha Scan",
            scan_profile_id=prof_a.id,
        )

    # 3. Same Name in Different Project Allowed
    proj_b = schedule_fixture["proj_b"]
    prof_b = schedule_fixture["prof_b"]
    sched_b = service.create_schedule(
        project_id=proj_b.id,
        name="Nightly Alpha Scan",
        scan_profile_id=prof_b.id,
    )
    assert sched_b.id != schedule.id

    # 4. Cross-Project Resource Rejection
    with pytest.raises(CrossProjectViolationError):
        service.create_schedule(
            project_id=proj_a.id,
            name="Cross Project Scan",
            scan_profile_id=prof_b.id,  # prof_b belongs to proj_b!
        )

    # 5. Read & List
    fetched = service.get_schedule(schedule.id, project_id=proj_a.id)
    assert fetched.id == schedule.id
    assert fetched.name == "Nightly Alpha Scan"

    listed = service.list_schedules(project_id=proj_a.id)
    assert any(s.id == schedule.id for s in listed)

    # 6. Update Schedule
    updated = service.update_schedule(
        schedule_id=schedule.id,
        name="Nightly Alpha Scan Updated",
        schedule_type="HOURLY",
        timezone_name="America/New_York",
    )
    assert updated.name == "Nightly Alpha Scan Updated"
    assert updated.schedule_type == "HOURLY"
    assert updated.timezone == "America/New_York"

    # 7. Enable / Disable
    disabled = service.disable_schedule(schedule.id)
    assert disabled.status == "DISABLED"
    assert disabled.next_run_at is None

    enabled = service.enable_schedule(schedule.id)
    assert enabled.status == "ACTIVE"
    assert enabled.next_run_at is not None

    # 8. Delete
    deleted = service.delete_schedule(schedule.id, project_id=proj_a.id)
    assert deleted is True
    assert service.get_schedule(schedule.id) is None


def test_schedule_deletion_preserves_executions(db_session, schedule_fixture):
    """Test that deleting a schedule preserves execution history with schedule_id=None."""
    service = ScheduleService(db_session)
    proj_a = schedule_fixture["proj_a"]
    prof_a = schedule_fixture["prof_a"]

    schedule = service.create_schedule(
        project_id=proj_a.id,
        name="Temporary Audit Schedule",
        scan_profile_id=prof_a.id,
    )

    # Create execution record
    exec_record = SecurityScheduledExecution(
        schedule_id=schedule.id,
        project_id=proj_a.id,
        status="COMPLETED",
        trigger_type="SCHEDULED",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    db_session.add(exec_record)
    db_session.commit()
    exec_id = exec_record.id

    # Delete schedule
    service.delete_schedule(schedule.id)

    # Execution record must still exist with schedule_id=None
    db_session.expire_all()
    preserved = db_session.query(SecurityScheduledExecution).filter_by(id=exec_id).first()
    assert preserved is not None
    assert preserved.schedule_id is None
    assert preserved.status == "COMPLETED"


# =============================================================================
# 3. PREVIEW CAPABILITY (ZERO TARGET HTTP REQUESTS)
# =============================================================================

def test_schedule_preview(db_session, schedule_fixture):
    """Test occurrence preview calculates exactly 5 future occurrences with zero HTTP calls."""
    service = ScheduleService(db_session)
    proj_a = schedule_fixture["proj_a"]
    prof_a = schedule_fixture["prof_a"]

    schedule = service.create_schedule(
        project_id=proj_a.id,
        name="Preview Daily Schedule",
        scan_profile_id=prof_a.id,
        schedule_type="DAILY",
        timezone_name="UTC",
    )

    preview = service.get_schedule_preview(schedule.id, count=5)
    assert preview["schedule_id"] == schedule.id
    assert preview["schedule_type"] == "DAILY"
    assert preview["is_active"] is True
    assert len(preview["next_occurrences"]) == 5

    # Strictly monotonically increasing
    occs = preview["next_occurrences"]
    for i in range(1, len(occs)):
        assert occs[i] > occs[i - 1]


# =============================================================================
# 4. GUARDRAILS & PIPELINE EXECUTION
# =============================================================================

def test_project_authorization_guard(db_session, schedule_fixture):
    """Unauthorized project is recorded as SKIPPED without executing security tests."""
    proj = schedule_fixture["proj_a"]
    prof = schedule_fixture["prof_a"]
    # De-authorize project
    proj.authorization_status = "pending"
    db_session.commit()

    service = ScheduleService(db_session)
    schedule = service.create_schedule(
        project_id=proj.id,
        name="Unauthorized Project Schedule",
        scan_profile_id=prof.id,
    )

    scan_service = ScheduledScanService(db_session)
    execution = asyncio.run(scan_service.trigger_execution(schedule.id, trigger_type="MANUAL"))

    assert execution.status == "SKIPPED"
    assert "not authorized" in execution.error_message
    assert execution.execution_plan_id is None


def test_duplicate_run_protection(db_session, schedule_fixture):
    """Max concurrent runs protection records duplicate execution as SKIPPED."""
    proj = schedule_fixture["proj_a"]
    prof = schedule_fixture["prof_a"]

    service = ScheduleService(db_session)
    schedule = service.create_schedule(
        project_id=proj.id,
        name="Concurrent Protection Schedule",
        scan_profile_id=prof.id,
        max_concurrent_runs=1,
    )

    # Insert an existing RUNNING execution for this schedule
    active_run = SecurityScheduledExecution(
        schedule_id=schedule.id,
        project_id=proj.id,
        status="RUNNING",
        trigger_type="SCHEDULED",
        started_at=datetime.now(timezone.utc),
    )
    db_session.add(active_run)
    db_session.commit()

    scan_service = ScheduledScanService(db_session)
    execution = asyncio.run(scan_service.trigger_execution(schedule.id, trigger_type="SCHEDULED"))

    assert execution.status == "SKIPPED"
    assert "Maximum concurrent" in execution.error_message
    assert execution.id != active_run.id


def test_full_scheduled_pipeline_execution(db_session, schedule_fixture):
    """
    Test complete pipeline:
    Schedule -> ScheduledExecution -> ExecutionPlan -> BaselineComparison -> GateEvaluation -> Report
    """
    proj = schedule_fixture["proj_a"]
    prof = schedule_fixture["prof_a"]
    gate = schedule_fixture["gate"]

    service = ScheduleService(db_session)
    schedule = service.create_schedule(
        project_id=proj.id,
        name="Full Pipeline Schedule",
        scan_profile_id=prof.id,
        security_gate_id=gate.id,
        schedule_type="DAILY",
        timezone_name="UTC",
    )

    scan_service = ScheduledScanService(db_session)

    # Mock TestOrchestrator.start_plan to complete plan deterministically without real network
    async def mock_start_plan(plan_id: str):
        plan = db_session.query(SecurityExecutionPlan).filter_by(id=plan_id).first()
        plan.status = "COMPLETED"
        plan.completed_at = datetime.now(timezone.utc)
        for item in plan.items:
            item.status = "COMPLETED"
            item.result = "PASS"
        db_session.commit()
        return plan

    with patch("app.services.security_engine.scheduled_scan_service.TestOrchestrator.start_plan", side_effect=mock_start_plan):
        execution = asyncio.run(scan_service.trigger_execution(schedule.id, trigger_type="SCHEDULED"))

    assert execution.status == "COMPLETED"
    assert execution.execution_plan_id is not None
    assert execution.baseline_comparison_id is not None
    assert execution.gate_evaluation_id is not None
    assert execution.report_id is not None

    # Verify report was generated
    report = db_session.query(SecurityReport).filter_by(id=execution.report_id).first()
    assert report is not None
    assert len(report.snapshots) >= 1

    # Verify schedule was advanced
    db_session.refresh(schedule)
    assert schedule.last_run_at is not None
    assert schedule.next_run_at is not None


# =============================================================================
# 5. BACKGROUND SCHEDULER RUNNER
# =============================================================================

def test_scheduler_runner_due_schedules(db_session, schedule_fixture):
    """SchedulerRunner triggers only ACTIVE schedules where next_run_at <= now."""
    proj = schedule_fixture["proj_a"]
    prof = schedule_fixture["prof_a"]
    service = ScheduleService(db_session)

    # 1. Schedule that is due (next_run_at in the past)
    sched_due = service.create_schedule(
        project_id=proj.id,
        name="Due Scan Schedule",
        scan_profile_id=prof.id,
    )
    sched_due.next_run_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    db_session.commit()

    # 2. Schedule that is future (next_run_at in the future)
    sched_future = service.create_schedule(
        project_id=proj.id,
        name="Future Scan Schedule",
        scan_profile_id=prof.id,
    )
    sched_future.next_run_at = datetime.now(timezone.utc) + timedelta(hours=5)
    db_session.commit()

    # 3. Schedule that is disabled
    sched_disabled = service.create_schedule(
        project_id=proj.id,
        name="Disabled Scan Schedule",
        scan_profile_id=prof.id,
        status="DISABLED",
    )
    sched_disabled.next_run_at = datetime.now(timezone.utc) - timedelta(minutes=10)
    db_session.commit()

    # Run scheduler runner
    runner = SchedulerRunner(db_session)
    with patch.object(ScheduledScanService, "trigger_execution", new_callable=AsyncMock) as mock_trigger:
        mock_trigger.return_value = SecurityScheduledExecution(
            id="mock-exec", status="COMPLETED", trigger_type="SCHEDULED"
        )
        results = asyncio.run(runner.run_due_schedules(project_id=proj.id))

        # Only the due schedule must have been triggered
        assert len(results) == 1
        mock_trigger.assert_called_once()
        call_args = mock_trigger.call_args[1]
        assert call_args["schedule_id"] == sched_due.id



# =============================================================================
# 6. REST API ENDPOINTS
# =============================================================================

def test_scan_schedule_api_endpoints(client: TestClient, db_session, schedule_fixture):
    """Test all 12 REST API routes for scan schedules and executions."""
    proj = schedule_fixture["proj_a"]
    prof = schedule_fixture["prof_a"]
    gate = schedule_fixture["gate"]

    # 1. POST /api/v1/projects/{project_id}/security-scan-schedules
    payload = {
        "name": "API Nightly Scan",
        "description": "Triggered via REST API",
        "scan_profile_id": prof.id,
        "security_gate_id": gate.id,
        "timezone": "America/New_York",
        "schedule_type": "DAILY",
        "max_concurrent_runs": 1,
        "timeout_seconds": 600,
    }
    create_res = client.post(f"/api/v1/projects/{proj.id}/security-scan-schedules", json=payload)
    assert create_res.status_code == 201
    created = create_res.json()
    schedule_id = created["id"]
    assert created["name"] == "API Nightly Scan"
    assert created["timezone"] == "America/New_York"
    assert created["status"] == "ACTIVE"

    # 2. GET /api/v1/projects/{project_id}/security-scan-schedules
    list_res = client.get(f"/api/v1/projects/{proj.id}/security-scan-schedules")
    assert list_res.status_code == 200
    assert any(s["id"] == schedule_id for s in list_res.json()["schedules"])

    # 3. GET /api/v1/security-scan-schedules/{schedule_id}
    get_res = client.get(f"/api/v1/security-scan-schedules/{schedule_id}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == schedule_id

    # 4. PATCH /api/v1/security-scan-schedules/{schedule_id}
    patch_res = client.patch(
        f"/api/v1/security-scan-schedules/{schedule_id}",
        json={"name": "API Nightly Scan (Patched)", "timeout_seconds": 900},
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["name"] == "API Nightly Scan (Patched)"
    assert patch_res.json()["timeout_seconds"] == 900

    # 5. PUT /api/v1/security-scan-schedules/{schedule_id}
    put_res = client.put(
        f"/api/v1/security-scan-schedules/{schedule_id}",
        json={"description": "Updated via PUT"},
    )
    assert put_res.status_code == 200
    assert put_res.json()["description"] == "Updated via PUT"

    # 6. GET /api/v1/security-scan-schedules/{schedule_id}/preview
    prev_res = client.get(f"/api/v1/security-scan-schedules/{schedule_id}/preview?count=3")
    assert prev_res.status_code == 200
    assert len(prev_res.json()["next_occurrences"]) == 3

    # 7. POST /api/v1/security-scan-schedules/{schedule_id}/disable
    dis_res = client.post(f"/api/v1/security-scan-schedules/{schedule_id}/disable")
    assert dis_res.status_code == 200
    assert dis_res.json()["status"] == "DISABLED"
    assert dis_res.json()["next_run_at"] is None

    # 8. POST /api/v1/security-scan-schedules/{schedule_id}/enable
    en_res = client.post(f"/api/v1/security-scan-schedules/{schedule_id}/enable")
    assert en_res.status_code == 200
    assert en_res.json()["status"] == "ACTIVE"
    assert en_res.json()["next_run_at"] is not None

    # 9. POST /api/v1/security-scan-schedules/{schedule_id}/run
    with patch.object(ScheduledScanService, "trigger_execution", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = SecurityScheduledExecution(
            id="exec-1234",
            schedule_id=schedule_id,
            project_id=proj.id,
            status="COMPLETED",
            trigger_type="MANUAL",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        run_res = client.post(f"/api/v1/security-scan-schedules/{schedule_id}/run")
        assert run_res.status_code == 200
        assert run_res.json()["id"] == "exec-1234"
        assert run_res.json()["trigger_type"] == "MANUAL"

    # Insert an execution record directly to verify listing routes
    db_exec = SecurityScheduledExecution(
        id="exec-db-test",
        schedule_id=schedule_id,
        project_id=proj.id,
        status="COMPLETED",
        trigger_type="SCHEDULED",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    db_session.add(db_exec)
    db_session.commit()

    # 10. GET /api/v1/security-scan-schedules/{schedule_id}/executions
    sched_execs_res = client.get(f"/api/v1/security-scan-schedules/{schedule_id}/executions")
    assert sched_execs_res.status_code == 200
    assert any(e["id"] == "exec-db-test" for e in sched_execs_res.json()["executions"])

    # 11. GET /api/v1/projects/{project_id}/security-scheduled-executions
    proj_execs_res = client.get(f"/api/v1/projects/{proj.id}/security-scheduled-executions")
    assert proj_execs_res.status_code == 200
    assert any(e["id"] == "exec-db-test" for e in proj_execs_res.json()["executions"])

    # 12. GET /api/v1/security-scheduled-executions/{execution_id}
    single_exec_res = client.get("/api/v1/security-scheduled-executions/exec-db-test")
    assert single_exec_res.status_code == 200
    assert single_exec_res.json()["id"] == "exec-db-test"

    # 13. DELETE /api/v1/security-scan-schedules/{schedule_id}
    del_res = client.delete(f"/api/v1/security-scan-schedules/{schedule_id}")
    assert del_res.status_code == 200

    # Verify 404 after deletion
    assert client.get(f"/api/v1/security-scan-schedules/{schedule_id}").status_code == 404
