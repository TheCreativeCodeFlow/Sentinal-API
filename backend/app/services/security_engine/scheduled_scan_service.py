"""
Stage 10.6: Scheduled & Continuous Security Scanning - Scheduled Scan Execution Service
Author: SentinelAPI Security Architecture Team

Deterministic execution coordinator for scheduled scans.
Pipeline:
    SecurityScanSchedule
            ↓
    SecurityScheduledExecution
            ↓
    ScanProfile -> SecurityExecutionPlan
            ↓
    TestOrchestrator -> Deterministic Security Engines
            ↓
    SecurityBaselineComparison (if gate/baseline present)
            ↓
    SecurityGateEvaluation (if gate present)
            ↓
    SecurityReport & Snapshot
            ↓
    Execution Complete & Schedule Advance

Strict Guarantees:
- Zero target HTTP calls executed directly; delegates strictly to existing deterministic engines.
- Project authorization guard strictly enforced.
- Concurrency & duplicate-run protection (max_concurrent_runs).
- Full audit lineage preservation (schedule_id, plan_id, comparison_id, gate_id, report_id).
- Safe failure handling and schedule advancement.
"""

import asyncio
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.models import (
    Project,
    SecurityScanSchedule,
    SecurityScheduledExecution,
    ScanProfile,
    SecurityGate,
    SecurityBaseline,
    SecurityExecutionPlan,
)
from app.services.security_engine.schedule_service import (
    ScheduleService,
    ScheduleNotFoundError,
    CrossProjectViolationError,
)
from app.services.security_engine.scan_profile_service import ScanProfileService
from app.services.security_engine.orchestrator import TestOrchestrator
from app.services.security_engine.baseline_service import BaselineComparisonService
from app.services.security_engine.security_gate_service import SecurityGateService
from app.services.security_engine.report_service import SecurityReportService


class ScheduledScanError(Exception):
    """Base exception for scheduled scan execution errors."""
    pass


class ScheduledScanService:
    """Service that orchestrates the entire scheduled scan execution pipeline."""

    def __init__(self, db: Session):
        self.db = db
        self.schedule_service = ScheduleService(db)

    async def trigger_execution(
        self,
        schedule_id: str,
        trigger_type: str = "SCHEDULED",
        scheduled_for: Optional[datetime] = None,
        project_id: Optional[int] = None,
    ) -> SecurityScheduledExecution:
        """
        Execute a scheduled scan pipeline deterministically.
        Guarantees:
        - Checks project authorization status.
        - Enforces max_concurrent_runs.
        - Automatically executes plan, baseline comparison, gate, and report.
        - Advances schedule next_run_at.
        """
        schedule = self.schedule_service.get_schedule(schedule_id, project_id=project_id)
        if not schedule:
            raise ScheduleNotFoundError(f"Security scan schedule '{schedule_id}' not found.")

        project = self.db.query(Project).filter(Project.id == schedule.project_id).first()
        if not project:
            raise ScheduleNotFoundError(f"Project with ID {schedule.project_id} not found.")

        now_utc = datetime.now(timezone.utc)
        sched_time = scheduled_for or schedule.next_run_at or now_utc

        # 1. Project Authorization Guard
        if (project.authorization_status or "").lower() != "authorized":
            exec_record = SecurityScheduledExecution(
                schedule_id=schedule.id,
                project_id=schedule.project_id,
                status="SKIPPED",
                trigger_type=trigger_type,
                scheduled_for=sched_time,
                started_at=now_utc,
                completed_at=now_utc,
                error_message=f"Project {project.id} is not authorized for security testing (status: '{project.authorization_status}').",
            )
            self.db.add(exec_record)
            self._advance_schedule(schedule, base_time=now_utc)
            self.db.commit()
            self.db.refresh(exec_record)
            return exec_record

        # 2. Scan Profile Active Check
        profile = self.db.query(ScanProfile).filter(ScanProfile.id == schedule.scan_profile_id).first()
        if not profile or profile.status != "ACTIVE":
            profile_name = profile.name if profile else schedule.scan_profile_id
            exec_record = SecurityScheduledExecution(
                schedule_id=schedule.id,
                project_id=schedule.project_id,
                status="SKIPPED",
                trigger_type=trigger_type,
                scheduled_for=sched_time,
                started_at=now_utc,
                completed_at=now_utc,
                error_message=f"Scan profile '{profile_name}' is disabled or not found.",
            )
            self.db.add(exec_record)
            self._advance_schedule(schedule, base_time=now_utc)
            self.db.commit()
            self.db.refresh(exec_record)
            return exec_record

        # 3. Duplicate-Run / Concurrency Protection
        active_runs = (
            self.db.query(SecurityScheduledExecution)
            .filter(
                SecurityScheduledExecution.schedule_id == schedule.id,
                SecurityScheduledExecution.status.in_(["QUEUED", "RUNNING"]),
            )
            .count()
        )
        if active_runs >= schedule.max_concurrent_runs:
            exec_record = SecurityScheduledExecution(
                schedule_id=schedule.id,
                project_id=schedule.project_id,
                status="SKIPPED",
                trigger_type=trigger_type,
                scheduled_for=sched_time,
                started_at=now_utc,
                completed_at=now_utc,
                error_message=f"Maximum concurrent scheduled executions ({schedule.max_concurrent_runs}) reached.",
            )
            self.db.add(exec_record)
            self._advance_schedule(schedule, base_time=now_utc)
            self.db.commit()
            self.db.refresh(exec_record)
            return exec_record

        # 4. Atomic Execution Record Creation
        exec_record = SecurityScheduledExecution(
            schedule_id=schedule.id,
            project_id=schedule.project_id,
            status="RUNNING",
            trigger_type=trigger_type,
            scheduled_for=sched_time,
            started_at=now_utc,
        )
        self.db.add(exec_record)
        self.db.commit()
        self.db.refresh(exec_record)

        # 5. Pipeline Execution
        try:
            timestamp_str = now_utc.strftime("%Y-%m-%d %H:%M:%S")

            # Step A: Create Execution Plan from Scan Profile
            profile_service = ScanProfileService(self.db)
            plan = profile_service.create_plan_from_profile(
                project_id=schedule.project_id,
                profile_id=schedule.scan_profile_id,
                name=f"Scheduled Plan - {schedule.name} - {timestamp_str}",
            )
            exec_record.execution_plan_id = plan.id
            self.db.commit()

            # Step B: Execute Plan via TestOrchestrator
            orchestrator = TestOrchestrator(self.db)
            await orchestrator.start_plan(plan.id)
            self.db.refresh(plan)

            # Step C: Baseline Comparison & Security Gate Evaluation
            baseline_service = BaselineComparisonService(self.db)
            comparison_id = None
            gate_eval_id = None

            if schedule.security_gate_id:
                gate = (
                    self.db.query(SecurityGate)
                    .filter(SecurityGate.id == schedule.security_gate_id)
                    .first()
                )
                if gate and gate.baseline_id and gate.status == "ACTIVE":
                    comparison = baseline_service.compare_baseline_with_plan(
                        baseline_id=gate.baseline_id,
                        execution_plan_id=plan.id,
                    )
                    comparison_id = comparison.id
                    exec_record.baseline_comparison_id = comparison_id
                    self.db.commit()

                    gate_service = SecurityGateService(self.db)
                    gate_eval = gate_service.evaluate_gate(
                        gate_id=gate.id,
                        baseline_comparison_id=comparison.id,
                        project_id=schedule.project_id,
                    )
                    gate_eval_id = gate_eval.id
                    exec_record.gate_evaluation_id = gate_eval_id
                    self.db.commit()

            elif not comparison_id:
                # If no gate, check for an active baseline in the project
                active_baseline = (
                    self.db.query(SecurityBaseline)
                    .filter(
                        SecurityBaseline.project_id == schedule.project_id,
                        SecurityBaseline.status == "ACTIVE",
                    )
                    .first()
                )
                if active_baseline:
                    comparison = baseline_service.compare_baseline_with_plan(
                        baseline_id=active_baseline.id,
                        execution_plan_id=plan.id,
                    )
                    comparison_id = comparison.id
                    exec_record.baseline_comparison_id = comparison_id
                    self.db.commit()

            # Step D: Security Report Generation & Evidence Snapshot
            report_service = SecurityReportService(self.db)
            report_name = f"Scheduled Report - {schedule.name} - {timestamp_str}"
            report = report_service.create_report(
                project_id=schedule.project_id,
                name=report_name,
                description=f"Generated automatically by schedule '{schedule.name}'",
                report_type="EXECUTION",
                source_execution_plan_id=plan.id,
                source_gate_evaluation_id=gate_eval_id,
            )
            report_service.generate_report(report.id, project_id=schedule.project_id)
            exec_record.report_id = report.id
            self.db.commit()

            # Step E: Mark Execution Complete
            exec_record.status = "COMPLETED"
            exec_record.completed_at = datetime.now(timezone.utc)
            self._advance_schedule(schedule, base_time=exec_record.started_at)
            self.db.commit()
            self.db.refresh(exec_record)

        except Exception as e:
            # Handle failure gracefully, recording failure and advancing schedule
            exec_record.status = "FAILED"
            exec_record.error_message = str(e)
            exec_record.completed_at = datetime.now(timezone.utc)
            self._advance_schedule(schedule, base_time=now_utc)
            self.db.commit()
            self.db.refresh(exec_record)

        return exec_record

    def _advance_schedule(self, schedule: SecurityScanSchedule, base_time: datetime) -> None:
        """Advance the schedule's last_run_at and next_run_at timestamps."""
        schedule.last_run_at = base_time
        if schedule.schedule_type == "ONCE":
            schedule.status = "EXPIRED"
            schedule.next_run_at = None
        else:
            next_run = self.schedule_service.calculate_next_run(
                schedule_type=schedule.schedule_type,
                timezone_name=schedule.timezone,
                cron_expression=schedule.cron_expression,
                scheduled_at=schedule.scheduled_at,
                start_at=schedule.start_at,
                end_at=schedule.end_at,
                base_time=base_time,
            )
            schedule.next_run_at = next_run
            if not next_run:
                schedule.status = "EXPIRED"

    def get_execution(
        self,
        execution_id: str,
        project_id: Optional[int] = None,
    ) -> Optional[SecurityScheduledExecution]:
        """Fetch scheduled execution details with project isolation."""
        execution = (
            self.db.query(SecurityScheduledExecution)
            .filter(SecurityScheduledExecution.id == execution_id)
            .first()
        )
        if not execution:
            return None

        if project_id is not None and execution.project_id != project_id:
            raise CrossProjectViolationError(
                f"Execution '{execution_id}' belongs to project {execution.project_id}, not {project_id}."
            )

        return execution

    def list_executions_for_schedule(
        self,
        schedule_id: str,
        project_id: Optional[int] = None,
        limit: int = 50,
    ) -> List[SecurityScheduledExecution]:
        """List historical executions for a schedule."""
        schedule = self.schedule_service.get_schedule(schedule_id, project_id=project_id)
        if not schedule:
            raise ScheduleNotFoundError(f"Security scan schedule '{schedule_id}' not found.")

        return (
            self.db.query(SecurityScheduledExecution)
            .filter(SecurityScheduledExecution.schedule_id == schedule_id)
            .order_by(SecurityScheduledExecution.created_at.desc())
            .limit(limit)
            .all()
        )

    def list_executions_for_project(
        self,
        project_id: int,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[SecurityScheduledExecution]:
        """List historical executions for a project."""
        query = (
            self.db.query(SecurityScheduledExecution)
            .filter(SecurityScheduledExecution.project_id == project_id)
        )
        if status:
            query = query.filter(SecurityScheduledExecution.status == status.upper())

        return query.order_by(SecurityScheduledExecution.created_at.desc()).limit(limit).all()
