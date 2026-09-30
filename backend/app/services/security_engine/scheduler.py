"""
Stage 10.6: Scheduled & Continuous Security Scanning - Scheduler Runner
Author: SentinelAPI Security Architecture Team

Background scheduler runner that finds and triggers due SecurityScanSchedules.
Guarantees:
- Zero direct HTTP calls to targets.
- Evaluates only ACTIVE schedules where next_run_at <= current UTC time.
- Delegates execution to ScheduledScanService.
- Idempotent and concurrency-safe.
"""

import asyncio
from typing import List, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models import SecurityScanSchedule, SecurityScheduledExecution
from app.services.security_engine.scheduled_scan_service import ScheduledScanService


class SchedulerRunner:
    """Runner for detecting and executing due security scan schedules."""

    def __init__(self, db: Session):
        self.db = db
        self.scan_service = ScheduledScanService(db)

    async def run_due_schedules(
        self,
        project_id: Optional[int] = None,
        max_batch_size: int = 20,
    ) -> List[SecurityScheduledExecution]:
        """
        Query and trigger all active schedules currently due for execution.
        """
        now_utc = datetime.now(timezone.utc)
        query = (
            self.db.query(SecurityScanSchedule)
            .filter(
                SecurityScanSchedule.status == "ACTIVE",
                SecurityScanSchedule.next_run_at.isnot(None),
                SecurityScanSchedule.next_run_at <= now_utc,
            )
        )
        if project_id is not None:
            query = query.filter(SecurityScanSchedule.project_id == project_id)

        due_schedules = query.order_by(SecurityScanSchedule.next_run_at.asc()).limit(max_batch_size).all()

        results: List[SecurityScheduledExecution] = []
        for schedule in due_schedules:
            exec_record = await self.scan_service.trigger_execution(
                schedule_id=schedule.id,
                trigger_type="SCHEDULED",
                scheduled_for=schedule.next_run_at,
            )
            results.append(exec_record)

        return results
