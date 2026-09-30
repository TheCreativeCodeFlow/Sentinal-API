"""
Stage 10.6: Scheduled & Continuous Security Scanning - Schedule Service
Author: SentinelAPI Security Architecture Team

Deterministic scheduling layer that manages project-scoped SecurityScanSchedules.
Guarantees:
- Strict project/tenant isolation.
- Full timezone awareness using zoneinfo and croniter (DST-safe).
- Recurrence calculation (ONCE, HOURLY, DAILY, WEEKLY, CRON).
- Preview generation without executing tests or plans (zero HTTP calls).
- State transitions (ACTIVE, DISABLED, EXPIRED).
"""

from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from croniter import croniter
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.models import (
    Project,
    SecurityScanSchedule,
    SecurityScheduledExecution,
    ScanProfile,
    SecurityGate,
)


class ScheduleError(Exception):
    """Base exception for schedule errors."""
    pass


class ScheduleNotFoundError(ScheduleError):
    """Raised when a schedule is not found."""
    pass


class DuplicateScheduleError(ScheduleError):
    """Raised when a schedule name already exists in the project."""
    pass


class InvalidScheduleError(ScheduleError):
    """Raised when schedule parameters, timezone, or cron expression are invalid."""
    pass


class CrossProjectViolationError(ScheduleError):
    """Raised when cross-project resources are linked or accessed."""
    pass


class DisabledScheduleError(ScheduleError):
    """Raised when an operation cannot be performed on a disabled schedule."""
    pass


class ScheduleService:
    """Service for managing SecurityScanSchedules with timezone-aware recurrence."""

    SCHEDULE_TYPES = {"ONCE", "HOURLY", "DAILY", "WEEKLY", "CRON"}
    STATUS_TYPES = {"ACTIVE", "DISABLED", "EXPIRED"}

    PRESET_CRONS = {
        "HOURLY": "0 * * * *",
        "DAILY": "0 0 * * *",
        "WEEKLY": "0 0 * * 0",
    }

    def __init__(self, db: Session):
        self.db = db

    # =========================================================================
    # Validation & Recurrence Calculation
    # =========================================================================

    def validate_timezone(self, tz_name: str) -> ZoneInfo:
        """Validate and return ZoneInfo object or raise InvalidScheduleError."""
        if not tz_name or not isinstance(tz_name, str):
            raise InvalidScheduleError("A valid IANA timezone string must be provided.")
        try:
            return ZoneInfo(tz_name.strip())
        except (ZoneInfoNotFoundError, ValueError, KeyError):
            raise InvalidScheduleError(f"Invalid timezone: '{tz_name}'. Must be a valid IANA timezone name.")

    def calculate_next_run(
        self,
        schedule_type: str,
        timezone_name: str,
        cron_expression: Optional[str] = None,
        scheduled_at: Optional[datetime] = None,
        start_at: Optional[datetime] = None,
        end_at: Optional[datetime] = None,
        base_time: Optional[datetime] = None,
    ) -> Optional[datetime]:
        """
        Calculate next run datetime in UTC.
        Deterministic, timezone-aware, DST-resilient.
        """
        tz = self.validate_timezone(timezone_name)
        stype = schedule_type.upper() if schedule_type else "DAILY"

        if stype not in self.SCHEDULE_TYPES:
            raise InvalidScheduleError(f"Unsupported schedule type '{schedule_type}'. Must be one of {sorted(self.SCHEDULE_TYPES)}.")

        now_utc = datetime.now(timezone.utc)
        if base_time is None:
            calc_base = now_utc
        else:
            calc_base = base_time if base_time.tzinfo else base_time.replace(tzinfo=timezone.utc)

        # Respect start_at: calculation shouldn't start before start_at
        if start_at:
            aware_start = start_at if start_at.tzinfo else start_at.replace(tzinfo=timezone.utc)
            if aware_start > calc_base:
                calc_base = aware_start - timedelta(seconds=1)

        # Check if already past end_at
        if end_at:
            aware_end = end_at if end_at.tzinfo else end_at.replace(tzinfo=timezone.utc)
            if calc_base >= aware_end:
                return None

        if stype == "ONCE":
            if not scheduled_at:
                raise InvalidScheduleError("Schedule type 'ONCE' requires 'scheduled_at' datetime.")
            target = scheduled_at if scheduled_at.tzinfo else scheduled_at.replace(tzinfo=timezone.utc)
            if target <= calc_base:
                return None
            if end_at and target > aware_end:
                return None
            return target.astimezone(timezone.utc)

        # Determine cron expression
        if stype == "CRON":
            if not cron_expression or not cron_expression.strip():
                raise InvalidScheduleError("Schedule type 'CRON' requires a valid 'cron_expression'.")
            expr = cron_expression.strip()
        else:
            expr = self.PRESET_CRONS.get(stype)
            if not expr:
                raise InvalidScheduleError(f"No cron pattern configured for schedule type '{stype}'.")

        if not croniter.is_valid(expr):
            raise InvalidScheduleError(f"Invalid cron expression: '{expr}'.")

        # Convert base to schedule's local timezone for croniter
        local_base = calc_base.astimezone(tz)
        try:
            cron = croniter(expr, local_base)
            next_local = cron.get_next(datetime)
            next_utc = next_local.astimezone(timezone.utc)
        except Exception as e:
            raise InvalidScheduleError(f"Error calculating next run with croniter: {str(e)}")

        # Respect end_at constraint
        if end_at:
            aware_end = end_at if end_at.tzinfo else end_at.replace(tzinfo=timezone.utc)
            if next_utc > aware_end:
                return None

        return next_utc

    def preview_schedule(
        self,
        schedule_type: str,
        timezone_name: str,
        cron_expression: Optional[str] = None,
        scheduled_at: Optional[datetime] = None,
        start_at: Optional[datetime] = None,
        end_at: Optional[datetime] = None,
        count: int = 5,
    ) -> List[datetime]:
        """
        Generate preview of next N occurrences without writing to DB or running tests.
        """
        occurrences: List[datetime] = []
        base = datetime.now(timezone.utc)

        for _ in range(max(1, min(count, 50))):
            nxt = self.calculate_next_run(
                schedule_type=schedule_type,
                timezone_name=timezone_name,
                cron_expression=cron_expression,
                scheduled_at=scheduled_at,
                start_at=start_at,
                end_at=end_at,
                base_time=base,
            )
            if not nxt:
                break
            occurrences.append(nxt)
            base = nxt

        return occurrences

    # =========================================================================
    # CRUD Operations
    # =========================================================================

    def create_schedule(
        self,
        project_id: int,
        name: str,
        scan_profile_id: str,
        description: Optional[str] = None,
        security_gate_id: Optional[str] = None,
        timezone_name: str = "UTC",
        schedule_type: str = "DAILY",
        cron_expression: Optional[str] = None,
        scheduled_at: Optional[datetime] = None,
        start_at: Optional[datetime] = None,
        end_at: Optional[datetime] = None,
        max_concurrent_runs: int = 1,
        timeout_seconds: int = 600,
        status: str = "ACTIVE",
    ) -> SecurityScanSchedule:
        """Create a new project-scoped SecurityScanSchedule."""
        clean_name = name.strip() if name else ""
        if not clean_name:
            raise InvalidScheduleError("Schedule name cannot be empty.")

        # Project existence check
        project = self.db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise ScheduleNotFoundError(f"Project with ID {project_id} not found.")

        # Scan profile validation
        profile = self.db.query(ScanProfile).filter(ScanProfile.id == scan_profile_id).first()
        if not profile:
            raise ScheduleNotFoundError(f"Scan profile '{scan_profile_id}' not found.")
        if profile.project_id != project_id:
            raise CrossProjectViolationError(
                f"Scan profile '{scan_profile_id}' belongs to project {profile.project_id}, not {project_id}."
            )

        # Gate validation
        if security_gate_id:
            gate = self.db.query(SecurityGate).filter(SecurityGate.id == security_gate_id).first()
            if not gate:
                raise ScheduleNotFoundError(f"Security gate '{security_gate_id}' not found.")
            if gate.project_id != project_id:
                raise CrossProjectViolationError(
                    f"Security gate '{security_gate_id}' belongs to project {gate.project_id}, not {project_id}."
                )

        # Status validation
        s_status = status.upper() if status else "ACTIVE"
        if s_status not in self.STATUS_TYPES:
            s_status = "ACTIVE"

        # Time range validation
        if start_at and end_at:
            aware_s = start_at if start_at.tzinfo else start_at.replace(tzinfo=timezone.utc)
            aware_e = end_at if end_at.tzinfo else end_at.replace(tzinfo=timezone.utc)
            if aware_e <= aware_s:
                raise InvalidScheduleError("Schedule 'end_at' must be strictly after 'start_at'.")

        # Timezone & Recurrence validation
        self.validate_timezone(timezone_name)

        next_run = None
        if s_status == "ACTIVE":
            next_run = self.calculate_next_run(
                schedule_type=schedule_type,
                timezone_name=timezone_name,
                cron_expression=cron_expression,
                scheduled_at=scheduled_at,
                start_at=start_at,
                end_at=end_at,
            )
            if not next_run:
                s_status = "EXPIRED"

        schedule = SecurityScanSchedule(
            project_id=project_id,
            name=clean_name,
            description=description.strip() if description else None,
            status=s_status,
            scan_profile_id=scan_profile_id,
            security_gate_id=security_gate_id,
            timezone=timezone_name.strip(),
            schedule_type=schedule_type.upper(),
            cron_expression=cron_expression.strip() if cron_expression else None,
            scheduled_at=scheduled_at,
            start_at=start_at,
            end_at=end_at,
            max_concurrent_runs=max(1, min(max_concurrent_runs, 10)),
            timeout_seconds=max(30, min(timeout_seconds, 86400)),
            next_run_at=next_run,
        )
        self.db.add(schedule)
        try:
            self.db.commit()
            self.db.refresh(schedule)
        except IntegrityError:
            self.db.rollback()
            raise DuplicateScheduleError(
                f"A security scan schedule named '{clean_name}' already exists in project {project_id}."
            )

        return schedule

    def get_schedule(
        self,
        schedule_id: str,
        project_id: Optional[int] = None,
    ) -> Optional[SecurityScanSchedule]:
        """Fetch a security scan schedule with project isolation check."""
        schedule = (
            self.db.query(SecurityScanSchedule)
            .filter(SecurityScanSchedule.id == schedule_id)
            .first()
        )
        if not schedule:
            return None

        if project_id is not None and schedule.project_id != project_id:
            raise CrossProjectViolationError(
                f"Schedule '{schedule_id}' belongs to project {schedule.project_id}, not {project_id}."
            )

        return schedule

    def list_schedules(
        self,
        project_id: int,
        status: Optional[str] = None,
    ) -> List[SecurityScanSchedule]:
        """List scan schedules for a project."""
        query = self.db.query(SecurityScanSchedule).filter(SecurityScanSchedule.project_id == project_id)
        if status:
            query = query.filter(SecurityScanSchedule.status == status.upper())
        return query.order_by(SecurityScanSchedule.created_at.desc()).all()

    def update_schedule(
        self,
        schedule_id: str,
        project_id: Optional[int] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        scan_profile_id: Optional[str] = None,
        security_gate_id: Optional[str] = None,
        timezone_name: Optional[str] = None,
        schedule_type: Optional[str] = None,
        cron_expression: Optional[str] = None,
        scheduled_at: Optional[datetime] = None,
        start_at: Optional[datetime] = None,
        end_at: Optional[datetime] = None,
        max_concurrent_runs: Optional[int] = None,
        timeout_seconds: Optional[int] = None,
        status: Optional[str] = None,
    ) -> SecurityScanSchedule:
        """Update a security scan schedule and recalculate next_run_at."""
        schedule = self.get_schedule(schedule_id, project_id=project_id)
        if not schedule:
            raise ScheduleNotFoundError(f"Security scan schedule '{schedule_id}' not found.")

        if name is not None:
            clean_name = name.strip()
            if not clean_name:
                raise InvalidScheduleError("Schedule name cannot be empty.")
            schedule.name = clean_name

        if description is not None:
            schedule.description = description.strip() if description else None

        if scan_profile_id is not None:
            profile = self.db.query(ScanProfile).filter(ScanProfile.id == scan_profile_id).first()
            if not profile:
                raise ScheduleNotFoundError(f"Scan profile '{scan_profile_id}' not found.")
            if profile.project_id != schedule.project_id:
                raise CrossProjectViolationError(
                    f"Scan profile '{scan_profile_id}' belongs to project {profile.project_id}, not {schedule.project_id}."
                )
            schedule.scan_profile_id = scan_profile_id

        if security_gate_id is not None:
            if security_gate_id == "" or security_gate_id is None:
                schedule.security_gate_id = None
            else:
                gate = self.db.query(SecurityGate).filter(SecurityGate.id == security_gate_id).first()
                if not gate:
                    raise ScheduleNotFoundError(f"Security gate '{security_gate_id}' not found.")
                if gate.project_id != schedule.project_id:
                    raise CrossProjectViolationError(
                        f"Security gate '{security_gate_id}' belongs to project {gate.project_id}, not {schedule.project_id}."
                    )
                schedule.security_gate_id = security_gate_id

        if timezone_name is not None:
            self.validate_timezone(timezone_name)
            schedule.timezone = timezone_name.strip()

        if schedule_type is not None:
            stype = schedule_type.upper()
            if stype not in self.SCHEDULE_TYPES:
                raise InvalidScheduleError(f"Unsupported schedule type '{schedule_type}'.")
            schedule.schedule_type = stype

        if cron_expression is not None:
            schedule.cron_expression = cron_expression.strip() if cron_expression else None

        if scheduled_at is not None:
            schedule.scheduled_at = scheduled_at

        if start_at is not None:
            schedule.start_at = start_at

        if end_at is not None:
            schedule.end_at = end_at

        if max_concurrent_runs is not None:
            schedule.max_concurrent_runs = max(1, min(max_concurrent_runs, 10))

        if timeout_seconds is not None:
            schedule.timeout_seconds = max(30, min(timeout_seconds, 86400))

        if status is not None:
            s_status = status.upper()
            if s_status in self.STATUS_TYPES:
                schedule.status = s_status

        # Validate start/end order
        if schedule.start_at and schedule.end_at:
            aware_s = schedule.start_at if schedule.start_at.tzinfo else schedule.start_at.replace(tzinfo=timezone.utc)
            aware_e = schedule.end_at if schedule.end_at.tzinfo else schedule.end_at.replace(tzinfo=timezone.utc)
            if aware_e <= aware_s:
                raise InvalidScheduleError("Schedule 'end_at' must be strictly after 'start_at'.")

        # Recalculate next run
        if schedule.status == "ACTIVE":
            next_run = self.calculate_next_run(
                schedule_type=schedule.schedule_type,
                timezone_name=schedule.timezone,
                cron_expression=schedule.cron_expression,
                scheduled_at=schedule.scheduled_at,
                start_at=schedule.start_at,
                end_at=schedule.end_at,
            )
            schedule.next_run_at = next_run
            if not next_run:
                schedule.status = "EXPIRED"
        else:
            schedule.next_run_at = None

        try:
            self.db.commit()
            self.db.refresh(schedule)
        except IntegrityError:
            self.db.rollback()
            raise DuplicateScheduleError(
                f"A security scan schedule named '{schedule.name}' already exists in project {schedule.project_id}."
            )

        return schedule

    def delete_schedule(
        self,
        schedule_id: str,
        project_id: Optional[int] = None,
    ) -> bool:
        """
        Delete a security scan schedule.
        Foreign key constraint on SecurityScheduledExecution sets schedule_id to NULL,
        preserving complete audit and execution history.
        """
        schedule = self.get_schedule(schedule_id, project_id=project_id)
        if not schedule:
            raise ScheduleNotFoundError(f"Security scan schedule '{schedule_id}' not found.")

        self.db.delete(schedule)
        self.db.commit()
        return True

    def enable_schedule(
        self,
        schedule_id: str,
        project_id: Optional[int] = None,
    ) -> SecurityScanSchedule:
        """Enable an inactive schedule and recalculate its next run time."""
        schedule = self.get_schedule(schedule_id, project_id=project_id)
        if not schedule:
            raise ScheduleNotFoundError(f"Security scan schedule '{schedule_id}' not found.")

        schedule.status = "ACTIVE"
        schedule.next_run_at = self.calculate_next_run(
            schedule_type=schedule.schedule_type,
            timezone_name=schedule.timezone,
            cron_expression=schedule.cron_expression,
            scheduled_at=schedule.scheduled_at,
            start_at=schedule.start_at,
            end_at=schedule.end_at,
        )
        if not schedule.next_run_at:
            schedule.status = "EXPIRED"

        self.db.commit()
        self.db.refresh(schedule)
        return schedule

    def disable_schedule(
        self,
        schedule_id: str,
        project_id: Optional[int] = None,
    ) -> SecurityScanSchedule:
        """Disable an active schedule and clear its next run time."""
        schedule = self.get_schedule(schedule_id, project_id=project_id)
        if not schedule:
            raise ScheduleNotFoundError(f"Security scan schedule '{schedule_id}' not found.")

        schedule.status = "DISABLED"
        schedule.next_run_at = None

        self.db.commit()
        self.db.refresh(schedule)
        return schedule

    def get_schedule_preview(
        self,
        schedule_id: str,
        project_id: Optional[int] = None,
        count: int = 5,
    ) -> Dict[str, Any]:
        """Generate occurrence preview for an existing schedule without running tests."""
        schedule = self.get_schedule(schedule_id, project_id=project_id)
        if not schedule:
            raise ScheduleNotFoundError(f"Security scan schedule '{schedule_id}' not found.")

        occurrences = self.preview_schedule(
            schedule_type=schedule.schedule_type,
            timezone_name=schedule.timezone,
            cron_expression=schedule.cron_expression,
            scheduled_at=schedule.scheduled_at,
            start_at=schedule.start_at,
            end_at=schedule.end_at,
            count=count,
        )

        return {
            "schedule_id": schedule.id,
            "name": schedule.name,
            "schedule_type": schedule.schedule_type,
            "timezone": schedule.timezone,
            "is_active": schedule.status == "ACTIVE",
            "is_expired": schedule.status == "EXPIRED" or len(occurrences) == 0,
            "next_occurrences": occurrences,
        }
