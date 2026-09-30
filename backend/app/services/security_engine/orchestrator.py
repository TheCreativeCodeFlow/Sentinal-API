"""
Stage 10.1: Security Test Orchestration & Execution Plans Service
Author: SentinelAPI Security Architecture Team

Provides a deterministic orchestration layer coordinating existing SecurityTests safely.
Features:
- Test Suites with execution ordering, active/disabled status, and item toggles.
- Execution Plans with deterministic execution modes (SEQUENTIAL, FAIL_FAST, CONTINUE_ON_FAILURE).
- Safe delegation to existing security testing engines (BOLA, BFLA, Property Exposure, Authentication).
- Progress tracking, aggregate result metrics, and cancellation support.
- Strict project authorization and cross-project isolation enforcement.
- Absolute prohibition against direct target HTTP calls, credential exposure, or AI hypothesis execution.
"""

from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.models import (
    Project,
    SecurityTest,
    SecurityTestSuite,
    SecurityTestSuiteItem,
    SecurityExecutionPlan,
    SecurityExecutionItem,
)


class OrchestrationError(Exception):
    """Base exception for orchestration engine errors."""
    pass


from app.services.security_engine.investigation_service import CrossProjectViolationError


class PlanStateError(OrchestrationError):
    """Raised when an execution plan is in an invalid state for an operation."""
    pass


class AuthorizationError(OrchestrationError):
    """Raised when a target project is not authorized for security testing."""
    pass


class EntityNotFoundError(OrchestrationError):
    """Raised when a required database entity is not found."""
    pass


class InvalidSuiteStateError(OrchestrationError):
    """Raised when a suite is in an invalid state for planning."""
    pass


class TestOrchestrator:
    """
    Deterministic coordinator for SecurityTests.
    Never executes target HTTP requests directly; delegates exclusively to deterministic engines.
    """
    __test__ = False

    def __init__(self, db: Session, app: Optional[Any] = None):
        self.db = db
        if app is not None:
            self.app = app
        else:
            try:
                from app.main import app as fastapi_app
                self.app = fastapi_app
            except ImportError:
                self.app = None

    # =========================================================================
    # Test Suite Management
    # =========================================================================

    def create_suite(
        self,
        project_id: int,
        name: str,
        description: Optional[str] = None,
        status: str = "ACTIVE",
    ) -> SecurityTestSuite:
        """Create a new test suite within a project."""
        project = self.db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise EntityNotFoundError(f"Project with ID {project_id} not found.")

        suite = SecurityTestSuite(
            project_id=project_id,
            name=name.strip(),
            description=description.strip() if description else None,
            status=status.upper(),
        )
        self.db.add(suite)
        self.db.commit()
        self.db.refresh(suite)
        return suite

    def get_suite(self, suite_id: str) -> Optional[SecurityTestSuite]:
        """Fetch a test suite by ID with its items."""
        return self.db.query(SecurityTestSuite).filter(SecurityTestSuite.id == suite_id).first()

    def list_suites(self, project_id: int) -> List[SecurityTestSuite]:
        """List all test suites for a project ordered by creation time descending."""
        return (
            self.db.query(SecurityTestSuite)
            .filter(SecurityTestSuite.project_id == project_id)
            .order_by(SecurityTestSuite.created_at.desc())
            .all()
        )

    def update_suite(
        self,
        suite_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        status: Optional[str] = None,
    ) -> SecurityTestSuite:
        """Update suite metadata or active status."""
        suite = self.get_suite(suite_id)
        if not suite:
            raise EntityNotFoundError(f"Test suite with ID {suite_id} not found.")

        if name is not None:
            suite.name = name.strip()
        if description is not None:
            suite.description = description.strip() if description else None
        if status is not None:
            suite.status = status.upper()

        self.db.commit()
        self.db.refresh(suite)
        return suite

    def delete_suite(self, suite_id: str) -> bool:
        """Delete a test suite and its items (cascading)."""
        suite = self.get_suite(suite_id)
        if not suite:
            raise EntityNotFoundError(f"Test suite with ID {suite_id} not found.")

        self.db.delete(suite)
        self.db.commit()
        return True

    def add_test_to_suite(
        self,
        suite_id: str,
        security_test_id: str,
        execution_order: Optional[int] = None,
        enabled: bool = True,
    ) -> SecurityTestSuiteItem:
        """
        Add a SecurityTest to a suite with execution ordering.
        Enforces cross-project isolation.
        """
        suite = self.get_suite(suite_id)
        if not suite:
            raise EntityNotFoundError(f"Test suite with ID {suite_id} not found.")

        test = self.db.query(SecurityTest).filter(SecurityTest.id == security_test_id).first()
        if not test:
            raise EntityNotFoundError(f"Security test with ID {security_test_id} not found.")

        if test.project_id != suite.project_id:
            raise CrossProjectViolationError(
                f"Security test '{security_test_id}' belongs to project {test.project_id}, "
                f"but suite '{suite_id}' belongs to project {suite.project_id}."
            )

        # Check if already in suite
        existing = (
            self.db.query(SecurityTestSuiteItem)
            .filter(
                SecurityTestSuiteItem.suite_id == suite_id,
                SecurityTestSuiteItem.security_test_id == security_test_id,
            )
            .first()
        )
        if existing:
            # Update enabled or order if specified
            if execution_order is not None:
                existing.execution_order = execution_order
            existing.enabled = enabled
            self.db.commit()
            self.db.refresh(existing)
            return existing

        # Determine next execution order if not specified
        existing_items = (
            self.db.query(SecurityTestSuiteItem)
            .filter(SecurityTestSuiteItem.suite_id == suite_id)
            .order_by(SecurityTestSuiteItem.execution_order.asc())
            .all()
        )
        max_order = max([item.execution_order for item in existing_items], default=0)

        if execution_order is None or execution_order <= 0:
            order_to_use = max_order + 1
        else:
            order_to_use = execution_order
            # Shift conflicting items up by 1 if there's an exact collision
            collision = any(item.execution_order == order_to_use for item in existing_items)
            if collision:
                for item in reversed(existing_items):
                    if item.execution_order >= order_to_use:
                        item.execution_order += 1
                self.db.flush()

        item = SecurityTestSuiteItem(
            suite_id=suite_id,
            security_test_id=security_test_id,
            execution_order=order_to_use,
            enabled=enabled,
        )
        self.db.add(item)
        self.db.commit()
        self.db.refresh(item)
        return item

    def remove_test_from_suite(self, suite_id: str, item_id: str) -> bool:
        """Remove a test item from a suite."""
        item = (
            self.db.query(SecurityTestSuiteItem)
            .filter(
                SecurityTestSuiteItem.suite_id == suite_id,
                SecurityTestSuiteItem.id == item_id,
            )
            .first()
        )
        if not item:
            raise EntityNotFoundError(f"Suite item with ID {item_id} not found in suite {suite_id}.")

        self.db.delete(item)
        self.db.commit()

        # Re-compact execution orders sequentially 1..N using two-pass to avoid unique constraint collisions
        remaining_items = (
            self.db.query(SecurityTestSuiteItem)
            .filter(SecurityTestSuiteItem.suite_id == suite_id)
            .order_by(SecurityTestSuiteItem.execution_order.asc())
            .all()
        )
        for idx, it in enumerate(remaining_items, start=1):
            it.execution_order = -idx
        self.db.flush()

        for idx, it in enumerate(remaining_items, start=1):
            it.execution_order = idx
        self.db.commit()

        return True

    def update_suite_item(
        self,
        suite_id: str,
        item_id: str,
        execution_order: Optional[int] = None,
        enabled: Optional[bool] = None,
    ) -> SecurityTestSuiteItem:
        """Update a suite item's enabled state or execution order."""
        item = (
            self.db.query(SecurityTestSuiteItem)
            .filter(
                SecurityTestSuiteItem.suite_id == suite_id,
                SecurityTestSuiteItem.id == item_id,
            )
            .first()
        )
        if not item:
            raise EntityNotFoundError(f"Suite item with ID {item_id} not found in suite {suite_id}.")

        if enabled is not None:
            item.enabled = enabled

        if execution_order is not None and execution_order != item.execution_order:
            # Reorder all items cleanly using two-pass to avoid unique collisions
            other_items = (
                self.db.query(SecurityTestSuiteItem)
                .filter(
                    SecurityTestSuiteItem.suite_id == suite_id,
                    SecurityTestSuiteItem.id != item_id,
                )
                .order_by(SecurityTestSuiteItem.execution_order.asc())
                .all()
            )
            target_idx = max(0, min(execution_order - 1, len(other_items)))
            other_items.insert(target_idx, item)
            for idx, it in enumerate(other_items, start=1):
                it.execution_order = -idx
            self.db.flush()
            for idx, it in enumerate(other_items, start=1):
                it.execution_order = idx

        self.db.commit()
        self.db.refresh(item)
        return item

    # =========================================================================
    # Execution Plan Management
    # =========================================================================

    def create_plan_from_suite(
        self,
        project_id: int,
        suite_id: str,
        name: Optional[str] = None,
        execution_mode: str = "SEQUENTIAL",
    ) -> SecurityExecutionPlan:
        """
        Create a deterministic execution plan from an active test suite.
        Only enabled tests are included in the execution plan.
        """
        suite = self.get_suite(suite_id)
        if not suite:
            raise EntityNotFoundError(f"Test suite with ID {suite_id} not found.")

        if suite.project_id != project_id:
            raise CrossProjectViolationError(
                f"Test suite '{suite_id}' belongs to project {suite.project_id}, not {project_id}."
            )

        if suite.status == "DISABLED":
            raise InvalidSuiteStateError(
                f"Test suite '{suite.name}' is DISABLED and cannot be used to create an execution plan."
            )

        enabled_items = [it for it in suite.items if it.enabled]
        # Validate that all tests belong to project
        for it in enabled_items:
            if it.security_test and it.security_test.project_id != project_id:
                raise CrossProjectViolationError(
                    f"Test '{it.security_test_id}' in suite belongs to a different project."
                )

        plan_name = name.strip() if name else f"{suite.name} - Plan"
        mode = execution_mode.upper() if execution_mode else "SEQUENTIAL"
        if mode not in ("SEQUENTIAL", "FAIL_FAST", "CONTINUE_ON_FAILURE"):
            mode = "SEQUENTIAL"

        plan = SecurityExecutionPlan(
            project_id=project_id,
            suite_id=suite_id,
            name=plan_name,
            status="READY" if enabled_items else "DRAFT",
            execution_mode=mode,
            total_tests=len(enabled_items),
            completed_tests=0,
            confirmed_findings=0,
            inconclusive_tests=0,
            failed_tests=0,
        )
        self.db.add(plan)
        self.db.flush()

        # Add execution items in sequential order
        for idx, it in enumerate(enabled_items, start=1):
            exec_item = SecurityExecutionItem(
                execution_plan_id=plan.id,
                security_test_id=it.security_test_id,
                execution_order=idx,
                status="QUEUED",
            )
            self.db.add(exec_item)

        self.db.commit()
        self.db.refresh(plan)
        return plan

    def create_plan_from_tests(
        self,
        project_id: int,
        security_test_ids: List[str],
        name: str,
        execution_mode: str = "SEQUENTIAL",
    ) -> SecurityExecutionPlan:
        """
        Create a deterministic execution plan directly from a list of SecurityTests.
        Enforces cross-project isolation.
        """
        project = self.db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise EntityNotFoundError(f"Project with ID {project_id} not found.")

        # Deduplicate while preserving order
        seen = set()
        deduped_ids = []
        for tid in security_test_ids:
            if tid not in seen:
                seen.add(tid)
                deduped_ids.append(tid)

        # Validate all tests exist and belong to project
        tests = self.db.query(SecurityTest).filter(SecurityTest.id.in_(deduped_ids)).all()
        test_map = {t.id: t for t in tests}

        for tid in deduped_ids:
            if tid not in test_map:
                raise EntityNotFoundError(f"Security test with ID '{tid}' not found.")
            if test_map[tid].project_id != project_id:
                raise CrossProjectViolationError(
                    f"Security test '{tid}' belongs to project {test_map[tid].project_id}, not {project_id}."
                )

        mode = execution_mode.upper() if execution_mode else "SEQUENTIAL"
        if mode not in ("SEQUENTIAL", "FAIL_FAST", "CONTINUE_ON_FAILURE"):
            mode = "SEQUENTIAL"

        plan = SecurityExecutionPlan(
            project_id=project_id,
            suite_id=None,
            name=name.strip(),
            status="READY" if deduped_ids else "DRAFT",
            execution_mode=mode,
            total_tests=len(deduped_ids),
            completed_tests=0,
            confirmed_findings=0,
            inconclusive_tests=0,
            failed_tests=0,
        )
        self.db.add(plan)
        self.db.flush()

        for idx, tid in enumerate(deduped_ids, start=1):
            exec_item = SecurityExecutionItem(
                execution_plan_id=plan.id,
                security_test_id=tid,
                execution_order=idx,
                status="QUEUED",
            )
            self.db.add(exec_item)

        self.db.commit()
        self.db.refresh(plan)
        return plan

    def get_plan(self, plan_id: str) -> Optional[SecurityExecutionPlan]:
        """Fetch an execution plan with its items."""
        return self.db.query(SecurityExecutionPlan).filter(SecurityExecutionPlan.id == plan_id).first()

    def list_plans(self, project_id: int) -> List[SecurityExecutionPlan]:
        """List all execution plans for a project ordered by creation time descending."""
        return (
            self.db.query(SecurityExecutionPlan)
            .filter(SecurityExecutionPlan.project_id == project_id)
            .order_by(SecurityExecutionPlan.created_at.desc())
            .all()
        )

    # =========================================================================
    # Plan Execution & Orchestration
    # =========================================================================

    async def start_plan(self, plan_id: str) -> SecurityExecutionPlan:
        """
        Execute a security execution plan deterministically.
        Rules:
        - Only explicitly authorized projects may execute.
        - Idempotency: cannot restart a RUNNING or COMPLETED plan.
        - Enforces execution mode (SEQUENTIAL, FAIL_FAST, CONTINUE_ON_FAILURE).
        - Delegates exclusively to existing deterministic security engines.
        """
        plan = self.get_plan(plan_id)
        if not plan:
            raise EntityNotFoundError(f"Execution plan with ID {plan_id} not found.")

        # Idempotency checks
        if plan.status in ("RUNNING", "COMPLETED"):
            raise PlanStateError(
                f"Execution plan '{plan_id}' is already {plan.status.lower()} and cannot be restarted."
            )
        if plan.status == "CANCELLED":
            raise PlanStateError(f"Cannot start cancelled execution plan '{plan_id}'.")

        # Project Authorization Guard
        project = plan.project
        if not project or (project.authorization_status or "").lower() != "authorized":
            raise AuthorizationError(
                "Target project has not been authorized for security testing. "
                "Set project authorization status to 'authorized'."
            )

        # Empty plan handling
        if plan.total_tests == 0:
            plan.status = "COMPLETED"
            plan.started_at = datetime.now(timezone.utc)
            plan.completed_at = datetime.now(timezone.utc)
            self.db.commit()
            self.db.refresh(plan)
            return plan

        # Mark plan as RUNNING
        plan.status = "RUNNING"
        plan.started_at = datetime.now(timezone.utc)
        self.db.commit()

        # Engine imports
        from app.services.security_engine.evaluator import BOLAEngine
        from app.services.security_engine.bfla_engine import BFLAEngine
        from app.services.security_engine.property_engine import PropertyExposureEngine
        from app.services.security_engine.auth_engine import AuthenticationEngine

        sorted_items = sorted(plan.items, key=lambda x: x.execution_order)
        fail_fast_triggered = False

        for item in sorted_items:
            # Check if plan was cancelled in database mid-execution
            self.db.refresh(plan)
            if plan.status == "CANCELLED":
                for rem in sorted_items:
                    if rem.status == "QUEUED":
                        rem.status = "CANCELLED"
                self.db.commit()
                break

            if item.status != "QUEUED":
                continue

            # Mark item as RUNNING
            item.status = "RUNNING"
            item.started_at = datetime.now(timezone.utc)
            self.db.commit()

            test = item.security_test
            t_type = (test.test_type if test and test.test_type else "BOLA").upper()

            # Delegate to existing deterministic engine
            if t_type == "BFLA":
                engine = BFLAEngine(db=self.db, app=self.app)
            elif t_type == "PROPERTY_EXPOSURE":
                engine = PropertyExposureEngine(db=self.db, app=self.app)
            elif t_type in ("AUTH_MISSING", "AUTH_INVALID", "AUTH_MALFORMED", "AUTH_EXPIRED", "AUTH_SCHEME"):
                engine = AuthenticationEngine(db=self.db, app=self.app)
            else:
                engine = BOLAEngine(db=self.db, app=self.app)

            try:
                execution = await engine.execute_test(test)
                item.test_execution_id = execution.id
                item.result = execution.result
                item.status = "COMPLETED" if execution.status == "COMPLETED" else "FAILED"

                if execution.result == "CONFIRMED":
                    plan.confirmed_findings += 1
                elif execution.result == "INCONCLUSIVE":
                    plan.inconclusive_tests += 1
                elif execution.result in ("ERROR", None) or execution.status == "FAILED":
                    plan.failed_tests += 1

            except Exception as exc:
                item.status = "FAILED"
                item.result = "ERROR"
                item.error_message = str(exc)
                plan.failed_tests += 1

            finally:
                item.completed_at = datetime.now(timezone.utc)
                plan.completed_tests += 1
                self.db.commit()

            # Enforce execution mode
            if plan.execution_mode == "FAIL_FAST":
                if item.status == "FAILED" or item.result == "ERROR":
                    fail_fast_triggered = True
                    for rem in sorted_items:
                        if rem.status == "QUEUED":
                            rem.status = "SKIPPED"
                    self.db.commit()
                    break

        # Finalize plan status
        self.db.refresh(plan)
        if plan.status != "CANCELLED":
            if fail_fast_triggered:
                plan.status = "FAILED"
            else:
                plan.status = "COMPLETED"
            plan.completed_at = datetime.now(timezone.utc)
            self.db.commit()

        self.db.refresh(plan)
        return plan

    def cancel_plan(self, plan_id: str) -> SecurityExecutionPlan:
        """
        Safely cancel an execution plan.
        Unstarted (QUEUED) items are marked CANCELLED.
        In-flight tests finish naturally without abrupt termination.
        """
        plan = self.get_plan(plan_id)
        if not plan:
            raise EntityNotFoundError(f"Execution plan with ID {plan_id} not found.")

        if plan.status in ("COMPLETED", "CANCELLED"):
            return plan

        plan.status = "CANCELLED"
        for item in plan.items:
            if item.status == "QUEUED":
                item.status = "CANCELLED"

        plan.completed_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(plan)
        return plan

    def get_plan_progress(self, plan_id: str) -> Dict[str, Any]:
        """Get live progress breakdown for an execution plan."""
        plan = self.get_plan(plan_id)
        if not plan:
            raise EntityNotFoundError(f"Execution plan with ID {plan_id} not found.")

        progress_percent = (
            round((plan.completed_tests / plan.total_tests) * 100.0, 1)
            if plan.total_tests > 0
            else 0.0
        )

        results_summary = {
            "PASS": 0,
            "CONFIRMED": 0,
            "INCONCLUSIVE": 0,
            "ERROR": 0,
        }
        for item in plan.items:
            if item.result and item.result in results_summary:
                results_summary[item.result] += 1

        return {
            "plan_id": plan.id,
            "project_id": plan.project_id,
            "name": plan.name,
            "status": plan.status,
            "execution_mode": plan.execution_mode,
            "total_tests": plan.total_tests,
            "completed_tests": plan.completed_tests,
            "progress_percent": progress_percent,
            "results_summary": results_summary,
            "items": plan.items,
            "started_at": plan.started_at,
            "completed_at": plan.completed_at,
        }
