"""
Stage 10.2: Security Baseline & Comparison Services
Author: SentinelAPI Security Architecture Team

Deterministic security baseline management and regression comparison engine.
Features:
- Baseline creation and versioning strictly from COMPLETED execution plans.
- Strict enforcement of single ACTIVE baseline per project (automatic archiving of previous active).
- Deterministic version sequencing (max(version) + 1).
- Multi-dimensional regression comparison:
  - REGRESSION: Previously PASS -> Now CONFIRMED finding.
  - IMPROVED: Previously CONFIRMED -> Now PASS.
  - UNCHANGED: Behavior matches baseline.
  - NEW_VIOLATION: New confirmed finding not in baseline.
  - NOT_APPLICABLE: Baseline control was not executed in current plan (NEVER assumed secure).
- Direct linkage to existing Finding records without duplicate finding generation.
- Zero target HTTP calls outside deterministic security engine boundary.
"""

from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError

from app.models import (
    Project,
    SecurityBaseline,
    SecurityBaselineControl,
    SecurityBaselineComparison,
    SecurityBaselineComparisonItem,
    SecurityExecutionPlan,
    SecurityExecutionItem,
    SecurityTest,
    Finding,
)


class BaselineError(Exception):
    """Base exception for baseline and comparison errors."""
    pass


class BaselineNotFoundError(BaselineError):
    """Raised when a baseline is not found."""
    pass


class ComparisonNotFoundError(BaselineError):
    """Raised when a baseline comparison is not found."""
    pass


class InvalidBaselinePlanError(BaselineError):
    """Raised when attempting to create a baseline from an incomplete execution plan."""
    pass


class CrossProjectViolationError(BaselineError):
    """Raised when attempting cross-project access for baselines or comparisons."""
    pass


class SecurityBaselineService:
    """
    Deterministic management service for Security Baselines.
    """
    __test__ = False

    def __init__(self, db: Session):
        self.db = db

    # =========================================================================
    # Baseline CRUD & State Management
    # =========================================================================

    def _get_next_version(self, project_id: int) -> int:
        """Deterministically calculate next version for project."""
        max_ver = (
            self.db.query(func.max(SecurityBaseline.version))
            .filter(SecurityBaseline.project_id == project_id)
            .scalar()
        )
        return (max_ver or 0) + 1

    def _archive_active_baselines(self, project_id: int, exclude_id: Optional[str] = None):
        """Ensure single ACTIVE baseline invariant within a project."""
        query = self.db.query(SecurityBaseline).filter(
            SecurityBaseline.project_id == project_id,
            SecurityBaseline.status == "ACTIVE",
        )
        if exclude_id:
            query = query.filter(SecurityBaseline.id != exclude_id)
        query.update({"status": "ARCHIVED"}, synchronize_session="fetch")

    def create_baseline(
        self,
        project_id: int,
        name: str,
        description: Optional[str] = None,
        source_execution_plan_id: Optional[str] = None,
        status: str = "DRAFT",
    ) -> SecurityBaseline:
        """Create a new security baseline with deterministic versioning."""
        project = self.db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise BaselineNotFoundError(f"Project with ID {project_id} not found.")

        b_status = status.upper() if status else "DRAFT"
        if b_status not in ("DRAFT", "ACTIVE", "ARCHIVED"):
            b_status = "DRAFT"

        if b_status == "ACTIVE":
            self._archive_active_baselines(project_id)

        version = self._get_next_version(project_id)

        baseline = SecurityBaseline(
            project_id=project_id,
            name=name.strip(),
            description=description.strip() if description else None,
            status=b_status,
            source_execution_plan_id=source_execution_plan_id,
            version=version,
        )
        self.db.add(baseline)
        self.db.commit()
        self.db.refresh(baseline)
        return baseline

    def get_baseline(
        self,
        baseline_id: str,
        project_id: Optional[int] = None,
    ) -> Optional[SecurityBaseline]:
        """Fetch baseline and verify cross-project isolation if project_id is given."""
        baseline = (
            self.db.query(SecurityBaseline)
            .filter(SecurityBaseline.id == baseline_id)
            .first()
        )
        if not baseline:
            return None

        if project_id is not None and baseline.project_id != project_id:
            raise CrossProjectViolationError(
                f"Baseline '{baseline_id}' belongs to project {baseline.project_id}, not {project_id}."
            )

        return baseline

    def list_baselines(
        self,
        project_id: int,
        status: Optional[str] = None,
    ) -> List[SecurityBaseline]:
        """List all baselines for a project ordered by version descending."""
        query = self.db.query(SecurityBaseline).filter(SecurityBaseline.project_id == project_id)
        if status:
            query = query.filter(SecurityBaseline.status == status.upper())
        return query.order_by(SecurityBaseline.version.desc()).all()

    def update_baseline(
        self,
        baseline_id: str,
        project_id: Optional[int] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        status: Optional[str] = None,
    ) -> SecurityBaseline:
        """Update baseline metadata or state."""
        baseline = self.get_baseline(baseline_id, project_id=project_id)
        if not baseline:
            raise BaselineNotFoundError(f"Baseline with ID {baseline_id} not found.")

        if name is not None:
            baseline.name = name.strip()

        if description is not None:
            baseline.description = description.strip() if description else None

        if status is not None:
            b_status = status.upper()
            if b_status in ("DRAFT", "ACTIVE", "ARCHIVED"):
                if b_status == "ACTIVE" and baseline.status != "ACTIVE":
                    self._archive_active_baselines(baseline.project_id, exclude_id=baseline.id)
                baseline.status = b_status

        self.db.commit()
        self.db.refresh(baseline)
        return baseline

    def activate_baseline(
        self,
        baseline_id: str,
        project_id: Optional[int] = None,
    ) -> SecurityBaseline:
        """Activate baseline, archiving any other active baseline for this project."""
        baseline = self.get_baseline(baseline_id, project_id=project_id)
        if not baseline:
            raise BaselineNotFoundError(f"Baseline with ID {baseline_id} not found.")

        self._archive_active_baselines(baseline.project_id, exclude_id=baseline.id)
        baseline.status = "ACTIVE"
        self.db.commit()
        self.db.refresh(baseline)
        return baseline

    def archive_baseline(
        self,
        baseline_id: str,
        project_id: Optional[int] = None,
    ) -> SecurityBaseline:
        """Archive baseline."""
        baseline = self.get_baseline(baseline_id, project_id=project_id)
        if not baseline:
            raise BaselineNotFoundError(f"Baseline with ID {baseline_id} not found.")

        baseline.status = "ARCHIVED"
        self.db.commit()
        self.db.refresh(baseline)
        return baseline

    # =========================================================================
    # Baseline Capture from Execution Plan
    # =========================================================================

    def create_baseline_from_execution_plan(
        self,
        project_id: int,
        execution_plan_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
    ) -> SecurityBaseline:
        """
        Capture a verified security baseline strictly from a COMPLETED execution plan.
        Incomplete plans are rejected.
        """
        plan = (
            self.db.query(SecurityExecutionPlan)
            .filter(SecurityExecutionPlan.id == execution_plan_id)
            .first()
        )
        if not plan:
            raise BaselineNotFoundError(f"Execution plan with ID {execution_plan_id} not found.")

        if plan.project_id != project_id:
            raise CrossProjectViolationError(
                f"Execution plan '{execution_plan_id}' belongs to project {plan.project_id}, not {project_id}."
            )

        if plan.status != "COMPLETED":
            raise InvalidBaselinePlanError(
                f"Cannot create baseline from execution plan '{execution_plan_id}' with status '{plan.status}'. "
                f"Execution plan status must be COMPLETED."
            )

        version = self._get_next_version(project_id)
        baseline_name = name.strip() if name else f"Baseline v{version} - {plan.name}"
        baseline_desc = (
            description.strip()
            if description
            else f"Baseline captured from execution plan '{plan.name}' ({plan.id}) completed at {plan.completed_at}"
        )

        baseline = SecurityBaseline(
            project_id=project_id,
            name=baseline_name,
            description=baseline_desc,
            status="DRAFT",
            source_execution_plan_id=plan.id,
            version=version,
        )
        self.db.add(baseline)
        self.db.flush()

        # Extract controls deterministically from completed execution items
        controls_by_key: Dict[tuple, SecurityBaselineControl] = {}

        for item in plan.items:
            # Only consider items with a resolved execution result
            if not item.result:
                continue

            test = item.security_test
            if not test:
                continue

            # Determine control_type
            test_type = test.test_type or "SECURITY_TEST"
            if test_type.startswith("AUTH_"):
                control_type = "AUTHENTICATION_REQUIRED"
            elif test_type == "BOLA":
                control_type = "BOLA_PROTECTION"
            elif test_type == "BFLA":
                control_type = "BFLA_PROTECTION"
            elif test_type.startswith("PROPERTY_"):
                control_type = "PROPERTY_PROTECTION"
            elif test_type.startswith("WORKFLOW_"):
                control_type = "WORKFLOW_PROTECTION"
            else:
                control_type = f"{test_type}_PROTECTION"

            # Determine target_type and target_id
            if test.endpoint:
                target_type = "ENDPOINT"
                target_id = str(test.endpoint.id)
            elif getattr(test, "victim_resource", None):
                target_type = "RESOURCE"
                target_id = str(test.victim_resource.id)
            else:
                target_type = "PROJECT"
                target_id = str(project_id)

            expected_behavior = item.result  # PASS, CONFIRMED, INCONCLUSIVE
            severity = "HIGH"
            if item.result == "CONFIRMED":
                severity = "HIGH"

            key = (control_type, target_type, target_id)
            # If multiple tests cover same control key, prioritize CONFIRMED over PASS
            if key not in controls_by_key or (
                expected_behavior == "CONFIRMED" and controls_by_key[key].expected_behavior != "CONFIRMED"
            ):
                control = SecurityBaselineControl(
                    baseline_id=baseline.id,
                    control_type=control_type,
                    target_type=target_type,
                    target_id=target_id,
                    expected_behavior=expected_behavior,
                    severity=severity,
                    enabled=True,
                    configuration={
                        "security_test_id": test.id,
                        "test_type": test_type,
                        "endpoint_path": test.endpoint.path if test.endpoint else None,
                    },
                )
                controls_by_key[key] = control

        for ctrl in controls_by_key.values():
            self.db.add(ctrl)

        self.db.commit()
        self.db.refresh(baseline)
        return baseline


class BaselineComparisonService:
    """
    Deterministic comparison engine between a SecurityBaseline and a SecurityExecutionPlan.
    """
    __test__ = False

    def __init__(self, db: Session):
        self.db = db

    def compare_baseline_with_plan(
        self,
        baseline_id: str,
        execution_plan_id: str,
    ) -> SecurityBaselineComparison:
        """
        Compare a security baseline against a completed execution plan.
        Rules:
        - Baseline and plan must belong to the same project.
        - Plan status must be COMPLETED.
        - Unexecuted tests in current plan are NOT assumed secure -> NOT_APPLICABLE.
        - Prior PASS -> Current CONFIRMED: REGRESSION.
        - Prior CONFIRMED -> Current PASS: IMPROVED.
        - Prior == Current: UNCHANGED.
        - New confirmed findings not in baseline: NEW_VIOLATION.
        - Links finding_id to existing Finding record without duplicate generation.
        """
        baseline = (
            self.db.query(SecurityBaseline)
            .filter(SecurityBaseline.id == baseline_id)
            .first()
        )
        if not baseline:
            raise BaselineNotFoundError(f"Baseline with ID {baseline_id} not found.")

        plan = (
            self.db.query(SecurityExecutionPlan)
            .filter(SecurityExecutionPlan.id == execution_plan_id)
            .first()
        )
        if not plan:
            raise BaselineNotFoundError(f"Execution plan with ID {execution_plan_id} not found.")

        if baseline.project_id != plan.project_id:
            raise CrossProjectViolationError(
                f"Baseline project ({baseline.project_id}) does not match execution plan project ({plan.project_id})."
            )

        if plan.status != "COMPLETED":
            raise InvalidBaselinePlanError(
                f"Execution plan '{execution_plan_id}' status is '{plan.status}'. "
                f"Comparisons can only be run against COMPLETED execution plans."
            )

        # Create comparison record
        comparison = SecurityBaselineComparison(
            baseline_id=baseline.id,
            execution_plan_id=plan.id,
            status="COMPLETED",
            summary={},
        )
        self.db.add(comparison)
        self.db.flush()

        # Map completed execution items from the current plan
        plan_items = plan.items
        executed_by_test_id: Dict[str, SecurityExecutionItem] = {
            it.security_test_id: it for it in plan_items if it.status == "COMPLETED" and it.result
        }

        # Collect findings linked to these tests/executions without creating duplicates
        test_ids = [it.security_test_id for it in plan_items]
        exec_ids = [it.test_execution_id for it in plan_items if it.test_execution_id]

        findings_map: Dict[str, Finding] = {}
        if test_ids or exec_ids:
            query = self.db.query(Finding).filter(Finding.project_id == plan.project_id)
            conditions = []
            if test_ids:
                conditions.append(Finding.security_test_id.in_(test_ids))
            if exec_ids:
                conditions.append(Finding.execution_id.in_(exec_ids))
            
            from sqlalchemy import or_
            findings = query.filter(or_(*conditions)).all()
            for f in findings:
                if f.security_test_id and f.security_test_id not in findings_map:
                    findings_map[f.security_test_id] = f

        comparison_items: List[SecurityBaselineComparisonItem] = []
        covered_test_ids = set()

        # 1. Evaluate baseline controls against current execution results
        for ctrl in baseline.controls:
            ctrl_cfg = ctrl.configuration or {}
            target_test_id = ctrl_cfg.get("security_test_id")

            # Find matching execution item in current plan
            matching_item = None
            if target_test_id and target_test_id in executed_by_test_id:
                matching_item = executed_by_test_id[target_test_id]
            else:
                # Fallback matching by target_type, target_id, and control_type
                for it in executed_by_test_id.values():
                    t = it.security_test
                    if not t:
                        continue
                    t_ep_id = str(t.endpoint.id) if t.endpoint else None
                    if ctrl.target_type == "ENDPOINT" and ctrl.target_id == t_ep_id:
                        matching_item = it
                        break

            # Handle unexecuted controls (CRITICAL: Never assume secure)
            if not matching_item:
                c_item = SecurityBaselineComparisonItem(
                    comparison_id=comparison.id,
                    control_id=ctrl.id,
                    security_test_id=target_test_id,
                    finding_id=None,
                    result="NOT_APPLICABLE",
                    previous_behavior=ctrl.expected_behavior,
                    current_behavior=None,
                    explanation=(
                        f"Control for {ctrl.target_type} '{ctrl.target_id}' ({ctrl.control_type}) "
                        f"was not executed in the current plan. Missing tests are not assumed secure."
                    ),
                    evidence_reference={"target_id": ctrl.target_id, "control_type": ctrl.control_type},
                )
                comparison_items.append(c_item)
                continue

            covered_test_ids.add(matching_item.security_test_id)
            prev = ctrl.expected_behavior
            curr = matching_item.result
            finding = findings_map.get(matching_item.security_test_id)

            evidence_ref = {
                "test_execution_id": matching_item.test_execution_id,
                "endpoint": matching_item.endpoint,
                "test_type": matching_item.test_type,
            }

            # Evaluate regression vs improvement vs unchanged
            if prev == "PASS" and curr == "CONFIRMED":
                comp_result = "REGRESSION"
                explanation = (
                    f"Security regression on {ctrl.target_type} '{ctrl.target_id}': "
                    f"previously secure ({prev}), but current execution confirmed a vulnerability."
                )
            elif prev == "CONFIRMED" and curr == "PASS":
                comp_result = "IMPROVED"
                explanation = (
                    f"Security improvement on {ctrl.target_type} '{ctrl.target_id}': "
                    f"previously confirmed vulnerability ({prev}) is now resolved ({curr})."
                )
            elif prev == curr:
                comp_result = "UNCHANGED"
                explanation = (
                    f"Security behavior on {ctrl.target_type} '{ctrl.target_id}' remained unchanged ({curr})."
                )
            else:
                comp_result = "UNCHANGED"
                explanation = (
                    f"Security evaluation on {ctrl.target_type} '{ctrl.target_id}': "
                    f"baseline '{prev}' -> current '{curr}'."
                )

            c_item = SecurityBaselineComparisonItem(
                comparison_id=comparison.id,
                control_id=ctrl.id,
                security_test_id=matching_item.security_test_id,
                finding_id=finding.id if (finding and comp_result in ("REGRESSION", "UNCHANGED")) else None,
                result=comp_result,
                previous_behavior=prev,
                current_behavior=curr,
                explanation=explanation,
                evidence_reference=evidence_ref,
            )
            comparison_items.append(c_item)

        # 2. Check for NEW_VIOLATION (findings produced in current plan not covered in baseline controls)
        for it in executed_by_test_id.values():
            if it.security_test_id in covered_test_ids:
                continue
            if it.result == "CONFIRMED":
                finding = findings_map.get(it.security_test_id)
                c_item = SecurityBaselineComparisonItem(
                    comparison_id=comparison.id,
                    control_id=None,
                    security_test_id=it.security_test_id,
                    finding_id=finding.id if finding else None,
                    result="NEW_VIOLATION",
                    previous_behavior=None,
                    current_behavior=it.result,
                    explanation=(
                        f"New security violation detected: test '{it.test_type}' on '{it.endpoint or 'Endpoint'}' "
                        f"produced a confirmed finding not present in baseline."
                    ),
                    evidence_reference={
                        "test_execution_id": it.test_execution_id,
                        "endpoint": it.endpoint,
                        "test_type": it.test_type,
                    },
                )
                comparison_items.append(c_item)

        for it in comparison_items:
            self.db.add(it)

        # Build summary metrics
        regressions = [i for i in comparison_items if i.result == "REGRESSION"]
        new_violations = [i for i in comparison_items if i.result == "NEW_VIOLATION"]
        improvements = [i for i in comparison_items if i.result == "IMPROVED"]
        unchanged = [i for i in comparison_items if i.result == "UNCHANGED"]
        not_applicable = [i for i in comparison_items if i.result == "NOT_APPLICABLE"]

        comparison.summary = {
            "total_evaluated": len(comparison_items),
            "regressions_count": len(regressions),
            "new_violations_count": len(new_violations),
            "improvements_count": len(improvements),
            "unchanged_count": len(unchanged),
            "not_applicable_count": len(not_applicable),
            "has_regressions": len(regressions) > 0,
            "has_new_violations": len(new_violations) > 0,
            "baseline_id": baseline.id,
            "baseline_name": baseline.name,
            "baseline_version": baseline.version,
            "execution_plan_id": plan.id,
            "execution_plan_name": plan.name,
        }

        self.db.commit()
        self.db.refresh(comparison)
        return comparison

    def get_comparison(self, comparison_id: str) -> Optional[SecurityBaselineComparison]:
        """Fetch comparison with its items."""
        return (
            self.db.query(SecurityBaselineComparison)
            .filter(SecurityBaselineComparison.id == comparison_id)
            .first()
        )

    def list_comparisons(
        self,
        project_id: int,
        baseline_id: Optional[str] = None,
    ) -> List[SecurityBaselineComparison]:
        """List baseline comparisons for a project."""
        query = (
            self.db.query(SecurityBaselineComparison)
            .join(SecurityBaseline, SecurityBaselineComparison.baseline_id == SecurityBaseline.id)
            .filter(SecurityBaseline.project_id == project_id)
        )
        if baseline_id:
            query = query.filter(SecurityBaselineComparison.baseline_id == baseline_id)
        return query.order_by(SecurityBaselineComparison.created_at.desc()).all()
