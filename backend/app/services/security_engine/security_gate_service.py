"""
Stage 10.3: CI/CD Security Regression Gates Service
Author: SentinelAPI Security Architecture Team

Deterministic security-gating engine evaluating completed security scans against established baselines.
Features:
- Project-scoped SecurityGate domain management.
- Deterministic failure and warning thresholds (max_regressions, max_new_violations, max_confirmed_findings, etc.).
- Strict precedence order: ERROR > FAIL > WARN > PASS.
- Full evidence traceability (finding IDs, comparison item IDs, security test IDs).
- Complete idempotency (reuses existing evaluation for the same gate + comparison pair).
- Zero target HTTP calls (consumes existing deterministic comparison results exclusively).
- Machine-readable CI/CD response format and standardized exit code semantics (PASS/WARN=0, FAIL=1, ERROR=2).
"""

from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from pydantic import ValidationError

from app.models import (
    Project,
    SecurityGate,
    SecurityGateEvaluation,
    SecurityGateEvaluationItem,
    SecurityBaseline,
    SecurityBaselineComparison,
    ScanProfile,
)
from app.schemas import (
    SecurityGateFailureRules,
    SecurityGateWarningRules,
)


class SecurityGateError(Exception):
    """Base exception for security gate errors."""
    pass


class GateNotFoundError(SecurityGateError):
    """Raised when a security gate is not found."""
    pass


class DuplicateGateError(SecurityGateError):
    """Raised when a security gate name conflicts within the same project."""
    pass


class DisabledGateError(SecurityGateError):
    """Raised when attempting to evaluate a disabled gate."""
    pass


class CrossProjectViolationError(SecurityGateError):
    """Raised when attempting cross-project access for gates or comparisons."""
    pass


class InvalidGateRuleError(SecurityGateError):
    """Raised when gate rule configuration fails validation."""
    pass


class InvalidEvaluationStateError(SecurityGateError):
    """Raised when gate evaluation cannot proceed due to invalid comparison/plan state."""
    pass


GATE_EXIT_CODES = {
    "PASS": 0,
    "WARN": 0,
    "FAIL": 1,
    "ERROR": 2,
}


def get_gate_exit_code(status: str) -> int:
    """Return standard CI exit code: PASS=0, WARN=0, FAIL=1, ERROR=2."""
    return GATE_EXIT_CODES.get(status.upper(), 2)


class SecurityGateService:
    """
    Deterministic management and evaluation engine for Security Gates.
    """
    __test__ = False

    def __init__(self, db: Session):
        self.db = db

    # =========================================================================
    # Rule Validation Helpers
    # =========================================================================

    @staticmethod
    def validate_rules(
        failure_rules: Optional[Dict[str, Any]] = None,
        warning_rules: Optional[Dict[str, Any]] = None,
    ) -> tuple[Dict[str, Any], Dict[str, Any]]:
        """Validate failure and warning rules using Pydantic schemas with forbid extra."""
        try:
            f_obj = SecurityGateFailureRules(**(failure_rules or {}))
            f_dict = f_obj.model_dump()
        except (ValidationError, TypeError) as e:
            raise InvalidGateRuleError(f"Invalid failure rules configuration: {e}")

        try:
            w_obj = SecurityGateWarningRules(**(warning_rules or {}))
            w_dict = w_obj.model_dump()
        except (ValidationError, TypeError) as e:
            raise InvalidGateRuleError(f"Invalid warning rules configuration: {e}")

        return f_dict, w_dict

    # =========================================================================
    # Security Gate CRUD
    # =========================================================================

    def create_gate(
        self,
        project_id: int,
        name: str,
        baseline_id: str,
        scan_profile_id: str,
        failure_rules: Optional[Dict[str, Any]] = None,
        warning_rules: Optional[Dict[str, Any]] = None,
        description: Optional[str] = None,
        status: str = "ACTIVE",
    ) -> SecurityGate:
        """Create a new project-scoped security gate."""
        project = self.db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise GateNotFoundError(f"Project with ID {project_id} not found.")

        g_name = name.strip()
        existing = (
            self.db.query(SecurityGate)
            .filter(SecurityGate.project_id == project_id, SecurityGate.name == g_name)
            .first()
        )
        if existing:
            raise DuplicateGateError(
                f"A security gate named '{g_name}' already exists in project {project_id}."
            )

        # Verify baseline exists and belongs to project
        baseline = (
            self.db.query(SecurityBaseline)
            .filter(SecurityBaseline.id == baseline_id)
            .first()
        )
        if not baseline:
            raise GateNotFoundError(f"Security baseline with ID '{baseline_id}' not found.")
        if baseline.project_id != project_id:
            raise CrossProjectViolationError(
                f"Security baseline '{baseline_id}' belongs to project {baseline.project_id}, not {project_id}."
            )

        # Verify scan profile exists and belongs to project
        profile = (
            self.db.query(ScanProfile)
            .filter(ScanProfile.id == scan_profile_id)
            .first()
        )
        if not profile:
            raise GateNotFoundError(f"Scan profile with ID '{scan_profile_id}' not found.")
        if profile.project_id != project_id:
            raise CrossProjectViolationError(
                f"Scan profile '{scan_profile_id}' belongs to project {profile.project_id}, not {project_id}."
            )

        # Validate rule configuration
        clean_failure_rules, clean_warning_rules = self.validate_rules(failure_rules, warning_rules)

        g_status = status.upper() if status else "ACTIVE"
        if g_status not in ("ACTIVE", "DISABLED"):
            g_status = "ACTIVE"

        gate = SecurityGate(
            project_id=project_id,
            name=g_name,
            description=description.strip() if description else None,
            status=g_status,
            baseline_id=baseline_id,
            scan_profile_id=scan_profile_id,
            failure_rules=clean_failure_rules,
            warning_rules=clean_warning_rules,
        )
        self.db.add(gate)
        try:
            self.db.commit()
            self.db.refresh(gate)
        except IntegrityError:
            self.db.rollback()
            raise DuplicateGateError(
                f"A security gate named '{g_name}' already exists in project {project_id}."
            )

        return gate

    def get_gate(
        self,
        gate_id: str,
        project_id: Optional[int] = None,
    ) -> Optional[SecurityGate]:
        """Fetch a security gate and enforce cross-project isolation."""
        gate = self.db.query(SecurityGate).filter(SecurityGate.id == gate_id).first()
        if not gate:
            return None

        if project_id is not None and gate.project_id != project_id:
            raise CrossProjectViolationError(
                f"Security gate '{gate_id}' belongs to project {gate.project_id}, not {project_id}."
            )

        return gate

    def list_gates(
        self,
        project_id: int,
        status: Optional[str] = None,
    ) -> List[SecurityGate]:
        """List all security gates for a project."""
        query = self.db.query(SecurityGate).filter(SecurityGate.project_id == project_id)
        if status:
            query = query.filter(SecurityGate.status == status.upper())
        return query.order_by(SecurityGate.created_at.desc()).all()

    def update_gate(
        self,
        gate_id: str,
        project_id: Optional[int] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        status: Optional[str] = None,
        baseline_id: Optional[str] = None,
        scan_profile_id: Optional[str] = None,
        failure_rules: Optional[Dict[str, Any]] = None,
        warning_rules: Optional[Dict[str, Any]] = None,
    ) -> SecurityGate:
        """Update a security gate."""
        gate = self.get_gate(gate_id, project_id=project_id)
        if not gate:
            raise GateNotFoundError(f"Security gate with ID '{gate_id}' not found.")

        if name is not None:
            clean_name = name.strip()
            if clean_name != gate.name:
                existing = (
                    self.db.query(SecurityGate)
                    .filter(
                        SecurityGate.project_id == gate.project_id,
                        SecurityGate.name == clean_name,
                        SecurityGate.id != gate_id,
                    )
                    .first()
                )
                if existing:
                    raise DuplicateGateError(
                        f"A security gate named '{clean_name}' already exists in project {gate.project_id}."
                    )
                gate.name = clean_name

        if description is not None:
            gate.description = description.strip() if description else None

        if status is not None:
            g_status = status.upper()
            if g_status in ("ACTIVE", "DISABLED"):
                gate.status = g_status

        if baseline_id is not None and baseline_id != gate.baseline_id:
            baseline = (
                self.db.query(SecurityBaseline)
                .filter(SecurityBaseline.id == baseline_id)
                .first()
            )
            if not baseline:
                raise GateNotFoundError(f"Security baseline with ID '{baseline_id}' not found.")
            if baseline.project_id != gate.project_id:
                raise CrossProjectViolationError(
                    f"Baseline '{baseline_id}' belongs to project {baseline.project_id}, not {gate.project_id}."
                )
            gate.baseline_id = baseline_id

        if scan_profile_id is not None and scan_profile_id != gate.scan_profile_id:
            profile = (
                self.db.query(ScanProfile)
                .filter(ScanProfile.id == scan_profile_id)
                .first()
            )
            if not profile:
                raise GateNotFoundError(f"Scan profile with ID '{scan_profile_id}' not found.")
            if profile.project_id != gate.project_id:
                raise CrossProjectViolationError(
                    f"Scan profile '{scan_profile_id}' belongs to project {profile.project_id}, not {gate.project_id}."
                )
            gate.scan_profile_id = scan_profile_id

        if failure_rules is not None or warning_rules is not None:
            new_f = failure_rules if failure_rules is not None else gate.failure_rules
            new_w = warning_rules if warning_rules is not None else gate.warning_rules
            clean_f, clean_w = self.validate_rules(new_f, new_w)
            gate.failure_rules = clean_f
            gate.warning_rules = clean_w

        try:
            self.db.commit()
            self.db.refresh(gate)
        except IntegrityError:
            self.db.rollback()
            raise DuplicateGateError(
                f"A security gate named '{gate.name}' already exists in project {gate.project_id}."
            )

        return gate

    def delete_gate(
        self,
        gate_id: str,
        project_id: Optional[int] = None,
    ) -> bool:
        """Delete a security gate."""
        gate = self.get_gate(gate_id, project_id=project_id)
        if not gate:
            raise GateNotFoundError(f"Security gate with ID '{gate_id}' not found.")

        self.db.delete(gate)
        self.db.commit()
        return True

    # =========================================================================
    # Security Gate Evaluation
    # =========================================================================

    def evaluate_gate(
        self,
        gate_id: str,
        baseline_comparison_id: str,
        project_id: Optional[int] = None,
    ) -> SecurityGateEvaluation:
        """
        Deterministically evaluates a SecurityGate against a SecurityBaselineComparison.
        Guarantees:
        - Absolute idempotency: returns existing evaluation if one exists for (gate_id, baseline_comparison_id).
        - ZERO target HTTP calls executed.
        - Strict precedence: ERROR > FAIL > WARN > PASS.
        - Full evidence traceability back to findings, comparison items, and security tests.
        """
        # Idempotency Check: if already evaluated, reuse the deterministic result
        existing_eval = (
            self.db.query(SecurityGateEvaluation)
            .filter(
                SecurityGateEvaluation.gate_id == gate_id,
                SecurityGateEvaluation.baseline_comparison_id == baseline_comparison_id,
            )
            .first()
        )
        if existing_eval:
            return existing_eval

        # 1. Validate Gate
        gate = self.get_gate(gate_id, project_id=project_id)
        if not gate:
            raise GateNotFoundError(f"Security gate with ID '{gate_id}' not found.")

        if gate.status == "DISABLED":
            raise DisabledGateError(
                f"Security gate '{gate.name}' is DISABLED and cannot evaluate."
            )

        # 2. Validate Baseline Comparison
        comparison = (
            self.db.query(SecurityBaselineComparison)
            .filter(SecurityBaselineComparison.id == baseline_comparison_id)
            .first()
        )
        if not comparison:
            raise InvalidEvaluationStateError(
                f"Security baseline comparison with ID '{baseline_comparison_id}' not found."
            )

        # Project Isolation Check
        if comparison.baseline and comparison.baseline.project_id != gate.project_id:
            raise CrossProjectViolationError(
                f"Comparison baseline project ({comparison.baseline.project_id}) does not match gate project ({gate.project_id})."
            )

        # Gate Baseline Match Check
        if comparison.baseline_id != gate.baseline_id:
            raise InvalidEvaluationStateError(
                f"Comparison baseline ('{comparison.baseline_id}') does not match gate configured baseline ('{gate.baseline_id}')."
            )

        # Plan Completion Check
        plan = comparison.execution_plan
        if not plan or plan.status != "COMPLETED":
            raise InvalidEvaluationStateError(
                f"Comparison execution plan is in status '{plan.status if plan else 'None'}'. "
                f"Security gate evaluation requires a COMPLETED execution plan."
            )

        # 3. Compute Deterministic Metrics
        comp_items = comparison.items or []
        regressions_items = [i for i in comp_items if i.result == "REGRESSION"]
        new_violations_items = [i for i in comp_items if i.result == "NEW_VIOLATION"]
        not_applicable_items = [i for i in comp_items if i.result == "NOT_APPLICABLE"]

        regressions_count = len(regressions_items)
        new_violations_count = len(new_violations_items)
        not_applicable_count = len(not_applicable_items)

        # Metrics from completed execution plan
        confirmed_findings = plan.confirmed_findings or 0
        failed_tests = plan.failed_tests or 0
        inconclusive_tests = plan.inconclusive_tests or 0
        # Count errors from execution items where status == FAILED or result == ERROR
        error_tests = sum(
            1 for it in (plan.items or []) if it.status == "FAILED" or it.result == "ERROR"
        )

        metrics = {
            "new_violations": new_violations_count,
            "regressions": regressions_count,
            "confirmed_findings": confirmed_findings,
            "failed_tests": failed_tests,
            "inconclusive_tests": inconclusive_tests,
            "errors": error_tests,
            "not_applicable": not_applicable_count,
        }

        # 4. Evaluate Thresholds
        f_rules = gate.failure_rules or {}
        w_rules = gate.warning_rules or {}

        max_regressions = f_rules.get("max_regressions", 0)
        max_new_violations = f_rules.get("max_new_violations", 0)
        max_confirmed_findings = f_rules.get("max_confirmed_findings", 0)
        max_failed_tests = f_rules.get("max_failed_tests", 0)

        max_inconclusive = w_rules.get("max_inconclusive", 0)
        max_errors = w_rules.get("max_errors", 0)
        max_not_applicable = w_rules.get("max_not_applicable", 999999)

        evaluation_items: List[SecurityGateEvaluationItem] = []
        failure_triggers = 0
        warning_triggers = 0

        # Helper to record rule evaluations
        def check_failure_rule(
            rule_type: str,
            actual: int,
            threshold: int,
            msg_tmpl: str,
            associated_items: Optional[List[Any]] = None,
        ):
            nonlocal failure_triggers
            is_triggered = actual > threshold
            if is_triggered:
                failure_triggers += 1

            # If there are specific items associated with this rule, create an item for each or a summary item
            if associated_items:
                for src in associated_items:
                    evaluation_items.append(
                        SecurityGateEvaluationItem(
                            rule_type=rule_type,
                            severity="FAILURE",
                            triggered=is_triggered,
                            actual_value=actual,
                            threshold=threshold,
                            message=f"{actual} {msg_tmpl} exceed threshold of {threshold}",
                            finding_id=getattr(src, "finding_id", None),
                            comparison_item_id=getattr(src, "id", None),
                            security_test_id=getattr(src, "security_test_id", None),
                        )
                    )
            else:
                evaluation_items.append(
                    SecurityGateEvaluationItem(
                        rule_type=rule_type,
                        severity="FAILURE",
                        triggered=is_triggered,
                        actual_value=actual,
                        threshold=threshold,
                        message=f"{actual} {msg_tmpl} exceed threshold of {threshold}",
                    )
                )

        def check_warning_rule(
            rule_type: str,
            actual: int,
            threshold: int,
            msg_tmpl: str,
            associated_items: Optional[List[Any]] = None,
        ):
            nonlocal warning_triggers
            is_triggered = actual > threshold
            if is_triggered:
                warning_triggers += 1

            if associated_items:
                for src in associated_items:
                    evaluation_items.append(
                        SecurityGateEvaluationItem(
                            rule_type=rule_type,
                            severity="WARNING",
                            triggered=is_triggered,
                            actual_value=actual,
                            threshold=threshold,
                            message=f"{actual} {msg_tmpl} exceed threshold of {threshold}",
                            finding_id=getattr(src, "finding_id", None),
                            comparison_item_id=getattr(src, "id", None),
                            security_test_id=getattr(src, "security_test_id", None),
                        )
                    )
            else:
                evaluation_items.append(
                    SecurityGateEvaluationItem(
                        rule_type=rule_type,
                        severity="WARNING",
                        triggered=is_triggered,
                        actual_value=actual,
                        threshold=threshold,
                        message=f"{actual} {msg_tmpl} exceed threshold of {threshold}",
                    )
                )

        # Evaluate Failure Rules
        check_failure_rule(
            "REGRESSION",
            regressions_count,
            max_regressions,
            "security regressions",
            regressions_items,
        )
        check_failure_rule(
            "NEW_VIOLATION",
            new_violations_count,
            max_new_violations,
            "new security violations",
            new_violations_items,
        )
        check_failure_rule(
            "CONFIRMED_FINDING",
            confirmed_findings,
            max_confirmed_findings,
            "confirmed findings",
        )
        check_failure_rule(
            "FAILED_TEST",
            failed_tests,
            max_failed_tests,
            "failed security tests",
        )

        # Evaluate Warning Rules
        check_warning_rule(
            "INCONCLUSIVE",
            inconclusive_tests,
            max_inconclusive,
            "inconclusive security tests",
        )
        check_warning_rule(
            "ERROR",
            error_tests,
            max_errors,
            "execution error tests",
        )
        check_warning_rule(
            "NOT_APPLICABLE",
            not_applicable_count,
            max_not_applicable,
            "untested baseline controls",
            not_applicable_items,
        )

        # 5. Precedence: ERROR > FAIL > WARN > PASS
        if failure_triggers > 0:
            eval_status = "FAIL"
        elif warning_triggers > 0:
            eval_status = "WARN"
        else:
            eval_status = "PASS"

        # Construct Triggered Rules Summary for CI/Auditability
        triggered_rules_summary = []
        for it in evaluation_items:
            if it.triggered:
                triggered_rules_summary.append({
                    "rule_type": it.rule_type,
                    "actual": it.actual_value,
                    "threshold": it.threshold,
                    "severity": it.severity,
                    "message": it.message,
                    "finding_id": it.finding_id,
                    "comparison_item_id": it.comparison_item_id,
                    "security_test_id": it.security_test_id,
                })

        summary = {
            "status": eval_status,
            "exit_code": get_gate_exit_code(eval_status),
            "gate_id": gate.id,
            "gate_name": gate.name,
            "baseline_id": gate.baseline_id,
            "baseline_name": gate.baseline.name if gate.baseline else None,
            "baseline_version": gate.baseline.version if gate.baseline else None,
            "scan_profile_id": gate.scan_profile_id,
            "scan_profile_name": gate.scan_profile.name if gate.scan_profile else None,
            "execution_plan_id": plan.id,
            "execution_plan_name": plan.name,
            "metrics": metrics,
            "failure_rules_snapshot": f_rules,
            "warning_rules_snapshot": w_rules,
            "triggered_rules_count": len(triggered_rules_summary),
        }

        # 6. Save Evaluation Record
        evaluation = SecurityGateEvaluation(
            gate_id=gate.id,
            project_id=gate.project_id,
            baseline_comparison_id=comparison.id,
            status=eval_status,
            failure_count=failure_triggers,
            warning_count=warning_triggers,
            confirmed_findings=confirmed_findings,
            regressions=regressions_count,
            new_violations=new_violations_count,
            failed_tests=failed_tests,
            inconclusive_tests=inconclusive_tests,
            error_tests=error_tests,
            summary=summary,
            evaluated_at=datetime.now(timezone.utc),
        )
        self.db.add(evaluation)
        self.db.flush()

        for it in evaluation_items:
            it.evaluation_id = evaluation.id
            self.db.add(it)

        self.db.commit()
        self.db.refresh(evaluation)
        return evaluation

    def get_evaluation(
        self,
        evaluation_id: str,
        project_id: Optional[int] = None,
    ) -> Optional[SecurityGateEvaluation]:
        """Fetch evaluation with cross-project isolation check."""
        evaluation = (
            self.db.query(SecurityGateEvaluation)
            .filter(SecurityGateEvaluation.id == evaluation_id)
            .first()
        )
        if not evaluation:
            return None

        if project_id is not None and evaluation.project_id != project_id:
            raise CrossProjectViolationError(
                f"Evaluation '{evaluation_id}' belongs to project {evaluation.project_id}, not {project_id}."
            )

        return evaluation

    def list_evaluations(
        self,
        project_id: int,
        gate_id: Optional[str] = None,
    ) -> List[SecurityGateEvaluation]:
        """List evaluations for a project."""
        query = (
            self.db.query(SecurityGateEvaluation)
            .filter(SecurityGateEvaluation.project_id == project_id)
        )
        if gate_id:
            query = query.filter(SecurityGateEvaluation.gate_id == gate_id)
        return query.order_by(SecurityGateEvaluation.evaluated_at.desc()).all()

    def get_ci_result(self, evaluation_id: str) -> Dict[str, Any]:
        """
        Generate lightweight machine-readable CI/CD result.
        Returns deterministic status, metrics, exit code, and triggered rules.
        """
        evaluation = self.get_evaluation(evaluation_id)
        if not evaluation:
            raise GateNotFoundError(f"Evaluation with ID '{evaluation_id}' not found.")

        gate = evaluation.gate
        baseline = gate.baseline if gate else None

        # Build triggered rules list with finding and test IDs
        rule_groups: Dict[str, Dict[str, Any]] = {}
        for it in evaluation.items:
            if it.triggered:
                if it.rule_type not in rule_groups:
                    rule_groups[it.rule_type] = {
                        "rule_type": it.rule_type,
                        "actual": it.actual_value,
                        "threshold": it.threshold,
                        "severity": it.severity,
                        "message": it.message,
                        "finding_ids": [],
                        "comparison_item_ids": [],
                        "security_test_ids": [],
                    }
                if it.finding_id and it.finding_id not in rule_groups[it.rule_type]["finding_ids"]:
                    rule_groups[it.rule_type]["finding_ids"].append(it.finding_id)
                if it.comparison_item_id and it.comparison_item_id not in rule_groups[it.rule_type]["comparison_item_ids"]:
                    rule_groups[it.rule_type]["comparison_item_ids"].append(it.comparison_item_id)
                if it.security_test_id and it.security_test_id not in rule_groups[it.rule_type]["security_test_ids"]:
                    rule_groups[it.rule_type]["security_test_ids"].append(it.security_test_id)

        metrics = {
            "new_violations": evaluation.new_violations,
            "regressions": evaluation.regressions,
            "confirmed_findings": evaluation.confirmed_findings,
            "failed_tests": evaluation.failed_tests,
            "inconclusive_tests": evaluation.inconclusive_tests,
            "errors": evaluation.error_tests,
            "not_applicable": (evaluation.summary or {}).get("metrics", {}).get("not_applicable", 0),
        }

        return {
            "status": evaluation.status,
            "exit_code": get_gate_exit_code(evaluation.status),
            "gate_id": evaluation.gate_id,
            "gate_name": gate.name if gate else "Unknown Gate",
            "baseline_version": baseline.version if baseline else None,
            "evaluation_id": evaluation.id,
            "metrics": metrics,
            "triggered_rules": list(rule_groups.values()),
            "evaluated_at": evaluation.evaluated_at,
        }
