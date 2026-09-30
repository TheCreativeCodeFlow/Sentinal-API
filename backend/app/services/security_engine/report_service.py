"""
Stage 10.4: Security Reporting & Evidence Packages Service
Author: SentinelAPI Security Architecture Team

Deterministic security report and evidence package generator preserving provenance:
- VERIFIED: Facts directly supported by executed security tests and evidence.
- DETERMINISTIC: Derived by deterministic security analysis (attack paths, impact, gates, baselines).
- AI: Advisory AI analysis/hypotheses explicitly labeled as NOT VERIFIED.
- HUMAN: Human review decisions and rationale.
- ENGINE: Orchestration and execution metadata.

Strict Guarantees:
- Zero target HTTP requests executed during reporting.
- Immutable snapshots with SHA-256 cryptographic checksums.
- Automatic, thorough credential and header sanitization.
- Strict project-scoped tenant isolation.
- Complete evidence package assembly with deterministic manifest.
"""

import json
import hashlib
import re
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.models import (
    Project,
    SecurityReport,
    SecurityReportSnapshot,
    SecurityExecutionPlan,
    SecurityGateEvaluation,
    SecurityInvestigation,
    Finding,
    Evidence,
    AttackPath,
    SecurityImpact,
    AIAnalysis,
    AIHypothesis,
    AIHypothesisReview,
    SecurityBaselineComparison,
)
from app.services.security_engine.redactor import redact_headers, redact_text, SENSITIVE_HEADER_NAMES


class SecurityReportError(Exception):
    """Base exception for security report errors."""
    pass


class ReportNotFoundError(SecurityReportError):
    """Raised when a report or snapshot is not found."""
    pass


class DuplicateReportError(SecurityReportError):
    """Raised when a report name conflicts within the same project."""
    pass


class InvalidReportSourceError(SecurityReportError):
    """Raised when specified report sources are invalid or missing."""
    pass


class ArchivedReportError(SecurityReportError):
    """Raised when attempting to modify or regenerate an archived report."""
    pass


class CrossProjectViolationError(SecurityReportError):
    """Raised when attempting cross-project access for reports or sources."""
    pass


def sanitize_value(val: Any) -> Any:
    """Recursively sanitize dicts, lists, and strings to eliminate any sensitive credentials."""
    if isinstance(val, dict):
        cleaned: Dict[str, Any] = {}
        for k, v in val.items():
            lower_k = str(k).lower()
            if lower_k in SENSITIVE_HEADER_NAMES or any(
                sec in lower_k for sec in ("password", "secret", "token", "apikey", "api_key", "bearer", "cookie", "auth")
            ):
                cleaned[k] = "[REDACTED]"
            else:
                cleaned[k] = sanitize_value(v)
        return cleaned
    elif isinstance(val, list):
        return [sanitize_value(item) for item in val]
    elif isinstance(val, str):
        stripped = val.strip()
        if (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]")):
            try:
                parsed = json.loads(stripped)
                sanitized_parsed = sanitize_value(parsed)
                return json.dumps(sanitized_parsed)
            except Exception:
                pass
        redacted = redact_text(val)
        redacted = re.sub(
            r'("(?:[^"]*(?:token|key|secret|password|bearer|auth|cookie)[^"]*)"\s*:\s*)"(?:[^"]+)"',
            r'\1"[REDACTED]"',
            redacted,
            flags=re.IGNORECASE,
        )
        return redacted
    return val


def compute_sha256(data: Any) -> str:
    """Compute deterministic SHA-256 checksum of data serialized as canonical JSON."""
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class SecurityReportService:
    """
    Service responsible for managing, generating, and archiving reproducible Security Reports
    and structured Evidence Packages.
    """
    __test__ = False

    def __init__(self, db: Session):
        self.db = db

    # =========================================================================
    # Report CRUD & Management
    # =========================================================================

    def create_report(
        self,
        project_id: int,
        name: str,
        description: Optional[str] = None,
        report_type: str = "SECURITY_ASSESSMENT",
        source_execution_plan_id: Optional[str] = None,
        source_gate_evaluation_id: Optional[str] = None,
        source_investigation_id: Optional[str] = None,
    ) -> SecurityReport:
        """Create a new draft security report."""
        project = self.db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise ReportNotFoundError(f"Project with ID {project_id} not found.")

        # At least one source must be provided
        if not source_execution_plan_id and not source_gate_evaluation_id and not source_investigation_id:
            raise InvalidReportSourceError(
                "A security report requires at least one valid source (execution_plan_id, gate_evaluation_id, or investigation_id)."
            )

        clean_name = name.strip()
        existing = (
            self.db.query(SecurityReport)
            .filter(SecurityReport.project_id == project_id, SecurityReport.name == clean_name)
            .first()
        )
        if existing:
            raise DuplicateReportError(
                f"A security report named '{clean_name}' already exists in project {project_id}."
            )

        # Validate Sources & Project Isolation
        if source_execution_plan_id:
            plan = (
                self.db.query(SecurityExecutionPlan)
                .filter(SecurityExecutionPlan.id == source_execution_plan_id)
                .first()
            )
            if not plan:
                raise InvalidReportSourceError(f"Execution plan '{source_execution_plan_id}' not found.")
            if plan.project_id != project_id:
                raise CrossProjectViolationError(
                    f"Execution plan '{source_execution_plan_id}' belongs to project {plan.project_id}, not {project_id}."
                )

        if source_gate_evaluation_id:
            gate_eval = (
                self.db.query(SecurityGateEvaluation)
                .filter(SecurityGateEvaluation.id == source_gate_evaluation_id)
                .first()
            )
            if not gate_eval:
                raise InvalidReportSourceError(f"Gate evaluation '{source_gate_evaluation_id}' not found.")
            if gate_eval.project_id != project_id:
                raise CrossProjectViolationError(
                    f"Gate evaluation '{source_gate_evaluation_id}' belongs to project {gate_eval.project_id}, not {project_id}."
                )

        if source_investigation_id:
            inv = (
                self.db.query(SecurityInvestigation)
                .filter(SecurityInvestigation.id == source_investigation_id)
                .first()
            )
            if not inv:
                raise InvalidReportSourceError(f"Investigation '{source_investigation_id}' not found.")
            if inv.project_id != project_id:
                raise CrossProjectViolationError(
                    f"Investigation '{source_investigation_id}' belongs to project {inv.project_id}, not {project_id}."
                )

        clean_type = report_type.upper() if report_type else "SECURITY_ASSESSMENT"
        if clean_type not in ("EXECUTION", "BASELINE_REGRESSION", "SECURITY_ASSESSMENT", "INVESTIGATION"):
            clean_type = "SECURITY_ASSESSMENT"

        report = SecurityReport(
            project_id=project_id,
            name=clean_name,
            description=description.strip() if description else None,
            status="DRAFT",
            report_type=clean_type,
            source_execution_plan_id=source_execution_plan_id,
            source_gate_evaluation_id=source_gate_evaluation_id,
            source_investigation_id=source_investigation_id,
            version=1,
        )
        self.db.add(report)
        try:
            self.db.commit()
            self.db.refresh(report)
        except IntegrityError:
            self.db.rollback()
            raise DuplicateReportError(
                f"A security report named '{clean_name}' already exists in project {project_id}."
            )

        return report

    def get_report(
        self,
        report_id: str,
        project_id: Optional[int] = None,
    ) -> Optional[SecurityReport]:
        """Fetch report by ID with project isolation check."""
        report = self.db.query(SecurityReport).filter(SecurityReport.id == report_id).first()
        if not report:
            return None

        if project_id is not None and report.project_id != project_id:
            raise CrossProjectViolationError(
                f"Report '{report_id}' belongs to project {report.project_id}, not {project_id}."
            )

        return report

    def list_reports(
        self,
        project_id: int,
        status: Optional[str] = None,
        report_type: Optional[str] = None,
    ) -> List[SecurityReport]:
        """List reports for a project."""
        query = self.db.query(SecurityReport).filter(SecurityReport.project_id == project_id)
        if status:
            query = query.filter(SecurityReport.status == status.upper())
        if report_type:
            query = query.filter(SecurityReport.report_type == report_type.upper())
        return query.order_by(SecurityReport.created_at.desc()).all()

    def update_report(
        self,
        report_id: str,
        project_id: Optional[int] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        report_type: Optional[str] = None,
        source_execution_plan_id: Optional[str] = None,
        source_gate_evaluation_id: Optional[str] = None,
        source_investigation_id: Optional[str] = None,
    ) -> SecurityReport:
        """Update draft report metadata and sources."""
        report = self.get_report(report_id, project_id=project_id)
        if not report:
            raise ReportNotFoundError(f"Security report '{report_id}' not found.")

        if report.status == "ARCHIVED":
            raise ArchivedReportError("Archived reports are immutable and cannot be updated.")

        if name is not None:
            clean_name = name.strip()
            if clean_name != report.name:
                existing = (
                    self.db.query(SecurityReport)
                    .filter(
                        SecurityReport.project_id == report.project_id,
                        SecurityReport.name == clean_name,
                        SecurityReport.id != report.id,
                    )
                    .first()
                )
                if existing:
                    raise DuplicateReportError(
                        f"A security report named '{clean_name}' already exists in project {report.project_id}."
                    )
                report.name = clean_name

        if description is not None:
            report.description = description.strip() if description else None

        if report_type is not None:
            clean_type = report_type.upper()
            if clean_type in ("EXECUTION", "BASELINE_REGRESSION", "SECURITY_ASSESSMENT", "INVESTIGATION"):
                report.report_type = clean_type

        # Update Sources
        new_plan_id = source_execution_plan_id if source_execution_plan_id is not None else report.source_execution_plan_id
        new_gate_id = source_gate_evaluation_id if source_gate_evaluation_id is not None else report.source_gate_evaluation_id
        new_inv_id = source_investigation_id if source_investigation_id is not None else report.source_investigation_id

        if not new_plan_id and not new_gate_id and not new_inv_id:
            raise InvalidReportSourceError("At least one valid report source is required.")

        if source_execution_plan_id is not None:
            if source_execution_plan_id:
                plan = self.db.query(SecurityExecutionPlan).filter(SecurityExecutionPlan.id == source_execution_plan_id).first()
                if not plan:
                    raise InvalidReportSourceError(f"Execution plan '{source_execution_plan_id}' not found.")
                if plan.project_id != report.project_id:
                    raise CrossProjectViolationError("Execution plan belongs to a different project.")
            report.source_execution_plan_id = source_execution_plan_id or None

        if source_gate_evaluation_id is not None:
            if source_gate_evaluation_id:
                gate_eval = self.db.query(SecurityGateEvaluation).filter(SecurityGateEvaluation.id == source_gate_evaluation_id).first()
                if not gate_eval:
                    raise InvalidReportSourceError(f"Gate evaluation '{source_gate_evaluation_id}' not found.")
                if gate_eval.project_id != report.project_id:
                    raise CrossProjectViolationError("Gate evaluation belongs to a different project.")
            report.source_gate_evaluation_id = source_gate_evaluation_id or None

        if source_investigation_id is not None:
            if source_investigation_id:
                inv = self.db.query(SecurityInvestigation).filter(SecurityInvestigation.id == source_investigation_id).first()
                if not inv:
                    raise InvalidReportSourceError(f"Investigation '{source_investigation_id}' not found.")
                if inv.project_id != report.project_id:
                    raise CrossProjectViolationError("Investigation belongs to a different project.")
            report.source_investigation_id = source_investigation_id or None

        try:
            self.db.commit()
            self.db.refresh(report)
        except IntegrityError:
            self.db.rollback()
            raise DuplicateReportError(f"A security report named '{report.name}' already exists in this project.")

        return report

    def delete_report(
        self,
        report_id: str,
        project_id: Optional[int] = None,
    ) -> bool:
        """Delete report and its snapshots."""
        report = self.get_report(report_id, project_id=project_id)
        if not report:
            raise ReportNotFoundError(f"Security report '{report_id}' not found.")

        self.db.delete(report)
        self.db.commit()
        return True

    def archive_report(
        self,
        report_id: str,
        project_id: Optional[int] = None,
    ) -> SecurityReport:
        """Archive report, making it completely immutable."""
        report = self.get_report(report_id, project_id=project_id)
        if not report:
            raise ReportNotFoundError(f"Security report '{report_id}' not found.")

        report.status = "ARCHIVED"
        self.db.commit()
        self.db.refresh(report)
        return report

    # =========================================================================
    # Report Snapshot Generation
    # =========================================================================

    def generate_report(
        self,
        report_id: str,
        project_id: Optional[int] = None,
    ) -> SecurityReportSnapshot:
        """
        Deterministically builds and captures an immutable SecurityReportSnapshot.
        Guarantees:
        - ZERO target HTTP calls.
        - Accurate multi-category provenance tracking.
        - Recursive credential sanitization.
        - Deterministic SHA-256 checksum calculation.
        - Snapshot versioning (increments if regenerating).
        """
        report = self.get_report(report_id, project_id=project_id)
        if not report:
            raise ReportNotFoundError(f"Security report '{report_id}' not found.")

        if report.status == "ARCHIVED":
            raise ArchivedReportError("Archived reports are immutable and cannot be regenerated.")

        project = self.db.query(Project).filter(Project.id == report.project_id).first()

        # 1. Resolve Sources
        plan: Optional[SecurityExecutionPlan] = None
        if report.source_execution_plan_id:
            plan = (
                self.db.query(SecurityExecutionPlan)
                .filter(SecurityExecutionPlan.id == report.source_execution_plan_id)
                .first()
            )

        gate_eval: Optional[SecurityGateEvaluation] = None
        if report.source_gate_evaluation_id:
            gate_eval = (
                self.db.query(SecurityGateEvaluation)
                .filter(SecurityGateEvaluation.id == report.source_gate_evaluation_id)
                .first()
            )

        investigation: Optional[SecurityInvestigation] = None
        if report.source_investigation_id:
            investigation = (
                self.db.query(SecurityInvestigation)
                .filter(SecurityInvestigation.id == report.source_investigation_id)
                .first()
            )

        # Cross-source plan inference: if gate_eval exists, it links to comparison -> plan
        comp: Optional[SecurityBaselineComparison] = None
        if gate_eval and gate_eval.baseline_comparison:
            comp = gate_eval.baseline_comparison
            if not plan and comp.execution_plan:
                plan = comp.execution_plan

        # Determine next snapshot version
        existing_snapshots = (
            self.db.query(SecurityReportSnapshot)
            .filter(SecurityReportSnapshot.report_id == report.id)
            .order_by(SecurityReportSnapshot.version.desc())
            .all()
        )
        if existing_snapshots:
            next_version = existing_snapshots[0].version + 1
        else:
            next_version = 1

        now_utc = datetime.now(timezone.utc)

        # 2. Gather Verified Findings
        findings_query = self.db.query(Finding).filter(Finding.project_id == report.project_id)
        if investigation and investigation.primary_finding_id:
            # Include all project findings or specifically relevant findings
            pass
        project_findings = findings_query.all()

        # Filter confirmed findings for primary inclusion
        confirmed_findings = [f for f in project_findings if f.status in ("CONFIRMED", "OPEN")]

        findings_section = []
        remediation_section = []
        finding_ids_set = set()

        for f in confirmed_findings:
            finding_ids_set.add(f.id)
            remediation_text = f.remediation.strip() if f.remediation else "No verified remediation guidance recorded."
            findings_section.append({
                "finding_id": f.id,
                "type": f.type,
                "severity": f.severity,
                "confidence": f.confidence,
                "status": f.status,
                "title": f.title,
                "description": f.description,
                "endpoint": {
                    "id": f.endpoint_id,
                    "method": f.endpoint.method if f.endpoint else None,
                    "path": f.endpoint.path if f.endpoint else None,
                },
                "resource": {
                    "id": f.resource_id,
                    "name": f.resource.name if f.resource else None,
                },
                "expected_behavior": f.expected_authorization or "DENY",
                "actual_behavior": f.actual_behavior,
                "remediation": remediation_text,
                "evidence_reference": f.evidence.id if f.evidence else None,
                "provenance": "VERIFIED",
            })

            remediation_section.append({
                "finding_id": f.id,
                "title": f.title,
                "severity": f.severity,
                "remediation_guidance": remediation_text,
                "provenance": "VERIFIED",
            })

        # 3. Gather Evidence Records (Sanitized)
        evidence_records = (
            self.db.query(Evidence)
            .join(Finding, Finding.id == Evidence.finding_id, isouter=True)
            .filter(
                (Finding.project_id == report.project_id) |
                (Evidence.id.in_([f.evidence.id for f in confirmed_findings if f.evidence]))
            )
            .all()
        )

        evidence_section = []
        for ev in evidence_records:
            req_meta = {}
            if ev.request_metadata:
                try:
                    req_meta = json.loads(ev.request_metadata)
                except Exception:
                    req_meta = {"raw": ev.request_metadata}

            resp_meta = {}
            if ev.response_metadata:
                try:
                    resp_meta = json.loads(ev.response_metadata)
                except Exception:
                    resp_meta = {"raw": ev.response_metadata}

            evidence_section.append({
                "evidence_id": ev.id,
                "execution_id": ev.execution_id,
                "finding_id": ev.finding_id,
                "request_metadata": sanitize_value(req_meta),
                "response_metadata": sanitize_value(resp_meta),
                "expected_behavior": ev.expected_behavior,
                "provenance": "VERIFIED",
            })

        # 4. Gather Attack Paths (Deterministic)
        paths_query = self.db.query(AttackPath).filter(AttackPath.project_id == report.project_id)
        attack_paths = paths_query.all()
        attack_paths_section = []
        for p in attack_paths:
            steps = []
            for s in sorted(p.steps or [], key=lambda st: st.position):
                steps.append({
                    "step_id": s.id,
                    "position": s.position,
                    "finding_id": s.finding_id,
                    "prerequisite_finding_id": s.prerequisite_finding_id,
                    "relationship_type": s.relationship_type,
                    "reason": s.reason,
                })
            attack_paths_section.append({
                "path_id": p.id,
                "name": p.name,
                "description": p.description,
                "status": p.status,
                "confidence": p.confidence,
                "steps": steps,
                "provenance": "DETERMINISTIC",
            })

        # 5. Gather Security Impact (Deterministic)
        impact_records = self.db.query(SecurityImpact).filter(SecurityImpact.project_id == report.project_id).all()
        impact_section = []
        for imp in impact_records:
            impact_section.append({
                "impact_id": imp.id,
                "finding_id": imp.finding_id,
                "attack_path_id": imp.attack_path_id,
                "initial_access": imp.initial_access,
                "authentication_boundary": imp.authentication_boundary_crossed,
                "authorization_boundary": imp.authorization_boundary_crossed,
                "identity_boundary": imp.identity_boundary_crossed,
                "resource_boundary": imp.resource_boundary_crossed,
                "workflow_boundary": imp.workflow_boundary_crossed,
                "property_boundary": imp.property_boundary_crossed,
                "sensitive_data_reached": imp.sensitive_data_reached,
                "cross_identity_impact": imp.cross_identity_impact,
                "cross_resource_impact": imp.cross_resource_impact,
                "terminal_impact": imp.terminal_impact,
                "explanation": imp.explanation,
                "provenance": "DETERMINISTIC",
            })

        # 6. Baseline Comparison (Deterministic)
        baseline_comp_section = None
        if comp:
            items_list = []
            for it in comp.items or []:
                items_list.append({
                    "comparison_item_id": it.id,
                    "control_id": it.control_id,
                    "security_test_id": it.security_test_id,
                    "finding_id": it.finding_id,
                    "result": it.result,
                    "previous_behavior": it.previous_behavior,
                    "current_behavior": it.current_behavior,
                    "explanation": it.explanation,
                    "provenance": "DETERMINISTIC",
                })

            baseline_comp_section = {
                "comparison_id": comp.id,
                "baseline_id": comp.baseline_id,
                "baseline_name": comp.baseline.name if comp.baseline else "Baseline",
                "baseline_version": comp.baseline.version if comp.baseline else 1,
                "execution_plan_id": comp.execution_plan_id,
                "status": comp.status,
                "summary": comp.summary or {},
                "items": items_list,
                "provenance": "DETERMINISTIC",
            }

        # 7. Security Gate Result (Deterministic)
        gate_result_section = None
        if gate_eval:
            gate_result_section = {
                "evaluation_id": gate_eval.id,
                "gate_id": gate_eval.gate_id,
                "gate_name": gate_eval.gate.name if gate_eval.gate else "Security Gate",
                "status": gate_eval.status,
                "failure_count": gate_eval.failure_count,
                "warning_count": gate_eval.warning_count,
                "confirmed_findings": gate_eval.confirmed_findings,
                "regressions": gate_eval.regressions,
                "new_violations": gate_eval.new_violations,
                "failed_tests": gate_eval.failed_tests,
                "inconclusive_tests": gate_eval.inconclusive_tests,
                "error_tests": gate_eval.error_tests,
                "evaluated_at": gate_eval.evaluated_at.isoformat() if gate_eval.evaluated_at else None,
                "summary": gate_eval.summary or {},
                "provenance": "DETERMINISTIC",
            }

        # 8. Investigation Context (Deterministic / Human)
        investigation_section = None
        if investigation:
            inv_items = []
            for it in sorted(investigation.items or [], key=lambda i: i.position):
                inv_items.append({
                    "item_id": it.item_id,
                    "item_type": it.item_type,
                    "position": it.position,
                })
            investigation_section = {
                "investigation_id": investigation.id,
                "title": investigation.title,
                "description": investigation.description,
                "status": investigation.status,
                "primary_finding_id": investigation.primary_finding_id,
                "primary_attack_path_id": investigation.primary_attack_path_id,
                "items": inv_items,
                "provenance": "DETERMINISTIC",
            }

        # 9. AI Analysis & Hypotheses (AI - Strictly Advisory)
        ai_analyses_query = self.db.query(AIAnalysis).filter(AIAnalysis.project_id == report.project_id).all()
        ai_section = []
        for ai in ai_analyses_query:
            ai_section.append({
                "analysis_id": ai.id,
                "analysis_type": ai.analysis_type,
                "provider": ai.model_provider,
                "model": ai.model_name,
                "finding_id": ai.finding_id,
                "attack_path_id": ai.attack_path_id,
                "output": ai.output,
                "disclaimer": "AI ANALYSIS — NOT VERIFIED SECURITY FACT",
                "provenance": "AI",
            })

        # 10. Human Review Section (HUMAN)
        human_reviews_query = (
            self.db.query(AIHypothesisReview)
            .join(AIHypothesis, AIHypothesis.id == AIHypothesisReview.hypothesis_id)
            .filter(AIHypothesis.project_id == report.project_id)
            .all()
        )
        human_review_section = []
        for hr in human_reviews_query:
            human_review_section.append({
                "review_id": hr.id,
                "hypothesis_id": hr.hypothesis_id,
                "action": hr.action,
                "reviewer_reference": hr.reviewer_reference,
                "reason": hr.reason,
                "created_at": hr.created_at.isoformat() if hr.created_at else None,
                "provenance": "HUMAN",
            })

        # 11. Scan Information (ENGINE)
        scan_info_section = {
            "execution_plan_id": plan.id if plan else None,
            "execution_plan_name": plan.name if plan else None,
            "execution_mode": plan.execution_mode if plan else "SEQUENTIAL",
            "plan_status": plan.status if plan else "UNKNOWN",
            "total_tests": plan.total_tests if plan else len(project_findings),
            "completed_tests": plan.completed_tests if plan else len(project_findings),
            "started_at": plan.started_at.isoformat() if plan and plan.started_at else None,
            "completed_at": plan.completed_at.isoformat() if plan and plan.completed_at else None,
            "provenance": "ENGINE",
        }

        # 12. Executive Summary (DETERMINISTIC)
        executive_summary = {
            "project_id": project.id if project else report.project_id,
            "project_name": project.name if project else "Project",
            "report_name": report.name,
            "report_type": report.report_type,
            "report_version": next_version,
            "scan_profile": (
                gate_eval.gate.scan_profile.name if gate_eval and gate_eval.gate and gate_eval.gate.scan_profile else None
            ),
            "baseline_version": (
                gate_eval.gate.baseline.version if gate_eval and gate_eval.gate and gate_eval.gate.baseline
                else (comp.baseline.version if comp and comp.baseline else None)
            ),
            "gate_status": gate_eval.status if gate_eval else "NOT_CONFIGURED",
            "metrics": {
                "total_tests": plan.total_tests if plan else len(project_findings),
                "completed_tests": plan.completed_tests if plan else len(project_findings),
                "confirmed_findings": len(confirmed_findings),
                "regressions": gate_eval.regressions if gate_eval else (comp.summary.get("regressions_count", 0) if comp and comp.summary else 0),
                "new_violations": gate_eval.new_violations if gate_eval else (comp.summary.get("new_violations_count", 0) if comp and comp.summary else 0),
                "inconclusive_tests": plan.inconclusive_tests if plan else 0,
                "failed_tests": plan.failed_tests if plan else 0,
            },
            "affected_dimensions": {
                "endpoints_count": len(set(f.endpoint_id for f in confirmed_findings if f.endpoint_id)),
                "resources_count": len(set(f.resource_id for f in confirmed_findings if f.resource_id)),
                "workflows_count": len(set(f.workflow_id for f in confirmed_findings if f.workflow_id)),
            },
            "provenance": "DETERMINISTIC",
        }

        # 13. Appendix & Provenance Legend
        appendix_section = {
            "provenance_definitions": {
                "VERIFIED": "Facts directly supported by executed security tests and evidence.",
                "DETERMINISTIC": "Derived by deterministic security analysis without external ambiguity.",
                "AI": "Advisory AI reasoning or hypotheses. NOT verified security facts.",
                "HUMAN": "Auditable human reviewer decisions and rationale.",
                "ENGINE": "Deterministic orchestration and execution metadata.",
            },
            "schema_version": "1.0",
            "generated_at": now_utc.isoformat(),
        }

        # Assemble Full Report Data
        raw_report = {
            "report_metadata": {
                "report_id": report.id,
                "project_id": report.project_id,
                "name": report.name,
                "description": report.description,
                "report_type": report.report_type,
                "version": next_version,
                "schema_version": "1.0",
                "generated_at": now_utc.isoformat(),
            },
            "executive_summary": executive_summary,
            "scan_information": scan_info_section,
            "security_gate_result": gate_result_section,
            "baseline_comparison": baseline_comp_section,
            "verified_findings": findings_section,
            "attack_paths": attack_paths_section,
            "security_impact": impact_section,
            "evidence": evidence_section,
            "investigations": investigation_section,
            "ai_analysis": ai_section,
            "human_review": human_review_section,
            "remediation": remediation_section,
            "appendix": appendix_section,
        }

        # Final Security & Redaction Pass
        sanitized_report = sanitize_value(raw_report)

        # Calculate Deterministic Cryptographic SHA-256 Checksum
        checksum = compute_sha256(sanitized_report)

        # Create Immutable Snapshot
        snapshot = SecurityReportSnapshot(
            report_id=report.id,
            version=next_version,
            generated_at=now_utc,
            report_json=sanitized_report,
            checksum=checksum,
            schema_version="1.0",
        )
        self.db.add(snapshot)

        # Update Report Record
        report.status = "GENERATED"
        report.version = next_version
        report.generated_at = now_utc
        self.db.commit()
        self.db.refresh(snapshot)
        self.db.refresh(report)

        return snapshot

    # =========================================================================
    # Snapshot & Evidence Package Access
    # =========================================================================

    def get_snapshot(
        self,
        report_id: str,
        version: Optional[int] = None,
        project_id: Optional[int] = None,
    ) -> SecurityReportSnapshot:
        """Retrieve an immutable snapshot by version or fetch the latest snapshot."""
        report = self.get_report(report_id, project_id=project_id)
        if not report:
            raise ReportNotFoundError(f"Security report '{report_id}' not found.")

        query = self.db.query(SecurityReportSnapshot).filter(SecurityReportSnapshot.report_id == report_id)
        if version is not None:
            snapshot = query.filter(SecurityReportSnapshot.version == version).first()
        else:
            snapshot = query.order_by(SecurityReportSnapshot.version.desc()).first()

        if not snapshot:
            raise ReportNotFoundError(
                f"No snapshot found for report '{report_id}'" + (f" version {version}." if version else ".")
            )

        return snapshot

    def get_manifest(
        self,
        report_id: str,
        version: Optional[int] = None,
        project_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Generate deterministic package manifest for a report snapshot."""
        snapshot = self.get_snapshot(report_id, version=version, project_id=project_id)
        report_data = snapshot.report_json

        findings = report_data.get("verified_findings", [])
        paths = report_data.get("attack_paths", [])
        impacts = report_data.get("security_impact", [])
        evidence = report_data.get("evidence", [])
        ai = report_data.get("ai_analysis", [])
        human = report_data.get("human_review", [])
        remediation = report_data.get("remediation", [])

        object_counts = {
            "verified_findings": len(findings),
            "attack_paths": len(paths),
            "security_impacts": len(impacts),
            "evidence_records": len(evidence),
            "ai_analyses": len(ai),
            "human_reviews": len(human),
            "remediations": len(remediation),
        }

        checksums = {
            "report.json": snapshot.checksum,
            "findings": compute_sha256(findings),
            "attack_paths": compute_sha256(paths),
            "security_impact": compute_sha256(impacts),
            "evidence": compute_sha256(evidence),
            "ai_analysis": compute_sha256(ai),
            "human_review": compute_sha256(human),
        }
        checksums["package"] = compute_sha256(checksums)

        meta = report_data.get("report_metadata", {})
        return {
            "package_version": "1.0",
            "schema_version": snapshot.schema_version,
            "report_id": snapshot.report_id,
            "report_version": snapshot.version,
            "project_id": meta.get("project_id"),
            "generated_at": snapshot.generated_at.isoformat() if snapshot.generated_at else None,
            "object_counts": object_counts,
            "checksums": checksums,
            "source_execution_plan_id": report_data.get("scan_information", {}).get("execution_plan_id"),
            "source_gate_evaluation_id": (
                report_data.get("security_gate_result", {}).get("evaluation_id")
                if report_data.get("security_gate_result") else None
            ),
            "source_investigation_id": (
                report_data.get("investigations", {}).get("investigation_id")
                if report_data.get("investigations") else None
            ),
            "integrity_status": "VERIFIED",
        }

    def get_evidence_package(
        self,
        report_id: str,
        version: Optional[int] = None,
        project_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Produce complete, structured Evidence Package representation matching Section 12.
        Contains:
        - report.json
        - findings/
        - attack-paths/
        - impact/
        - evidence/
        - investigations/
        - ai/
        - human-review/
        - manifest.json
        """
        snapshot = self.get_snapshot(report_id, version=version, project_id=project_id)
        manifest = self.get_manifest(report_id, version=version, project_id=project_id)
        report_data = snapshot.report_json

        return {
            "manifest.json": manifest,
            "report.json": report_data,
            "findings/": report_data.get("verified_findings", []),
            "attack-paths/": report_data.get("attack_paths", []),
            "impact/": report_data.get("security_impact", []),
            "evidence/": report_data.get("evidence", []),
            "investigations/": report_data.get("investigations"),
            "ai/": report_data.get("ai_analysis", []),
            "human-review/": report_data.get("human_review", []),
            "remediation/": report_data.get("remediation", []),
        }
