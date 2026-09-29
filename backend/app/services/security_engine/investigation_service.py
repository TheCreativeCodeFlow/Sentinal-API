"""
Stage 9.3: Security Investigation Workspace Service
Author: SentinelAPI Security Architecture Team

Unified investigation workspace that connects confirmed findings, evidence,
correlations, attack paths, security impact, AI reasoning, hypotheses, human reviews,
and resulting deterministic SecurityTests.

SECURITY & ARCHITECTURAL BOUNDARIES:
- Product integration and analytical consolidation ONLY.
- Never executes target API requests.
- Strictly enforces project isolation across all attached entities.
- Clearly delineates VERIFIED FACT, DETERMINISTIC ANALYSIS, AI INTERPRETATION,
  AI HYPOTHESIS, HUMAN DECISION, and DETERMINISTIC TEST RESULT.
- Never presents AI interpretation as verified evidence.
- Full sanitization and zero credential exposure.
"""

from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timezone
import json
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models import (
    Project,
    Finding,
    Evidence,
    TestExecution,
    SecurityTest,
    Workflow,
    WorkflowExecution,
    WorkflowAttackScenario,
    AttackGraph,
    AttackGraphNode,
    AttackPath,
    AttackPathStep,
    SecurityImpact,
    AIAnalysis,
    AIHypothesis,
    AIHypothesisReview,
    FindingCorrelation,
    SecurityInvestigation,
    InvestigationItem,
)
from app.services.security_engine.redactor import redact_headers, redact_text


VALID_ITEM_TYPES = {
    "FINDING",
    "EVIDENCE",
    "ATTACK_GRAPH",
    "ATTACK_PATH",
    "SECURITY_IMPACT",
    "AI_ANALYSIS",
    "AI_HYPOTHESIS",
    "SECURITY_TEST",
    "WORKFLOW_EXECUTION",
}


class InvestigationServiceError(Exception):
    """Base exception for investigation operations."""
    pass


class CrossProjectViolationError(InvestigationServiceError):
    """Raised when an entity belongs to a different project."""
    pass


class InvalidFindingStateError(InvestigationServiceError):
    """Raised when an inconclusive or error finding is used incorrectly."""
    pass


class InvestigationService:
    """
    Manages security investigations, contextual graph discovery,
    provenance tracking, and immutable lifecycle timelines.
    """

    def __init__(self, db: Session):
        self.db = db

    def _verify_project_authorized(self, project_id: int) -> Project:
        """Ensure project exists and is authorized for security testing."""
        project = self.db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise InvestigationServiceError(f"Project {project_id} not found")
        if project.authorization_status not in ("authorized", "verified"):
            raise InvestigationServiceError(
                f"Project {project_id} is '{project.authorization_status}'. "
                "Only authorized projects can be investigated."
            )
        return project

    def _get_entity_project_id(self, item_type: str, item_id: str) -> Optional[int]:
        """Resolves the project_id for any supported entity type."""
        if item_type == "FINDING":
            f = self.db.query(Finding).filter(Finding.id == item_id).first()
            return f.project_id if f else None

        if item_type == "EVIDENCE":
            e = self.db.query(Evidence).filter(Evidence.id == item_id).first()
            if not e:
                return None
            if e.finding:
                return e.finding.project_id
            if e.execution and e.execution.security_test:
                return e.execution.security_test.project_id
            if e.workflow_execution and e.workflow_execution.workflow:
                return e.workflow_execution.workflow.project_id
            if e.attack_scenario and e.attack_scenario.workflow:
                return e.attack_scenario.workflow.project_id
            return None

        if item_type == "ATTACK_GRAPH":
            ag = self.db.query(AttackGraph).filter(AttackGraph.id == item_id).first()
            return ag.project_id if ag else None

        if item_type == "ATTACK_PATH":
            ap = self.db.query(AttackPath).filter(AttackPath.id == item_id).first()
            return ap.project_id if ap else None

        if item_type == "SECURITY_IMPACT":
            si = self.db.query(SecurityImpact).filter(SecurityImpact.id == item_id).first()
            return si.project_id if si else None

        if item_type == "AI_ANALYSIS":
            aa = self.db.query(AIAnalysis).filter(AIAnalysis.id == item_id).first()
            return aa.project_id if aa else None

        if item_type == "AI_HYPOTHESIS":
            ah = self.db.query(AIHypothesis).filter(AIHypothesis.id == item_id).first()
            return ah.project_id if ah else None

        if item_type == "SECURITY_TEST":
            st = self.db.query(SecurityTest).filter(SecurityTest.id == item_id).first()
            return st.project_id if st else None

        if item_type == "WORKFLOW_EXECUTION":
            we = self.db.query(WorkflowExecution).filter(WorkflowExecution.id == item_id).first()
            return we.workflow.project_id if (we and we.workflow) else None

        return None

    def create_investigation(
        self,
        project_id: int,
        title: str,
        description: Optional[str] = None,
        primary_finding_id: Optional[str] = None,
        primary_attack_path_id: Optional[str] = None,
    ) -> SecurityInvestigation:
        """Create a new security investigation with strict project boundary checks."""
        self._verify_project_authorized(project_id)

        if primary_finding_id:
            finding = self.db.query(Finding).filter(Finding.id == primary_finding_id).first()
            if not finding:
                raise InvestigationServiceError(f"Primary finding '{primary_finding_id}' not found")
            if finding.project_id != project_id:
                raise CrossProjectViolationError(
                    f"Finding {primary_finding_id} belongs to project {finding.project_id}, not {project_id}"
                )

        if primary_attack_path_id:
            path = self.db.query(AttackPath).filter(AttackPath.id == primary_attack_path_id).first()
            if not path:
                raise InvestigationServiceError(f"Primary attack path '{primary_attack_path_id}' not found")
            if path.project_id != project_id:
                raise CrossProjectViolationError(
                    f"Attack path {primary_attack_path_id} belongs to project {path.project_id}, not {project_id}"
                )

        investigation = SecurityInvestigation(
            project_id=project_id,
            title=title,
            description=description,
            status="OPEN",
            primary_finding_id=primary_finding_id,
            primary_attack_path_id=primary_attack_path_id,
        )
        self.db.add(investigation)
        self.db.commit()
        self.db.refresh(investigation)

        # If primary finding or path is supplied, attach them as initial items
        if primary_finding_id:
            self._attach_item_internal(investigation, "FINDING", primary_finding_id, position=1)
        if primary_attack_path_id:
            self._attach_item_internal(investigation, "ATTACK_PATH", primary_attack_path_id, position=2 if primary_finding_id else 1)

        return investigation

    def create_from_finding(
        self,
        project_id: int,
        finding_id: str,
        title: Optional[str] = None,
        description: Optional[str] = None,
        force_new: bool = False,
    ) -> SecurityInvestigation:
        """
        Creates an investigation from a confirmed finding, automatically discovering
        existing deterministic context and preventing duplicate investigations.
        """
        self._verify_project_authorized(project_id)

        finding = self.db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            raise InvestigationServiceError(f"Finding '{finding_id}' not found")
        if finding.project_id != project_id:
            raise CrossProjectViolationError(
                f"Finding {finding_id} belongs to project {finding.project_id}, not {project_id}"
            )

        # CONFIRMED Finding Requirement
        if finding.status != "CONFIRMED":
            raise InvalidFindingStateError(
                f"Finding '{finding_id}' has status '{finding.status}'. "
                "Investigations can only be initiated from CONFIRMED findings."
            )

        # Prevent duplicate investigations unless explicitly requested
        if not force_new:
            existing = (
                self.db.query(SecurityInvestigation)
                .filter(
                    SecurityInvestigation.project_id == project_id,
                    SecurityInvestigation.primary_finding_id == finding_id,
                    SecurityInvestigation.status.in_(["OPEN", "IN_REVIEW"]),
                )
                .first()
            )
            if existing:
                return existing

        inv_title = title or f"Investigation: {finding.title}"
        inv_desc = description or f"Auto-discovered investigation workflow for confirmed finding '{finding.title}'."

        investigation = SecurityInvestigation(
            project_id=project_id,
            title=inv_title,
            description=inv_desc,
            status="OPEN",
            primary_finding_id=finding_id,
        )
        self.db.add(investigation)
        self.db.commit()
        self.db.refresh(investigation)

        # Automatically discover and attach deterministic context
        self._auto_discover_context_from_finding(investigation, finding)

        return investigation

    def create_from_attack_path(
        self,
        project_id: int,
        attack_path_id: str,
        title: Optional[str] = None,
        description: Optional[str] = None,
        force_new: bool = False,
    ) -> SecurityInvestigation:
        """
        Creates an investigation centered on an attack path, automatically discovering
        graph nodes, steps, and associated findings.
        """
        self._verify_project_authorized(project_id)

        path = self.db.query(AttackPath).filter(AttackPath.id == attack_path_id).first()
        if not path:
            raise InvestigationServiceError(f"Attack path '{attack_path_id}' not found")
        if path.project_id != project_id:
            raise CrossProjectViolationError(
                f"Attack path {attack_path_id} belongs to project {path.project_id}, not {project_id}"
            )

        if not force_new:
            existing = (
                self.db.query(SecurityInvestigation)
                .filter(
                    SecurityInvestigation.project_id == project_id,
                    SecurityInvestigation.primary_attack_path_id == attack_path_id,
                    SecurityInvestigation.status.in_(["OPEN", "IN_REVIEW"]),
                )
                .first()
            )
            if existing:
                return existing

        inv_title = title or f"Investigation: {path.name}"
        inv_desc = description or f"Investigation workflow centered on Attack Path '{path.name}'."

        investigation = SecurityInvestigation(
            project_id=project_id,
            title=inv_title,
            description=inv_desc,
            status="OPEN",
            primary_attack_path_id=attack_path_id,
        )
        self.db.add(investigation)
        self.db.commit()
        self.db.refresh(investigation)

        self._auto_discover_context_from_path(investigation, path)

        return investigation

    def _auto_discover_context_from_finding(
        self, investigation: SecurityInvestigation, finding: Finding
    ) -> None:
        """
        Automated context discovery following the strict lineage:
        Finding -> Evidence -> Related Findings -> Attack Graph -> Attack Path ->
        Security Impact -> AI Analyses -> AI Hypotheses -> Converted SecurityTests -> Workflow Executions
        """
        attached_findings: List[str] = [finding.id]
        attached_paths: List[str] = []
        attached_analyses: List[str] = []

        # 1. Primary Finding
        self._attach_item_internal(investigation, "FINDING", finding.id)

        # 2. Evidence
        if finding.evidence:
            self._attach_item_internal(investigation, "EVIDENCE", finding.evidence.id)
        elif finding.execution and finding.execution.evidence:
            for ev in finding.execution.evidence:
                self._attach_item_internal(investigation, "EVIDENCE", ev.id)

        # 3. Related Findings (via deterministic correlations)
        correlations = (
            self.db.query(FindingCorrelation)
            .filter(
                FindingCorrelation.project_id == investigation.project_id,
                (FindingCorrelation.finding_a_id == finding.id)
                | (FindingCorrelation.finding_b_id == finding.id),
            )
            .all()
        )
        for c in correlations:
            rel_id = c.finding_b_id if c.finding_a_id == finding.id else c.finding_a_id
            rel_finding = self.db.query(Finding).filter(Finding.id == rel_id).first()
            if rel_finding and rel_finding.status not in ("INCONCLUSIVE", "ERROR", "FALSE_POSITIVE"):
                if rel_finding.id not in attached_findings:
                    self._attach_item_internal(investigation, "FINDING", rel_finding.id)
                    attached_findings.append(rel_finding.id)
                    if rel_finding.evidence:
                        self._attach_item_internal(investigation, "EVIDENCE", rel_finding.evidence.id)

        # 4. Attack Graph
        graph_nodes = (
            self.db.query(AttackGraphNode)
            .filter(AttackGraphNode.finding_id == finding.id)
            .all()
        )
        for gn in graph_nodes:
            self._attach_item_internal(investigation, "ATTACK_GRAPH", gn.graph_id)

        # 5. Attack Path
        path_steps = (
            self.db.query(AttackPathStep)
            .filter(AttackPathStep.finding_id.in_(attached_findings))
            .all()
        )
        for ps in path_steps:
            if ps.attack_path_id not in attached_paths:
                self._attach_item_internal(investigation, "ATTACK_PATH", ps.attack_path_id)
                attached_paths.append(ps.attack_path_id)
                if not investigation.primary_attack_path_id:
                    investigation.primary_attack_path_id = ps.attack_path_id

        # 6. Security Impact
        impacts = (
            self.db.query(SecurityImpact)
            .filter(
                SecurityImpact.project_id == investigation.project_id,
                (SecurityImpact.finding_id.in_(attached_findings))
                | (SecurityImpact.attack_path_id.in_(attached_paths)),
            )
            .all()
        )
        for imp in impacts:
            self._attach_item_internal(investigation, "SECURITY_IMPACT", imp.id)

        # 7. AI Analyses
        analyses = (
            self.db.query(AIAnalysis)
            .filter(
                AIAnalysis.project_id == investigation.project_id,
                (AIAnalysis.finding_id.in_(attached_findings))
                | (AIAnalysis.attack_path_id.in_(attached_paths)),
            )
            .all()
        )
        for a in analyses:
            self._attach_item_internal(investigation, "AI_ANALYSIS", a.id)
            attached_analyses.append(a.id)

        # 8. AI Hypotheses
        hypotheses = (
            self.db.query(AIHypothesis)
            .filter(
                AIHypothesis.project_id == investigation.project_id,
                (AIHypothesis.finding_id.in_(attached_findings))
                | (AIHypothesis.attack_path_id.in_(attached_paths))
                | (AIHypothesis.ai_analysis_id.in_(attached_analyses)),
            )
            .all()
        )
        for h in hypotheses:
            self._attach_item_internal(investigation, "AI_HYPOTHESIS", h.id)
            # 9. Converted SecurityTests
            if h.security_test_id:
                self._attach_item_internal(investigation, "SECURITY_TEST", str(h.security_test_id))

        if finding.security_test_id:
            self._attach_item_internal(investigation, "SECURITY_TEST", str(finding.security_test_id))

        # 10. Workflow Executions
        if finding.workflow_execution_id:
            self._attach_item_internal(investigation, "WORKFLOW_EXECUTION", finding.workflow_execution_id)
        elif finding.evidence and finding.evidence.workflow_execution_id:
            self._attach_item_internal(investigation, "WORKFLOW_EXECUTION", finding.evidence.workflow_execution_id)

    def _auto_discover_context_from_path(
        self, investigation: SecurityInvestigation, path: AttackPath
    ) -> None:
        """Automated context discovery when starting an investigation from an attack path."""
        # 1. Attack Path
        self._attach_item_internal(investigation, "ATTACK_PATH", path.id)

        # 2. Attack Graph
        if path.attack_graph_id:
            self._attach_item_internal(investigation, "ATTACK_GRAPH", path.attack_graph_id)

        # 3. Path Step Findings & Evidence
        path_finding_ids: List[str] = []
        for step in path.steps:
            if step.finding_id:
                path_finding_ids.append(step.finding_id)
                self._attach_item_internal(investigation, "FINDING", step.finding_id)
                f = self.db.query(Finding).filter(Finding.id == step.finding_id).first()
                if f and f.evidence:
                    self._attach_item_internal(investigation, "EVIDENCE", f.evidence.id)

        if path_finding_ids and not investigation.primary_finding_id:
            investigation.primary_finding_id = path_finding_ids[0]

        # 4. Security Impacts
        impacts = (
            self.db.query(SecurityImpact)
            .filter(
                SecurityImpact.project_id == investigation.project_id,
                (SecurityImpact.attack_path_id == path.id)
                | (SecurityImpact.finding_id.in_(path_finding_ids)),
            )
            .all()
        )
        for imp in impacts:
            self._attach_item_internal(investigation, "SECURITY_IMPACT", imp.id)

        # 5. AI Analyses
        analyses = (
            self.db.query(AIAnalysis)
            .filter(
                AIAnalysis.project_id == investigation.project_id,
                (AIAnalysis.attack_path_id == path.id)
                | (AIAnalysis.finding_id.in_(path_finding_ids)),
            )
            .all()
        )
        analysis_ids = []
        for a in analyses:
            self._attach_item_internal(investigation, "AI_ANALYSIS", a.id)
            analysis_ids.append(a.id)

        # 6. AI Hypotheses
        hypotheses = (
            self.db.query(AIHypothesis)
            .filter(
                AIHypothesis.project_id == investigation.project_id,
                (AIHypothesis.attack_path_id == path.id)
                | (AIHypothesis.finding_id.in_(path_finding_ids))
                | (AIHypothesis.ai_analysis_id.in_(analysis_ids)),
            )
            .all()
        )
        for h in hypotheses:
            self._attach_item_internal(investigation, "AI_HYPOTHESIS", h.id)
            if h.security_test_id:
                self._attach_item_internal(investigation, "SECURITY_TEST", str(h.security_test_id))

    def _attach_item_internal(
        self,
        investigation: SecurityInvestigation,
        item_type: str,
        item_id: str,
        position: Optional[int] = None,
    ) -> Optional[InvestigationItem]:
        """Internal idempotent attachment that avoids throwing on duplicates during discovery."""
        try:
            return self.attach_item(investigation.id, item_type, item_id, position=position)
        except InvestigationServiceError:
            return None

    def attach_item(
        self,
        investigation_id: str,
        item_type: str,
        item_id: str,
        position: Optional[int] = None,
    ) -> InvestigationItem:
        """
        Attach an item to the investigation with strict project isolation,
        finding validity enforcement, and duplicate prevention.
        """
        investigation = (
            self.db.query(SecurityInvestigation)
            .filter(SecurityInvestigation.id == investigation_id)
            .first()
        )
        if not investigation:
            raise InvestigationServiceError(f"Investigation '{investigation_id}' not found")

        item_type_upper = item_type.upper()
        if item_type_upper not in VALID_ITEM_TYPES:
            raise InvestigationServiceError(
                f"Invalid item_type '{item_type}'. Must be one of: {sorted(list(VALID_ITEM_TYPES))}"
            )

        # Check entity existence and project isolation
        entity_project_id = self._get_entity_project_id(item_type_upper, item_id)
        if entity_project_id is None:
            raise InvestigationServiceError(f"{item_type_upper} entity '{item_id}' not found")

        if entity_project_id != investigation.project_id:
            raise CrossProjectViolationError(
                f"Entity {item_id} ({item_type_upper}) belongs to project {entity_project_id}, "
                f"while investigation belongs to project {investigation.project_id}"
            )

        # Prevent attaching INCONCLUSIVE or ERROR findings as verified findings
        if item_type_upper == "FINDING":
            f = self.db.query(Finding).filter(Finding.id == item_id).first()
            if f and f.status in ("INCONCLUSIVE", "ERROR"):
                raise InvalidFindingStateError(
                    f"Cannot attach finding '{item_id}' with status '{f.status}' as a verified finding."
                )

        # Check for duplicates
        existing = (
            self.db.query(InvestigationItem)
            .filter(
                InvestigationItem.investigation_id == investigation_id,
                InvestigationItem.item_type == item_type_upper,
                InvestigationItem.item_id == str(item_id),
            )
            .first()
        )
        if existing:
            raise InvestigationServiceError(
                f"Item {item_type_upper}:{item_id} is already attached to investigation {investigation_id}"
            )

        # Compute next position if not specified
        if position is None:
            max_pos = (
                self.db.query(func.max(InvestigationItem.position))
                .filter(InvestigationItem.investigation_id == investigation_id)
                .scalar()
            )
            target_pos = (max_pos or 0) + 1
        else:
            target_pos = position
            # If position collision, shift higher positions
            collision = (
                self.db.query(InvestigationItem)
                .filter(
                    InvestigationItem.investigation_id == investigation_id,
                    InvestigationItem.position == target_pos,
                )
                .first()
            )
            if collision:
                (
                    self.db.query(InvestigationItem)
                    .filter(
                        InvestigationItem.investigation_id == investigation_id,
                        InvestigationItem.position >= target_pos,
                    )
                    .update({"position": InvestigationItem.position + 1})
                )

        item = InvestigationItem(
            investigation_id=investigation_id,
            item_type=item_type_upper,
            item_id=str(item_id),
            position=target_pos,
        )
        self.db.add(item)
        self.db.commit()
        self.db.refresh(item)
        return item

    def detach_item(self, investigation_id: str, item_id: str) -> bool:
        """
        Detach an item from the investigation by item record ID or target entity ID,
        then normalize positions.
        """
        item = (
            self.db.query(InvestigationItem)
            .filter(
                InvestigationItem.investigation_id == investigation_id,
                (InvestigationItem.id == item_id) | (InvestigationItem.item_id == item_id),
            )
            .first()
        )
        if not item:
            return False

        self.db.delete(item)
        self.db.commit()

        # Re-index remaining items sequentially
        remaining = (
            self.db.query(InvestigationItem)
            .filter(InvestigationItem.investigation_id == investigation_id)
            .order_by(InvestigationItem.position.asc())
            .all()
        )
        for idx, itm in enumerate(remaining, start=1):
            itm.position = idx
        self.db.commit()
        return True

    def update_investigation(
        self,
        investigation_id: str,
        title: Optional[str] = None,
        description: Optional[str] = None,
        status: Optional[str] = None,
    ) -> SecurityInvestigation:
        """Update mutable fields of an investigation."""
        inv = (
            self.db.query(SecurityInvestigation)
            .filter(SecurityInvestigation.id == investigation_id)
            .first()
        )
        if not inv:
            raise InvestigationServiceError(f"Investigation '{investigation_id}' not found")

        if title is not None:
            inv.title = title
        if description is not None:
            inv.description = description
        if status is not None:
            valid_statuses = ("OPEN", "IN_REVIEW", "RESOLVED", "ARCHIVED")
            if status not in valid_statuses:
                raise InvestigationServiceError(f"Status must be one of: {valid_statuses}")
            inv.status = status
            if status == "RESOLVED":
                inv.resolved_at = datetime.now(timezone.utc)
            else:
                inv.resolved_at = None

        self.db.commit()
        self.db.refresh(inv)
        return inv

    def get_investigation_timeline(self, investigation_id: str) -> List[Dict[str, Any]]:
        """
        Builds a deterministic, chronological timeline of all events across attached entities.
        Uses only existing audit timestamps.
        Each event is clearly labeled with its provenance category:
        VERIFIED, DETERMINISTIC, AI, HUMAN, or ENGINE.
        """
        inv = (
            self.db.query(SecurityInvestigation)
            .filter(SecurityInvestigation.id == investigation_id)
            .first()
        )
        if not inv:
            raise InvestigationServiceError(f"Investigation '{investigation_id}' not found")

        events: List[Dict[str, Any]] = []

        # Investigation itself
        events.append({
            "id": f"evt-inv-created-{inv.id}",
            "event_type": "INVESTIGATION_OPENED",
            "category": "HUMAN",
            "timestamp": inv.created_at.isoformat() if inv.created_at else None,
            "title": "Investigation Opened",
            "description": f"Security tester initiated investigation: '{inv.title}'",
            "source_type": "INVESTIGATION",
            "source_id": inv.id,
            "metadata": {"status": inv.status},
        })

        # Process each attached item
        for item in inv.items:
            t = item.item_type
            iid = item.item_id

            if t == "FINDING":
                f = self.db.query(Finding).filter(Finding.id == iid).first()
                if f:
                    events.append({
                        "id": f"evt-finding-{f.id}",
                        "event_type": "FINDING_CREATED",
                        "category": "VERIFIED",
                        "timestamp": f.created_at.isoformat() if f.created_at else None,
                        "title": f"Verified Finding: {f.title}",
                        "description": f"Confirmed {f.type} vulnerability discovered (Severity: {f.severity}).",
                        "source_type": "FINDING",
                        "source_id": f.id,
                        "metadata": {"type": f.type, "severity": f.severity, "status": f.status},
                    })

            elif t == "EVIDENCE":
                ev = self.db.query(Evidence).filter(Evidence.id == iid).first()
                if ev:
                    events.append({
                        "id": f"evt-evidence-{ev.id}",
                        "event_type": "EVIDENCE_CAPTURED",
                        "category": "VERIFIED",
                        "timestamp": ev.created_at.isoformat() if ev.created_at else None,
                        "title": "HTTP Traffic Evidence Captured",
                        "description": f"Sanitized reproducible request/response telemetry recorded (reproducibility: {ev.reproducibility_status}).",
                        "source_type": "EVIDENCE",
                        "source_id": ev.id,
                        "metadata": {"reproducibility": ev.reproducibility_status},
                    })

            elif t == "ATTACK_GRAPH":
                ag = self.db.query(AttackGraph).filter(AttackGraph.id == iid).first()
                if ag:
                    events.append({
                        "id": f"evt-graph-{ag.id}",
                        "event_type": "CORRELATION_GRAPH_BUILT",
                        "category": "DETERMINISTIC",
                        "timestamp": ag.created_at.isoformat() if ag.created_at else None,
                        "title": f"Attack Graph Synthesized: {ag.name}",
                        "description": f"Deterministic correlation of findings into explainable attack graph.",
                        "source_type": "ATTACK_GRAPH",
                        "source_id": ag.id,
                        "metadata": {"node_count": len(ag.nodes), "edge_count": len(ag.edges)},
                    })

            elif t == "ATTACK_PATH":
                ap = self.db.query(AttackPath).filter(AttackPath.id == iid).first()
                if ap:
                    events.append({
                        "id": f"evt-path-{ap.id}",
                        "event_type": "ATTACK_PATH_GENERATED",
                        "category": "DETERMINISTIC",
                        "timestamp": ap.created_at.isoformat() if ap.created_at else None,
                        "title": f"Attack Path Generated: {ap.name}",
                        "description": f"Deterministic ordered multi-step security chain computed (Confidence: {ap.confidence}).",
                        "source_type": "ATTACK_PATH",
                        "source_id": ap.id,
                        "metadata": {"confidence": ap.confidence, "step_count": len(ap.steps)},
                    })

            elif t == "SECURITY_IMPACT":
                imp = self.db.query(SecurityImpact).filter(SecurityImpact.id == iid).first()
                if imp:
                    events.append({
                        "id": f"evt-impact-{imp.id}",
                        "event_type": "IMPACT_ANALYZED",
                        "category": "DETERMINISTIC",
                        "timestamp": imp.created_at.isoformat() if imp.created_at else None,
                        "title": f"Security Impact Analyzed: {imp.terminal_impact}",
                        "description": imp.explanation or f"Terminal impact classified as {imp.terminal_impact}.",
                        "source_type": "SECURITY_IMPACT",
                        "source_id": imp.id,
                        "metadata": {"terminal_impact": imp.terminal_impact},
                    })

            elif t == "AI_ANALYSIS":
                aa = self.db.query(AIAnalysis).filter(AIAnalysis.id == iid).first()
                if aa:
                    events.append({
                        "id": f"evt-ai-analysis-{aa.id}",
                        "event_type": "AI_ANALYSIS_GENERATED",
                        "category": "AI",
                        "timestamp": aa.created_at.isoformat() if aa.created_at else None,
                        "title": f"AI Security Reasoning: {aa.analysis_type}",
                        "description": f"Grounded reasoning synthesized by {aa.model_provider}/{aa.model_name}.",
                        "source_type": "AI_ANALYSIS",
                        "source_id": aa.id,
                        "metadata": {"provider": aa.model_provider, "status": aa.status},
                    })

            elif t == "AI_HYPOTHESIS":
                ah = self.db.query(AIHypothesis).filter(AIHypothesis.id == iid).first()
                if ah:
                    events.append({
                        "id": f"evt-ai-hypo-{ah.id}",
                        "event_type": "AI_HYPOTHESIS_GENERATED",
                        "category": "AI",
                        "timestamp": ah.created_at.isoformat() if ah.created_at else None,
                        "title": f"AI Test Hypothesis Proposed ({ah.suggested_test_type})",
                        "description": ah.hypothesis,
                        "source_type": "AI_HYPOTHESIS",
                        "source_id": ah.id,
                        "metadata": {"test_type": ah.suggested_test_type, "status": ah.status, "confidence": ah.confidence},
                    })

                    # Human reviews for this hypothesis
                    for rev in ah.reviews:
                        events.append({
                            "id": f"evt-human-review-{rev.id}",
                            "event_type": f"HUMAN_{rev.action}",
                            "category": "HUMAN",
                            "timestamp": rev.created_at.isoformat() if rev.created_at else None,
                            "title": f"Human Review: Hypothesis {rev.action}",
                            "description": f"Reviewer '{rev.reviewer_reference}' marked hypothesis as {rev.action}. Reason: '{rev.reason or 'None'}'",
                            "source_type": "AI_HYPOTHESIS_REVIEW",
                            "source_id": rev.id,
                            "metadata": {"reviewer": rev.reviewer_reference, "action": rev.action},
                        })

                    # If converted to SecurityTest
                    if ah.status == "CONVERTED" and ah.security_test_id:
                        events.append({
                            "id": f"evt-hypo-converted-{ah.id}",
                            "event_type": "HYPOTHESIS_CONVERTED",
                            "category": "HUMAN",
                            "timestamp": ah.updated_at.isoformat() if ah.updated_at else None,
                            "title": "Hypothesis Converted to Security Test",
                            "description": f"Approved hypothesis converted into deterministic SecurityTest (ID: {ah.security_test_id}).",
                            "source_type": "SECURITY_TEST",
                            "source_id": str(ah.security_test_id),
                            "metadata": {"test_id": ah.security_test_id},
                        })

            elif t == "SECURITY_TEST":
                st = self.db.query(SecurityTest).filter(SecurityTest.id == iid).first()
                if st:
                    # Executions for this test
                    for ex in st.executions:
                        events.append({
                            "id": f"evt-test-exec-{ex.id}",
                            "event_type": "SECURITY_TEST_EXECUTED",
                            "category": "ENGINE",
                            "timestamp": ex.created_at.isoformat() if ex.created_at else None,
                            "title": f"Security Test Executed ({st.test_type})",
                            "description": f"Deterministic engine executed test. Result: {ex.result}.",
                            "source_type": "TEST_EXECUTION",
                            "source_id": ex.id,
                            "metadata": {"test_type": st.test_type, "result": ex.result, "status": ex.status},
                        })

            elif t == "WORKFLOW_EXECUTION":
                we = self.db.query(WorkflowExecution).filter(WorkflowExecution.id == iid).first()
                if we:
                    events.append({
                        "id": f"evt-wf-exec-{we.id}",
                        "event_type": "WORKFLOW_EXECUTED",
                        "category": "ENGINE",
                        "timestamp": we.created_at.isoformat() if we.created_at else None,
                        "title": f"Workflow Executed: {we.workflow.name if we.workflow else 'Workflow'}",
                        "description": f"Workflow execution completed with result {we.result}.",
                        "source_type": "WORKFLOW_EXECUTION",
                        "source_id": we.id,
                        "metadata": {"result": we.result, "status": we.status},
                    })

        # Sort timeline chronologically by ISO timestamp string
        events.sort(key=lambda e: e.get("timestamp") or "")
        return events

    def get_investigation_context(self, investigation_id: str) -> Dict[str, Any]:
        """
        Aggregates and formats all attached entities into a fully sanitized,
        structured investigation context.
        Strictly excludes passwords, tokens, auth headers, cookies, api keys,
        credential_encrypted, and secret property values.
        """
        inv = (
            self.db.query(SecurityInvestigation)
            .filter(SecurityInvestigation.id == investigation_id)
            .first()
        )
        if not inv:
            raise InvestigationServiceError(f"Investigation '{investigation_id}' not found")

        evidence_list: List[Dict[str, Any]] = []
        findings_list: List[Dict[str, Any]] = []
        graphs_list: List[Dict[str, Any]] = []
        paths_list: List[Dict[str, Any]] = []
        impacts_list: List[Dict[str, Any]] = []
        analyses_list: List[Dict[str, Any]] = []
        hypotheses_list: List[Dict[str, Any]] = []
        tests_list: List[Dict[str, Any]] = []
        workflow_executions_list: List[Dict[str, Any]] = []

        for item in inv.items:
            t = item.item_type
            iid = item.item_id

            if t == "FINDING":
                f = self.db.query(Finding).filter(Finding.id == iid).first()
                if f:
                    findings_list.append({
                        "id": f.id,
                        "title": f.title,
                        "type": f.type,
                        "severity": f.severity,
                        "confidence": f.confidence,
                        "status": f.status,
                        "description": redact_text(f.description),
                        "remediation": f.remediation,
                        "endpoint": f"{f.endpoint.method} {f.endpoint.path}" if f.endpoint else None,
                        "attacker_identity": f.attacker_identity.name if f.attacker_identity else None,
                        "created_at": f.created_at.isoformat() if f.created_at else None,
                    })

            elif t == "EVIDENCE":
                ev = self.db.query(Evidence).filter(Evidence.id == iid).first()
                if ev:
                    # Sanitize request/response metadata
                    req_meta = {}
                    if ev.request_metadata:
                        try:
                            parsed_req = json.loads(ev.request_metadata) if isinstance(ev.request_metadata, str) else ev.request_metadata
                            if isinstance(parsed_req, dict):
                                if "headers" in parsed_req and isinstance(parsed_req["headers"], dict):
                                    parsed_req["headers"] = redact_headers(parsed_req["headers"])
                                req_meta = parsed_req
                        except Exception:
                            pass

                    resp_meta = {}
                    if ev.response_metadata:
                        try:
                            parsed_resp = json.loads(ev.response_metadata) if isinstance(ev.response_metadata, str) else ev.response_metadata
                            if isinstance(parsed_resp, dict):
                                if "headers" in parsed_resp and isinstance(parsed_resp["headers"], dict):
                                    parsed_resp["headers"] = redact_headers(parsed_resp["headers"])
                                resp_meta = parsed_resp
                        except Exception:
                            pass

                    evidence_list.append({
                        "id": ev.id,
                        "finding_id": ev.finding_id,
                        "expected_behavior": ev.expected_behavior,
                        "actual_behavior": ev.actual_behavior,
                        "reproducibility_status": ev.reproducibility_status,
                        "redacted_request": redact_text(ev.redacted_request or ""),
                        "redacted_response": redact_text(ev.redacted_response or ""),
                        "request_metadata": req_meta,
                        "response_metadata": resp_meta,
                        "created_at": ev.created_at.isoformat() if ev.created_at else None,
                    })

            elif t == "ATTACK_GRAPH":
                ag = self.db.query(AttackGraph).filter(AttackGraph.id == iid).first()
                if ag:
                    graphs_list.append({
                        "id": ag.id,
                        "name": ag.name,
                        "status": ag.status,
                        "node_count": len(ag.nodes),
                        "edge_count": len(ag.edges),
                        "nodes": [
                            {"id": n.id, "node_type": n.node_type, "label": n.label, "finding_id": n.finding_id}
                            for n in ag.nodes
                        ],
                        "edges": [
                            {"id": e.id, "source": e.source_node_id, "target": e.target_node_id, "type": e.relationship_type, "reason": e.reason}
                            for e in ag.edges
                        ],
                        "created_at": ag.created_at.isoformat() if ag.created_at else None,
                    })

            elif t == "ATTACK_PATH":
                ap = self.db.query(AttackPath).filter(AttackPath.id == iid).first()
                if ap:
                    paths_list.append({
                        "id": ap.id,
                        "name": ap.name,
                        "description": ap.description,
                        "status": ap.status,
                        "confidence": ap.confidence,
                        "step_count": len(ap.steps),
                        "steps": [
                            {
                                "position": s.position,
                                "finding_id": s.finding_id,
                                "relationship_type": s.relationship_type,
                                "reason": s.reason,
                            }
                            for s in sorted(ap.steps, key=lambda x: x.position)
                        ],
                        "created_at": ap.created_at.isoformat() if ap.created_at else None,
                    })

            elif t == "SECURITY_IMPACT":
                imp = self.db.query(SecurityImpact).filter(SecurityImpact.id == iid).first()
                if imp:
                    impacts_list.append({
                        "id": imp.id,
                        "attack_path_id": imp.attack_path_id,
                        "finding_id": imp.finding_id,
                        "terminal_impact": imp.terminal_impact,
                        "explanation": imp.explanation,
                        "initial_access": imp.initial_access,
                        "authentication_boundary_crossed": imp.authentication_boundary_crossed,
                        "authorization_boundary_crossed": imp.authorization_boundary_crossed,
                        "cross_identity_impact": imp.cross_identity_impact,
                        "sensitive_data_reached": imp.sensitive_data_reached,
                        "created_at": imp.created_at.isoformat() if imp.created_at else None,
                    })

            elif t == "AI_ANALYSIS":
                aa = self.db.query(AIAnalysis).filter(AIAnalysis.id == iid).first()
                if aa:
                    analyses_list.append({
                        "id": aa.id,
                        "analysis_type": aa.analysis_type,
                        "status": aa.status,
                        "model_provider": aa.model_provider,
                        "model_name": aa.model_name,
                        "finding_id": aa.finding_id,
                        "attack_path_id": aa.attack_path_id,
                        "output": aa.output,
                        "created_at": aa.created_at.isoformat() if aa.created_at else None,
                    })

            elif t == "AI_HYPOTHESIS":
                ah = self.db.query(AIHypothesis).filter(AIHypothesis.id == iid).first()
                if ah:
                    hypotheses_list.append({
                        "id": ah.id,
                        "hypothesis": ah.hypothesis,
                        "reason": ah.reason,
                        "suggested_test_type": ah.suggested_test_type,
                        "confidence": ah.confidence,
                        "requires_human_review": ah.requires_human_review,
                        "status": ah.status,
                        "reviewed_by": ah.reviewed_by,
                        "reviewed_at": ah.reviewed_at.isoformat() if ah.reviewed_at else None,
                        "rejection_reason": ah.rejection_reason,
                        "security_test_id": ah.security_test_id,
                        "required_context": ah.required_context,
                        "reviews": [
                            {
                                "id": r.id,
                                "action": r.action,
                                "reviewer": r.reviewer_reference,
                                "reason": r.reason,
                                "created_at": r.created_at.isoformat() if r.created_at else None,
                            }
                            for r in ah.reviews
                        ],
                        "created_at": ah.created_at.isoformat() if ah.created_at else None,
                    })

            elif t == "SECURITY_TEST":
                st = self.db.query(SecurityTest).filter(SecurityTest.id == iid).first()
                if st:
                    tests_list.append({
                        "id": st.id,
                        "test_type": st.test_type,
                        "status": st.status,
                        "endpoint": f"{st.endpoint.method} {st.endpoint.path}" if st.endpoint else None,
                        "attacker_identity": st.attacker_identity.name if st.attacker_identity else None,
                        "execution_count": len(st.executions),
                        "latest_result": st.executions[-1].result if st.executions else None,
                        "created_at": st.created_at.isoformat() if st.created_at else None,
                    })

            elif t == "WORKFLOW_EXECUTION":
                we = self.db.query(WorkflowExecution).filter(WorkflowExecution.id == iid).first()
                if we:
                    workflow_executions_list.append({
                        "id": we.id,
                        "workflow_name": we.workflow.name if we.workflow else None,
                        "status": we.status,
                        "result": we.result,
                        "step_count": len(we.step_executions),
                        "created_at": we.created_at.isoformat() if we.created_at else None,
                    })

        primary_f_data = None
        if inv.primary_finding:
            pf = inv.primary_finding
            primary_f_data = {
                "id": pf.id,
                "title": pf.title,
                "type": pf.type,
                "severity": pf.severity,
                "confidence": pf.confidence,
                "status": pf.status,
                "description": pf.description,
                "endpoint": f"{pf.endpoint.method} {pf.endpoint.path}" if pf.endpoint else None,
            }

        primary_p_data = None
        if inv.primary_attack_path:
            pp = inv.primary_attack_path
            primary_p_data = {
                "id": pp.id,
                "name": pp.name,
                "confidence": pp.confidence,
                "status": pp.status,
                "step_count": len(pp.steps),
            }

        summary_counts = {
            "findings": len(findings_list),
            "evidence": len(evidence_list),
            "attack_graphs": len(graphs_list),
            "attack_paths": len(paths_list),
            "security_impacts": len(impacts_list),
            "ai_analyses": len(analyses_list),
            "ai_hypotheses": len(hypotheses_list),
            "security_tests": len(tests_list),
            "workflow_executions": len(workflow_executions_list),
        }

        # Formatted investigation header detail
        inv_detail = {
            "id": inv.id,
            "project_id": inv.project_id,
            "title": inv.title,
            "description": inv.description,
            "status": inv.status,
            "primary_finding_id": inv.primary_finding_id,
            "primary_attack_path_id": inv.primary_attack_path_id,
            "primary_finding_title": inv.primary_finding.title if inv.primary_finding else None,
            "primary_finding_severity": inv.primary_finding.severity if inv.primary_finding else None,
            "primary_attack_path_name": inv.primary_attack_path.name if inv.primary_attack_path else None,
            "created_at": inv.created_at,
            "updated_at": inv.updated_at,
            "resolved_at": inv.resolved_at,
            "item_count": len(inv.items),
            "items": [
                {
                    "id": itm.id,
                    "investigation_id": itm.investigation_id,
                    "item_type": itm.item_type,
                    "item_id": itm.item_id,
                    "position": itm.position,
                    "created_at": itm.created_at,
                }
                for itm in inv.items
            ],
        }

        return {
            "investigation": inv_detail,
            "primary_finding": primary_f_data,
            "primary_attack_path": primary_p_data,
            "evidence": evidence_list,
            "findings": findings_list,
            "attack_graphs": graphs_list,
            "attack_paths": paths_list,
            "security_impacts": impacts_list,
            "ai_analyses": analyses_list,
            "ai_hypotheses": hypotheses_list,
            "security_tests": tests_list,
            "workflow_executions": workflow_executions_list,
            "summary_counts": summary_counts,
        }
