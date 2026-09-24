"""
Stage 8.2: Deterministic Attack Path Detection Engine
Author: SentinelAPI Security Architecture Team

Converts deterministic finding correlations and attack graph structures into
explainable, ordered attack paths representing logically chained security conditions.
Completely offline analytical engine - never executes target APIs.
"""

from typing import List, Dict, Any, Tuple, Optional, Set
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models import (
    Project,
    Finding,
    Endpoint,
    Identity,
    Resource,
    Workflow,
    AttackGraph,
    AttackGraphNode,
    AttackGraphEdge,
    FindingCorrelation,
    AttackPath,
    AttackPathStep,
)


class AttackPathEngine:
    def __init__(self, db: Session):
        self.db = db

    def is_confirmed(self, finding: Optional[Finding]) -> bool:
        """
        Only analyze confirmed findings. Strictly exclude inconclusive, error,
        false-positive, or passing execution findings.
        """
        if not finding:
            return False
        if finding.status in ("INCONCLUSIVE", "ERROR", "FALSE_POSITIVE"):
            return False
        if finding.execution and finding.execution.result in ("INCONCLUSIVE", "ERROR", "PASS"):
            return False
        if finding.workflow_execution and finding.workflow_execution.result in ("INCONCLUSIVE", "ERROR", "PASS"):
            return False
        return True

    def is_auth_finding(self, finding: Finding) -> bool:
        """Identify if a finding is related to authentication security."""
        ft = (finding.type or "").upper()
        if ft.startswith("AUTH_") or ft in (
            "AUTHENTICATION_BYPASS",
            "AUTH_MISSING",
            "AUTH_INVALID",
            "AUTH_MALFORMED",
            "AUTH_EXPIRED",
            "AUTH_SCHEME",
            "INVALID_AUTH_ACCEPTED",
            "EXPIRED_AUTH_ACCEPTED",
            "AUTHENTICATION_INCONSISTENCY",
        ):
            return True
        if finding.authentication_mechanism:
            return True
        return False

    def is_authz_finding(self, finding: Finding) -> bool:
        """Identify if a finding is related to authorization controls."""
        ft = (finding.type or "").upper()
        return ft in (
            "BOLA",
            "BFLA",
            "BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION",
            "PROPERTY_LEVEL_AUTHORIZATION_BYPASS",
            "FUNCTION_LEVEL_AUTHORIZATION_BYPASS",
        ) or ft.startswith("BOLA") or ft.startswith("BFLA")

    def is_workflow_finding(self, finding: Finding) -> bool:
        """Identify if a finding is related to workflow business logic."""
        if finding.workflow_id is not None or finding.attack_scenario_id is not None:
            return True
        ft = (finding.type or "").upper()
        return ft in (
            "INVALID_STATE_TRANSITION",
            "WORKFLOW_BYPASS",
            "STEP_REPLAY_ACCEPTED",
            "STEP_ORDER_VIOLATION",
            "UNAUTHORIZED_STATE_TRANSITION",
            "IDENTITY_SESSION_POISONING",
            "CROSS_IDENTITY_STATE_ACCESS",
            "STEP_REPLAY",
            "STEP_SKIP",
            "STEP_REORDER",
            "IDENTITY_SWITCH",
            "CROSS_IDENTITY_CONTINUATION",
        )

    def is_property_finding(self, finding: Finding) -> bool:
        """Identify if a finding is related to property exposure or mass assignment."""
        ft = (finding.type or "").upper()
        return (
            ft in (
                "PROPERTY_EXPOSURE",
                "EXCESSIVE_DATA_EXPOSURE",
                "MASS_ASSIGNMENT_CANDIDATE",
                "SENSITIVE_PROPERTY_EXPOSURE",
                "BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION",
            )
            or (finding.exposed_properties is not None and len(str(finding.exposed_properties).strip()) > 0)
        )

    def evaluate_candidate_transition(
        self,
        f1: Finding,
        f2: Finding,
        correlations_by_pair: Dict[Tuple[str, str], List[FindingCorrelation]],
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluate if a directed transition f1 -> f2 is valid according to
        deterministic attack path chain rules (Patterns A, B, C, D).
        Requires concrete context matching and explicit correlation.
        """
        # Security Boundary: Must belong to the exact same project
        if f1.project_id != f2.project_id:
            return None

        # Both findings must be confirmed
        if not self.is_confirmed(f1) or not self.is_confirmed(f2):
            return None

        # Look up explicit FindingCorrelation records between the pair
        pair_key = (min(str(f1.id), str(f2.id)), max(str(f1.id), str(f2.id)))
        corrs = correlations_by_pair.get(pair_key, [])
        if not corrs:
            return None

        # ----------------------------------------------------------------------
        # Pattern A: AUTH -> AUTHORIZATION
        # ----------------------------------------------------------------------
        if self.is_auth_finding(f1) and self.is_authz_finding(f2):
            same_ep = bool(f1.endpoint_id and f2.endpoint_id and f1.endpoint_id == f2.endpoint_id)
            same_id = bool(f1.attacker_identity_id and f2.attacker_identity_id and f1.attacker_identity_id == f2.attacker_identity_id)

            if same_ep or same_id:
                # Relationship Type
                has_authz_rel = any(c.relationship_type == "AUTH_TO_AUTHORIZATION" for c in corrs)
                rel_type = "AUTH_TO_AUTHORIZATION" if has_authz_rel else corrs[0].relationship_type

                # Deterministic Confidence Rule
                # HIGH: both same endpoint and same identity, or explicitly strong correlation
                # MEDIUM: only same endpoint without same identity
                if (same_ep and same_id) or any(c.confidence == "HIGH" for c in corrs):
                    conf = "HIGH"
                else:
                    conf = "MEDIUM"

                ctx_items = []
                if same_ep:
                    ep_path = f1.endpoint.path if f1.endpoint else f"Endpoint #{f1.endpoint_id}"
                    ctx_items.append(f"endpoint '{ep_path}'")
                if same_id:
                    id_name = f1.attacker_identity.name if f1.attacker_identity else f"Identity #{f1.attacker_identity_id}"
                    ctx_items.append(f"identity '{id_name}'")
                ctx_desc = " and ".join(ctx_items) if ctx_items else "shared target context"

                reason = (
                    f"Authentication finding '{f1.title}' ({f1.type}) bypasses access verification on {ctx_desc}, "
                    f"directly enabling subsequent authorization exploit '{f2.title}' ({f2.type})."
                )
                return {
                    "relationship_type": rel_type,
                    "confidence": conf,
                    "reason": reason,
                }

        # ----------------------------------------------------------------------
        # Pattern B: AUTHORIZATION -> PROPERTY
        # ----------------------------------------------------------------------
        if self.is_authz_finding(f1) and self.is_property_finding(f2):
            # Must involve the same resource
            if f1.resource_id and f2.resource_id and f1.resource_id == f2.resource_id:
                res_name = f1.resource.name if f1.resource else f1.resource_id
                has_prop_chain = any(c.relationship_type == "PROPERTY_EXPOSURE_CHAIN" for c in corrs)
                rel_type = "PROPERTY_EXPOSURE_CHAIN" if has_prop_chain else corrs[0].relationship_type

                reason = (
                    f"Authorization finding '{f1.title}' ({f1.type}) grants access to resource '{res_name}', "
                    f"which is subsequently compromised in property exposure finding '{f2.title}'."
                )
                return {
                    "relationship_type": rel_type,
                    "confidence": "HIGH",
                    "reason": reason,
                }

        # ----------------------------------------------------------------------
        # Pattern C: AUTHORIZATION -> WORKFLOW
        # ----------------------------------------------------------------------
        if self.is_authz_finding(f1) and self.is_workflow_finding(f2):
            shared_ctx = []
            if f1.attacker_identity_id and f2.attacker_identity_id and f1.attacker_identity_id == f2.attacker_identity_id:
                id_name = f1.attacker_identity.name if f1.attacker_identity else f1.attacker_identity_id
                shared_ctx.append(f"identity '{id_name}'")
            if f1.resource_id and f2.resource_id and f1.resource_id == f2.resource_id:
                res_name = f1.resource.name if f1.resource else f1.resource_id
                shared_ctx.append(f"resource '{res_name}'")
            if f1.workflow_id and f2.workflow_id and f1.workflow_id == f2.workflow_id:
                wf_name = f1.workflow.name if f1.workflow else f1.workflow_id
                shared_ctx.append(f"workflow '{wf_name}'")

            if shared_ctx:
                has_wf_rel = any(c.relationship_type == "AUTHORIZATION_TO_WORKFLOW" for c in corrs)
                rel_type = "AUTHORIZATION_TO_WORKFLOW" if has_wf_rel else corrs[0].relationship_type

                reason = (
                    f"Authorization vulnerability '{f1.title}' ({f1.type}) compromises access controls, allowing exploitation "
                    f"of business logic workflow state transitions in finding '{f2.title}' ({f2.type}) via shared {', '.join(shared_ctx)}."
                )
                return {
                    "relationship_type": rel_type,
                    "confidence": "HIGH",
                    "reason": reason,
                }

        # ----------------------------------------------------------------------
        # Pattern D: WORKFLOW -> PROPERTY
        # ----------------------------------------------------------------------
        if self.is_workflow_finding(f1) and self.is_property_finding(f2):
            # Must involve the same resource
            if f1.resource_id and f2.resource_id and f1.resource_id == f2.resource_id:
                res_name = f1.resource.name if f1.resource else f1.resource_id
                has_prop_chain = any(c.relationship_type == "PROPERTY_EXPOSURE_CHAIN" for c in corrs)
                rel_type = "PROPERTY_EXPOSURE_CHAIN" if has_prop_chain else corrs[0].relationship_type

                reason = (
                    f"Workflow business logic finding '{f1.title}' ({f1.type}) moves resource '{res_name}' into "
                    f"an unauthorized state, exposing sensitive property attributes in finding '{f2.title}'."
                )
                return {
                    "relationship_type": rel_type,
                    "confidence": "HIGH",
                    "reason": reason,
                }

        return None

    def analyze_project_attack_paths(self, project_id: int) -> Dict[str, Any]:
        """
        Execute deterministic attack path detection for a project.
        Analytical only - NO target API requests are made.
        Operates ONLY on confirmed findings, deterministic FindingCorrelation records,
        and existing AttackGraph nodes/edges.
        """
        project = self.db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise ValueError(f"Project with ID {project_id} not found")

        # 1. Fetch confirmed findings for this project
        all_findings = self.db.query(Finding).filter(Finding.project_id == project_id).all()
        confirmed_findings = [f for f in all_findings if self.is_confirmed(f)]
        confirmed_findings.sort(key=lambda x: str(x.id))
        findings_map: Dict[str, Finding] = {str(f.id): f for f in confirmed_findings}

        # 2. Check for an existing active AttackGraph (operate strictly on existing graph)
        active_graph = (
            self.db.query(AttackGraph)
            .filter(AttackGraph.project_id == project_id, AttackGraph.status == "ACTIVE")
            .order_by(AttackGraph.created_at.desc())
            .first()
        )
        if not active_graph:
            return {
                "project_id": project_id,
                "attack_graph_id": "",
                "paths_count": 0,
                "paths": [],
            }

        # 3. Fetch FindingCorrelation records mapped by (min_id, max_id)
        corrs = (
            self.db.query(FindingCorrelation)
            .filter(FindingCorrelation.project_id == project_id)
            .all()
        )
        correlations_by_pair: Dict[Tuple[str, str], List[FindingCorrelation]] = {}
        for c in corrs:
            k = (min(str(c.finding_a_id), str(c.finding_b_id)), max(str(c.finding_a_id), str(c.finding_b_id)))
            correlations_by_pair.setdefault(k, []).append(c)

        # 4. Build directed transition graph
        transitions: Dict[str, Dict[str, Dict[str, Any]]] = {}
        in_degrees: Dict[str, int] = {f_id: 0 for f_id in findings_map}

        for u_id, u_finding in findings_map.items():
            transitions[u_id] = {}
            for v_id, v_finding in findings_map.items():
                if u_id == v_id:
                    continue
                trans = self.evaluate_candidate_transition(u_finding, v_finding, correlations_by_pair)
                if trans:
                    transitions[u_id][v_id] = trans
                    in_degrees[v_id] = in_degrees.get(v_id, 0) + 1

        # 5. Extract simple candidate paths using cycle-free DFS
        candidate_paths: List[List[str]] = []

        def dfs(current_id: str, path_so_far: List[str]):
            has_child = False
            # Deterministic ordering by target finding ID
            for next_id in sorted(transitions.get(current_id, {}).keys()):
                if next_id not in path_so_far:
                    has_child = True
                    dfs(next_id, path_so_far + [next_id])
            if not has_child and len(path_so_far) >= 2:
                candidate_paths.append(list(path_so_far))

        # Start from root nodes (in_degree == 0 with outgoing transitions)
        root_ids = [u_id for u_id in sorted(findings_map.keys()) if in_degrees.get(u_id, 0) == 0 and len(transitions.get(u_id, {})) > 0]
        for r_id in root_ids:
            dfs(r_id, [r_id])

        # If any node with transitions was not covered by root DFS (e.g. cycle components)
        visited_nodes = {node for p in candidate_paths for node in p}
        for u_id in sorted(findings_map.keys()):
            if u_id not in visited_nodes and len(transitions.get(u_id, {})) > 0:
                dfs(u_id, [u_id])

        # 6. Deduplicate equivalent/subsegment paths
        # Sort candidates: longest first, then lexicographically for determinism
        candidate_paths.sort(key=lambda p: (-len(p), p))

        distinct_paths: List[List[str]] = []
        for cand in candidate_paths:
            is_subsegment = False
            for existing in distinct_paths:
                if len(existing) > len(cand):
                    m = len(cand)
                    for i in range(len(existing) - m + 1):
                        if existing[i : i + m] == cand:
                            is_subsegment = True
                            break
                    if is_subsegment:
                        break
            if not is_subsegment and cand not in distinct_paths:
                distinct_paths.append(cand)

        # 7. Persist attack paths and steps idempotently
        # Delete existing attack paths for this project
        self.db.query(AttackPath).filter(AttackPath.project_id == project_id).delete()
        self.db.flush()

        persisted_paths: List[AttackPath] = []

        for p_finding_ids in distinct_paths:
            p_findings = [findings_map[fid] for fid in p_finding_ids]

            # Path Confidence: HIGH if all edges are HIGH; MEDIUM if any edge is MEDIUM
            path_confidence = "HIGH"
            for i in range(len(p_finding_ids) - 1):
                u_id = p_finding_ids[i]
                v_id = p_finding_ids[i + 1]
                t_info = transitions[u_id][v_id]
                if t_info.get("confidence") == "MEDIUM":
                    path_confidence = "MEDIUM"

            # Deterministic Title
            path_name = f"Attack Path: {' → '.join(f.type for f in p_findings)}"

            # Synthesize Human-Readable Explanation
            f0 = p_findings[0]
            f0_target = f"endpoint '{f0.endpoint.path}'" if f0.endpoint else (f"resource '{f0.resource.name}'" if f0.resource else f"finding '{f0.title}'")
            narrative_parts = [
                f"Attack path initiated through confirmed {f0.type} finding '{f0.title}' on {f0_target}."
            ]
            for i in range(1, len(p_findings)):
                u_id = p_finding_ids[i - 1]
                v_id = p_finding_ids[i]
                t_info = transitions[u_id][v_id]
                narrative_parts.append(t_info["reason"])

            path_desc = " ".join(narrative_parts)

            attack_path = AttackPath(
                project_id=project_id,
                attack_graph_id=active_graph.id if active_graph else "",
                name=path_name,
                description=path_desc,
                status="ACTIVE",
                confidence=path_confidence,
            )
            self.db.add(attack_path)
            self.db.flush()

            # Create Steps
            for pos, f in enumerate(p_findings, start=1):
                if pos == 1:
                    step = AttackPathStep(
                        attack_path_id=attack_path.id,
                        position=pos,
                        finding_id=f.id,
                        prerequisite_finding_id=None,
                        relationship_type="INITIAL_COMPROMISE",
                        reason=f"Initial entry condition: confirmed {f.type} finding '{f.title}' establishes attacker foothold.",
                    )
                else:
                    prev_f = p_findings[pos - 2]
                    t_info = transitions[str(prev_f.id)][str(f.id)]
                    step = AttackPathStep(
                        attack_path_id=attack_path.id,
                        position=pos,
                        finding_id=f.id,
                        prerequisite_finding_id=prev_f.id,
                        relationship_type=t_info["relationship_type"],
                        reason=t_info["reason"],
                    )
                self.db.add(step)

            self.db.flush()
            persisted_paths.append(attack_path)

        self.db.commit()

        # Refresh all paths to load relationships
        for p in persisted_paths:
            self.db.refresh(p)

        return {
            "project_id": project_id,
            "attack_graph_id": active_graph.id if active_graph else "",
            "paths_count": len(persisted_paths),
            "paths": persisted_paths,
        }

    def rebuild_attack_path(self, path_id: str) -> AttackPath:
        """
        Rebuild / re-verify an existing attack path completely offline.
        Verifies that all steps remain confirmed and valid.
        """
        attack_path = self.db.query(AttackPath).filter(AttackPath.id == path_id).first()
        if not attack_path:
            raise ValueError(f"Attack path with ID {path_id} not found")

        # Load ordered steps
        steps = (
            self.db.query(AttackPathStep)
            .filter(AttackPathStep.attack_path_id == path_id)
            .order_by(AttackPathStep.position.asc())
            .all()
        )

        all_valid = True
        for step in steps:
            finding = self.db.query(Finding).filter(Finding.id == step.finding_id).first()
            if not self.is_confirmed(finding):
                all_valid = False
                break

        if not all_valid or len(steps) < 2:
            attack_path.status = "ARCHIVED"
            attack_path.updated_at = datetime.now(timezone.utc)
            self.db.commit()
            self.db.refresh(attack_path)
            return attack_path

        attack_path.status = "ACTIVE"
        attack_path.updated_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(attack_path)
        return attack_path
