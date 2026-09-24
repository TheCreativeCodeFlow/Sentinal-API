"""
Stage 8.1: Deterministic Finding Correlation & Attack Graph Engine
Author: SentinelAPI Security Architecture Team

Analyzes confirmed security findings deterministically without issuing API requests,
identifies multi-vulnerability relationships, and constructs an explainable, reproducible
attack graph.
"""

from typing import List, Dict, Any, Tuple, Optional, Set
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models import (
    Project,
    Finding,
    Endpoint,
    Identity,
    Role,
    Resource,
    Workflow,
    WorkflowExecution,
    AttackGraph,
    AttackGraphNode,
    AttackGraphEdge,
    FindingCorrelation,
)


class CorrelationEngine:
    def __init__(self, db: Session):
        self.db = db

    def is_confirmed(self, finding: Finding) -> bool:
        """Only correlate confirmed findings. Reject inconclusive, error, or false positive."""
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
        if finding.workflow_id is not None:
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
        )

    def is_property_finding(self, finding: Finding) -> bool:
        """Identify if a finding is related to property exposure/mass assignment."""
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

    def evaluate_finding_pair(self, fa: Finding, fb: Finding) -> List[Dict[str, Any]]:
        """
        Evaluate deterministic relationships between two confirmed findings in the same project.
        Returns a list of relationship dictionaries.
        """
        correlations = []

        # Rule A: SAME_IDENTITY
        # Two findings reference the same attacker_identity_id
        if fa.attacker_identity_id and fb.attacker_identity_id and fa.attacker_identity_id == fb.attacker_identity_id:
            correlations.append({
                "relationship_type": "SAME_IDENTITY",
                "confidence": "HIGH",
                "reason": f"Both findings share the same attacker identity (ID: {fa.attacker_identity_id}).",
            })

        # Rule B: SAME_ENDPOINT
        # Two findings reference the same endpoint_id
        if fa.endpoint_id and fb.endpoint_id and fa.endpoint_id == fb.endpoint_id:
            correlations.append({
                "relationship_type": "SAME_ENDPOINT",
                "confidence": "HIGH",
                "reason": f"Both findings target the same API endpoint (ID: {fa.endpoint_id}).",
            })

        # Rule C: SAME_RESOURCE
        # Two findings reference the same resource_id
        if fa.resource_id and fb.resource_id and fa.resource_id == fb.resource_id:
            correlations.append({
                "relationship_type": "SAME_RESOURCE",
                "confidence": "HIGH",
                "reason": f"Both findings target or access the same resource entity (ID: {fa.resource_id}).",
            })

        # Rule D: SAME_WORKFLOW
        # Two findings reference the same workflow_id
        if fa.workflow_id and fb.workflow_id and fa.workflow_id == fb.workflow_id:
            correlations.append({
                "relationship_type": "SAME_WORKFLOW",
                "confidence": "HIGH",
                "reason": f"Both findings occur within the same stateful workflow (ID: {fa.workflow_id}).",
            })

        # Rule E: SAME_EXECUTION
        # Two findings reference the same workflow_execution_id or execution_id
        if (fa.workflow_execution_id and fb.workflow_execution_id and fa.workflow_execution_id == fb.workflow_execution_id) or (
            fa.execution_id and fb.execution_id and fa.execution_id == fb.execution_id
        ):
            correlations.append({
                "relationship_type": "SAME_EXECUTION",
                "confidence": "HIGH",
                "reason": "Both findings were confirmed within the same test execution run.",
            })

        # Rule F: AUTH_TO_AUTHORIZATION
        # An authentication finding and authorization finding reference the same endpoint and identity
        fa_is_auth = self.is_auth_finding(fa)
        fb_is_auth = self.is_auth_finding(fb)
        fa_is_authz = self.is_authz_finding(fa)
        fb_is_authz = self.is_authz_finding(fb)

        if ((fa_is_auth and fb_is_authz) or (fb_is_auth and fa_is_authz)) and (
            fa.endpoint_id and fb.endpoint_id and fa.endpoint_id == fb.endpoint_id
        ) and (
            fa.attacker_identity_id and fb.attacker_identity_id and fa.attacker_identity_id == fb.attacker_identity_id
        ):
            correlations.append({
                "relationship_type": "AUTH_TO_AUTHORIZATION",
                "confidence": "HIGH",
                "reason": f"Authentication flaw correlates directly with authorization bypass on endpoint {fa.endpoint_id} under identity {fa.attacker_identity_id}.",
            })

        # Rule G: AUTHORIZATION_TO_WORKFLOW
        # An authorization finding and workflow finding reference the same identity/resource/workflow context
        fa_is_wf = self.is_workflow_finding(fa)
        fb_is_wf = self.is_workflow_finding(fb)

        if ((fa_is_authz and fb_is_wf) or (fb_is_authz and fa_is_wf)):
            shared_contexts = []
            if fa.attacker_identity_id and fb.attacker_identity_id and fa.attacker_identity_id == fb.attacker_identity_id:
                shared_contexts.append(f"identity '{fa.attacker_identity_id}'")
            if fa.resource_id and fb.resource_id and fa.resource_id == fb.resource_id:
                shared_contexts.append(f"resource '{fa.resource_id}'")
            if fa.endpoint_id and fb.endpoint_id and fa.endpoint_id == fb.endpoint_id:
                shared_contexts.append(f"endpoint '{fa.endpoint_id}'")
            if fa.workflow_id and fb.workflow_id and fa.workflow_id == fb.workflow_id:
                shared_contexts.append(f"workflow '{fa.workflow_id}'")

            if shared_contexts:
                correlations.append({
                    "relationship_type": "AUTHORIZATION_TO_WORKFLOW",
                    "confidence": "HIGH",
                    "reason": f"Authorization vulnerability links into business logic workflow violation via shared {', '.join(shared_contexts)}.",
                })

        # Rule H: PROPERTY_EXPOSURE_CHAIN
        # A property exposure finding references the same resource involved in another authorization/workflow finding
        fa_is_prop = self.is_property_finding(fa)
        fb_is_prop = self.is_property_finding(fb)

        if ((fa_is_prop and (fb_is_authz or fb_is_wf)) or (fb_is_prop and (fa_is_authz or fa_is_wf))) and (
            fa.resource_id and fb.resource_id and fa.resource_id == fb.resource_id
        ):
            correlations.append({
                "relationship_type": "PROPERTY_EXPOSURE_CHAIN",
                "confidence": "HIGH",
                "reason": f"Property exposure finding on resource '{fa.resource_id}' chains into authorization or workflow vulnerability on the same resource.",
            })

        # Rule I: SAME_AUTHENTICATION
        if fa.authentication_mechanism and fb.authentication_mechanism and fa.authentication_mechanism == fb.authentication_mechanism:
            # Overlapping context (same endpoint or same identity)
            if (fa.endpoint_id and fb.endpoint_id and fa.endpoint_id == fb.endpoint_id) or (
                fa.attacker_identity_id and fb.attacker_identity_id and fa.attacker_identity_id == fb.attacker_identity_id
            ):
                correlations.append({
                    "relationship_type": "SAME_AUTHENTICATION",
                    "confidence": "MEDIUM",
                    "reason": f"Both findings share the same authentication mechanism ({fa.authentication_mechanism}) with overlapping context.",
                })

        return correlations

    def run_correlation(self, project_id: int) -> Dict[str, Any]:
        """
        Execute deterministic correlation and attack graph construction for a project.
        Analytical only - NO external or target HTTP requests are made.
        """
        project = self.db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise ValueError(f"Project with ID {project_id} not found")

        # 1. Fetch confirmed findings for this project only
        all_findings = self.db.query(Finding).filter(Finding.project_id == project_id).all()
        confirmed_findings = [f for f in all_findings if self.is_confirmed(f)]
        # Sort deterministically by id
        confirmed_findings.sort(key=lambda x: str(x.id))

        # 2. Fetch existing correlations for deduplication
        existing_corrs = (
            self.db.query(FindingCorrelation)
            .filter(FindingCorrelation.project_id == project_id)
            .all()
        )
        existing_pair_rels: Set[Tuple[str, str, str]] = {
            (c.finding_a_id, c.finding_b_id, c.relationship_type) for c in existing_corrs
        }

        new_correlations_count = 0
        all_project_correlations: List[FindingCorrelation] = list(existing_corrs)

        # 3. Pairwise deterministic evaluation
        n = len(confirmed_findings)
        for i in range(n):
            for j in range(i + 1, n):
                fa = confirmed_findings[i]
                fb = confirmed_findings[j]

                # Ensure deterministic ordering by finding ID
                first_id = min(str(fa.id), str(fb.id))
                second_id = max(str(fa.id), str(fb.id))
                finding_a = fa if str(fa.id) == first_id else fb
                finding_b = fb if str(fb.id) == second_id else fa

                pair_relationships = self.evaluate_finding_pair(finding_a, finding_b)
                for rel in pair_relationships:
                    key = (first_id, second_id, rel["relationship_type"])
                    if key not in existing_pair_rels:
                        new_corr = FindingCorrelation(
                            project_id=project_id,
                            finding_a_id=first_id,
                            finding_b_id=second_id,
                            relationship_type=rel["relationship_type"],
                            confidence=rel["confidence"],
                            reason=rel["reason"],
                        )
                        self.db.add(new_corr)
                        self.db.flush()
                        existing_pair_rels.add(key)
                        all_project_correlations.append(new_corr)
                        new_correlations_count += 1

        self.db.commit()

        # 4. Construct / Update Attack Graph
        graph = self._construct_attack_graph(project, confirmed_findings, all_project_correlations)

        return {
            "project_id": project_id,
            "confirmed_findings_count": len(confirmed_findings),
            "correlations_count": len(all_project_correlations),
            "new_correlations_count": new_correlations_count,
            "graph_id": graph.id,
            "node_count": len(graph.nodes),
            "edge_count": len(graph.edges),
            "correlations": all_project_correlations,
            "graph": graph,
        }

    def _construct_attack_graph(
        self,
        project: Project,
        findings: List[Finding],
        correlations: List[FindingCorrelation],
    ) -> AttackGraph:
        """
        Construct a deterministic, reproducible attack graph with finding nodes,
        context nodes (only for entities that exist in DB), and relationship edges.
        """
        # Clean up existing active graph or create new one
        existing_graph = (
            self.db.query(AttackGraph)
            .filter(AttackGraph.project_id == project.id, AttackGraph.status == "ACTIVE")
            .first()
        )

        if existing_graph:
            # Delete nodes & edges of existing graph to recreate deterministically
            self.db.query(AttackGraphEdge).filter(AttackGraphEdge.graph_id == existing_graph.id).delete()
            self.db.query(AttackGraphNode).filter(AttackGraphNode.graph_id == existing_graph.id).delete()
            graph = existing_graph
            graph.updated_at = datetime.now(timezone.utc)
        else:
            graph = AttackGraph(
                project_id=project.id,
                name=f"{project.name} Attack Graph",
                description=f"Deterministic correlation attack graph for {project.name}",
                status="ACTIVE",
            )
            self.db.add(graph)
            self.db.flush()

        node_registry: Dict[str, AttackGraphNode] = {}
        edge_registry: Set[Tuple[str, str, str]] = set()

        def get_or_create_node(node_key: str, node_type: str, label: str, finding_id: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> AttackGraphNode:
            if node_key in node_registry:
                return node_registry[node_key]
            node = AttackGraphNode(
                graph_id=graph.id,
                finding_id=finding_id,
                node_type=node_type,
                label=label,
                node_metadata=metadata or {},
            )
            self.db.add(node)
            self.db.flush()
            node_registry[node_key] = node
            return node

        def add_edge(source_node: AttackGraphNode, target_node: AttackGraphNode, rel_type: str, confidence: str, reason: str, metadata: Optional[Dict[str, Any]] = None):
            edge_key = (source_node.id, target_node.id, rel_type)
            if edge_key in edge_registry:
                return
            edge = AttackGraphEdge(
                graph_id=graph.id,
                source_node_id=source_node.id,
                target_node_id=target_node.id,
                relationship_type=rel_type,
                confidence=confidence,
                reason=reason,
                edge_metadata=metadata or {},
            )
            self.db.add(edge)
            self.db.flush()
            edge_registry.add(edge_key)

        # A. Create Finding nodes and connect to their existing Context nodes
        for f in findings:
            f_key = f"FINDING:{f.id}"
            f_node = get_or_create_node(
                node_key=f_key,
                node_type="FINDING",
                label=f"[{f.severity}] {f.title}",
                finding_id=f.id,
                metadata={
                    "finding_id": f.id,
                    "type": f.type,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "title": f.title,
                    "endpoint_id": f.endpoint_id,
                    "identity_id": f.attacker_identity_id,
                    "resource_id": f.resource_id,
                    "workflow_id": f.workflow_id,
                },
            )

            # Context Node: Endpoint (only if endpoint exists)
            if f.endpoint_id:
                ep = self.db.query(Endpoint).filter(Endpoint.id == f.endpoint_id).first()
                if ep:
                    ep_key = f"ENDPOINT:{ep.id}"
                    ep_node = get_or_create_node(
                        node_key=ep_key,
                        node_type="ENDPOINT",
                        label=f"{ep.method} {ep.path}",
                        metadata={"endpoint_id": ep.id, "method": ep.method, "path": ep.path},
                    )
                    add_edge(
                        source_node=f_node,
                        target_node=ep_node,
                        rel_type="FINDING_TO_ENDPOINT",
                        confidence="HIGH",
                        reason=f"Finding targets endpoint '{ep.method} {ep.path}'.",
                    )

            # Context Node: Resource (only if resource exists)
            if f.resource_id:
                res = self.db.query(Resource).filter(Resource.id == f.resource_id).first()
                if res:
                    res_key = f"RESOURCE:{res.id}"
                    res_node = get_or_create_node(
                        node_key=res_key,
                        node_type="RESOURCE",
                        label=f"Resource: {res.name}",
                        metadata={"resource_id": res.id, "name": res.name, "resource_type": res.resource_type},
                    )
                    add_edge(
                        source_node=f_node,
                        target_node=res_node,
                        rel_type="FINDING_TO_RESOURCE",
                        confidence="HIGH",
                        reason=f"Finding impacts resource '{res.name}'.",
                    )

            # Context Node: Identity & Role (only if identity exists)
            if f.attacker_identity_id:
                ident = self.db.query(Identity).filter(Identity.id == f.attacker_identity_id).first()
                if ident:
                    ident_key = f"IDENTITY:{ident.id}"
                    ident_node = get_or_create_node(
                        node_key=ident_key,
                        node_type="IDENTITY",
                        label=f"Identity: {ident.name}",
                        metadata={"identity_id": ident.id, "name": ident.name, "auth_type": ident.auth_type},
                    )
                    add_edge(
                        source_node=f_node,
                        target_node=ident_node,
                        rel_type="SAME_IDENTITY",
                        confidence="HIGH",
                        reason=f"Finding involves identity '{ident.name}'.",
                    )

                    # Context Node: Role (only if role exists)
                    if ident.role_id:
                        role = self.db.query(Role).filter(Role.id == ident.role_id).first()
                        if role:
                            role_key = f"ROLE:{role.id}"
                            role_node = get_or_create_node(
                                node_key=role_key,
                                node_type="ROLE",
                                label=f"Role: {role.name}",
                                metadata={"role_id": role.id, "name": role.name},
                            )
                            add_edge(
                                source_node=ident_node,
                                target_node=role_node,
                                rel_type="IDENTITY_TO_ROLE",
                                confidence="HIGH",
                                reason=f"Identity '{ident.name}' is assigned role '{role.name}'.",
                            )

            # Context Node: Workflow (only if workflow exists)
            if f.workflow_id:
                wf = self.db.query(Workflow).filter(Workflow.id == f.workflow_id).first()
                if wf:
                    wf_key = f"WORKFLOW:{wf.id}"
                    wf_node = get_or_create_node(
                        node_key=wf_key,
                        node_type="WORKFLOW",
                        label=f"Workflow: {wf.name}",
                        metadata={"workflow_id": wf.id, "name": wf.name},
                    )
                    add_edge(
                        source_node=wf_node,
                        target_node=f_node,
                        rel_type="WORKFLOW_TO_FINDING",
                        confidence="HIGH",
                        reason=f"Workflow '{wf.name}' contains finding '{f.title}'.",
                    )

            # Context Node: Workflow Execution (only if execution exists)
            if f.workflow_execution_id:
                wf_exec = self.db.query(WorkflowExecution).filter(WorkflowExecution.id == f.workflow_execution_id).first()
                if wf_exec:
                    wfe_key = f"WORKFLOW_EXECUTION:{wf_exec.id}"
                    wfe_node = get_or_create_node(
                        node_key=wfe_key,
                        node_type="WORKFLOW_EXECUTION",
                        label=f"Execution #{wf_exec.id[:8]}",
                        metadata={"execution_id": wf_exec.id, "result": wf_exec.result},
                    )
                    add_edge(
                        source_node=f_node,
                        target_node=wfe_node,
                        rel_type="SAME_EXECUTION",
                        confidence="HIGH",
                        reason=f"Finding confirmed during execution {wf_exec.id[:8]}.",
                    )

            # Context Node: Authentication (only if mechanism recorded)
            if f.authentication_mechanism:
                auth_key = f"AUTHENTICATION:{f.authentication_mechanism}"
                auth_node = get_or_create_node(
                    node_key=auth_key,
                    node_type="AUTHENTICATION",
                    label=f"Auth: {f.authentication_mechanism}",
                    metadata={"mechanism": f.authentication_mechanism},
                )
                add_edge(
                    source_node=f_node,
                    target_node=auth_node,
                    rel_type="SAME_AUTHENTICATION",
                    confidence="HIGH",
                    reason=f"Finding targets authentication mechanism {f.authentication_mechanism}.",
                )

            # Context Node: Property (only if exposed properties present)
            if f.exposed_properties:
                prop_key = f"PROPERTY:{f.id}"
                prop_node = get_or_create_node(
                    node_key=prop_key,
                    node_type="PROPERTY",
                    label=f"Exposed: {str(f.exposed_properties)[:30]}",
                    metadata={"exposed_properties": f.exposed_properties},
                )
                add_edge(
                    source_node=f_node,
                    target_node=prop_node,
                    rel_type="PROPERTY_EXPOSURE_CHAIN",
                    confidence="HIGH",
                    reason=f"Finding exposes properties {str(f.exposed_properties)[:30]}.",
                )

        # B. Add Finding-to-Finding correlation edges
        for corr in correlations:
            key_a = f"FINDING:{corr.finding_a_id}"
            key_b = f"FINDING:{corr.finding_b_id}"
            if key_a in node_registry and key_b in node_registry:
                node_a = node_registry[key_a]
                node_b = node_registry[key_b]
                add_edge(
                    source_node=node_a,
                    target_node=node_b,
                    rel_type=corr.relationship_type,
                    confidence=corr.confidence,
                    reason=corr.reason,
                    metadata={"correlation_id": corr.id},
                )

        self.db.commit()
        self.db.refresh(graph)
        return graph
