"""
Stage 8.3: Deterministic Security Impact Analysis Engine
Author: SentinelAPI Security Architecture Team

Analyzes confirmed security findings and deterministic attack paths to expose concrete
security impact dimensions (boundaries crossed, terminal impact, sensitive data reached,
and cross-boundary traversal). Completely offline analytical engine - never executes target APIs.
"""

from typing import List, Dict, Any, Optional, Set
from datetime import datetime, timezone
import json
from sqlalchemy.orm import Session
from app.models import (
    Project,
    Finding,
    Endpoint,
    Identity,
    Resource,
    ResourceProperty,
    ResourceOwnership,
    Workflow,
    AttackPath,
    AttackPathStep,
    SecurityImpact,
)


class ImpactEngine:
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

    def evaluate_findings_impact(
        self,
        findings: List[Finding],
        is_path: bool = False,
    ) -> Dict[str, Any]:
        """
        Deterministically evaluate concrete security impact dimensions for a collection of findings.
        """
        # Filter confirmed findings only
        confirmed = [f for f in findings if self.is_confirmed(f)]
        if not confirmed:
            return {
                "initial_access": False,
                "authentication_boundary_crossed": False,
                "authorization_boundary_crossed": False,
                "identity_boundary_crossed": False,
                "resource_boundary_crossed": False,
                "workflow_boundary_crossed": False,
                "property_boundary_crossed": False,
                "sensitive_data_reached": False,
                "cross_identity_impact": False,
                "cross_resource_impact": False,
                "terminal_impact": "NONE",
                "explanation": "No confirmed findings available for impact assessment.",
                "identities_involved": [],
                "resources_involved": [],
                "sensitive_properties_reached": [],
                "boundaries_crossed": [],
            }

        # 1. Boundary & Initial Access Checks
        initial_access = any(self.is_auth_finding(f) for f in confirmed)
        auth_crossed = any(self.is_auth_finding(f) for f in confirmed)
        authz_crossed = any(self.is_authz_finding(f) for f in confirmed)
        wf_crossed = any(self.is_workflow_finding(f) for f in confirmed)
        prop_crossed = any(self.is_property_finding(f) for f in confirmed)

        # Resource boundary
        res_crossed = any(
            f.resource_id is not None and (self.is_authz_finding(f) or self.is_workflow_finding(f) or self.is_property_finding(f))
            for f in confirmed
        )

        # 2. Cross-Identity Impact & Identity Boundary
        cross_id = False
        identities_involved_set: Set[str] = set()

        for f in confirmed:
            if f.attacker_identity:
                identities_involved_set.add(f.attacker_identity.name)
            elif f.attacker_identity_id:
                identities_involved_set.add(f"Identity #{f.attacker_identity_id}")

            # Check SecurityTest victim vs attacker
            if f.security_test and f.security_test.victim_identity_id:
                victim_id = f.security_test.victim_identity_id
                if f.security_test.attacker_identity_id and f.security_test.attacker_identity_id != victim_id:
                    cross_id = True
                    victim = self.db.query(Identity).filter(Identity.id == victim_id).first()
                    if victim:
                        identities_involved_set.add(victim.name)
                    else:
                        identities_involved_set.add(f"Identity #{victim_id}")

            # Check ResourceOwnership
            if f.resource_id and f.attacker_identity_id:
                ownerships = self.db.query(ResourceOwnership).filter(ResourceOwnership.resource_id == f.resource_id).all()
                for o in ownerships:
                    if o.identity_id != f.attacker_identity_id:
                        cross_id = True
                        if o.identity:
                            identities_involved_set.add(o.identity.name)

            # Check finding type or description indicators
            ft_upper = (f.type or "").upper()
            if ft_upper in ("IDENTITY_SWITCH", "CROSS_IDENTITY_CONTINUATION", "CROSS_IDENTITY_STATE_ACCESS"):
                cross_id = True

            text = f"{(f.title or '')} {(f.description or '')}".upper()
            if "VICTIM" in text or "CROSS-IDENTITY" in text or "CROSS IDENTITY" in text or "OTHER USER" in text:
                cross_id = True

        # Multiple distinct attacker identities in path
        distinct_attacker_ids = {f.attacker_identity_id for f in confirmed if f.attacker_identity_id}
        if len(distinct_attacker_ids) > 1:
            cross_id = True

        identity_crossed = cross_id

        # 3. Cross-Resource Impact & Resource Collection
        resources_involved_set: Set[str] = set()
        resource_ids_set: Set[str] = set()

        for f in confirmed:
            if f.resource:
                resources_involved_set.add(f.resource.name)
                resource_ids_set.add(f.resource.id)
            elif f.resource_id:
                resources_involved_set.add(f"Resource #{f.resource_id}")
                resource_ids_set.add(f.resource_id)

        cross_res = len(resource_ids_set) > 1

        # 4. Sensitive Data Reached & Property Sensitivity
        is_secret = False
        is_sensitive = False
        sensitive_props_reached_set: Set[str] = set()

        for f in confirmed:
            if not self.is_property_finding(f):
                continue

            exposed_prop_names: List[str] = []
            if f.exposed_properties:
                try:
                    parsed = json.loads(f.exposed_properties)
                    if isinstance(parsed, list):
                        exposed_prop_names.extend(str(item) for item in parsed)
                    elif isinstance(parsed, str):
                        exposed_prop_names.append(parsed)
                except Exception:
                    exposed_prop_names.append(str(f.exposed_properties))

            if f.resource_id:
                props = self.db.query(ResourceProperty).filter(ResourceProperty.resource_id == f.resource_id).all()
                for p in props:
                    p_sens = (p.sensitivity or "").upper()
                    # Check if property was exposed
                    matched = False
                    if exposed_prop_names:
                        if p.name in exposed_prop_names or any(p.name in exp for exp in exposed_prop_names):
                            matched = True
                        elif p_sens in ("SENSITIVE", "SECRET"):
                            matched = True
                    elif p.name in f"{(f.title or '')} {(f.description or '')}":
                        matched = True

                    if matched:
                        if p_sens == "SECRET":
                            is_secret = True
                            sensitive_props_reached_set.add(f"{p.name} (SECRET)")
                        elif p_sens == "SENSITIVE":
                            is_sensitive = True
                            sensitive_props_reached_set.add(f"{p.name} (SENSITIVE)")

            # Check finding text metadata for explicit secret / sensitive indicators
            f_text = f"{(f.type or '')} {(f.title or '')} {(f.description or '')}".upper()
            if "SECRET" in f_text:
                is_secret = True
                if exposed_prop_names:
                    for ep_name in exposed_prop_names:
                        sensitive_props_reached_set.add(f"{ep_name} (SECRET)")
                else:
                    sensitive_props_reached_set.add("Resource Secret (SECRET)")
            elif "SENSITIVE" in f_text:
                is_sensitive = True
                if exposed_prop_names:
                    for ep_name in exposed_prop_names:
                        sensitive_props_reached_set.add(f"{ep_name} (SENSITIVE)")
                else:
                    sensitive_props_reached_set.add("Resource PII (SENSITIVE)")

        sensitive_data_reached = is_secret or is_sensitive

        # 5. Terminal Impact Selection
        terminal_candidates = []
        if prop_crossed and sensitive_data_reached:
            terminal_candidates.append("SENSITIVE_PROPERTY_EXPOSURE")
        if cross_id:
            terminal_candidates.append("CROSS_IDENTITY_ACCESS")
        if wf_crossed:
            terminal_candidates.append("PRIVILEGED_WORKFLOW_ACCESS")

        if len(terminal_candidates) > 1:
            terminal_impact = "MULTI_BOUNDARY_ACCESS"
        elif len(terminal_candidates) == 1:
            terminal_impact = terminal_candidates[0]
        elif res_crossed or authz_crossed:
            terminal_impact = "RESOURCE_ACCESS"
        else:
            terminal_impact = "NONE"

        # 6. Boundaries Crossed List
        boundaries_crossed = []
        if auth_crossed:
            boundaries_crossed.append("AUTHENTICATION")
        if authz_crossed:
            boundaries_crossed.append("AUTHORIZATION")
        if identity_crossed:
            boundaries_crossed.append("IDENTITY")
        if res_crossed:
            boundaries_crossed.append("RESOURCE")
        if wf_crossed:
            boundaries_crossed.append("WORKFLOW")
        if prop_crossed:
            boundaries_crossed.append("PROPERTY")

        # 7. Synthesize Human-Readable Deterministic Explanation
        boundaries_lower = []
        if auth_crossed:
            boundaries_lower.append("authentication")
        if authz_crossed:
            boundaries_lower.append("authorization")
        if identity_crossed:
            boundaries_lower.append("identity")
        if res_crossed:
            boundaries_lower.append("resource")
        if wf_crossed:
            boundaries_lower.append("workflow")
        if prop_crossed:
            boundaries_lower.append("property")

        if not boundaries_lower:
            b_str = "no security boundaries"
        elif len(boundaries_lower) == 1:
            b_str = f"{boundaries_lower[0]} boundary"
        elif len(boundaries_lower) == 2:
            b_str = f"{boundaries_lower[0]} and {boundaries_lower[1]} boundaries"
        else:
            b_str = f"{', '.join(boundaries_lower[:-1])}, and {boundaries_lower[-1]} boundaries"

        prefix = "Confirmed attack path crosses " if is_path else "Confirmed finding crosses "
        explanation = f"{prefix}{b_str}"

        if sensitive_data_reached:
            sens_tag = "SECRET" if is_secret else "SENSITIVE"
            explanation += f" and reaches a {sens_tag} property"

        if cross_id:
            explanation += ", compromising cross-identity boundaries"

        if cross_res:
            explanation += ", traversing multiple resources"

        explanation += f". Resulting in terminal impact: {terminal_impact}."

        return {
            "initial_access": initial_access,
            "authentication_boundary_crossed": auth_crossed,
            "authorization_boundary_crossed": authz_crossed,
            "identity_boundary_crossed": identity_crossed,
            "resource_boundary_crossed": res_crossed,
            "workflow_boundary_crossed": wf_crossed,
            "property_boundary_crossed": prop_crossed,
            "sensitive_data_reached": sensitive_data_reached,
            "cross_identity_impact": cross_id,
            "cross_resource_impact": cross_res,
            "terminal_impact": terminal_impact,
            "explanation": explanation,
            "identities_involved": sorted(identities_involved_set),
            "resources_involved": sorted(resources_involved_set),
            "sensitive_properties_reached": sorted(sensitive_props_reached_set),
            "boundaries_crossed": boundaries_crossed,
        }

    def evaluate_path_impact(self, path: AttackPath) -> Dict[str, Any]:
        """Evaluate security impact for an AttackPath."""
        steps = sorted(path.steps, key=lambda s: s.position)
        findings = [s.finding for s in steps if s.finding]
        return self.evaluate_findings_impact(findings, is_path=True)

    def evaluate_finding_impact(self, finding: Finding) -> Dict[str, Any]:
        """Evaluate security impact for a standalone Finding."""
        return self.evaluate_findings_impact([finding], is_path=False)

    def run_impact_analysis(self, project_id: int) -> Dict[str, Any]:
        """
        Execute deterministic security impact analysis for a project.
        Completely offline - never executes target APIs.
        """
        project = self.db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise ValueError(f"Project with ID {project_id} not found")

        # 1. Fetch confirmed findings for this project
        all_findings = self.db.query(Finding).filter(Finding.project_id == project_id).all()
        confirmed_findings = [f for f in all_findings if self.is_confirmed(f)]
        confirmed_finding_ids = {f.id for f in confirmed_findings}

        # 2. Fetch active AttackPaths for this project
        active_paths = (
            self.db.query(AttackPath)
            .filter(AttackPath.project_id == project_id, AttackPath.status == "ACTIVE")
            .order_by(AttackPath.created_at.desc())
            .all()
        )

        # 3. Clean previous SecurityImpact records for idempotency
        self.db.query(SecurityImpact).filter(SecurityImpact.project_id == project_id).delete()
        self.db.flush()

        persisted_impacts: List[SecurityImpact] = []
        path_covered_finding_ids: Set[str] = set()

        # 4. Generate impact for each active AttackPath
        for path in active_paths:
            eval_res = self.evaluate_path_impact(path)
            # Find terminal finding in path
            terminal_finding_id = path.steps[-1].finding_id if path.steps else None

            # Mark findings as covered
            for step in path.steps:
                path_covered_finding_ids.add(step.finding_id)

            impact = SecurityImpact(
                project_id=project_id,
                attack_path_id=path.id,
                finding_id=terminal_finding_id,
                initial_access=eval_res["initial_access"],
                authentication_boundary_crossed=eval_res["authentication_boundary_crossed"],
                authorization_boundary_crossed=eval_res["authorization_boundary_crossed"],
                identity_boundary_crossed=eval_res["identity_boundary_crossed"],
                resource_boundary_crossed=eval_res["resource_boundary_crossed"],
                workflow_boundary_crossed=eval_res["workflow_boundary_crossed"],
                property_boundary_crossed=eval_res["property_boundary_crossed"],
                sensitive_data_reached=eval_res["sensitive_data_reached"],
                cross_identity_impact=eval_res["cross_identity_impact"],
                cross_resource_impact=eval_res["cross_resource_impact"],
                terminal_impact=eval_res["terminal_impact"],
                explanation=eval_res["explanation"],
            )
            self.db.add(impact)
            self.db.flush()
            persisted_impacts.append(impact)

        # 5. Generate impact for standalone confirmed findings not covered in attack paths
        standalone_findings = [f for f in confirmed_findings if f.id not in path_covered_finding_ids]
        for f in standalone_findings:
            eval_res = self.evaluate_finding_impact(f)
            impact = SecurityImpact(
                project_id=project_id,
                attack_path_id=None,
                finding_id=f.id,
                initial_access=eval_res["initial_access"],
                authentication_boundary_crossed=eval_res["authentication_boundary_crossed"],
                authorization_boundary_crossed=eval_res["authorization_boundary_crossed"],
                identity_boundary_crossed=eval_res["identity_boundary_crossed"],
                resource_boundary_crossed=eval_res["resource_boundary_crossed"],
                workflow_boundary_crossed=eval_res["workflow_boundary_crossed"],
                property_boundary_crossed=eval_res["property_boundary_crossed"],
                sensitive_data_reached=eval_res["sensitive_data_reached"],
                cross_identity_impact=eval_res["cross_identity_impact"],
                cross_resource_impact=eval_res["cross_resource_impact"],
                terminal_impact=eval_res["terminal_impact"],
                explanation=eval_res["explanation"],
            )
            self.db.add(impact)
            self.db.flush()
            persisted_impacts.append(impact)

        self.db.commit()

        for imp in persisted_impacts:
            self.db.refresh(imp)

        return {
            "project_id": project_id,
            "impacts_count": len(persisted_impacts),
            "impacts": persisted_impacts,
        }

    def rebuild_security_impact(self, impact_id: str) -> SecurityImpact:
        """
        Rebuild and re-verify an existing SecurityImpact record completely offline.
        """
        impact = self.db.query(SecurityImpact).filter(SecurityImpact.id == impact_id).first()
        if not impact:
            raise ValueError(f"SecurityImpact with ID {impact_id} not found")

        if impact.attack_path_id:
            path = self.db.query(AttackPath).filter(AttackPath.id == impact.attack_path_id).first()
            if not path or path.status != "ACTIVE":
                impact.terminal_impact = "NONE"
                impact.explanation = "Associated attack path is no longer active."
                impact.initial_access = False
                impact.authentication_boundary_crossed = False
                impact.authorization_boundary_crossed = False
                impact.identity_boundary_crossed = False
                impact.resource_boundary_crossed = False
                impact.workflow_boundary_crossed = False
                impact.property_boundary_crossed = False
                impact.sensitive_data_reached = False
                impact.cross_identity_impact = False
                impact.cross_resource_impact = False
            else:
                eval_res = self.evaluate_path_impact(path)
                for key in (
                    "initial_access",
                    "authentication_boundary_crossed",
                    "authorization_boundary_crossed",
                    "identity_boundary_crossed",
                    "resource_boundary_crossed",
                    "workflow_boundary_crossed",
                    "property_boundary_crossed",
                    "sensitive_data_reached",
                    "cross_identity_impact",
                    "cross_resource_impact",
                    "terminal_impact",
                    "explanation",
                ):
                    setattr(impact, key, eval_res[key])
        elif impact.finding_id:
            finding = self.db.query(Finding).filter(Finding.id == impact.finding_id).first()
            if not finding or not self.is_confirmed(finding):
                impact.terminal_impact = "NONE"
                impact.explanation = "Associated finding is no longer confirmed."
                impact.initial_access = False
                impact.authentication_boundary_crossed = False
                impact.authorization_boundary_crossed = False
                impact.identity_boundary_crossed = False
                impact.resource_boundary_crossed = False
                impact.workflow_boundary_crossed = False
                impact.property_boundary_crossed = False
                impact.sensitive_data_reached = False
                impact.cross_identity_impact = False
                impact.cross_resource_impact = False
            else:
                eval_res = self.evaluate_finding_impact(finding)
                for key in (
                    "initial_access",
                    "authentication_boundary_crossed",
                    "authorization_boundary_crossed",
                    "identity_boundary_crossed",
                    "resource_boundary_crossed",
                    "workflow_boundary_crossed",
                    "property_boundary_crossed",
                    "sensitive_data_reached",
                    "cross_identity_impact",
                    "cross_resource_impact",
                    "terminal_impact",
                    "explanation",
                ):
                    setattr(impact, key, eval_res[key])

        impact.updated_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(impact)
        return impact
