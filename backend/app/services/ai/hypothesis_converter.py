"""
Stage 9.2: Hypothesis to SecurityTest Converter
Author: SentinelAPI Security Architecture Team

Converts human-approved AI security hypotheses into deterministic SecurityTest configurations.
IMPORTANT:
- Strictly NON-EXECUTABLE. This component does not make any target API requests.
- Converts approved hypothesis metadata into allowlisted SecurityTest configuration fields.
- Transitions hypothesis status from APPROVED to CONVERTED.
- The resulting SecurityTest must be executed separately via the existing security testing engine.
"""

import json
from typing import Tuple, Optional, Dict, Any
from sqlalchemy.orm import Session

from app.models import (
    AIHypothesis,
    SecurityTest,
    Project,
    Endpoint,
    Identity,
    Resource,
)


class HypothesisConversionError(ValueError):
    """Raised when an unapproved hypothesis or invalid entity configuration cannot be converted."""
    pass


class HypothesisConverter:
    """Converts approved AI hypotheses into deterministic SecurityTest records."""

    def __init__(self, db: Session):
        self.db = db

    def convert_hypothesis(
        self,
        hypothesis_id: str,
        reviewer_reference: Optional[str] = None,
    ) -> Tuple[AIHypothesis, SecurityTest]:
        """
        Convert an approved AI hypothesis into an existing SecurityTest record.
        Enforces:
        - Hypothesis status must be strictly 'APPROVED'.
        - Unapproved, pending, or rejected hypotheses CANNOT be converted.
        - Only allowlisted SecurityTest fields are populated.
        - ZERO target API HTTP requests are made.
        """
        hypothesis = self.db.query(AIHypothesis).filter(AIHypothesis.id == hypothesis_id).first()
        if not hypothesis:
            raise HypothesisConversionError(f"AI hypothesis '{hypothesis_id}' not found.")

        if hypothesis.status != "APPROVED":
            raise HypothesisConversionError(
                f"Cannot convert hypothesis in '{hypothesis.status}' status. "
                f"Only 'APPROVED' hypotheses can be converted into security tests."
            )

        project = self.db.query(Project).filter(Project.id == hypothesis.project_id).first()
        if not project or project.authorization_status != "authorized":
            raise HypothesisConversionError(f"Project {hypothesis.project_id} is not authorized for testing.")

        req_context: Dict[str, Any] = hypothesis.required_context if isinstance(hypothesis.required_context, dict) else {}

        # 1. Resolve Endpoint
        endpoint_id = req_context.get("endpoint_id")
        if not endpoint_id and hypothesis.finding and hypothesis.finding.endpoint_id:
            endpoint_id = hypothesis.finding.endpoint_id
        if not endpoint_id and hypothesis.attack_path and hypothesis.attack_path.steps:
            for s in hypothesis.attack_path.steps:
                if s.finding and s.finding.endpoint_id:
                    endpoint_id = s.finding.endpoint_id
                    break

        if not endpoint_id:
            # Fall back to first available endpoint in project
            ep = self.db.query(Endpoint).join(Endpoint.api).filter(Endpoint.api.has(project_id=project.id)).first()
            if ep:
                endpoint_id = ep.id
            else:
                raise HypothesisConversionError(f"Cannot convert hypothesis: no endpoints configured for project {project.id}.")

        # 2. Resolve Attacker Identity
        attacker_identity_id = req_context.get("attacker_identity_id") or req_context.get("identity_id")
        if not attacker_identity_id and hypothesis.finding and hypothesis.finding.attacker_identity_id:
            attacker_identity_id = hypothesis.finding.attacker_identity_id
        if not attacker_identity_id:
            first_ident = self.db.query(Identity).filter(Identity.project_id == project.id).first()
            if first_ident:
                attacker_identity_id = first_ident.id

        # 3. Resolve Victim Identity (for BOLA / multi-tenant isolation)
        victim_identity_id = req_context.get("victim_identity_id")
        if not victim_identity_id and attacker_identity_id:
            # Pick an alternate identity in the same project
            alt_ident = self.db.query(Identity).filter(
                Identity.project_id == project.id,
                Identity.id != attacker_identity_id
            ).first()
            if alt_ident:
                victim_identity_id = alt_ident.id

        # 4. Resolve Resource
        victim_resource_id = req_context.get("victim_resource_id") or req_context.get("resource_id")
        if not victim_resource_id and hypothesis.finding and hypothesis.finding.resource_id:
            victim_resource_id = hypothesis.finding.resource_id
        if not victim_resource_id:
            first_res = self.db.query(Resource).filter(Resource.project_id == project.id).first()
            if first_res:
                victim_resource_id = first_res.id

        # 5. Build Allowlisted SecurityTest
        config_payload = {
            "converted_from_ai_hypothesis": True,
            "hypothesis_id": hypothesis.id,
            "hypothesis_text": hypothesis.hypothesis,
            "hypothesis_reason": hypothesis.reason,
            "confidence": hypothesis.confidence,
            "suggested_test_type": hypothesis.suggested_test_type,
            "converted_by": reviewer_reference or hypothesis.reviewed_by or "system",
        }

        security_test = SecurityTest(
            project_id=project.id,
            endpoint_id=endpoint_id,
            test_type=hypothesis.suggested_test_type,
            attacker_identity_id=attacker_identity_id,
            victim_identity_id=victim_identity_id,
            victim_resource_id=victim_resource_id,
            victim_resource_instance_id=req_context.get("victim_resource_instance_id", "test_victim_inst_1"),
            attacker_resource_instance_id=req_context.get("attacker_resource_instance_id", "test_attacker_inst_1"),
            expected_access="DENY",
            status="configured",
            configuration=json.dumps(config_payload),
        )
        self.db.add(security_test)
        self.db.commit()
        self.db.refresh(security_test)

        # 6. Update Hypothesis status to CONVERTED
        hypothesis.status = "CONVERTED"
        hypothesis.security_test_id = security_test.id
        self.db.commit()
        self.db.refresh(hypothesis)

        return hypothesis, security_test
