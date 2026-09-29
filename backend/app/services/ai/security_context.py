"""
Stage 9.1: AI Security Context Builder
Author: SentinelAPI Security Architecture Team

Converts deterministic SentinelAPI data into a strictly bounded, sanitized,
structured context for AI security reasoning.

SAFETY & PRIVACY CONSTRAINTS:
- Explicit allowlists for all fields.
- Strict exclusion of raw credentials, tokens, cookies, passwords, and secret values.
- Prompt injection defense via structured escaping and explicit delimiter tags.
- Strict payload truncation and context size caps.
- Strict distinction between verified facts and deterministic interpretations.
"""

from typing import Dict, Any, Optional, List
import json
from sqlalchemy.orm import Session
from app.models import (
    Project,
    Finding,
    Evidence,
    Endpoint,
    Identity,
    Role,
    Resource,
    ResourceProperty,
    Workflow,
    AttackPath,
    SecurityImpact,
)

# Maximum string length for untrusted target content (prevents context bloat and prompt overflow)
MAX_UNTRUSTED_CONTENT_LENGTH = 1000


def sanitize_untrusted_text(content: Optional[str], source_label: str) -> str:
    """
    Wrap untrusted target-controlled content with explicit delimiters and truncate.
    Prevents prompt injection attacks originating from target response bodies,
    headers, OpenAPI specifications, or resource metadata.
    """
    if not content:
        return ""
    text = str(content)
    # Neutralize closing delimiter tag if present in target text
    text = text.replace("</untrusted_target_content>", "[ESCAPED_DELIMITER]")
    if len(text) > MAX_UNTRUSTED_CONTENT_LENGTH:
        text = text[:MAX_UNTRUSTED_CONTENT_LENGTH] + "... [TRUNCATED_FOR_SECURITY]"
    return f'<untrusted_target_content source="{source_label}">\n{text}\n</untrusted_target_content>'


class SecurityContextBuilder:
    """
    Constructs sanitized, bounded security contexts for AI reasoning tasks.
    Enforces strict zero-credential persistence and explicit allowlisting.
    """

    def __init__(self, db: Session):
        self.db = db

    def is_confirmed(self, finding: Optional[Finding]) -> bool:
        """Only analyze confirmed findings. Exclude inconclusive, error, or passing findings."""
        if not finding:
            return False
        if finding.status in ("INCONCLUSIVE", "ERROR", "FALSE_POSITIVE"):
            return False
        if finding.execution and finding.execution.result in ("INCONCLUSIVE", "ERROR", "PASS"):
            return False
        if finding.workflow_execution and finding.workflow_execution.result in ("INCONCLUSIVE", "ERROR", "PASS"):
            return False
        return True

    def build_project_summary(self, project: Project) -> Dict[str, Any]:
        """Allowlisted, sanitized project summary (strictly non-sensitive)."""
        return {
            "id": project.id,
            "name": project.name,
            "environment": project.environment,
            "authorization_status": project.authorization_status,
        }

    def build_evidence_summary(self, evidence: Optional[Evidence]) -> Dict[str, Any]:
        """
        Allowlisted, sanitized evidence summary.
        Excludes all authorization tokens, cookies, session IDs, and raw secret values.
        """
        if not evidence:
            return {
                "evidence_present": False,
            }

        http_status = getattr(evidence, "http_status", None)
        response_time_ms = getattr(evidence, "response_time_ms", None)
        raw_headers = {}
        body = getattr(evidence, "redacted_response", None) or getattr(evidence, "response_body", None) or ""

        if evidence.response_metadata:
            try:
                meta = json.loads(evidence.response_metadata) if isinstance(evidence.response_metadata, str) else evidence.response_metadata
                if isinstance(meta, dict):
                    if http_status is None:
                        http_status = meta.get("status_code")
                    if response_time_ms is None:
                        response_time_ms = meta.get("duration_ms")
                    raw_headers = meta.get("headers", {})
            except Exception:
                pass

        if not raw_headers and hasattr(evidence, "response_headers") and getattr(evidence, "response_headers"):
            try:
                raw_headers = json.loads(evidence.response_headers) if isinstance(evidence.response_headers, str) else evidence.response_headers
            except Exception:
                pass

        # Sanitize headers: allow only harmless structural header names, never values of sensitive headers
        sanitized_headers = {}
        if isinstance(raw_headers, dict):
            for k, v in raw_headers.items():
                k_lower = str(k).lower()
                if any(s in k_lower for s in ("auth", "cookie", "token", "key", "secret", "session", "jwt", "bearer", "credential")):
                    sanitized_headers[k] = "[REDACTED_BY_POLICY]"
                else:
                    sanitized_headers[k] = str(v)[:100]

        return {
            "evidence_present": True,
            "id": evidence.id,
            "http_status": http_status,
            "response_time_ms": response_time_ms,
            "sanitized_response_headers": sanitized_headers,
            "untrusted_response_body_sample": sanitize_untrusted_text(body, "target_http_response"),
        }

    def build_finding_context(self, finding: Finding) -> Dict[str, Any]:
        """
        Build bounded context for a single confirmed Finding.
        Raises ValueError if finding is not confirmed.
        """
        if not self.is_confirmed(finding):
            raise ValueError(f"Finding {finding.id} is not confirmed (status: {finding.status}). AI analysis strictly requires confirmed findings.")

        project = self.db.query(Project).filter(Project.id == finding.project_id).first()
        if not project:
            raise ValueError(f"Project for finding {finding.id} not found.")

        # Allowlisted endpoint metadata
        endpoint_data = None
        if finding.endpoint:
            endpoint_data = {
                "id": finding.endpoint.id,
                "method": finding.endpoint.method,
                "path": finding.endpoint.path,
                "summary": finding.endpoint.summary,
            }

        # Allowlisted identity metadata (strictly exclude credentials, passwords, tokens)
        identity_data = None
        if finding.attacker_identity:
            identity_data = {
                "id": finding.attacker_identity.id,
                "name": finding.attacker_identity.name,
                "auth_type": finding.attacker_identity.auth_type,
                "environment": finding.attacker_identity.environment,
                "credential_configured": bool(finding.attacker_identity.credential_value or finding.attacker_identity.credential_reference),
                # Note: credential_value, credential_reference, passwords, and tokens are STRICTLY OMITTED
            }

        # Allowlisted resource metadata
        resource_data = None
        if finding.resource:
            resource_data = {
                "id": finding.resource.id,
                "name": finding.resource.name,
                "resource_type": finding.resource.resource_type,
            }

        # Allowlisted property metadata (names and sensitivity categories only, NO raw property values)
        exposed_properties_info = []
        if finding.resource_id:
            props = self.db.query(ResourceProperty).filter(ResourceProperty.resource_id == finding.resource_id).all()
            for p in props:
                exposed_properties_info.append({
                    "name": p.name,
                    "data_type": p.data_type,
                    "sensitivity": p.sensitivity,  # PUBLIC, INTERNAL, SENSITIVE, SECRET
                })

        # Evidence summary
        evidence_summary = self.build_evidence_summary(finding.evidence)

        # Check if finding is part of any deterministic SecurityImpact
        impact = self.db.query(SecurityImpact).filter(SecurityImpact.finding_id == finding.id).first()
        deterministic_impact = None
        if impact:
            deterministic_impact = {
                "id": impact.id,
                "initial_access": impact.initial_access,
                "terminal_impact": impact.terminal_impact,
                "boundaries_crossed": [
                    b for b, flag in [
                        ("AUTHENTICATION", impact.authentication_boundary_crossed),
                        ("AUTHORIZATION", impact.authorization_boundary_crossed),
                        ("IDENTITY", impact.identity_boundary_crossed),
                        ("RESOURCE", impact.resource_boundary_crossed),
                        ("WORKFLOW", impact.workflow_boundary_crossed),
                        ("PROPERTY", impact.property_boundary_crossed),
                    ] if flag
                ],
                "sensitive_data_reached": impact.sensitive_data_reached,
                "cross_identity_impact": impact.cross_identity_impact,
                "cross_resource_impact": impact.cross_resource_impact,
                "deterministic_explanation": impact.explanation,
            }

        return {
            "context_type": "FINDING_ANALYSIS",
            "project": self.build_project_summary(project),
            "verified_facts": {
                "finding": {
                    "id": finding.id,
                    "type": finding.type,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "status": finding.status,
                    "title": finding.title,
                    "description": finding.description,
                    "remediation_guidance": finding.remediation,
                    "actual_behavior": sanitize_untrusted_text(finding.actual_behavior, "finding_actual_behavior"),
                    "expected_authorization": finding.expected_authorization,
                },
                "endpoint": endpoint_data,
                "attacker_identity": identity_data,
                "resource": resource_data,
                "resource_properties_schema": exposed_properties_info,
                "evidence": evidence_summary,
            },
            "deterministic_interpretations": {
                "security_impact": deterministic_impact,
            },
        }

    def build_attack_path_context(self, path: AttackPath) -> Dict[str, Any]:
        """
        Build bounded context for an active deterministic AttackPath.
        Includes ordered steps, finding summaries, and associated security impact.
        """
        project = self.db.query(Project).filter(Project.id == path.project_id).first()
        if not project:
            raise ValueError(f"Project for attack path {path.id} not found.")

        steps_data = []
        ordered_steps = sorted(path.steps, key=lambda s: s.position)
        for s in ordered_steps:
            finding = s.finding
            steps_data.append({
                "position": s.position,
                "relationship_type": s.relationship_type,
                "reason": s.reason,
                "finding": {
                    "id": finding.id if finding else s.finding_id,
                    "title": finding.title if finding else "Unknown",
                    "type": finding.type if finding else "Unknown",
                    "severity": finding.severity if finding else "Unknown",
                    "endpoint_path": finding.endpoint.path if (finding and finding.endpoint) else None,
                    "resource_name": finding.resource.name if (finding and finding.resource) else None,
                    "identity_name": finding.attacker_identity.name if (finding and finding.attacker_identity) else None,
                },
            })

        # Associated Security Impact
        impact = self.db.query(SecurityImpact).filter(SecurityImpact.attack_path_id == path.id).first()
        impact_data = None
        if impact:
            impact_data = {
                "id": impact.id,
                "terminal_impact": impact.terminal_impact,
                "initial_access": impact.initial_access,
                "boundaries_crossed": [
                    b for b, flag in [
                        ("AUTHENTICATION", impact.authentication_boundary_crossed),
                        ("AUTHORIZATION", impact.authorization_boundary_crossed),
                        ("IDENTITY", impact.identity_boundary_crossed),
                        ("RESOURCE", impact.resource_boundary_crossed),
                        ("WORKFLOW", impact.workflow_boundary_crossed),
                        ("PROPERTY", impact.property_boundary_crossed),
                    ] if flag
                ],
                "sensitive_data_reached": impact.sensitive_data_reached,
                "cross_identity_impact": impact.cross_identity_impact,
                "cross_resource_impact": impact.cross_resource_impact,
                "deterministic_explanation": impact.explanation,
            }

        return {
            "context_type": "ATTACK_PATH_ANALYSIS",
            "project": self.build_project_summary(project),
            "verified_facts": {
                "attack_path": {
                    "id": path.id,
                    "name": path.name,
                    "description": path.description,
                    "status": path.status,
                    "confidence": path.confidence,
                    "step_count": len(steps_data),
                },
                "ordered_steps": steps_data,
            },
            "deterministic_interpretations": {
                "security_impact": impact_data,
            },
        }

    def build_impact_context(self, impact: SecurityImpact) -> Dict[str, Any]:
        """
        Build bounded context for a SecurityImpact record.
        Includes boundary crossing data, terminal impact, and underlying finding/path.
        """
        project = self.db.query(Project).filter(Project.id == impact.project_id).first()
        if not project:
            raise ValueError(f"Project for impact {impact.id} not found.")

        underlying_path = None
        if impact.attack_path:
            underlying_path = {
                "id": impact.attack_path.id,
                "name": impact.attack_path.name,
                "confidence": impact.attack_path.confidence,
                "step_count": len(impact.attack_path.steps),
            }

        underlying_finding = None
        if impact.finding:
            underlying_finding = {
                "id": impact.finding.id,
                "title": impact.finding.title,
                "type": impact.finding.type,
                "severity": impact.finding.severity,
            }

        boundaries = []
        if impact.authentication_boundary_crossed:
            boundaries.append("AUTHENTICATION")
        if impact.authorization_boundary_crossed:
            boundaries.append("AUTHORIZATION")
        if impact.identity_boundary_crossed:
            boundaries.append("IDENTITY")
        if impact.resource_boundary_crossed:
            boundaries.append("RESOURCE")
        if impact.workflow_boundary_crossed:
            boundaries.append("WORKFLOW")
        if impact.property_boundary_crossed:
            boundaries.append("PROPERTY")

        return {
            "context_type": "IMPACT_ANALYSIS",
            "project": self.build_project_summary(project),
            "verified_facts": {
                "boundaries_crossed": boundaries,
                "initial_access": impact.initial_access,
                "sensitive_data_reached": impact.sensitive_data_reached,
                "cross_identity_impact": impact.cross_identity_impact,
                "cross_resource_impact": impact.cross_resource_impact,
                "underlying_finding": underlying_finding,
                "underlying_attack_path": underlying_path,
            },
            "deterministic_interpretations": {
                "security_impact": {
                    "id": impact.id,
                    "terminal_impact": impact.terminal_impact,
                    "explanation": impact.explanation,
                },
            },
        }
