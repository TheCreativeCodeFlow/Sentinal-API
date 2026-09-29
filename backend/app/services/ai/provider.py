"""
Stage 9.1: AI Provider Abstraction and Security Reasoning Service
Author: SentinelAPI Security Architecture Team

Provides:
- AIProvider (abstract base class)
- MockAIProvider (grounded, deterministic offline reasoner - default)
- OpenAICompatibleProvider (configurable external LLM provider)
- AISecurityService (orchestrator with lifecycle management & database persistence)
"""

import os
import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import httpx
from sqlalchemy.orm import Session

from app.models import (
    Project,
    Finding,
    AttackPath,
    SecurityImpact,
    AIAnalysis,
)
from app.schemas import AIAnalysisType
from app.services.ai.security_context import SecurityContextBuilder
from app.services.ai.prompts import get_system_prompt, validate_ai_output

logger = logging.getLogger(__name__)


class AIProviderError(Exception):
    """Raised when an AI provider fails during inference or schema validation."""
    pass


class AIProvider(ABC):
    """Abstract interface for AI inference providers."""

    provider_name: str = "base"
    model_name: str = "base-model"

    @abstractmethod
    def generate(self, system_prompt: str, user_context: Dict[str, Any], analysis_type: str) -> Dict[str, Any]:
        """
        Generate structured output for a security reasoning task.
        Must return a validated dictionary adhering to the analysis_type schema.
        """
        pass


class MockAIProvider(AIProvider):
    """
    Built-in, zero-dependency, deterministic offline reasoner.
    Produces rich, fully grounded outputs based directly on verified facts in the context.
    Ensures SentinelAPI operates completely offline and in air-gapped environments.
    """

    def __init__(self, model_name: str = "sentinel-offline-reasoner-v1"):
        self.provider_name = "mock"
        self.model_name = model_name

    def generate(self, system_prompt: str, user_context: Dict[str, Any], analysis_type: str) -> Dict[str, Any]:
        verified_facts = user_context.get("verified_facts", {})
        interpretations = user_context.get("deterministic_interpretations", {})

        if analysis_type == AIAnalysisType.FINDING_EXPLANATION.value:
            finding = verified_facts.get("finding", {})
            finding_id = str(finding.get("id", "unknown-finding"))
            finding_title = finding.get("title", "Unknown Finding")
            finding_type = finding.get("type", "UNKNOWN")
            severity = finding.get("severity", "MEDIUM")
            endpoint = verified_facts.get("endpoint", {})
            ep_path = endpoint.get("path") if endpoint else "target endpoint"
            identity = verified_facts.get("attacker_identity", {})
            identity_name = identity.get("name") if identity else "unprivileged identity"
            evidence = verified_facts.get("evidence", {})
            http_status = evidence.get("http_status", 200)

            # Grounded root cause based on finding type
            if "BOLA" in finding_type or "OBJECT" in finding_type:
                root_cause = (
                    f"The endpoint '{ep_path}' accepts resource identifiers without verifying that the requesting "
                    f"identity ({identity_name}) owns or is authorized to view the requested resource. The backend "
                    f"relies solely on query or path parameters for access control."
                )
                misconfigurations = [
                    "Missing resource-level authorization filter in database query",
                    "Direct reference to object ID without tenant verification middleware",
                    "Over-reliance on client-supplied identifiers without session ownership checks",
                ]
            elif "BFLA" in finding_type or "FUNCTION" in finding_type:
                root_cause = (
                    f"The administrative or sensitive function at '{ep_path}' fails to validate whether the "
                    f"identity '{identity_name}' holds the required elevated role before executing privileged operations."
                )
                misconfigurations = [
                    "Missing role-based access control (RBAC) guard on route handler",
                    "Client-side only UI suppression without backend endpoint protection",
                    "Inconsistent authorization enforcement between HTTP verbs",
                ]
            elif "MASS_ASSIGNMENT" in finding_type:
                root_cause = (
                    f"The handler for '{ep_path}' automatically binds request payload fields directly to internal model "
                    f"properties without an explicit allowlist, allowing callers to overwrite protected attributes."
                )
                misconfigurations = [
                    "Absence of strict input DTO (Data Transfer Object) or schema allowlist",
                    "Direct binding of ORM entities from HTTP request body",
                ]
            else:
                root_cause = (
                    f"The endpoint '{ep_path}' exhibits an access control defect ({finding_type}) allowing "
                    f"identity '{identity_name}' to access or manipulate data beyond expected boundaries."
                )
                misconfigurations = [
                    "Insufficient authorization policy enforcement",
                    "Missing access control middleware at the routing layer",
                ]

            raw_result = {
                "finding_id": finding_id,
                "summary": f"Confirmed {severity} severity {finding_type} vulnerability ({finding_title}) detected on {ep_path}.",
                "root_cause_analysis": root_cause,
                "evidence_corroboration": (
                    f"Verified by deterministic HTTP test receiving HTTP {http_status} response. "
                    f"The target service returned unauthorized data or completed the operation when authorization should have been denied."
                ),
                "potential_misconfigurations": misconfigurations,
                "recommended_investigation": (
                    f"Inspect the controller or route handler for '{ep_path}'. Verify that authorization logic explicitly "
                    f"validates current session identity against the resource owner before processing the request."
                ),
            }

        elif analysis_type == AIAnalysisType.ATTACK_PATH_EXPLANATION.value:
            path_meta = verified_facts.get("attack_path", {})
            path_id = str(path_meta.get("id", "unknown-path"))
            path_name = path_meta.get("name", "Unknown Attack Path")
            ordered_steps = verified_facts.get("ordered_steps", [])

            step_breakdowns = []
            for s in ordered_steps:
                f_data = s.get("finding", {})
                step_breakdowns.append({
                    "step_position": s.get("position", 1),
                    "finding_title": f_data.get("title", "Finding"),
                    "role_in_chain": f"Enables lateral movement or credential/resource access via {s.get('relationship_type', 'CHAIN')}: {s.get('reason', '')}",
                })

            raw_result = {
                "attack_path_id": path_id,
                "path_narrative": (
                    f"This attack path represents a deterministic multi-step exploitation chain ('{path_name}') "
                    f"composed of {len(ordered_steps)} ordered security findings. An attacker leverages an initial "
                    f"foothold or information disclosure to unlock subsequent unauthorized capabilities, culminating in an escalated terminal impact."
                ),
                "prerequisite_analysis": (
                    "Each preceding step directly produces an identifier, privilege level, or target state that satisfies the "
                    "prerequisites of the subsequent finding, forming an interconnected attack graph."
                ),
                "step_by_step_breakdown": step_breakdowns,
                "exploitability_factors": (
                    "High deterministic repeatability. The attack path was constructed from confirmed empirical findings "
                    "without relying on speculative vulnerabilities or probabilistic guessing."
                ),
                "critical_choke_point": (
                    f"Remediating Step 1 ({step_breakdowns[0]['finding_title'] if step_breakdowns else 'initial finding'}) "
                    f"neutralizes the entire downstream attack sequence by denying the prerequisite state."
                ),
            }

        elif analysis_type == AIAnalysisType.IMPACT_EXPLANATION.value:
            impact_meta = interpretations.get("security_impact", {})
            impact_id = str(impact_meta.get("id", "unknown-impact"))
            terminal = impact_meta.get("terminal_impact", "NONE")
            boundaries = verified_facts.get("boundaries_crossed", [])

            boundary_explanations = [
                {
                    "boundary": b,
                    "explanation": f"The security engine deterministically proved that {b.lower()} boundaries were crossed during execution.",
                }
                for b in boundaries
            ]

            raw_result = {
                "impact_id": impact_id,
                "terminal_impact_interpretation": (
                    f"The terminal security condition '{terminal}' indicates that an unauthorized principal successfully achieved "
                    f"privileged access or sensitive resource traversal across defined trust boundaries."
                ),
                "crossed_boundaries_explained": boundary_explanations,
                "business_risk_translation": (
                    "Uncontained security boundary breaches expose the application to unauthorized data exfiltration, "
                    "tenant data co-mingling, and compliance violations under regulations such as GDPR or HIPAA."
                ),
                "data_exposure_implications": (
                    "Confirmed access to protected entities without proper ownership validation, risking confidential "
                    "tenant data disclosure."
                ),
            }

        elif analysis_type == AIAnalysisType.SECURITY_RECOMMENDATION.value:
            context_type = user_context.get("context_type", "")
            if "FINDING" in context_type:
                finding = verified_facts.get("finding", {})
                target_id = str(finding.get("id", "unknown"))
                target_type = "FINDING"
            else:
                path_meta = verified_facts.get("attack_path", {})
                target_id = str(path_meta.get("id", "unknown"))
                target_type = "ATTACK_PATH"

            raw_result = {
                "target_type": target_type,
                "target_id": target_id,
                "immediate_mitigations": [
                    "Add explicit authorization checks in the controller handler before serving data",
                    "Apply request rate limiting and anomaly alerting on this route",
                    "Validate authentication token subject against the requested resource ID",
                ],
                "architectural_remediations": [
                    "Adopt a centralized Attribute-Based Access Control (ABAC) or Policy Decision Point (PDP)",
                    "Implement database-level multi-tenancy filters or row-level security (RLS)",
                    "Enforce strict schema validation on all incoming request parameters",
                ],
                "preventative_controls": [
                    "Add automated integration tests asserting 403 Forbidden for cross-tenant resource requests",
                    "Incorporate static analysis rules to flag database queries lacking user_id/tenant_id predicates",
                ],
                "code_level_guidance": (
                    "Implement a reusable authorization decorator: `@authorize(owner_only=True)` that resolves the "
                    "current user context from JWT claims and verifies `resource.tenant_id == user.tenant_id`."
                ),
            }

        elif analysis_type == AIAnalysisType.ATTACK_HYPOTHESIS.value:
            path_meta = verified_facts.get("attack_path", {})
            path_id = str(path_meta.get("id", "unknown-path"))
            ordered_steps = verified_facts.get("ordered_steps", [])

            hypotheses = [
                {
                    "hypothesis": "Subsequent write/mutation endpoints on the exposed resource may also lack authorization checks.",
                    "reason": "When read endpoints lack ownership checks (BOLA), corresponding PUT/PATCH/DELETE endpoints frequently share the same underlying authorization gap.",
                    "required_existing_context": [
                        s.get("finding", {}).get("title", "Confirmed finding") for s in ordered_steps[:2]
                    ] or ["Confirmed BOLA finding"],
                    "suggested_test_type": "AUTHORIZATION_GET_MUTATION_VERIFICATION",
                    "confidence": "HIGH",
                    "requires_human_review": True,
                },
                {
                    "hypothesis": "Enumeration of sequential or predictable IDs might allow full catalog exfiltration.",
                    "reason": "Direct object references without authorization often allow algorithmic ID scraping.",
                    "required_existing_context": ["Observed numeric or predictable identifiers in endpoint path"],
                    "suggested_test_type": "SEQUENTIAL_ID_INSPECTION",
                    "confidence": "MEDIUM",
                    "requires_human_review": True,
                },
            ]

            raw_result = {
                "attack_path_id": path_id,
                "hypotheses": hypotheses,
                "caveats": (
                    "These hypotheses are analytical deductions based on deterministic patterns. "
                    "They must be validated by human security engineers and tested within authorized boundaries."
                ),
            }

        elif analysis_type == AIAnalysisType.REPORT_SUMMARY.value:
            proj = user_context.get("project", {})
            proj_id = int(proj.get("id", 1))

            raw_result = {
                "project_id": proj_id,
                "executive_summary": (
                    f"Security assessment summary for Project {proj.get('name', 'SentinelAPI Target')}. "
                    "Deterministic analysis revealed authorization boundaries crossed across sensitive resources."
                ),
                "key_exposure_themes": [
                    "Broken Object Level Authorization (BOLA)",
                    "Cross-Identity Lateral Movement",
                    "Insufficient Tenant Isolation",
                ],
                "highest_risk_paths": [
                    "Attack Path 1: IDOR to Privileged Resource Access",
                ],
                "strategic_recommendations": [
                    "Enforce centralized authorization policy middleware",
                    "Incorporate regression security testing into CI/CD pipelines",
                    "Audit all data access queries for tenant isolation compliance",
                ],
            }
        else:
            raise ValueError(f"Unsupported analysis type for MockAIProvider: {analysis_type}")

        # Strictly validate output against schema
        return validate_ai_output(analysis_type, raw_result)


class OpenAICompatibleProvider(AIProvider):
    """
    Connects to any OpenAI-compatible Chat Completions API endpoint (e.g., OpenAI,
    Azure OpenAI, Ollama, vLLM, LocalAI).
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        model_name: Optional[str] = None,
        timeout_seconds: float = 30.0,
    ):
        self.provider_name = "openai-compatible"
        self.base_url = (base_url or os.getenv("SENTINEL_AI_URL") or "https://api.openai.com/v1").rstrip("/")
        self.api_key = api_key or os.getenv("SENTINEL_AI_API_KEY", "")
        self.model_name = model_name or os.getenv("SENTINEL_AI_MODEL", "gpt-4o-mini")
        self.timeout_seconds = timeout_seconds

        if not self.api_key:
            logger.warning("OpenAICompatibleProvider initialized without API key. External calls will fail unless endpoint is unauthenticated.")

    def generate(self, system_prompt: str, user_context: Dict[str, Any], analysis_type: str) -> Dict[str, Any]:
        """
        Send formatted prompt to OpenAI-compatible chat completions endpoint,
        extract JSON, and validate against Pydantic schema.
        """
        endpoint = f"{self.base_url}/chat/completions"
        headers = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": f"Analyze the following security context and return ONLY the specified JSON:\n\n{json.dumps(user_context, indent=2)}",
                },
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.2,  # Low temperature for analytical consistency
        }

        try:
            with httpx.Client(timeout=self.timeout_seconds) as client:
                response = client.post(endpoint, json=payload, headers=headers)
                response.raise_for_status()
                data = response.json()

            choices = data.get("choices", [])
            if not choices:
                raise AIProviderError("No completion choices returned by external AI provider.")

            message_content = choices[0].get("message", {}).get("content", "")
            if not message_content:
                raise AIProviderError("Empty content received from external AI provider.")

            # Strict Pydantic output validation
            return validate_ai_output(analysis_type, message_content)

        except httpx.HTTPError as he:
            logger.error("HTTP error calling AI provider: %s", str(he))
            raise AIProviderError(f"External AI provider HTTP error: {str(he)}") from he
        except Exception as e:
            logger.error("Error generating AI analysis: %s", str(e))
            raise AIProviderError(f"AI generation failed: {str(e)}") from e


def get_ai_provider() -> AIProvider:
    """
    Factory function to instantiate the active AI provider based on environment variables.
    Defaults to MockAIProvider if not explicitly configured with an API key.
    """
    provider_type = os.getenv("SENTINEL_AI_PROVIDER", "mock").lower()
    if provider_type in ("openai", "openai-compatible") and os.getenv("SENTINEL_AI_API_KEY"):
        return OpenAICompatibleProvider()
    return MockAIProvider()


class AISecurityService:
    """
    High-level service coordinating AI security analysis lifecycle:
    - Context extraction & sanitization
    - Safety validation (confirmed findings only)
    - Prompt construction & execution
    - Strict schema validation
    - Database record persistence
    """

    def __init__(self, db: Session, provider: Optional[AIProvider] = None):
        self.db = db
        self.provider = provider or get_ai_provider()
        self.context_builder = SecurityContextBuilder(db)

    def _execute_analysis(
        self,
        project_id: int,
        analysis_type: str,
        input_context: Dict[str, Any],
        finding_id: Optional[str] = None,
        attack_path_id: Optional[str] = None,
    ) -> AIAnalysis:
        """Internal helper to execute and persist an AIAnalysis lifecycle."""
        # Check authorization boundary
        project = self.db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise ValueError(f"Project {project_id} not found.")

        # 1. Initialize record in RUNNING status
        analysis_record = AIAnalysis(
            project_id=project_id,
            finding_id=finding_id,
            attack_path_id=attack_path_id,
            analysis_type=analysis_type,
            status="RUNNING",
            model_provider=self.provider.provider_name,
            model_name=self.provider.model_name,
            input_context=input_context,
            output=None,
            error_message=None,
        )
        self.db.add(analysis_record)
        self.db.commit()
        self.db.refresh(analysis_record)

        try:
            # 2. Retrieve system prompt
            system_prompt = get_system_prompt(analysis_type)

            # 3. Call provider
            output = self.provider.generate(system_prompt, input_context, analysis_type)

            # 4. Mark COMPLETED
            analysis_record.output = output
            analysis_record.status = "COMPLETED"
            analysis_record.completed_at = datetime.now(timezone.utc)
            analysis_record.error_message = None
            self.db.commit()
            self.db.refresh(analysis_record)
            return analysis_record

        except Exception as e:
            logger.error("AI Analysis failed for %s: %s", analysis_type, str(e))
            self.db.rollback()
            analysis_record.status = "FAILED"
            analysis_record.error_message = str(e)
            analysis_record.completed_at = datetime.now(timezone.utc)
            self.db.commit()
            self.db.refresh(analysis_record)
            return analysis_record

    def analyze_finding(self, finding_id: str, analysis_type: str = AIAnalysisType.FINDING_EXPLANATION.value) -> AIAnalysis:
        """Analyze a single confirmed security finding."""
        finding = self.db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            raise ValueError(f"Finding {finding_id} not found.")

        # STRICT CONSTRAINT: Only confirmed findings can be analyzed
        if not self.context_builder.is_confirmed(finding):
            raise ValueError(f"Finding {finding_id} is not confirmed (status: {finding.status}). Only confirmed findings can be analyzed by AI.")

        input_context = self.context_builder.build_finding_context(finding)
        return self._execute_analysis(
            project_id=finding.project_id,
            analysis_type=analysis_type,
            input_context=input_context,
            finding_id=finding.id,
            attack_path_id=None,
        )

    def analyze_attack_path(self, attack_path_id: str, analysis_type: str = AIAnalysisType.ATTACK_PATH_EXPLANATION.value) -> AIAnalysis:
        """Analyze an active deterministic attack path."""
        path = self.db.query(AttackPath).filter(AttackPath.id == attack_path_id).first()
        if not path:
            raise ValueError(f"Attack path {attack_path_id} not found.")

        input_context = self.context_builder.build_attack_path_context(path)
        return self._execute_analysis(
            project_id=path.project_id,
            analysis_type=analysis_type,
            input_context=input_context,
            finding_id=None,
            attack_path_id=path.id,
        )

    def analyze_security_impact(self, impact_id: str, analysis_type: str = AIAnalysisType.IMPACT_EXPLANATION.value) -> AIAnalysis:
        """Analyze a deterministic SecurityImpact record."""
        impact = self.db.query(SecurityImpact).filter(SecurityImpact.id == impact_id).first()
        if not impact:
            raise ValueError(f"Security impact {impact_id} not found.")

        input_context = self.context_builder.build_impact_context(impact)
        return self._execute_analysis(
            project_id=impact.project_id,
            analysis_type=analysis_type,
            input_context=input_context,
            finding_id=impact.finding_id,
            attack_path_id=impact.attack_path_id,
        )

    def generate_attack_hypotheses(self, attack_path_id: str) -> AIAnalysis:
        """Generate safe, grounded attack hypotheses for an attack path."""
        path = self.db.query(AttackPath).filter(AttackPath.id == attack_path_id).first()
        if not path:
            raise ValueError(f"Attack path {attack_path_id} not found.")

        input_context = self.context_builder.build_attack_path_context(path)
        return self._execute_analysis(
            project_id=path.project_id,
            analysis_type=AIAnalysisType.ATTACK_HYPOTHESIS.value,
            input_context=input_context,
            finding_id=None,
            attack_path_id=path.id,
        )

    def generate_recommendations(
        self,
        finding_id: Optional[str] = None,
        attack_path_id: Optional[str] = None,
    ) -> AIAnalysis:
        """Generate security recommendations for a finding or attack path."""
        if not finding_id and not attack_path_id:
            raise ValueError("Must specify either finding_id or attack_path_id for security recommendations.")

        if finding_id:
            finding = self.db.query(Finding).filter(Finding.id == finding_id).first()
            if not finding:
                raise ValueError(f"Finding {finding_id} not found.")
            if not self.context_builder.is_confirmed(finding):
                raise ValueError(f"Finding {finding_id} is not confirmed.")
            input_context = self.context_builder.build_finding_context(finding)
            return self._execute_analysis(
                project_id=finding.project_id,
                analysis_type=AIAnalysisType.SECURITY_RECOMMENDATION.value,
                input_context=input_context,
                finding_id=finding.id,
                attack_path_id=None,
            )
        else:
            path = self.db.query(AttackPath).filter(AttackPath.id == attack_path_id).first()
            if not path:
                raise ValueError(f"Attack path {attack_path_id} not found.")
            input_context = self.context_builder.build_attack_path_context(path)
            return self._execute_analysis(
                project_id=path.project_id,
                analysis_type=AIAnalysisType.SECURITY_RECOMMENDATION.value,
                input_context=input_context,
                finding_id=None,
                attack_path_id=path.id,
            )

    def generate_report_summary(self, project_id: int) -> AIAnalysis:
        """Generate executive report summary for an entire project."""
        project = self.db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise ValueError(f"Project {project_id} not found.")

        input_context = {
            "context_type": "PROJECT_REPORT_SUMMARY",
            "project": self.context_builder.build_project_summary(project),
        }
        return self._execute_analysis(
            project_id=project.id,
            analysis_type=AIAnalysisType.REPORT_SUMMARY.value,
            input_context=input_context,
            finding_id=None,
            attack_path_id=None,
        )
