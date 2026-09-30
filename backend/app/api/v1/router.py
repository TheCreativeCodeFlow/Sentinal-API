from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form
from sqlalchemy.orm import Session
from typing import List, Optional

from app.core.db import get_db
from app.models import (
    Project,
    API,
    Endpoint,
    Schema,
    Role,
    Identity,
    Resource,
    ResourceOwnership,
    SecurityTest,
    TestExecution,
    Finding,
    Evidence,
    EndpointAuthorizationPolicy,
    AuthorizationMatrixRule,
    ResourceProperty,
    PropertyAuthorizationRule,
    AuthenticationPolicy,
    Workflow,
    WorkflowStep,
    WorkflowState,
    WorkflowTransition,
    WorkflowExecution,
    WorkflowStepExecution,
    WorkflowAttackScenario,
    WorkflowAttackStep,
    AttackGraph,
    AttackGraphNode,
    AttackGraphEdge,
    FindingCorrelation,
    AttackPath,
    AttackPathStep,
    SecurityImpact,
    AIAnalysis,
    AIHypothesis,
    AIHypothesisReview,
    SecurityInvestigation,
    InvestigationItem,
    SecurityTestSuite,
    SecurityTestSuiteItem,
    SecurityExecutionPlan,
    SecurityExecutionItem,
    ScanProfile,
    SecurityBaseline,
    SecurityBaselineControl,
    SecurityBaselineComparison,
    SecurityBaselineComparisonItem,
    SecurityGate,
    SecurityGateEvaluation,
    SecurityGateEvaluationItem,
    SecurityReport,
    SecurityReportSnapshot,
)
from app.schemas import (
    ProjectCreate,
    ProjectUpdate,
    ProjectInDB,
    APICreate,
    APIUpdate,
    APIInDB,
    EndpointCreate,
    EndpointUpdate,
    EndpointInDB,
    OpenAPIUpload,
    EndpointFilter,
    AuthSchemeCreate,
    AuthSchemeInDB,
    RoleBase,
    RoleCreate,
    RoleUpdate,
    RoleInDB,
    RoleDetail,
    RoleMember,
    IdentityCreate,
    IdentityUpdate,
    IdentityInDB,
    IdentityDetail,
    IdentityRoleAssign,
    ResourceCreate,
    ResourceUpdate,
    ResourceInDB,
    ResourceDetail,
    ResourceOwnershipCreate,
    ResourceOwnershipInDB,
    EndpointResourceAssign,
    AuthorizationModelView,
    AuthModelIdentityNode,
    AuthModelResourceItem,
    SecurityTestCreate,
    SecurityTestInDB,
    TestExecutionInDB,
    FindingInDB,
    FindingDetail,
    EvidenceInDB,
    EndpointAuthorizationPolicyCreate,
    EndpointAuthorizationPolicyUpdate,
    EndpointAuthorizationPolicyInDB,
    AuthorizationMatrixRuleCreate,
    AuthorizationMatrixRuleUpdate,
    AuthorizationMatrixRuleInDB,
    AuthorizationMatrixCell,
    AuthorizationMatrixEndpointRow,
    AuthorizationMatrixView,
    BFLATestGenerateRequest,
    BFLATestGenerateResult,
    ResourcePropertyBase,
    ResourcePropertyCreate,
    ResourcePropertyUpdate,
    ResourcePropertyInDB,
    PropertyAuthorizationRuleBase,
    PropertyAuthorizationRuleCreate,
    PropertyAuthorizationRuleInDB,
    PropertyRuleBulkItem,
    PropertyMatrixBulkUpdate,
    PropertyMatrixRow,
    PropertyMatrixView,
    CandidateProperty,
    PropertyDiscoveryRequest,
    PropertyDiscoveryResponse,
    AuthenticationPolicyBase,
    AuthenticationPolicyCreate,
    AuthenticationPolicyUpdate,
    AuthenticationPolicyInDB,
    AuthTestGenerationResponse,
    WorkflowCreate,
    WorkflowUpdate,
    WorkflowInDB,
    WorkflowDetailInDB,
    WorkflowStepCreate,
    WorkflowStepUpdate,
    WorkflowStepInDB,
    WorkflowStateCreate,
    WorkflowStateUpdate,
    WorkflowStateInDB,
    WorkflowTransitionCreate,
    WorkflowTransitionUpdate,
    WorkflowTransitionInDB,
    WorkflowStepExecutionInDB,
    WorkflowExecutionInDB,
    WorkflowExecutionDetailInDB,
    WorkflowAttackStepBase,
    WorkflowAttackStepCreate,
    WorkflowAttackStepInDB,
    WorkflowAttackScenarioBase,
    WorkflowAttackScenarioCreate,
    WorkflowAttackScenarioInDB,
    WorkflowAttackScenarioDetailInDB,
    WorkflowAttackScenarioGenerateRequest,
    WorkflowAttackScenarioGenerateResult,
    AttackGraphNodeBase,
    AttackGraphNodeInDB,
    AttackGraphEdgeBase,
    AttackGraphEdgeInDB,
    AttackGraphBase,
    AttackGraphInDB,
    AttackGraphDetailInDB,
    FindingCorrelationInDB,
    CorrelationRunResponse,
    AttackPathStepInDB,
    AttackPathInDB,
    AttackPathDetailInDB,
    AttackPathAnalysisResponse,
    SecurityImpactBase,
    SecurityImpactInDB,
    SecurityImpactDetailInDB,
    SecurityImpactAnalysisResponse,
    AIAnalysisType,
    AIAnalysisBase,
    AIAnalysisInDB,
    AIAnalysisDetailInDB,
    AIAnalysisResponse,
    AIAnalysesListResponse,
    AIAnalyzeRequest,
    AIHypothesisStatus,
    AIHypothesisBase,
    AIHypothesisInDB,
    AIHypothesisDetailInDB,
    AIHypothesisReviewInDB,
    AIHypothesisApprovalRequest,
    AIHypothesisRejectionRequest,
    AIHypothesisConvertRequest,
    AIHypothesisConvertResponse,
    AIHypothesisListResponse,
    AIHypothesisAuditResponse,
    SecurityInvestigationStatus,
    InvestigationItemType,
    SecurityInvestigationBase,
    SecurityInvestigationCreate,
    SecurityInvestigationUpdate,
    SecurityInvestigationInDB,
    SecurityInvestigationDetailInDB,
    SecurityInvestigationListResponse,
    InvestigationItemBase,
    InvestigationItemCreate,
    InvestigationItemInDB,
    InvestigationTimelineEvent,
    InvestigationTimelineResponse,
    InvestigationContextResponse,
    TestSuiteStatus,
    ExecutionPlanStatus,
    ExecutionMode,
    ExecutionItemStatus,
    SecurityTestSuiteItemBase,
    SecurityTestSuiteItemCreate,
    SecurityTestSuiteItemUpdate,
    SecurityTestSuiteItemInDB,
    SecurityTestSuiteBase,
    SecurityTestSuiteCreate,
    SecurityTestSuiteUpdate,
    SecurityTestSuiteInDB,
    SecurityTestSuiteListResponse,
    SecurityExecutionItemInDB,
    SecurityExecutionPlanBase,
    SecurityExecutionPlanCreate,
    SecurityExecutionPlanInDB,
    SecurityExecutionPlanListResponse,
    SecurityExecutionProgressResponse,
    ScanProfileCreate,
    ScanProfileUpdate,
    ScanProfileInDB,
    ScanProfileListResponse,
    ScanProfilePreviewResponse,
    TestSelectionReason,
    PlanFromProfileRequest,
    SecurityBaselineCreate,
    SecurityBaselineUpdate,
    SecurityBaselineInDB,
    SecurityBaselineListResponse,
    BaselineFromPlanRequest,
    SecurityBaselineControlInDB,
    SecurityBaselineComparisonInDB,
    SecurityBaselineComparisonItemInDB,
    SecurityBaselineComparisonDetailResponse,
    SecurityGateCreate,
    SecurityGateUpdate,
    SecurityGateInDB,
    SecurityGateListResponse,
    SecurityGateEvaluationItemInDB,
    SecurityGateEvaluationInDB,
    SecurityGateEvaluateRequest,
    SecurityGateEvaluationListResponse,
    SecurityGateCIResult,
    SecurityReportCreate,
    SecurityReportUpdate,
    SecurityReportInDB,
    SecurityReportListResponse,
    SecurityReportSnapshotInDB,
    SecurityReportManifest,
    SecurityReportDetailResponse,
)
from app.services.security_engine.redactor import SENSITIVE_HEADER_NAMES
from app.services.security_engine.correlation_engine import CorrelationEngine
from app.services.security_engine.attack_path_engine import AttackPathEngine
from app.services.security_engine.impact_engine import ImpactEngine
from app.services.security_engine.investigation_service import (
    InvestigationService,
    InvestigationServiceError,
    CrossProjectViolationError,
    InvalidFindingStateError,
)
from app.services.security_engine.orchestrator import (
    TestOrchestrator,
    OrchestrationError,
    PlanStateError,
    AuthorizationError as OrchestratorAuthorizationError,
    EntityNotFoundError as OrchestratorEntityNotFoundError,
    InvalidSuiteStateError,
)
from app.services.security_engine.scan_profile_service import (
    ScanProfileService,
    ScanProfileError,
    ProfileNotFoundError,
    DuplicateProfileError,
    DisabledProfileError,
)
from app.services.security_engine.baseline_service import (
    SecurityBaselineService,
    BaselineComparisonService,
    BaselineError,
    BaselineNotFoundError,
    ComparisonNotFoundError,
    InvalidBaselinePlanError,
)
from app.services.security_engine.security_gate_service import (
    SecurityGateService,
    SecurityGateError,
    GateNotFoundError,
    DuplicateGateError,
    DisabledGateError,
    InvalidGateRuleError,
    InvalidEvaluationStateError,
    get_gate_exit_code,
)
from app.services.security_engine.report_service import (
    SecurityReportService,
    SecurityReportError,
    ReportNotFoundError,
    DuplicateReportError,
    InvalidReportSourceError,
    ArchivedReportError,
)
from app.services.ai import (
    AISecurityService,
    HypothesisReviewService,
    HypothesisReviewError,
    HypothesisConverter,
    HypothesisConversionError,
)



def get_project_or_404(project_id: int, db: Session):
    """Helper to get project or raise 404."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with id {project_id} not found",
        )
    return project


def get_api_or_404(api_id: int, project_id: int, db: Session):
    """Helper to get API or raise 404."""
    api = (
        db.query(API)
        .filter(API.project_id == project_id, API.id == api_id)
        .first()
    )
    if not api:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API with id {api_id} not found in project {project_id}",
        )
    return api


def get_role_or_404(role_id: str, db: Session) -> Role:
    """Helper to get role or raise 404."""
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Role with id {role_id} not found",
        )
    return role


def get_identity_or_404(identity_id: str, db: Session) -> Identity:
    """Helper to get identity or raise 404."""
    identity = db.query(Identity).filter(Identity.id == identity_id).first()
    if not identity:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Identity with id {identity_id} not found",
        )
    return identity


def get_resource_or_404(resource_id: str, db: Session) -> Resource:
    """Helper to get resource or raise 404."""
    resource = db.query(Resource).filter(Resource.id == resource_id).first()
    if not resource:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Resource with id {resource_id} not found",
        )
    return resource


def get_endpoint_or_404(endpoint_id: int, db: Session) -> Endpoint:
    """Helper to get endpoint or raise 404."""
    endpoint = db.query(Endpoint).filter(Endpoint.id == endpoint_id).first()
    if not endpoint:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Endpoint with id {endpoint_id} not found",
        )
    return endpoint


import json

def get_ownership_or_404(ownership_id: str, db: Session) -> ResourceOwnership:
    """Helper to get resource ownership or raise 404."""
    ownership = db.query(ResourceOwnership).filter(ResourceOwnership.id == ownership_id).first()
    if not ownership:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Resource ownership with id {ownership_id} not found",
        )
    return ownership


def get_security_test_or_404(test_id: str, db: Session) -> SecurityTest:
    """Helper to get security test or raise 404."""
    test = db.query(SecurityTest).filter(SecurityTest.id == test_id).first()
    if not test:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security test with id {test_id} not found",
        )
    return test


def get_execution_or_404(execution_id: str, db: Session) -> TestExecution:
    """Helper to get test execution or raise 404."""
    execution = db.query(TestExecution).filter(TestExecution.id == execution_id).first()
    if not execution:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Test execution with id {execution_id} not found",
        )
    return execution


def get_property_or_404(property_id: str, db: Session) -> ResourceProperty:
    """Helper to get resource property or raise 404."""
    prop = db.query(ResourceProperty).filter(ResourceProperty.id == property_id).first()
    if not prop:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Resource property with id {property_id} not found",
        )
    return prop


def get_finding_or_404(finding_id: str, db: Session) -> Finding:
    """Helper to get finding or raise 404."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding with id {finding_id} not found",
        )
    return finding


def get_workflow_or_404(workflow_id: str, db: Session) -> Workflow:
    """Helper to get workflow or raise 404."""
    wf = db.query(Workflow).filter(Workflow.id == workflow_id).first()
    if not wf:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workflow with id {workflow_id} not found",
        )
    return wf


def get_workflow_step_or_404(step_id: str, db: Session) -> WorkflowStep:
    """Helper to get workflow step or raise 404."""
    step = db.query(WorkflowStep).filter(WorkflowStep.id == step_id).first()
    if not step:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workflow step with id {step_id} not found",
        )
    return step


def get_workflow_state_or_404(state_id: str, db: Session) -> WorkflowState:
    """Helper to get workflow state or raise 404."""
    st = db.query(WorkflowState).filter(WorkflowState.id == state_id).first()
    if not st:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workflow state with id {state_id} not found",
        )
    return st


def get_workflow_transition_or_404(transition_id: str, db: Session) -> WorkflowTransition:
    """Helper to get workflow transition or raise 404."""
    tr = db.query(WorkflowTransition).filter(WorkflowTransition.id == transition_id).first()
    if not tr:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workflow transition with id {transition_id} not found",
        )
    return tr


SENSITIVE_KEY_PATTERNS = {
    "password", "secret", "token", "api_key", "apikey", "access_token",
    "refresh_token", "private_key", "authorization", "auth_token", "session_id", "cookie",
}


def validate_request_template(template: Optional[dict]) -> None:
    """
    Validate that request_template does not contain raw sensitive secrets.
    Placeholders like {{...}} or [REDACTED] are allowed.
    """
    if not template or not isinstance(template, dict):
        return

    def check_item(key: str, val: Any):
        lower_k = str(key).lower()
        if isinstance(val, str):
            val_trimmed = val.strip()
            # If the string contains Bearer
            if val_trimmed.lower().startswith("bearer "):
                token_part = val_trimmed[7:].strip()
                if not (
                    (token_part.startswith("{{") and token_part.endswith("}}"))
                    or token_part == "[REDACTED]"
                    or token_part == ""
                ):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Raw credentials or secrets are not allowed in request_template for '{key}'. Use placeholders like 'Bearer {{{{token}}}}' or '[REDACTED]'.",
                    )
                return

            # If the key name itself suggests sensitivity
            is_sensitive_key = (
                lower_k in SENSITIVE_HEADER_NAMES
                or any(p in lower_k for p in SENSITIVE_KEY_PATTERNS)
            )
            if is_sensitive_key:
                if not (
                    (val_trimmed.startswith("{{") and val_trimmed.endswith("}}"))
                    or val_trimmed == "[REDACTED]"
                    or val_trimmed == ""
                ):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Raw credentials or secrets are not allowed in request_template key '{key}'. Use placeholders like '{{{{{key}}}}}' or '[REDACTED]'.",
                    )
        elif isinstance(val, dict):
            for sub_k, sub_v in val.items():
                check_item(sub_k, sub_v)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    for sub_k, sub_v in item.items():
                        check_item(sub_k, sub_v)

    for k, v in template.items():
        check_item(k, v)


def format_security_test_response(test: SecurityTest, db: Session) -> SecurityTestInDB:
    endpoint = test.endpoint
    attacker = test.attacker_identity
    victim_ident = test.victim_identity
    victim_res = test.victim_resource
    latest_exec = (
        db.query(TestExecution)
        .filter(TestExecution.security_test_id == test.id)
        .order_by(TestExecution.created_at.desc())
        .first()
    )
    executions_count = db.query(TestExecution).filter(TestExecution.security_test_id == test.id).count()
    findings_count = db.query(Finding).filter(Finding.security_test_id == test.id).count()
    
    cfg = None
    if test.configuration:
        try:
            cfg = json.loads(test.configuration)
        except Exception:
            cfg = None

    return SecurityTestInDB(
        id=test.id,
        project_id=test.project_id,
        endpoint_id=test.endpoint_id,
        endpoint_method=endpoint.method if endpoint else None,
        endpoint_path=endpoint.path if endpoint else None,
        test_type=test.test_type,
        attacker_identity_id=test.attacker_identity_id,
        attacker_identity_name=attacker.name if attacker else None,
        attacker_role_name=attacker.role.name if (attacker and attacker.role) else None,
        victim_identity_id=test.victim_identity_id,
        victim_identity_name=victim_ident.name if victim_ident else None,
        victim_resource_id=test.victim_resource_id,
        victim_resource_name=victim_res.name if victim_res else None,
        victim_resource_instance_id=test.victim_resource_instance_id,
        attacker_resource_instance_id=test.attacker_resource_instance_id,
        expected_access=test.expected_access or "DENY",
        status=test.status,
        configuration=cfg,
        created_at=test.created_at,
        updated_at=test.updated_at,
        latest_result=latest_exec.result if latest_exec else None,
        executions_count=executions_count,
        findings_count=findings_count,
    )


def format_evidence_response(evidence: Optional[Evidence]) -> Optional[EvidenceInDB]:
    if not evidence:
        return None
    req_meta = None
    if evidence.request_metadata:
        try:
            req_meta = json.loads(evidence.request_metadata)
        except Exception:
            req_meta = None
    resp_meta = None
    if evidence.response_metadata:
        try:
            resp_meta = json.loads(evidence.response_metadata)
        except Exception:
            resp_meta = None

    return EvidenceInDB(
        id=evidence.id,
        execution_id=evidence.execution_id,
        workflow_execution_id=evidence.workflow_execution_id,
        workflow_step_execution_id=evidence.workflow_step_execution_id,
        finding_id=evidence.finding_id,
        request_metadata=req_meta,
        response_metadata=resp_meta,
        expected_behavior=evidence.expected_behavior,
        actual_behavior=evidence.actual_behavior,
        redacted_request=evidence.redacted_request,
        redacted_response=evidence.redacted_response,
        reproducibility_status=evidence.reproducibility_status,
        created_at=evidence.created_at,
    )


def format_execution_response(execution: TestExecution) -> TestExecutionInDB:
    ev_data = format_evidence_response(execution.evidence)
    return TestExecutionInDB(
        id=execution.id,
        security_test_id=execution.security_test_id,
        status=execution.status,
        result=execution.result,
        result_reason=execution.result_reason,
        started_at=execution.started_at,
        completed_at=execution.completed_at,
        http_status=execution.http_status,
        duration_ms=execution.duration_ms,
        error_category=execution.error_category,
        created_at=execution.created_at,
        evidence=ev_data,
    )


def format_property_response(prop: ResourceProperty) -> ResourcePropertyInDB:
    rule_items = [
        PropertyAuthorizationRuleInDB.model_validate(r)
        for r in prop.rules
    ]
    return ResourcePropertyInDB(
        id=prop.id,
        resource_id=prop.resource_id,
        name=prop.name,
        data_type=prop.data_type,
        sensitivity=prop.sensitivity,
        description=prop.description,
        created_at=prop.created_at,
        updated_at=prop.updated_at,
        rules=rule_items,
    )


def format_finding_response(finding: Finding, db: Session) -> FindingInDB:
    endpoint = finding.endpoint or (finding.security_test.endpoint if finding.security_test else None)
    attacker = finding.attacker_identity or (finding.security_test.attacker_identity if finding.security_test else None)
    attacker_role = finding.attacker_role or (attacker.role if attacker else None)
    victim_res = finding.security_test.victim_resource if finding.security_test else None
    if not victim_res and finding.resource_id:
        victim_res = db.query(Resource).filter(Resource.id == finding.resource_id).first()

    workflow_name = finding.workflow.name if finding.workflow else None
    workflow_step_name = finding.workflow_step.name if finding.workflow_step else None

    exposed_props = None
    if finding.exposed_properties:
        try:
            exposed_props = json.loads(finding.exposed_properties)
        except Exception:
            exposed_props = [finding.exposed_properties]

    return FindingInDB(
        id=finding.id,
        project_id=finding.project_id,
        security_test_id=finding.security_test_id,
        execution_id=finding.execution_id,
        workflow_id=finding.workflow_id,
        workflow_execution_id=finding.workflow_execution_id,
        workflow_step_id=finding.workflow_step_id,
        endpoint_id=finding.endpoint_id or (endpoint.id if endpoint else None),
        attacker_identity_id=finding.attacker_identity_id or (attacker.id if attacker else None),
        attacker_role_id=finding.attacker_role_id or (attacker_role.id if attacker_role else None),
        type=finding.type,
        severity=finding.severity,
        confidence=finding.confidence,
        status=finding.status,
        title=finding.title,
        description=finding.description,
        remediation=finding.remediation,
        expected_authorization=finding.expected_authorization,
        actual_behavior=finding.actual_behavior,
        created_at=finding.created_at,
        updated_at=finding.updated_at,
        endpoint_method=endpoint.method if endpoint else None,
        endpoint_path=endpoint.path if endpoint else None,
        resource_id=finding.resource_id or (victim_res.id if victim_res else None),
        exposed_properties=exposed_props,
        authentication_mechanism=finding.authentication_mechanism,
        attacker_identity_name=attacker.name if attacker else None,
        attacker_role_name=attacker_role.name if attacker_role else None,
        victim_resource_name=victim_res.name if victim_res else None,
        victim_resource_instance_id=finding.security_test.victim_resource_instance_id if finding.security_test else None,
        workflow_name=workflow_name,
        workflow_step_name=workflow_step_name,
        attack_scenario_id=finding.attack_scenario_id,
        attack_scenario_name=finding.attack_scenario.name if finding.attack_scenario else None,
        attack_scenario_type=finding.attack_scenario.scenario_type if finding.attack_scenario else None,
    )


def format_finding_detail(finding: Finding, db: Session) -> FindingDetail:
    base = format_finding_response(finding, db)
    ev = db.query(Evidence).filter(Evidence.finding_id == finding.id).first()
    if not ev and finding.execution:
        ev = finding.execution.evidence
    if not ev and finding.workflow_execution_id:
        ev = db.query(Evidence).filter(Evidence.workflow_execution_id == finding.workflow_execution_id).first()
    if not ev and finding.attack_scenario_id:
        ev = db.query(Evidence).filter(Evidence.attack_scenario_id == finding.attack_scenario_id).first()
    ev_in_db = format_evidence_response(ev)

    data = base.model_dump()
    if ev:
        if not data.get("actual_behavior"):
            data["actual_behavior"] = ev.actual_behavior
        data["expected_behavior"] = ev.expected_behavior
    data["evidence"] = ev_in_db
    return FindingDetail(**data)


def format_identity_response(identity: Identity) -> IdentityInDB:
    data = IdentityInDB.model_validate(identity)
    if identity.role:
        data.role_name = identity.role.name
    return data


def format_role_response(role: Role, db: Session) -> RoleInDB:
    data = RoleInDB.model_validate(role)
    data.identities_count = db.query(Identity).filter(Identity.role_id == role.id).count()
    return data


def format_resource_response(resource: Resource, db: Session) -> ResourceInDB:
    data = ResourceInDB.model_validate(resource)
    data.ownerships_count = db.query(ResourceOwnership).filter(ResourceOwnership.resource_id == resource.id).count()
    data.endpoints_count = db.query(Endpoint).filter(Endpoint.resource_id == resource.id).count()
    return data


def format_endpoint_response(endpoint: Endpoint) -> EndpointInDB:
    data = EndpointInDB.model_validate(endpoint)
    if endpoint.resource:
        data.resource_name = endpoint.resource.name
    return data


def format_policy_response(policy: EndpointAuthorizationPolicy, db: Session) -> EndpointAuthorizationPolicyInDB:
    endpoint = policy.endpoint
    return EndpointAuthorizationPolicyInDB(
        id=policy.id,
        project_id=policy.project_id,
        endpoint_id=policy.endpoint_id,
        endpoint_method=endpoint.method if endpoint else None,
        endpoint_path=endpoint.path if endpoint else None,
        authentication_required=policy.authentication_required,
        notes=policy.notes,
        allowed_roles=[RoleBase(name=r.name, description=r.description) for r in policy.allowed_roles],
        denied_roles=[RoleBase(name=r.name, description=r.description) for r in policy.denied_roles],
        created_at=policy.created_at,
        updated_at=policy.updated_at,
    )


def format_rule_response(rule: AuthorizationMatrixRule, db: Session) -> AuthorizationMatrixRuleInDB:
    return AuthorizationMatrixRuleInDB(
        id=rule.id,
        project_id=rule.project_id,
        endpoint_id=rule.endpoint_id,
        role_id=rule.role_id,
        role_name=rule.role.name if rule.role else None,
        identity_id=rule.identity_id,
        identity_name=rule.identity.name if rule.identity else None,
        http_method=rule.http_method,
        expected_access=rule.expected_access,
        created_at=rule.created_at,
        updated_at=rule.updated_at,
    )


def format_workflow_step_response(step: WorkflowStep) -> WorkflowStepInDB:
    endpoint_path = step.endpoint.path if step.endpoint else None
    endpoint_method = step.endpoint.method if step.endpoint else None
    identity_name = step.identity.name if step.identity else None
    return WorkflowStepInDB(
        id=step.id,
        workflow_id=step.workflow_id,
        step_order=step.step_order,
        endpoint_id=step.endpoint_id,
        endpoint_path=endpoint_path,
        endpoint_method=endpoint_method,
        identity_id=step.identity_id,
        identity_name=identity_name,
        http_method=step.http_method,
        name=step.name,
        description=step.description,
        request_template=step.request_template,
        expected_status_codes=step.expected_status_codes or [200],
        created_at=step.created_at,
        updated_at=step.updated_at,
    )


def format_workflow_state_response(state: WorkflowState) -> WorkflowStateInDB:
    return WorkflowStateInDB(
        id=state.id,
        workflow_id=state.workflow_id,
        name=state.name,
        description=state.description,
        is_initial=state.is_initial,
        is_terminal=state.is_terminal,
        created_at=state.created_at,
        updated_at=state.updated_at,
    )


def format_workflow_transition_response(trans: WorkflowTransition) -> WorkflowTransitionInDB:
    from_name = trans.from_state.name if trans.from_state else None
    to_name = trans.to_state.name if trans.to_state else None
    step_name = trans.step.name if trans.step else None
    return WorkflowTransitionInDB(
        id=trans.id,
        workflow_id=trans.workflow_id,
        from_state_id=trans.from_state_id,
        from_state_name=from_name,
        to_state_id=trans.to_state_id,
        to_state_name=to_name,
        step_id=trans.step_id,
        step_name=step_name,
        expected_behavior=trans.expected_behavior,
        description=trans.description,
        created_at=trans.created_at,
        updated_at=trans.updated_at,
    )


def format_workflow_response(workflow: Workflow, db: Session) -> WorkflowInDB:
    step_count = len(workflow.steps) if workflow.steps else 0
    state_count = len(workflow.states) if workflow.states else 0
    transition_count = len(workflow.transitions) if workflow.transitions else 0
    return WorkflowInDB(
        id=workflow.id,
        project_id=workflow.project_id,
        name=workflow.name,
        description=workflow.description,
        status=workflow.status,
        step_count=step_count,
        state_count=state_count,
        transition_count=transition_count,
        created_at=workflow.created_at,
        updated_at=workflow.updated_at,
    )


def format_workflow_detail(workflow: Workflow, db: Session) -> WorkflowDetailInDB:
    steps = [format_workflow_step_response(s) for s in workflow.steps]
    states = [format_workflow_state_response(st) for st in workflow.states]
    transitions = [format_workflow_transition_response(t) for t in workflow.transitions]
    return WorkflowDetailInDB(
        id=workflow.id,
        project_id=workflow.project_id,
        name=workflow.name,
        description=workflow.description,
        status=workflow.status,
        steps=steps,
        states=states,
        transitions=transitions,
        created_at=workflow.created_at,
        updated_at=workflow.updated_at,
    )


def get_workflow_execution_or_404(execution_id: str, db: Session) -> WorkflowExecution:
    """Helper to get workflow execution or raise 404."""
    we = db.query(WorkflowExecution).filter(WorkflowExecution.id == execution_id).first()
    if not we:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workflow execution with id {execution_id} not found",
        )
    return we


def format_workflow_step_execution_response(step_exec: WorkflowStepExecution) -> WorkflowStepExecutionInDB:
    return WorkflowStepExecutionInDB(
        id=step_exec.id,
        workflow_execution_id=step_exec.workflow_execution_id,
        step_id=step_exec.step_id,
        attack_step_id=step_exec.attack_step_id,
        step_order=step_exec.step_order,
        http_method=step_exec.http_method,
        endpoint_path=step_exec.endpoint_path,
        action=step_exec.action,
        identity_id=step_exec.identity_id,
        identity_name=step_exec.identity_name,
        status=step_exec.status,
        request_summary=step_exec.request_summary,
        response_summary=step_exec.response_summary,
        status_code=step_exec.status_code,
        latency_ms=step_exec.latency_ms,
        state_before=step_exec.state_before,
        state_after=step_exec.state_after,
        transition_expected=step_exec.transition_expected,
        transition_result=step_exec.transition_result,
        correlation_id=step_exec.correlation_id,
        error_message=step_exec.error_message,
        created_at=step_exec.created_at,
        step_name=step_exec.step.name if step_exec.step else None,
    )


def format_workflow_execution_response(execution: WorkflowExecution, db: Session) -> WorkflowExecutionInDB:
    step_count = len(execution.step_executions) if execution.step_executions else 0
    findings_count = len(execution.findings) if execution.findings else 0
    return WorkflowExecutionInDB(
        id=execution.id,
        workflow_id=execution.workflow_id,
        attack_scenario_id=execution.attack_scenario_id,
        status=execution.status,
        result=execution.result,
        result_reason=execution.result_reason,
        triggered_by=execution.triggered_by,
        current_state_id=execution.current_state_id,
        correlation_id=execution.correlation_id,
        started_at=execution.started_at,
        completed_at=execution.completed_at,
        error_message=execution.error_message,
        created_at=execution.created_at,
        step_count=step_count,
        findings_count=findings_count,
    )


def format_workflow_execution_detail(execution: WorkflowExecution, db: Session) -> WorkflowExecutionDetailInDB:
    base = format_workflow_execution_response(execution, db)
    step_execs = [
        format_workflow_step_execution_response(se)
        for se in sorted(execution.step_executions, key=lambda s: s.step_order)
    ]
    findings = [format_finding_response(f, db) for f in execution.findings]
    return WorkflowExecutionDetailInDB(
        **base.model_dump(),
        workflow_name=execution.workflow.name if execution.workflow else None,
        current_state_name=execution.current_state.name if execution.current_state else None,
        attack_scenario_name=execution.attack_scenario.name if execution.attack_scenario else None,
        attack_scenario_type=execution.attack_scenario.scenario_type if execution.attack_scenario else None,
        step_executions=step_execs,
        findings=findings,
    )


def get_attack_scenario_or_404(scenario_id: str, db: Session) -> WorkflowAttackScenario:
    """Helper to get attack scenario or raise 404."""
    sc = db.query(WorkflowAttackScenario).filter(WorkflowAttackScenario.id == scenario_id).first()
    if not sc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workflow attack scenario with id {scenario_id} not found",
        )
    return sc


def format_workflow_attack_step_response(step: WorkflowAttackStep) -> WorkflowAttackStepInDB:
    endpoint_method = step.source_step.http_method if step.source_step else None
    endpoint_path = (
        step.source_step.endpoint.path
        if (step.source_step and step.source_step.endpoint)
        else None
    )
    return WorkflowAttackStepInDB(
        id=step.id,
        scenario_id=step.scenario_id,
        source_step_id=step.source_step_id,
        position=step.position,
        action=step.action,
        identity_id=step.identity_id,
        expected_behavior=step.expected_behavior,
        configuration=step.configuration,
        created_at=step.created_at,
        source_step_name=step.source_step.name if step.source_step else None,
        endpoint_method=endpoint_method,
        endpoint_path=endpoint_path,
        identity_name=step.identity.name if step.identity else None,
    )


def format_workflow_attack_scenario_response(scenario: WorkflowAttackScenario, db: Session) -> WorkflowAttackScenarioInDB:
    step_count = len(scenario.steps) if scenario.steps else 0
    execution_count = len(scenario.executions) if scenario.executions else 0
    findings_count = len(scenario.findings) if scenario.findings else 0
    latest_result = scenario.executions[0].result if scenario.executions else None
    return WorkflowAttackScenarioInDB(
        id=scenario.id,
        workflow_id=scenario.workflow_id,
        name=scenario.name,
        description=scenario.description,
        scenario_type=scenario.scenario_type,
        status=scenario.status,
        created_at=scenario.created_at,
        updated_at=scenario.updated_at,
        step_count=step_count,
        execution_count=execution_count,
        findings_count=findings_count,
        latest_result=latest_result,
    )


def format_workflow_attack_scenario_detail(scenario: WorkflowAttackScenario, db: Session) -> WorkflowAttackScenarioDetailInDB:
    base = format_workflow_attack_scenario_response(scenario, db)
    steps = [
        format_workflow_attack_step_response(s)
        for s in sorted(scenario.steps, key=lambda s: s.position)
    ]
    latest_exec = (
        format_workflow_execution_response(scenario.executions[0], db)
        if scenario.executions
        else None
    )
    return WorkflowAttackScenarioDetailInDB(
        **base.model_dump(),
        workflow_name=scenario.workflow.name if scenario.workflow else None,
        steps=steps,
        latest_execution=latest_exec,
    )


# Main router for API
router = APIRouter(tags=["api"])


@router.get("/auth/verify")
def verify_api_authentication():
    """Verify that connection to SentinelAPI is functional and API token is valid."""
    return {
        "status": "authenticated",
        "message": "SentinelAPI connection and credentials valid.",
    }


# Project endpoints
project_router = APIRouter(prefix="/projects", tags=["projects"])


@project_router.post("/", response_model=ProjectInDB, status_code=status.HTTP_201_CREATED)
def create_project(
    project_in: ProjectCreate,
    db: Session = Depends(get_db),
):
    """Create a new project."""
    import json as _json
    
    project = Project(
        name=project_in.name,
        description=project_in.description,
        environment=project_in.environment,
        base_url=project_in.base_url,
        authorization_status=project_in.authorization_status,
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


@project_router.get("/", response_model=List[ProjectInDB])
def list_projects(
    authorization_status: Optional[str] = None,
    environment: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """List projects with optional filtering."""
    query = db.query(Project)
    if authorization_status:
        query = query.filter(Project.authorization_status == authorization_status)
    if environment:
        query = query.filter(Project.environment == environment)
    return query.all()


@project_router.get("/{project_id}", response_model=ProjectInDB)
def get_project(
    project_id: int,
    db: Session = Depends(get_db),
):
    """Get a single project by ID."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with id {project_id} not found",
        )
    return project


@project_router.put("/{project_id}", response_model=ProjectInDB)
def update_project(
    project_id: int,
    project_in: ProjectUpdate,
    db: Session = Depends(get_db),
):
    """Update a project."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with id {project_id} not found",
        )
    
    update_data = project_in.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(project, field, value)
    
    db.commit()
    db.refresh(project)
    return project


@project_router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(
    project_id: int,
    db: Session = Depends(get_db),
):
    """Delete a project and all associated data."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with id {project_id} not found",
        )
    
    db.delete(project)
    db.commit()
    return None


# API endpoints within a project
api_router = APIRouter(prefix="/{project_id}/apis", tags=["apis"])


@api_router.post("/", response_model=APIInDB, status_code=status.HTTP_201_CREATED)
def create_api(
    project_id: int,
    api_in: APICreate,
    db: Session = Depends(get_db),
):
    """Create a new API within a project."""
    project = get_project_or_404(project_id, db)
    
    api = API(
        project_id=project_id,
        name=api_in.name,
        version=api_in.version,
        title=api_in.title,
        url=api_in.url,
        format=api_in.format or "openapi3",
        status="pending",
    )
    db.add(api)
    db.commit()
    db.refresh(api)
    return api


@api_router.get("/", response_model=List[APIInDB])
def list_apis(
    project_id: int,
    db: Session = Depends(get_db),
):
    """List APIs within a project."""
    project = get_project_or_404(project_id, db)
    query = db.query(API).filter(API.project_id == project_id)
    return query.all()


@api_router.get("/{api_id}", response_model=APIInDB)
def get_api(
    project_id: int,
    api_id: int,
    db: Session = Depends(get_db),
):
    """Get a single API by ID within a project."""
    api = get_api_or_404(api_id, project_id, db)
    return api


@api_router.put("/{api_id}", response_model=APIInDB)
def update_api(
    project_id: int,
    api_id: int,
    api_in: APIUpdate,
    db: Session = Depends(get_db),
):
    """Update an API."""
    api = get_api_or_404(api_id, project_id, db)
    
    update_data = api_in.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(api, field, value)
    
    db.commit()
    db.refresh(api)
    return api


@api_router.delete("/{api_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_api(
    project_id: int,
    api_id: int,
    db: Session = Depends(get_db),
):
    """Delete an API."""
    api = get_api_or_404(api_id, project_id, db)
    
    db.delete(api)
    db.commit()
    return None


# Endpoint endpoints within an API
endpoint_router = APIRouter(prefix="/{api_id}/endpoints", tags=["endpoints"])


@endpoint_router.get("/", response_model=List[EndpointInDB])
def list_endpoints(
    api_id: int,
    db: Session = Depends(get_db),
):
    """List endpoints within an API."""
    get_api_or_404(api_id, api_id, db)  # Verify API exists
    query = db.query(Endpoint).filter(Endpoint.api_id == api_id)
    return query.all()


@endpoint_router.get("/{endpoint_id}", response_model=EndpointInDB)
def get_endpoint(
    api_id: int,
    endpoint_id: int,
    db: Session = Depends(get_db),
):
    """Get a single endpoint by ID."""
    endpoint = (
        db.query(Endpoint)
        .filter(Endpoint.api_id == api_id, Endpoint.id == endpoint_id)
        .first()
    )
    if not endpoint:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Endpoint with id {endpoint_id} not found in API {api_id}",
        )
    return endpoint


# OpenAPI ingestion endpoint
ingest_router = APIRouter(prefix="/{project_id}/ingest", tags=["ingestion"])


@ingest_router.post("/", status_code=status.HTTP_202_ACCEPTED)
async def ingest_openapi_spec(
    project_id: int,
    file: UploadFile = File(...),
    api_name: Optional[str] = Form(None),
    api_version: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    """Upload and ingest an OpenAPI 3.x specification."""
    # Read file content
    content = await file.read()
    spec_content = content.decode("utf-8")
    
    # Ingest the spec
    from app.services.openapi import ingest_openapi
    result = ingest_openapi(spec_content, project_id, api_name, api_version, db=db)
    
    return result


# ==============================================================================
# STAGE 2: Role Routers
# ==============================================================================
role_router = APIRouter(prefix="/roles", tags=["roles"])


@project_router.post("/{project_id}/roles/", response_model=RoleInDB, status_code=status.HTTP_201_CREATED)
def create_role_for_project(
    project_id: int,
    role_in: RoleCreate,
    db: Session = Depends(get_db),
):
    """Create a new role in a project."""
    get_project_or_404(project_id, db)
    existing = (
        db.query(Role)
        .filter(Role.project_id == project_id, Role.name == role_in.name)
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Role with name '{role_in.name}' already exists in this project",
        )
    role = Role(
        project_id=project_id,
        name=role_in.name,
        description=role_in.description,
    )
    db.add(role)
    db.commit()
    db.refresh(role)
    return format_role_response(role, db)


@project_router.get("/{project_id}/roles/", response_model=List[RoleInDB])
def list_roles_for_project(
    project_id: int,
    db: Session = Depends(get_db),
):
    """List all roles in a project."""
    get_project_or_404(project_id, db)
    roles = db.query(Role).filter(Role.project_id == project_id).all()
    return [format_role_response(r, db) for r in roles]


@role_router.get("/", response_model=List[RoleInDB])
def list_roles(
    project_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    """List roles, optionally filtered by project_id."""
    query = db.query(Role)
    if project_id is not None:
        query = query.filter(Role.project_id == project_id)
    roles = query.all()
    return [format_role_response(r, db) for r in roles]


@role_router.get("/{role_id}", response_model=RoleDetail)
def get_role(
    role_id: str,
    db: Session = Depends(get_db),
):
    """Get single role by ID, including its members."""
    role = get_role_or_404(role_id, db)
    members = db.query(Identity).filter(Identity.role_id == role.id).all()
    role_in_db = format_role_response(role, db)
    return RoleDetail(
        **role_in_db.model_dump(),
        members=[RoleMember.model_validate(m) for m in members],
    )


@role_router.put("/{role_id}", response_model=RoleInDB)
def update_role(
    role_id: str,
    role_in: RoleUpdate,
    db: Session = Depends(get_db),
):
    """Update a role."""
    role = get_role_or_404(role_id, db)
    if role_in.name and role_in.name != role.name:
        existing = (
            db.query(Role)
            .filter(Role.project_id == role.project_id, Role.name == role_in.name)
            .first()
        )
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Role with name '{role_in.name}' already exists in this project",
            )
    update_data = role_in.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(role, field, value)
    db.commit()
    db.refresh(role)
    return format_role_response(role, db)


@role_router.delete("/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_role(
    role_id: str,
    db: Session = Depends(get_db),
):
    """Delete a role."""
    role = get_role_or_404(role_id, db)
    db.query(Identity).filter(Identity.role_id == role.id).update({"role_id": None})
    db.delete(role)
    db.commit()
    return None


@role_router.post("/{role_id}/assign/{identity_id}", response_model=IdentityInDB)
def assign_role_to_identity(
    role_id: str,
    identity_id: str,
    db: Session = Depends(get_db),
):
    """Assign a role to an identity."""
    role = get_role_or_404(role_id, db)
    identity = get_identity_or_404(identity_id, db)
    if role.project_id != identity.project_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Role and Identity must belong to the same project",
        )
    identity.role_id = role.id
    db.commit()
    db.refresh(identity)
    return format_identity_response(identity)


@role_router.get("/{role_id}/members", response_model=List[RoleMember])
def get_role_members(
    role_id: str,
    db: Session = Depends(get_db),
):
    """Get all identities assigned to a role."""
    role = get_role_or_404(role_id, db)
    members = db.query(Identity).filter(Identity.role_id == role.id).all()
    return [RoleMember.model_validate(m) for m in members]


# ==============================================================================
# STAGE 2: Identity Routers
# ==============================================================================
identity_router = APIRouter(prefix="/identities", tags=["identities"])


@project_router.post("/{project_id}/identities/", response_model=IdentityInDB, status_code=status.HTTP_201_CREATED)
def create_identity_for_project(
    project_id: int,
    identity_in: IdentityCreate,
    db: Session = Depends(get_db),
):
    """Create an identity in a project."""
    get_project_or_404(project_id, db)
    existing = (
        db.query(Identity)
        .filter(Identity.project_id == project_id, Identity.name == identity_in.name)
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Identity with name '{identity_in.name}' already exists in this project",
        )
    if identity_in.role_id:
        role = get_role_or_404(identity_in.role_id, db)
        if role.project_id != project_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Assigned role belongs to a different project",
            )
    
    # Credential security: reference masking if not explicitly set
    credential_ref = identity_in.credential_reference
    if not credential_ref and identity_in.credential_value:
        masked_suffix = identity_in.credential_value[-4:] if len(identity_in.credential_value) >= 4 else "••••"
        credential_ref = f"token_***{masked_suffix}"
    
    identity = Identity(
        project_id=project_id,
        role_id=identity_in.role_id,
        name=identity_in.name,
        description=identity_in.description,
        auth_type=identity_in.auth_type,
        environment=identity_in.environment,
        credential_reference=credential_ref,
        credential_status=identity_in.credential_status,
        credential_value=identity_in.credential_value,
    )
    db.add(identity)
    db.commit()
    db.refresh(identity)
    return format_identity_response(identity)


@project_router.get("/{project_id}/identities/", response_model=List[IdentityInDB])
def list_identities_for_project(
    project_id: int,
    role_id: Optional[str] = None,
    auth_type: Optional[str] = None,
    environment: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """List identities within a project with optional filtering."""
    get_project_or_404(project_id, db)
    query = db.query(Identity).filter(Identity.project_id == project_id)
    if role_id:
        query = query.filter(Identity.role_id == role_id)
    if auth_type:
        query = query.filter(Identity.auth_type == auth_type)
    if environment:
        query = query.filter(Identity.environment == environment)
    identities = query.all()
    return [format_identity_response(i) for i in identities]


@identity_router.get("/", response_model=List[IdentityInDB])
def list_identities(
    project_id: Optional[int] = None,
    role_id: Optional[str] = None,
    auth_type: Optional[str] = None,
    environment: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """List all identities with optional filtering."""
    query = db.query(Identity)
    if project_id is not None:
        query = query.filter(Identity.project_id == project_id)
    if role_id:
        query = query.filter(Identity.role_id == role_id)
    if auth_type:
        query = query.filter(Identity.auth_type == auth_type)
    if environment:
        query = query.filter(Identity.environment == environment)
    identities = query.all()
    return [format_identity_response(i) for i in identities]


@identity_router.get("/{identity_id}", response_model=IdentityDetail)
def get_identity(
    identity_id: str,
    db: Session = Depends(get_db),
):
    """Get identity by ID."""
    identity = get_identity_or_404(identity_id, db)
    base_res = format_identity_response(identity)
    owned_count = (
        db.query(ResourceOwnership)
        .filter(ResourceOwnership.identity_id == identity.id)
        .count()
    )
    return IdentityDetail(
        **base_res.model_dump(),
        owned_resources_count=owned_count,
    )


@identity_router.put("/{identity_id}", response_model=IdentityInDB)
def update_identity(
    identity_id: str,
    identity_in: IdentityUpdate,
    db: Session = Depends(get_db),
):
    """Update identity details."""
    identity = get_identity_or_404(identity_id, db)
    if identity_in.name and identity_in.name != identity.name:
        existing = (
            db.query(Identity)
            .filter(Identity.project_id == identity.project_id, Identity.name == identity_in.name)
            .first()
        )
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Identity with name '{identity_in.name}' already exists in this project",
            )
    if identity_in.role_id:
        role = get_role_or_404(identity_in.role_id, db)
        if role.project_id != identity.project_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Assigned role belongs to a different project",
            )
    
    update_data = identity_in.model_dump(exclude_unset=True)
    if "credential_value" in update_data and update_data["credential_value"]:
        if "credential_reference" not in update_data or not update_data["credential_reference"]:
            val = update_data["credential_value"]
            masked_suffix = val[-4:] if len(val) >= 4 else "••••"
            identity.credential_reference = f"token_***{masked_suffix}"
    for field, value in update_data.items():
        setattr(identity, field, value)
    db.commit()
    db.refresh(identity)
    return format_identity_response(identity)


@identity_router.delete("/{identity_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_identity(
    identity_id: str,
    db: Session = Depends(get_db),
):
    """Delete an identity and cascade ownerships."""
    identity = get_identity_or_404(identity_id, db)
    db.delete(identity)
    db.commit()
    return None


@identity_router.put("/{identity_id}/role", response_model=IdentityInDB)
def set_identity_role(
    identity_id: str,
    assign_in: IdentityRoleAssign,
    db: Session = Depends(get_db),
):
    """Assign or unassign a role for an identity."""
    identity = get_identity_or_404(identity_id, db)
    if assign_in.role_id:
        role = get_role_or_404(assign_in.role_id, db)
        if role.project_id != identity.project_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Role and Identity must belong to the same project",
            )
        identity.role_id = role.id
    else:
        identity.role_id = None
    db.commit()
    db.refresh(identity)
    return format_identity_response(identity)


# ==============================================================================
# STAGE 2: Resource Routers
# ==============================================================================
resource_router = APIRouter(prefix="/resources", tags=["resources"])


@project_router.post("/{project_id}/resources/", response_model=ResourceInDB, status_code=status.HTTP_201_CREATED)
def create_resource_for_project(
    project_id: int,
    resource_in: ResourceCreate,
    db: Session = Depends(get_db),
):
    """Create a resource in a project."""
    get_project_or_404(project_id, db)
    existing = (
        db.query(Resource)
        .filter(Resource.project_id == project_id, Resource.name == resource_in.name)
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Resource with name '{resource_in.name}' already exists in this project",
        )
    if resource_in.api_id:
        api = db.query(API).filter(API.id == resource_in.api_id).first()
        if not api or api.project_id != project_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"API with id {resource_in.api_id} not found in this project",
            )
    resource = Resource(
        project_id=project_id,
        api_id=resource_in.api_id,
        name=resource_in.name,
        description=resource_in.description,
        resource_type=resource_in.resource_type,
    )
    db.add(resource)
    db.commit()
    db.refresh(resource)
    return format_resource_response(resource, db)


@project_router.get("/{project_id}/resources/", response_model=List[ResourceInDB])
def list_resources_for_project(
    project_id: int,
    db: Session = Depends(get_db),
):
    """List resources in a project."""
    get_project_or_404(project_id, db)
    resources = db.query(Resource).filter(Resource.project_id == project_id).all()
    return [format_resource_response(r, db) for r in resources]


@resource_router.get("/", response_model=List[ResourceInDB])
def list_resources(
    project_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    """List resources, optionally filtered by project_id."""
    query = db.query(Resource)
    if project_id is not None:
        query = query.filter(Resource.project_id == project_id)
    resources = query.all()
    return [format_resource_response(r, db) for r in resources]


@resource_router.get("/{resource_id}", response_model=ResourceDetail)
def get_resource(
    resource_id: str,
    db: Session = Depends(get_db),
):
    """Get single resource by ID with ownerships and associated endpoints."""
    resource = get_resource_or_404(resource_id, db)
    ownerships = (
        db.query(ResourceOwnership)
        .filter(ResourceOwnership.resource_id == resource.id)
        .all()
    )
    endpoints = (
        db.query(Endpoint)
        .filter(Endpoint.resource_id == resource.id)
        .all()
    )
    
    ownerships_data = []
    for o in ownerships:
        o_data = ResourceOwnershipInDB.model_validate(o)
        o_data.identity_name = o.identity.name if o.identity else None
        o_data.resource_name = resource.name
        ownerships_data.append(o_data)
        
    base_data = format_resource_response(resource, db)
    return ResourceDetail(
        **base_data.model_dump(),
        ownerships=ownerships_data,
        endpoints=[format_endpoint_response(ep) for ep in endpoints],
    )


@resource_router.put("/{resource_id}", response_model=ResourceInDB)
def update_resource(
    resource_id: str,
    resource_in: ResourceUpdate,
    db: Session = Depends(get_db),
):
    """Update resource details."""
    resource = get_resource_or_404(resource_id, db)
    if resource_in.name and resource_in.name != resource.name:
        existing = (
            db.query(Resource)
            .filter(Resource.project_id == resource.project_id, Resource.name == resource_in.name)
            .first()
        )
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Resource with name '{resource_in.name}' already exists in this project",
            )
    update_data = resource_in.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(resource, field, value)
    db.commit()
    db.refresh(resource)
    return format_resource_response(resource, db)


@resource_router.delete("/{resource_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_resource(
    resource_id: str,
    db: Session = Depends(get_db),
):
    """Delete resource (disassociates endpoints and deletes ownerships)."""
    resource = get_resource_or_404(resource_id, db)
    db.query(Endpoint).filter(Endpoint.resource_id == resource.id).update({"resource_id": None})
    db.delete(resource)
    db.commit()
    return None


@resource_router.post("/{resource_id}/ownerships/", response_model=ResourceOwnershipInDB, status_code=status.HTTP_201_CREATED)
def create_resource_ownership(
    resource_id: str,
    ownership_in: ResourceOwnershipCreate,
    db: Session = Depends(get_db),
):
    """Create ownership connecting a Resource to an Identity."""
    resource = get_resource_or_404(resource_id, db)
    identity = get_identity_or_404(ownership_in.identity_id, db)
    if resource.project_id != identity.project_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Resource and Identity must belong to the same project",
        )
    ownership = ResourceOwnership(
        resource_id=resource.id,
        identity_id=identity.id,
        resource_instance_id=ownership_in.resource_instance_id,
        ownership_type=ownership_in.ownership_type,
        description=ownership_in.description,
    )
    db.add(ownership)
    db.commit()
    db.refresh(ownership)
    out = ResourceOwnershipInDB.model_validate(ownership)
    out.identity_name = identity.name
    out.resource_name = resource.name
    return out


@resource_router.get("/{resource_id}/ownerships/", response_model=List[ResourceOwnershipInDB])
def list_resource_ownerships(
    resource_id: str,
    db: Session = Depends(get_db),
):
    """List ownership records for a resource."""
    resource = get_resource_or_404(resource_id, db)
    ownerships = (
        db.query(ResourceOwnership)
        .filter(ResourceOwnership.resource_id == resource.id)
        .all()
    )
    res_list = []
    for o in ownerships:
        out = ResourceOwnershipInDB.model_validate(o)
        out.identity_name = o.identity.name if o.identity else None
        out.resource_name = resource.name
        res_list.append(out)
    return res_list


@resource_router.get("/{resource_id}/endpoints", response_model=List[EndpointInDB])
def list_endpoints_for_resource(
    resource_id: str,
    db: Session = Depends(get_db),
):
    """List all endpoints associated with a resource."""
    resource = get_resource_or_404(resource_id, db)
    endpoints = db.query(Endpoint).filter(Endpoint.resource_id == resource.id).all()
    return [format_endpoint_response(ep) for ep in endpoints]


# ==============================================================================
# STAGE 2: Ownership & Endpoint Association Routers
# ==============================================================================
ownership_router = APIRouter(prefix="/ownerships", tags=["ownerships"])


@ownership_router.delete("/{ownership_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_ownership(
    ownership_id: str,
    db: Session = Depends(get_db),
):
    """Delete an ownership record."""
    ownership = get_ownership_or_404(ownership_id, db)
    db.delete(ownership)
    db.commit()
    return None


endpoint_assoc_router = APIRouter(prefix="/endpoints", tags=["endpoints"])


@endpoint_assoc_router.put("/{endpoint_id}/resource", response_model=EndpointInDB)
def associate_endpoint_with_resource(
    endpoint_id: int,
    assign_in: EndpointResourceAssign,
    db: Session = Depends(get_db),
):
    """Associate or disassociate an endpoint with a resource."""
    endpoint = db.query(Endpoint).filter(Endpoint.id == endpoint_id).first()
    if not endpoint:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Endpoint with id {endpoint_id} not found",
        )
    if assign_in.resource_id:
        resource = get_resource_or_404(assign_in.resource_id, db)
        endpoint.resource_id = resource.id
    else:
        endpoint.resource_id = None
    db.commit()
    db.refresh(endpoint)
    return format_endpoint_response(endpoint)


# ==============================================================================
# STAGE 2: Authorization Model View
# ==============================================================================
@project_router.get("/{project_id}/authorization-model", response_model=AuthorizationModelView)
def get_authorization_model(
    project_id: int,
    db: Session = Depends(get_db),
):
    """Get the full authorization model hierarchy (Identity -> Role -> Resources)."""
    project = get_project_or_404(project_id, db)
    identities = db.query(Identity).filter(Identity.project_id == project.id).all()
    
    nodes: List[AuthModelIdentityNode] = []
    for identity in identities:
        role_name = identity.role.name if identity.role else "Unassigned"
        role_id = identity.role_id
        
        # Resources owned by this identity
        ownerships = (
            db.query(ResourceOwnership)
            .filter(ResourceOwnership.identity_id == identity.id)
            .all()
        )
        
        resource_items: List[AuthModelResourceItem] = []
        for o in ownerships:
            res = o.resource
            if not res:
                continue
            endpoints = db.query(Endpoint).filter(Endpoint.resource_id == res.id).all()
            endpoint_labels = [f"{ep.method} {ep.path}" for ep in endpoints]
            resource_items.append(
                AuthModelResourceItem(
                    resource_id=res.id,
                    resource_name=res.name,
                    resource_type=res.resource_type,
                    instance_id=o.resource_instance_id,
                    ownership_type=o.ownership_type,
                    associated_endpoints=endpoint_labels,
                )
            )
        
        nodes.append(
            AuthModelIdentityNode(
                identity_id=identity.id,
                identity_name=identity.name,
                role_id=role_id,
                role_name=role_name,
                auth_type=identity.auth_type,
                environment=identity.environment,
                credential_status=identity.credential_status,
                resources=resource_items,
            )
        )
    
    total_roles = db.query(Role).filter(Role.project_id == project.id).count()
    total_resources = db.query(Resource).filter(Resource.project_id == project.id).count()
    
    return AuthorizationModelView(
        project_id=project.id,
        project_name=project.name,
        nodes=nodes,
        total_identities=len(identities),
        total_roles=total_roles,
        total_resources=total_resources,
    )


# ==============================================================================
# STAGE 3: Security Testing & Findings Routers
# ==============================================================================

security_test_router = APIRouter(tags=["Security Tests"])
finding_router = APIRouter(tags=["Findings"])


@security_test_router.post("/projects/{project_id}/security-tests/", response_model=SecurityTestInDB, status_code=status.HTTP_201_CREATED)
def create_security_test(
    project_id: int,
    test_in: SecurityTestCreate,
    db: Session = Depends(get_db),
):
    """Create a new BOLA security test for an endpoint in an authorized project."""
    project = get_project_or_404(project_id, db)

    # 1. Target Authorization Check (SAFETY)
    if project.authorization_status.lower() != "authorized":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target project has not been authorized for security testing. Please set project authorization status to 'authorized'.",
        )

    # 2. Validate Endpoint
    endpoint = db.query(Endpoint).filter(Endpoint.id == test_in.endpoint_id).first()
    if not endpoint:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Endpoint with id {test_in.endpoint_id} not found",
        )
    if endpoint.api.project_id != project_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Endpoint belongs to a different project",
        )

    # 3. Safe HTTP method validation
    if endpoint.method.upper() not in ["GET", "HEAD"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Method '{endpoint.method}' is not supported. Only safe HTTP methods (GET, HEAD) are allowed for security testing.",
        )

    is_bfla = (test_in.test_type or "BOLA").upper() == "BFLA"
    is_prop = (test_in.test_type or "BOLA").upper() == "PROPERTY_EXPOSURE"
    is_auth = (test_in.test_type or "BOLA").upper() in ("AUTH_MISSING", "AUTH_INVALID", "AUTH_MALFORMED", "AUTH_EXPIRED", "AUTH_SCHEME")

    # 4. Validate Attacker Identity
    attacker = None
    if test_in.attacker_identity_id:
        attacker = get_identity_or_404(test_in.attacker_identity_id, db)
        if attacker.project_id != project_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Attacker identity belongs to a different project",
            )
    elif not is_auth:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="attacker_identity_id is required",
        )

    victim_resource_id = None
    victim_instance_id = None
    attacker_instance_id = None
    victim_identity_id = None
    expected_access = test_in.expected_access or "DENY"

    if is_auth:
        # Authentication testing does not require victim identity or domain resource binding
        pass
    elif is_prop:
        # Property Exposure testing: check property exposure for role on resource
        res_id = test_in.victim_resource_id or endpoint.resource_id
        if not res_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Endpoint or test configuration must be associated with a domain resource for property exposure testing.",
            )
        victim_resource = get_resource_or_404(res_id, db)
        if victim_resource.project_id != project_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Victim resource belongs to a different project",
            )
        victim_resource_id = victim_resource.id

        if test_in.victim_identity_id:
            victim_ident = get_identity_or_404(test_in.victim_identity_id, db)
            if victim_ident.project_id != project_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Victim identity belongs to a different project",
                )
            victim_identity_id = victim_ident.id

        victim_instance_id = test_in.victim_resource_instance_id
        if not victim_instance_id:
            query = db.query(ResourceOwnership).filter(
                ResourceOwnership.resource_id == victim_resource.id,
                ResourceOwnership.resource_instance_id.isnot(None),
            )
            if test_in.victim_identity_id:
                query = query.filter(ResourceOwnership.identity_id == test_in.victim_identity_id)
            ownership = query.first()
            if ownership and ownership.resource_instance_id:
                victim_instance_id = ownership.resource_instance_id

        attacker_instance_id = test_in.attacker_resource_instance_id

    elif is_bfla:
        # BFLA testing: function-level authorization
        # Validate attacker credentials if not anonymous
        is_anon = (
            attacker.auth_type.lower() == "none"
            or attacker.name.lower() == "anonymous"
            or (not attacker.credential_value and not attacker.credential_reference)
        )
        # BFLA allows anonymous testing against protected endpoints
    else:
        # BOLA testing: resource-level authorization
        if not endpoint.resource_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Endpoint must be associated with a domain resource before configuring BOLA tests.",
            )

        if not attacker.credential_value and not attacker.credential_reference:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Attacker identity must have configured authentication credentials.",
            )

        # Validate Victim Resource
        res_id = test_in.victim_resource_id or endpoint.resource_id
        victim_resource = get_resource_or_404(res_id, db)
        if victim_resource.project_id != project_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Victim resource belongs to a different project",
            )
        victim_resource_id = victim_resource.id

        # Validate Victim Identity if provided
        if test_in.victim_identity_id:
            victim_ident = get_identity_or_404(test_in.victim_identity_id, db)
            if victim_ident.project_id != project_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Victim identity belongs to a different project",
                )
            victim_identity_id = victim_ident.id

        # Resolve Victim Resource Instance ID
        victim_instance_id = test_in.victim_resource_instance_id
        if not victim_instance_id:
            query = db.query(ResourceOwnership).filter(
                ResourceOwnership.resource_id == victim_resource.id,
                ResourceOwnership.resource_instance_id.isnot(None),
            )
            if test_in.victim_identity_id:
                query = query.filter(ResourceOwnership.identity_id == test_in.victim_identity_id)
            ownership = query.first()
            if ownership and ownership.resource_instance_id:
                victim_instance_id = ownership.resource_instance_id

        if not victim_instance_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A victim resource instance identifier (for path substitution or target verification) is required.",
            )

        # Resolve Attacker Resource Instance ID (if any, for baseline)
        attacker_instance_id = test_in.attacker_resource_instance_id
        if not attacker_instance_id:
            att_ownership = db.query(ResourceOwnership).filter(
                ResourceOwnership.resource_id == victim_resource.id,
                ResourceOwnership.identity_id == attacker.id,
                ResourceOwnership.resource_instance_id.isnot(None),
            ).first()
            if att_ownership and att_ownership.resource_instance_id:
                attacker_instance_id = att_ownership.resource_instance_id

    # Store configuration
    cfg_str = json.dumps(test_in.configuration) if test_in.configuration else None

    security_test = SecurityTest(
        project_id=project_id,
        endpoint_id=endpoint.id,
        test_type=test_in.test_type or "BOLA",
        attacker_identity_id=attacker.id if attacker else None,
        victim_identity_id=victim_identity_id,
        victim_resource_id=victim_resource_id,
        victim_resource_instance_id=victim_instance_id,
        attacker_resource_instance_id=attacker_instance_id,
        expected_access=expected_access,
        status="configured",
        configuration=cfg_str,
    )
    db.add(security_test)
    db.commit()
    db.refresh(security_test)
    return format_security_test_response(security_test, db)


@security_test_router.get("/projects/{project_id}/security-tests/", response_model=List[SecurityTestInDB])
def list_security_tests_for_project(
    project_id: int,
    test_type: Optional[str] = None,
    status_filter: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """List all security tests configured for a project."""
    get_project_or_404(project_id, db)
    query = db.query(SecurityTest).filter(SecurityTest.project_id == project_id)
    if test_type:
        query = query.filter(SecurityTest.test_type == test_type)
    if status_filter:
        query = query.filter(SecurityTest.status == status_filter)
    tests = query.order_by(SecurityTest.created_at.desc()).all()
    return [format_security_test_response(t, db) for t in tests]


@security_test_router.get("/security-tests/{test_id}", response_model=SecurityTestInDB)
def get_security_test(
    test_id: str,
    db: Session = Depends(get_db),
):
    """Get security test details."""
    test = get_security_test_or_404(test_id, db)
    return format_security_test_response(test, db)


@security_test_router.post("/security-tests/{test_id}/execute", response_model=TestExecutionInDB)
async def execute_security_test(
    test_id: str,
    db: Session = Depends(get_db),
):
    """Execute a configured security test asynchronously (BOLA, BFLA, or PROPERTY_EXPOSURE)."""
    test = get_security_test_or_404(test_id, db)

    # Safety validation
    if not test.project or test.project.authorization_status.lower() != "authorized":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target project has not been authorized for security testing. Set project authorization status to 'authorized'.",
        )

    from app.main import app as fastapi_app
    from app.services.security_engine.evaluator import BOLAEngine
    from app.services.security_engine.bfla_engine import BFLAEngine
    from app.services.security_engine.property_engine import PropertyExposureEngine
    from app.services.security_engine.auth_engine import AuthenticationEngine

    t_type = test.test_type.upper()
    if t_type == "BFLA":
        engine = BFLAEngine(db=db, app=fastapi_app)
    elif t_type == "PROPERTY_EXPOSURE":
        engine = PropertyExposureEngine(db=db, app=fastapi_app)
    elif t_type in ("AUTH_MISSING", "AUTH_INVALID", "AUTH_MALFORMED", "AUTH_EXPIRED", "AUTH_SCHEME"):
        engine = AuthenticationEngine(db=db, app=fastapi_app)
    else:
        engine = BOLAEngine(db=db, app=fastapi_app)

    execution = await engine.execute_test(test)
    return format_execution_response(execution)


@security_test_router.post("/projects/{project_id}/generate-bfla-tests", response_model=BFLATestGenerateResult)
def generate_bfla_tests_for_project(
    project_id: int,
    request_in: BFLATestGenerateRequest,
    db: Session = Depends(get_db),
):
    """Automatically generate controlled BFLA security tests for safe endpoints."""
    from app.services.security_engine.generator import BFLATestGenerator
    try:
        created_tests, skipped = BFLATestGenerator.generate_tests(
            db=db,
            project_id=project_id,
            endpoint_ids=request_in.endpoint_ids if not request_in.target_all_safe_endpoints else None,
        )
        return BFLATestGenerateResult(
            generated_count=len(created_tests),
            skipped_count=skipped,
            tests=[format_security_test_response(t, db) for t in created_tests],
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@security_test_router.get("/security-tests/{test_id}/executions", response_model=List[TestExecutionInDB])
def list_test_executions(
    test_id: str,
    db: Session = Depends(get_db),
):
    """List executions for a security test."""
    get_security_test_or_404(test_id, db)
    executions = (
        db.query(TestExecution)
        .filter(TestExecution.security_test_id == test_id)
        .order_by(TestExecution.created_at.desc())
        .all()
    )
    return [format_execution_response(e) for e in executions]


@security_test_router.get("/executions/{execution_id}", response_model=TestExecutionInDB)
def get_test_execution(
    execution_id: str,
    db: Session = Depends(get_db),
):
    """Get test execution details including redacted evidence."""
    execution = get_execution_or_404(execution_id, db)
    return format_execution_response(execution)


# --- Findings Routes ---

AUTH_FINDING_TYPES = [
    "AUTHENTICATION_BYPASS",
    "INVALID_AUTH_ACCEPTED",
    "MALFORMED_AUTH_HANDLING",
    "EXPIRED_AUTH_ACCEPTED",
    "AUTHENTICATION_INCONSISTENCY",
]


@finding_router.get("/projects/{project_id}/findings", response_model=List[FindingInDB])
@finding_router.get("/projects/{project_id}/findings/", response_model=List[FindingInDB])
def list_findings_for_project(
    project_id: int,
    severity: Optional[str] = None,
    status_filter: Optional[str] = None,
    type_filter: Optional[str] = None,
    category: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """List findings for a project with optional filtering by severity, status, category, or type."""
    get_project_or_404(project_id, db)
    query = db.query(Finding).filter(Finding.project_id == project_id)
    if severity:
        query = query.filter(Finding.severity == severity.upper())
    if status_filter:
        query = query.filter(Finding.status == status_filter.upper())
    if type_filter:
        if type_filter.upper() == "AUTHENTICATION":
            query = query.filter(Finding.type.in_(AUTH_FINDING_TYPES))
        else:
            query = query.filter(Finding.type == type_filter.upper())
    if category:
        cat = category.upper().strip()
        if cat == "AUTHENTICATION":
            query = query.filter(Finding.type.in_(AUTH_FINDING_TYPES))
        elif cat == "BOLA":
            query = query.filter(Finding.type == "BOLA")
        elif cat == "BFLA":
            query = query.filter(Finding.type == "BFLA")
        elif cat == "PROPERTY_EXPOSURE":
            query = query.filter(Finding.type == "PROPERTY_EXPOSURE")
    findings = query.order_by(Finding.created_at.desc()).all()
    return [format_finding_response(f, db) for f in findings]


@finding_router.get("/findings/{finding_id}", response_model=FindingDetail)
def get_finding(
    finding_id: str,
    db: Session = Depends(get_db),
):
    """Get detailed finding information including evidence and remediation."""
    finding = get_finding_or_404(finding_id, db)
    return format_finding_detail(finding, db)


@finding_router.get("/findings/{finding_id}/evidence", response_model=EvidenceInDB)
def get_finding_evidence(
    finding_id: str,
    db: Session = Depends(get_db),
):
    """Get raw evidence for a finding."""
    finding = get_finding_or_404(finding_id, db)
    evidence = db.query(Evidence).filter(Evidence.finding_id == finding.id).first()
    if not evidence and finding.execution:
        evidence = finding.execution.evidence
    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence for finding {finding_id} not found",
        )
    return format_evidence_response(evidence)


@finding_router.post("/findings/{finding_id}/replay", response_model=TestExecutionInDB)
async def replay_test_for_finding(
    finding_id: str,
    db: Session = Depends(get_db),
):
    """Replay security test for an existing finding in the same authorized context."""
    finding = get_finding_or_404(finding_id, db)
    test = finding.security_test
    if not test:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Associated security test not found",
        )
    if not test.project or test.project.authorization_status.lower() != "authorized":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target project has not been authorized for security testing. Please set project authorization status to 'authorized'.",
        )

    from app.main import app as fastapi_app
    from app.services.security_engine.evaluator import BOLAEngine
    from app.services.security_engine.bfla_engine import BFLAEngine
    from app.services.security_engine.property_engine import PropertyExposureEngine
    from app.services.security_engine.auth_engine import AuthenticationEngine

    t_type = test.test_type.upper() if test else ""
    f_type = finding.type.upper() if finding else ""
    if t_type == "BFLA" or f_type == "BFLA":
        engine = BFLAEngine(db=db, app=fastapi_app)
    elif t_type == "PROPERTY_EXPOSURE" or f_type == "PROPERTY_EXPOSURE":
        engine = PropertyExposureEngine(db=db, app=fastapi_app)
    elif (
        t_type in ("AUTH_MISSING", "AUTH_INVALID", "AUTH_MALFORMED", "AUTH_EXPIRED", "AUTH_SCHEME")
        or f_type in ("AUTHENTICATION_BYPASS", "INVALID_AUTH_ACCEPTED", "MALFORMED_AUTH_HANDLING", "EXPIRED_AUTH_ACCEPTED", "AUTHENTICATION_INCONSISTENCY")
    ):
        engine = AuthenticationEngine(db=db, app=fastapi_app)
    else:
        engine = BOLAEngine(db=db, app=fastapi_app)

    execution = await engine.execute_test(test)
    return format_execution_response(execution)


# --- Authorization Matrix Routes ---

matrix_router = APIRouter(tags=["Authorization Matrix"])


@matrix_router.get("/projects/{project_id}/authorization-matrix", response_model=AuthorizationMatrixView)
def get_authorization_matrix(
    project_id: int,
    db: Session = Depends(get_db),
):
    """
    Get the complete Authorization Matrix (Identity/Role x Endpoint x HTTP Method x Expected Access)
    with latest execution status and open findings.
    """
    project = get_project_or_404(project_id, db)
    roles = db.query(Role).filter(Role.project_id == project_id).order_by(Role.name).all()
    endpoints = (
        db.query(Endpoint)
        .join(Endpoint.api)
        .filter(Endpoint.api.has(project_id=project_id))
        .order_by(Endpoint.path, Endpoint.method)
        .all()
    )

    # Fetch all matrix rules for this project
    rules = db.query(AuthorizationMatrixRule).filter(AuthorizationMatrixRule.project_id == project_id).all()
    rule_map = {(r.endpoint_id, r.role_id): r for r in rules}

    # Fetch policies
    policies = db.query(EndpointAuthorizationPolicy).filter(EndpointAuthorizationPolicy.project_id == project_id).all()
    policy_map = {p.endpoint_id: p for p in policies}

    # Fetch BFLA security tests and their latest executions / findings
    bfla_tests = db.query(SecurityTest).filter(
        SecurityTest.project_id == project_id,
        SecurityTest.test_type == "BFLA",
    ).all()

    test_map = {}
    for t in bfla_tests:
        if t.attacker_identity and t.attacker_identity.role_id:
            test_map[(t.endpoint_id, t.attacker_identity.role_id)] = t

    open_findings = db.query(Finding).filter(
        Finding.project_id == project_id,
        Finding.type == "BFLA",
        Finding.status != "RESOLVED",
    ).all()
    finding_map = {}
    for f in open_findings:
        if f.endpoint_id and f.attacker_role_id:
            finding_map[(f.endpoint_id, f.attacker_role_id)] = f

    endpoint_rows = []
    total_cells = 0
    confirmed_count = 0
    pass_count = 0
    untested_count = 0

    roles_data = [format_role_response(r, db) for r in roles]

    for ep in endpoints:
        policy = policy_map.get(ep.id)
        cells = {}

        for role in roles:
            total_cells += 1
            rule = rule_map.get((ep.id, role.id))
            expected_access = "UNKNOWN"

            if rule and rule.expected_access in ["ALLOW", "DENY", "UNKNOWN"]:
                expected_access = rule.expected_access
            elif policy:
                if any(ar.id == role.id for ar in policy.allowed_roles):
                    expected_access = "ALLOW"
                elif any(dr.id == role.id for dr in policy.denied_roles):
                    expected_access = "DENY"

            # Check test and execution status
            test = test_map.get((ep.id, role.id))
            test_status = "NOT TESTED"
            sec_test_id = None
            latest_exec_id = None
            latest_result = None
            finding_id = None

            if test:
                sec_test_id = test.id
                latest_exec = (
                    db.query(TestExecution)
                    .filter(TestExecution.security_test_id == test.id)
                    .order_by(TestExecution.created_at.desc())
                    .first()
                )
                if latest_exec and latest_exec.result:
                    test_status = latest_exec.result
                    latest_exec_id = latest_exec.id
                    latest_result = latest_exec.result

            # Check finding map
            f = finding_map.get((ep.id, role.id))
            if f:
                finding_id = f.id
                test_status = "CONFIRMED"
                latest_result = "CONFIRMED"

            if test_status == "CONFIRMED":
                confirmed_count += 1
            elif test_status == "PASS":
                pass_count += 1
            else:
                untested_count += 1

            cells[role.id] = AuthorizationMatrixCell(
                endpoint_id=ep.id,
                role_id=role.id,
                role_name=role.name,
                http_method=ep.method,
                expected_access=expected_access,
                test_status=test_status,
                security_test_id=sec_test_id,
                latest_execution_id=latest_exec_id,
                latest_result=latest_result,
                finding_id=finding_id,
            )

        endpoint_rows.append(
            AuthorizationMatrixEndpointRow(
                endpoint_id=ep.id,
                method=ep.method,
                path=ep.path,
                summary=ep.summary,
                authentication_required=policy.authentication_required if policy else True,
                policy_notes=policy.notes if policy else None,
                cells=cells,
            )
        )

    return AuthorizationMatrixView(
        project_id=project.id,
        project_name=project.name,
        roles=roles_data,
        endpoints=endpoint_rows,
        total_cells=total_cells,
        confirmed_count=confirmed_count,
        pass_count=pass_count,
        untested_count=untested_count,
    )


@matrix_router.post("/projects/{project_id}/authorization-matrix/rules", response_model=AuthorizationMatrixRuleInDB)
def create_or_update_matrix_rule(
    project_id: int,
    rule_in: AuthorizationMatrixRuleCreate,
    db: Session = Depends(get_db),
):
    """Create or update an authorization matrix rule."""
    get_project_or_404(project_id, db)
    endpoint = get_endpoint_or_404(rule_in.endpoint_id, db)
    if endpoint.api and endpoint.api.project_id != project_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Endpoint belongs to a different project",
        )

    if rule_in.role_id:
        role = get_role_or_404(rule_in.role_id, db)
        if role.project_id != project_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Role belongs to a different project",
            )

    if rule_in.identity_id:
        ident = get_identity_or_404(rule_in.identity_id, db)
        if ident.project_id != project_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Identity belongs to a different project",
            )

    expected_access = rule_in.expected_access.upper().strip()
    if expected_access not in ["ALLOW", "DENY", "UNKNOWN"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid expected access '{rule_in.expected_access}'. Must be ALLOW, DENY, or UNKNOWN.",
        )

    # Upsert rule
    rule = (
        db.query(AuthorizationMatrixRule)
        .filter(
            AuthorizationMatrixRule.project_id == project_id,
            AuthorizationMatrixRule.endpoint_id == rule_in.endpoint_id,
            AuthorizationMatrixRule.role_id == rule_in.role_id,
            AuthorizationMatrixRule.http_method == rule_in.http_method.upper(),
        )
        .first()
    )

    if rule:
        rule.expected_access = expected_access
    else:
        rule = AuthorizationMatrixRule(
            project_id=project_id,
            endpoint_id=rule_in.endpoint_id,
            role_id=rule_in.role_id,
            identity_id=rule_in.identity_id,
            http_method=rule_in.http_method.upper(),
            expected_access=expected_access,
        )
        db.add(rule)

    db.commit()
    db.refresh(rule)
    return format_rule_response(rule, db)


@matrix_router.put("/projects/{project_id}/authorization-matrix/rules", response_model=List[AuthorizationMatrixRuleInDB])
def bulk_update_matrix_rules(
    project_id: int,
    rules_in: List[AuthorizationMatrixRuleCreate],
    db: Session = Depends(get_db),
):
    """Bulk upsert authorization matrix rules for a project."""
    get_project_or_404(project_id, db)
    results = []
    for r_in in rules_in:
        endpoint = get_endpoint_or_404(r_in.endpoint_id, db)
        if endpoint.api and endpoint.api.project_id != project_id:
            continue

        if r_in.role_id:
            role = get_role_or_404(r_in.role_id, db)
            if role.project_id != project_id:
                continue

        expected_access = r_in.expected_access.upper().strip()
        if expected_access not in ["ALLOW", "DENY", "UNKNOWN"]:
            continue

        rule = (
            db.query(AuthorizationMatrixRule)
            .filter(
                AuthorizationMatrixRule.project_id == project_id,
                AuthorizationMatrixRule.endpoint_id == r_in.endpoint_id,
                AuthorizationMatrixRule.role_id == r_in.role_id,
                AuthorizationMatrixRule.http_method == r_in.http_method.upper(),
            )
            .first()
        )
        if rule:
            rule.expected_access = expected_access
        else:
            rule = AuthorizationMatrixRule(
                project_id=project_id,
                endpoint_id=r_in.endpoint_id,
                role_id=r_in.role_id,
                identity_id=r_in.identity_id,
                http_method=r_in.http_method.upper(),
                expected_access=expected_access,
            )
            db.add(rule)
        results.append(rule)

    db.commit()
    for r in results:
        db.refresh(r)
    return [format_rule_response(r, db) for r in results]


@matrix_router.delete("/authorization-matrix/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_matrix_rule(
    rule_id: str,
    db: Session = Depends(get_db),
):
    """Delete an authorization matrix rule."""
    rule = db.query(AuthorizationMatrixRule).filter(AuthorizationMatrixRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule {rule_id} not found")
    db.delete(rule)
    db.commit()
    return None


# --- Endpoint Authorization Policy Routes ---

policy_router = APIRouter(tags=["Endpoint Authorization Policies"])


@policy_router.get("/endpoints/{endpoint_id}/policy", response_model=EndpointAuthorizationPolicyInDB)
def get_endpoint_policy(
    endpoint_id: int,
    db: Session = Depends(get_db),
):
    """Get authorization policy for an endpoint."""
    endpoint = get_endpoint_or_404(endpoint_id, db)
    policy = db.query(EndpointAuthorizationPolicy).filter(EndpointAuthorizationPolicy.endpoint_id == endpoint_id).first()
    if not policy:
        project_id = endpoint.api.project_id if endpoint.api else 1
        policy = EndpointAuthorizationPolicy(
            project_id=project_id,
            endpoint_id=endpoint.id,
            authentication_required=True,
            notes="",
        )
        db.add(policy)
        db.commit()
        db.refresh(policy)
    return format_policy_response(policy, db)


@policy_router.put("/endpoints/{endpoint_id}/policy", response_model=EndpointAuthorizationPolicyInDB)
def update_endpoint_policy(
    endpoint_id: int,
    policy_in: EndpointAuthorizationPolicyUpdate,
    db: Session = Depends(get_db),
):
    """Create or update endpoint authorization policy."""
    endpoint = get_endpoint_or_404(endpoint_id, db)
    project_id = endpoint.api.project_id if endpoint.api else 1

    policy = db.query(EndpointAuthorizationPolicy).filter(EndpointAuthorizationPolicy.endpoint_id == endpoint_id).first()
    if not policy:
        policy = EndpointAuthorizationPolicy(
            project_id=project_id,
            endpoint_id=endpoint_id,
            authentication_required=policy_in.authentication_required if policy_in.authentication_required is not None else True,
            notes=policy_in.notes,
        )
        db.add(policy)
    else:
        if policy_in.authentication_required is not None:
            policy.authentication_required = policy_in.authentication_required
        if policy_in.notes is not None:
            policy.notes = policy_in.notes

    if policy_in.allowed_role_ids is not None:
        allowed_roles = []
        for r_id in policy_in.allowed_role_ids:
            role = get_role_or_404(r_id, db)
            if role.project_id != project_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Role {role.name} belongs to a different project",
                )
            allowed_roles.append(role)
        policy.allowed_roles = allowed_roles

    if policy_in.denied_role_ids is not None:
        denied_roles = []
        for r_id in policy_in.denied_role_ids:
            role = get_role_or_404(r_id, db)
            if role.project_id != project_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Role {role.name} belongs to a different project",
                )
            denied_roles.append(role)
        policy.denied_roles = denied_roles

    db.commit()
    db.refresh(policy)
    return format_policy_response(policy, db)


# --- Property Security Routes ---

property_router = APIRouter(tags=["Property Security"])


@property_router.get("/resources/{resource_id}/properties", response_model=List[ResourcePropertyInDB])
def list_resource_properties(
    resource_id: str,
    db: Session = Depends(get_db),
):
    """List all defined properties for a resource."""
    get_resource_or_404(resource_id, db)
    props = (
        db.query(ResourceProperty)
        .filter(ResourceProperty.resource_id == resource_id)
        .order_by(ResourceProperty.name)
        .all()
    )
    return [format_property_response(p) for p in props]


@property_router.post("/resources/{resource_id}/properties", response_model=ResourcePropertyInDB, status_code=status.HTTP_201_CREATED)
def create_resource_property(
    resource_id: str,
    prop_in: ResourcePropertyCreate,
    db: Session = Depends(get_db),
):
    """Create a new property for a domain resource."""
    resource = get_resource_or_404(resource_id, db)
    existing = (
        db.query(ResourceProperty)
        .filter(
            ResourceProperty.resource_id == resource_id,
            ResourceProperty.name == prop_in.name,
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Property '{prop_in.name}' already exists for resource '{resource.name}'",
        )

    sens = (prop_in.sensitivity or "INTERNAL").upper()
    valid_sensitivities = ["PUBLIC", "INTERNAL", "SENSITIVE", "SECRET"]
    if sens not in valid_sensitivities:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid sensitivity '{sens}'. Must be one of: {', '.join(valid_sensitivities)}",
        )

    new_prop = ResourceProperty(
        resource_id=resource.id,
        name=prop_in.name,
        data_type=prop_in.data_type or "string",
        sensitivity=sens,
        description=prop_in.description,
    )
    db.add(new_prop)
    db.flush()

    if prop_in.initial_rules:
        for role_id, access in prop_in.initial_rules.items():
            role = get_role_or_404(role_id, db)
            if role.project_id != resource.project_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Role {role.name} belongs to a different project",
                )
            acc = access.upper()
            if acc in ["ALLOW", "DENY", "UNKNOWN"]:
                rule = PropertyAuthorizationRule(
                    resource_property_id=new_prop.id,
                    role_id=role.id,
                    access=acc,
                )
                db.add(rule)

    db.commit()
    db.refresh(new_prop)
    return format_property_response(new_prop)


@property_router.post("/resources/{resource_id}/properties/bulk", response_model=List[ResourcePropertyInDB], status_code=status.HTTP_201_CREATED)
def bulk_create_resource_properties(
    resource_id: str,
    props_in: List[ResourcePropertyCreate],
    db: Session = Depends(get_db),
):
    """Bulk create or update properties for a resource."""
    resource = get_resource_or_404(resource_id, db)
    created_props = []
    valid_sensitivities = ["PUBLIC", "INTERNAL", "SENSITIVE", "SECRET"]

    for prop_in in props_in:
        existing = (
            db.query(ResourceProperty)
            .filter(
                ResourceProperty.resource_id == resource_id,
                ResourceProperty.name == prop_in.name,
            )
            .first()
        )
        if existing:
            if prop_in.data_type:
                existing.data_type = prop_in.data_type
            if prop_in.sensitivity:
                sens = prop_in.sensitivity.upper()
                if sens in valid_sensitivities:
                    existing.sensitivity = sens
            if prop_in.description is not None:
                existing.description = prop_in.description
            created_props.append(existing)
            continue

        sens = (prop_in.sensitivity or "INTERNAL").upper()
        if sens not in valid_sensitivities:
            sens = "INTERNAL"

        new_prop = ResourceProperty(
            resource_id=resource.id,
            name=prop_in.name,
            data_type=prop_in.data_type or "string",
            sensitivity=sens,
            description=prop_in.description,
        )
        db.add(new_prop)
        created_props.append(new_prop)

    db.commit()
    for p in created_props:
        db.refresh(p)
    return [format_property_response(p) for p in created_props]


@property_router.get("/properties/{property_id}", response_model=ResourcePropertyInDB)
def get_resource_property(
    property_id: str,
    db: Session = Depends(get_db),
):
    """Get single resource property detail with rules."""
    prop = get_property_or_404(property_id, db)
    return format_property_response(prop)


@property_router.put("/properties/{property_id}", response_model=ResourcePropertyInDB)
def update_resource_property(
    property_id: str,
    prop_in: ResourcePropertyUpdate,
    db: Session = Depends(get_db),
):
    """Update resource property definition."""
    prop = get_property_or_404(property_id, db)
    if prop_in.name is not None:
        existing = (
            db.query(ResourceProperty)
            .filter(
                ResourceProperty.resource_id == prop.resource_id,
                ResourceProperty.name == prop_in.name,
                ResourceProperty.id != property_id,
            )
            .first()
        )
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Property '{prop_in.name}' already exists for this resource",
            )
        prop.name = prop_in.name
    if prop_in.data_type is not None:
        prop.data_type = prop_in.data_type
    if prop_in.sensitivity is not None:
        sens = prop_in.sensitivity.upper()
        valid_sensitivities = ["PUBLIC", "INTERNAL", "SENSITIVE", "SECRET"]
        if sens not in valid_sensitivities:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid sensitivity '{sens}'. Must be one of: {', '.join(valid_sensitivities)}",
            )
        prop.sensitivity = sens
    if prop_in.description is not None:
        prop.description = prop_in.description

    db.commit()
    db.refresh(prop)
    return format_property_response(prop)


@property_router.delete("/properties/{property_id}", status_code=status.HTTP_200_OK)
def delete_resource_property(
    property_id: str,
    db: Session = Depends(get_db),
):
    """Delete a resource property and its authorization rules."""
    prop = get_property_or_404(property_id, db)
    db.query(PropertyAuthorizationRule).filter(
        PropertyAuthorizationRule.resource_property_id == property_id
    ).delete()
    db.delete(prop)
    db.commit()
    return {"message": "Resource property and associated rules deleted successfully"}


@property_router.get("/resources/{resource_id}/property-matrix", response_model=PropertyMatrixView)
def get_resource_property_matrix(
    resource_id: str,
    db: Session = Depends(get_db),
):
    """Get the Property Authorization Matrix (Properties x Roles) for a resource."""
    resource = get_resource_or_404(resource_id, db)
    roles = db.query(Role).filter(Role.project_id == resource.project_id).order_by(Role.name).all()
    properties = (
        db.query(ResourceProperty)
        .filter(ResourceProperty.resource_id == resource_id)
        .order_by(ResourceProperty.name)
        .all()
    )

    matrix_rows = []
    for prop in properties:
        rule_map = {rule.role_id: rule.access for rule in prop.rules}
        for role in roles:
            if role.id not in rule_map:
                rule_map[role.id] = "UNKNOWN"
        matrix_rows.append(
            PropertyMatrixRow(
                id=prop.id,
                name=prop.name,
                data_type=prop.data_type,
                sensitivity=prop.sensitivity,
                description=prop.description,
                rules=rule_map,
            )
        )

    return PropertyMatrixView(
        resource_id=resource.id,
        resource_name=resource.name,
        project_id=resource.project_id,
        roles=[format_role_response(r, db) for r in roles],
        properties=matrix_rows,
        total_properties=len(matrix_rows),
    )


@property_router.post("/properties/{property_id}/rules", response_model=PropertyAuthorizationRuleInDB)
def set_property_rule(
    property_id: str,
    rule_in: PropertyAuthorizationRuleCreate,
    db: Session = Depends(get_db),
):
    """Set or update an authorization rule for a single property and role."""
    prop = get_property_or_404(property_id, db)
    role = get_role_or_404(rule_in.role_id, db)
    if role.project_id != prop.resource.project_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Role belongs to a different project than resource",
        )

    access = rule_in.access.upper()
    if access not in ["ALLOW", "DENY", "UNKNOWN"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Access must be ALLOW, DENY, or UNKNOWN",
        )

    rule = (
        db.query(PropertyAuthorizationRule)
        .filter(
            PropertyAuthorizationRule.resource_property_id == property_id,
            PropertyAuthorizationRule.role_id == rule_in.role_id,
        )
        .first()
    )

    if rule:
        rule.access = access
    else:
        rule = PropertyAuthorizationRule(
            resource_property_id=property_id,
            role_id=rule_in.role_id,
            access=access,
        )
        db.add(rule)

    db.commit()
    db.refresh(rule)
    return PropertyAuthorizationRuleInDB.model_validate(rule)


@property_router.put("/resources/{resource_id}/property-matrix/bulk", response_model=PropertyMatrixView)
def bulk_update_property_matrix(
    resource_id: str,
    bulk_in: PropertyMatrixBulkUpdate,
    db: Session = Depends(get_db),
):
    """Bulk update property authorization rules for a resource."""
    resource = get_resource_or_404(resource_id, db)

    for item in bulk_in.rules:
        prop = get_property_or_404(item.property_id, db)
        if prop.resource_id != resource_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Property {prop.id} does not belong to resource {resource_id}",
            )
        role = get_role_or_404(item.role_id, db)
        if role.project_id != resource.project_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Role {role.id} belongs to a different project",
            )
        access = item.access.upper()
        if access not in ["ALLOW", "DENY", "UNKNOWN"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid access '{item.access}'. Must be ALLOW, DENY, or UNKNOWN",
            )

        rule = (
            db.query(PropertyAuthorizationRule)
            .filter(
                PropertyAuthorizationRule.resource_property_id == item.property_id,
                PropertyAuthorizationRule.role_id == item.role_id,
            )
            .first()
        )

        if rule:
            rule.access = access
        else:
            rule = PropertyAuthorizationRule(
                resource_property_id=item.property_id,
                role_id=item.role_id,
                access=access,
            )
            db.add(rule)

    db.commit()
    return get_resource_property_matrix(resource_id, db)


@property_router.post("/resources/{resource_id}/discover-properties", response_model=PropertyDiscoveryResponse)
def discover_properties(
    resource_id: str,
    req_in: PropertyDiscoveryRequest,
    db: Session = Depends(get_db),
):
    """
    Discover candidate properties from a sample JSON response or recorded endpoint execution evidence.
    Applies heuristic sensitivity classification (e.g. token, secret, role, notes).
    Does NOT automatically create findings or mutate resources without user action.
    """
    resource = get_resource_or_404(resource_id, db)
    from app.services.security_engine.response_analyzer import (
        extract_property_paths,
        discover_candidate_sensitive_properties,
        classify_property_heuristic,
    )

    data_payload = None

    if req_in.sample_json:
        try:
            data_payload = json.loads(req_in.sample_json)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid JSON provided in sample_json: {str(e)}",
            )
    elif req_in.endpoint_id:
        endpoint = get_endpoint_or_404(req_in.endpoint_id, db)
        if endpoint.api and endpoint.api.project_id != resource.project_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Endpoint belongs to a different project",
            )
        latest_exec = (
            db.query(TestExecution)
            .join(TestExecution.security_test)
            .filter(SecurityTest.endpoint_id == endpoint.id)
            .order_by(TestExecution.created_at.desc())
            .first()
        )
        if latest_exec and latest_exec.evidence and latest_exec.evidence.response_metadata:
            try:
                resp_meta = json.loads(latest_exec.evidence.response_metadata)
                body = resp_meta.get("body")
                if isinstance(body, (dict, list)):
                    data_payload = body
                elif isinstance(body, str):
                    data_payload = json.loads(body)
            except Exception:
                pass

        if data_payload is None and endpoint.schemas:
            schema_data = endpoint.schemas[0]
            if schema_data.schema_metadata:
                try:
                    s_meta = json.loads(schema_data.schema_metadata)
                    props = s_meta.get("properties", {})
                    if props:
                        data_payload = {k: "sample" for k in props.keys()}
                except Exception:
                    pass

    if data_payload is None:
        return PropertyDiscoveryResponse(discovered_properties=[], total_discovered=0)

    paths = extract_property_paths(data_payload)
    candidate_list = discover_candidate_sensitive_properties(data_payload)
    candidate_map = {c["path"]: c for c in candidate_list}

    def _get_path_sample_and_type(obj, path: str):
        parts = [p.replace("[]", "") for p in path.split(".")]
        curr = obj
        for p in parts:
            if isinstance(curr, list) and curr:
                curr = curr[0]
            if isinstance(curr, dict) and p in curr:
                curr = curr[p]
            else:
                return "string", None
        if isinstance(curr, bool):
            return "boolean", str(curr).lower()
        elif isinstance(curr, (int, float)):
            return "number", str(curr)
        elif isinstance(curr, dict):
            return "object", "{...}"
        elif isinstance(curr, list):
            return "array", "[...]"
        elif curr is None:
            return "null", None
        return "string", str(curr)[:100]

    results = []
    seen = set()
    for path in sorted(paths):
        if path in seen:
            continue
        seen.add(path)
        d_type, sample = _get_path_sample_and_type(data_payload, path)
        if path in candidate_map:
            cand_info = candidate_map[path]
            results.append(
                CandidateProperty(
                    path=path,
                    data_type=d_type,
                    suggested_sensitivity=cand_info.get("suggested_sensitivity", "SENSITIVE"),
                    matched_heuristic=cand_info.get("matched_keyword"),
                    sample_value=sample,
                )
            )
        else:
            heuristic = classify_property_heuristic(path)
            if heuristic:
                results.append(
                    CandidateProperty(
                        path=path,
                        data_type=d_type,
                        suggested_sensitivity=heuristic.get("suggested_sensitivity", "INTERNAL"),
                        matched_heuristic=heuristic.get("matched_keyword"),
                        sample_value=sample,
                    )
                )
            else:
                results.append(
                    CandidateProperty(
                        path=path,
                        data_type=d_type,
                        suggested_sensitivity="PUBLIC",
                        matched_heuristic=None,
                        sample_value=sample,
                    )
                )

    return PropertyDiscoveryResponse(
        discovered_properties=results,
        total_discovered=len(results),
    )


# ==============================================================================
# STAGE 6: Authentication Security Routes
# ==============================================================================

auth_security_router = APIRouter(tags=["Authentication Security"])


@auth_security_router.get("/endpoints/{endpoint_id}/auth-policy", response_model=AuthenticationPolicyInDB)
def get_endpoint_auth_policy(
    endpoint_id: int,
    db: Session = Depends(get_db),
):
    """Get the authentication policy for an endpoint."""
    endpoint = get_endpoint_or_404(endpoint_id, db)
    policy = (
        db.query(AuthenticationPolicy)
        .filter(AuthenticationPolicy.endpoint_id == endpoint.id)
        .first()
    )
    if not policy:
        now = datetime.now(timezone.utc)
        return AuthenticationPolicyInDB(
            id=f"default-{endpoint.id}",
            project_id=endpoint.api.project_id if endpoint.api else 0,
            endpoint_id=endpoint.id,
            endpoint_method=endpoint.method,
            endpoint_path=endpoint.path,
            authentication_required=True,
            authentication_scheme="bearer_token",
            expected_denial_status=401,
            notes=None,
            created_at=now,
            updated_at=now,
        )

    return AuthenticationPolicyInDB(
        id=policy.id,
        project_id=policy.project_id,
        endpoint_id=policy.endpoint_id,
        endpoint_method=endpoint.method,
        endpoint_path=endpoint.path,
        authentication_required=policy.authentication_required,
        authentication_scheme=policy.authentication_scheme,
        expected_denial_status=policy.expected_denial_status,
        notes=policy.notes,
        created_at=policy.created_at,
        updated_at=policy.updated_at,
    )


@auth_security_router.put("/endpoints/{endpoint_id}/auth-policy", response_model=AuthenticationPolicyInDB)
def update_endpoint_auth_policy(
    endpoint_id: int,
    policy_in: AuthenticationPolicyUpdate,
    db: Session = Depends(get_db),
):
    """Create or update authentication policy for an endpoint."""
    endpoint = get_endpoint_or_404(endpoint_id, db)
    project_id = endpoint.api.project_id if endpoint.api else 0

    policy = (
        db.query(AuthenticationPolicy)
        .filter(AuthenticationPolicy.endpoint_id == endpoint.id)
        .first()
    )

    if not policy:
        policy = AuthenticationPolicy(
            project_id=project_id,
            endpoint_id=endpoint.id,
            authentication_required=policy_in.authentication_required if policy_in.authentication_required is not None else True,
            authentication_scheme=policy_in.authentication_scheme or "bearer_token",
            expected_denial_status=policy_in.expected_denial_status or 401,
            notes=policy_in.notes,
        )
        db.add(policy)
    else:
        if policy_in.authentication_required is not None:
            policy.authentication_required = policy_in.authentication_required
        if policy_in.authentication_scheme is not None:
            policy.authentication_scheme = policy_in.authentication_scheme
        if policy_in.expected_denial_status is not None:
            policy.expected_denial_status = policy_in.expected_denial_status
        if policy_in.notes is not None:
            policy.notes = policy_in.notes
        policy.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(policy)

    return AuthenticationPolicyInDB(
        id=policy.id,
        project_id=policy.project_id,
        endpoint_id=policy.endpoint_id,
        endpoint_method=endpoint.method,
        endpoint_path=endpoint.path,
        authentication_required=policy.authentication_required,
        authentication_scheme=policy.authentication_scheme,
        expected_denial_status=policy.expected_denial_status,
        notes=policy.notes,
        created_at=policy.created_at,
        updated_at=policy.updated_at,
    )


@auth_security_router.post("/projects/{project_id}/generate-auth-tests", response_model=AuthTestGenerationResponse)
def generate_auth_tests_for_project(
    project_id: int,
    db: Session = Depends(get_db),
):
    """Automatically generate controlled authentication security tests for safe endpoints."""
    from app.services.security_engine.auth_generator import AuthenticationTestGenerator
    try:
        created_tests, skipped = AuthenticationTestGenerator.generate_tests(
            db=db,
            project_id=project_id,
        )
        return AuthTestGenerationResponse(
            project_id=project_id,
            generated_count=len(created_tests),
            skipped_count=skipped,
            test_ids=[t.id for t in created_tests],
            message=f"Generated {len(created_tests)} authentication test(s) ({skipped} skipped/duplicate).",
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


# ==============================================================================
# STAGE 7.1: Stateful Workflow & Business Logic Security Endpoints
# ==============================================================================

workflow_router = APIRouter(tags=["workflows"])

# ----------------- WORKFLOW CRUD -----------------

@workflow_router.get("/projects/{project_id}/workflows", response_model=List[WorkflowInDB])
def list_project_workflows(
    project_id: int,
    db: Session = Depends(get_db),
):
    """List all workflows defined in a project."""
    get_project_or_404(project_id, db)
    workflows = (
        db.query(Workflow)
        .filter(Workflow.project_id == project_id)
        .order_by(Workflow.created_at.desc())
        .all()
    )
    return [format_workflow_response(w, db) for w in workflows]


@workflow_router.post("/projects/{project_id}/workflows", response_model=WorkflowInDB, status_code=status.HTTP_201_CREATED)
def create_workflow(
    project_id: int,
    workflow_in: WorkflowCreate,
    db: Session = Depends(get_db),
):
    """Create a new workflow model for a project."""
    get_project_or_404(project_id, db)

    status_val = workflow_in.status.upper()
    if status_val not in ["DRAFT", "ACTIVE", "DISABLED"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status '{workflow_in.status}'. Allowed statuses: DRAFT, ACTIVE, DISABLED.",
        )

    # Project-scoped unique name check
    existing = (
        db.query(Workflow)
        .filter(Workflow.project_id == project_id, Workflow.name == workflow_in.name)
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Workflow with name '{workflow_in.name}' already exists in this project.",
        )

    workflow = Workflow(
        project_id=project_id,
        name=workflow_in.name,
        description=workflow_in.description,
        status=status_val,
    )
    db.add(workflow)
    db.commit()
    db.refresh(workflow)
    return format_workflow_response(workflow, db)


@workflow_router.get("/workflows/{workflow_id}", response_model=WorkflowDetailInDB)
def get_workflow(
    workflow_id: str,
    db: Session = Depends(get_db),
):
    """Get full details of a workflow including steps, states, and transitions."""
    workflow = get_workflow_or_404(workflow_id, db)
    return format_workflow_detail(workflow, db)


@workflow_router.patch("/workflows/{workflow_id}", response_model=WorkflowInDB)
def update_workflow(
    workflow_id: str,
    workflow_update: WorkflowUpdate,
    db: Session = Depends(get_db),
):
    """Update workflow name, description, or status."""
    workflow = get_workflow_or_404(workflow_id, db)

    if workflow_update.name is not None and workflow_update.name != workflow.name:
        dup = (
            db.query(Workflow)
            .filter(
                Workflow.project_id == workflow.project_id,
                Workflow.name == workflow_update.name,
                Workflow.id != workflow.id,
            )
            .first()
        )
        if dup:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Workflow with name '{workflow_update.name}' already exists in this project.",
            )
        workflow.name = workflow_update.name

    if workflow_update.description is not None:
        workflow.description = workflow_update.description

    if workflow_update.status is not None:
        status_val = workflow_update.status.upper()
        if status_val not in ["DRAFT", "ACTIVE", "DISABLED"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status '{workflow_update.status}'. Allowed statuses: DRAFT, ACTIVE, DISABLED.",
            )
        workflow.status = status_val

    db.commit()
    db.refresh(workflow)
    return format_workflow_response(workflow, db)


@workflow_router.delete("/workflows/{workflow_id}")
def delete_workflow(
    workflow_id: str,
    db: Session = Depends(get_db),
):
    """Delete a workflow and cascade delete all its steps, states, and transitions."""
    workflow = get_workflow_or_404(workflow_id, db)
    db.delete(workflow)
    db.commit()
    return {"message": f"Workflow {workflow_id} deleted successfully"}


# ----------------- WORKFLOW STEP CRUD -----------------

@workflow_router.get("/workflows/{workflow_id}/steps", response_model=List[WorkflowStepInDB])
def list_workflow_steps(
    workflow_id: str,
    db: Session = Depends(get_db),
):
    """List all steps for a workflow ordered by step_order."""
    workflow = get_workflow_or_404(workflow_id, db)
    return [format_workflow_step_response(s) for s in workflow.steps]


@workflow_router.post("/workflows/{workflow_id}/steps", response_model=WorkflowStepInDB, status_code=status.HTTP_201_CREATED)
def create_workflow_step(
    workflow_id: str,
    step_in: WorkflowStepCreate,
    db: Session = Depends(get_db),
):
    """Add a step to a workflow."""
    workflow = get_workflow_or_404(workflow_id, db)

    # Safe HTTP methods check
    method = step_in.http_method.upper()
    if method not in ["GET", "HEAD"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Only safe HTTP methods (GET, HEAD) are allowed for workflow steps, got {step_in.http_method}",
        )

    # Request template secret validation
    validate_request_template(step_in.request_template)

    # Verify endpoint belongs to the same project
    endpoint = db.query(Endpoint).filter(Endpoint.id == step_in.endpoint_id).first()
    if not endpoint:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Endpoint with id {step_in.endpoint_id} not found",
        )
    if not endpoint.api or endpoint.api.project_id != workflow.project_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Endpoint does not belong to the same project as the workflow",
        )

    # Verify identity belongs to the same project if provided
    if step_in.identity_id:
        identity = db.query(Identity).filter(Identity.id == step_in.identity_id).first()
        if not identity:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Identity with id {step_in.identity_id} not found",
            )
        if identity.project_id != workflow.project_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Identity does not belong to the same project as the workflow",
            )

    # Uniqueness of step_order per workflow
    existing_order = (
        db.query(WorkflowStep)
        .filter(
            WorkflowStep.workflow_id == workflow_id,
            WorkflowStep.step_order == step_in.step_order,
        )
        .first()
    )
    if existing_order:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Step with order {step_in.step_order} already exists in this workflow",
        )

    step = WorkflowStep(
        workflow_id=workflow_id,
        step_order=step_in.step_order,
        endpoint_id=step_in.endpoint_id,
        identity_id=step_in.identity_id,
        http_method=method,
        name=step_in.name,
        description=step_in.description,
        request_template=step_in.request_template,
        expected_status_codes=step_in.expected_status_codes or [200],
    )
    db.add(step)
    db.commit()
    db.refresh(step)
    return format_workflow_step_response(step)


@workflow_router.get("/workflows/{workflow_id}/steps/{step_id}", response_model=WorkflowStepInDB)
@workflow_router.get("/workflow-steps/{step_id}", response_model=WorkflowStepInDB)
def get_workflow_step(
    step_id: str,
    workflow_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Get a workflow step by ID."""
    step = get_workflow_step_or_404(step_id, db)
    if workflow_id and step.workflow_id != workflow_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workflow step {step_id} not found in workflow {workflow_id}",
        )
    return format_workflow_step_response(step)


@workflow_router.patch("/workflows/{workflow_id}/steps/{step_id}", response_model=WorkflowStepInDB)
@workflow_router.patch("/workflow-steps/{step_id}", response_model=WorkflowStepInDB)
def update_workflow_step(
    step_id: str,
    step_update: WorkflowStepUpdate,
    workflow_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Update a workflow step."""
    step = get_workflow_step_or_404(step_id, db)
    if workflow_id and step.workflow_id != workflow_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workflow step {step_id} not found in workflow {workflow_id}",
        )
    workflow = step.workflow

    if step_update.http_method is not None:
        method = step_update.http_method.upper()
        if method not in ["GET", "HEAD"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Only safe HTTP methods (GET, HEAD) are allowed for workflow steps, got {step_update.http_method}",
            )
        step.http_method = method

    if step_update.request_template is not None:
        validate_request_template(step_update.request_template)
        step.request_template = step_update.request_template

    if step_update.endpoint_id is not None and step_update.endpoint_id != step.endpoint_id:
        endpoint = db.query(Endpoint).filter(Endpoint.id == step_update.endpoint_id).first()
        if not endpoint:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Endpoint with id {step_update.endpoint_id} not found",
            )
        if not endpoint.api or endpoint.api.project_id != workflow.project_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Endpoint does not belong to the same project as the workflow",
            )
        step.endpoint_id = step_update.endpoint_id

    if step_update.identity_id is not None:
        if step_update.identity_id != "":
            identity = db.query(Identity).filter(Identity.id == step_update.identity_id).first()
            if not identity:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Identity with id {step_update.identity_id} not found",
                )
            if identity.project_id != workflow.project_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Identity does not belong to the same project as the workflow",
                )
            step.identity_id = step_update.identity_id
        else:
            step.identity_id = None

    if step_update.step_order is not None and step_update.step_order != step.step_order:
        dup = (
            db.query(WorkflowStep)
            .filter(
                WorkflowStep.workflow_id == step.workflow_id,
                WorkflowStep.step_order == step_update.step_order,
                WorkflowStep.id != step.id,
            )
            .first()
        )
        if dup:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Step with order {step_update.step_order} already exists in this workflow",
            )
        step.step_order = step_update.step_order

    if step_update.name is not None:
        step.name = step_update.name
    if step_update.description is not None:
        step.description = step_update.description
    if step_update.expected_status_codes is not None:
        step.expected_status_codes = step_update.expected_status_codes

    db.commit()
    db.refresh(step)
    return format_workflow_step_response(step)


@workflow_router.delete("/workflows/{workflow_id}/steps/{step_id}")
@workflow_router.delete("/workflow-steps/{step_id}")
def delete_workflow_step(
    step_id: str,
    workflow_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Delete a workflow step."""
    step = get_workflow_step_or_404(step_id, db)
    if workflow_id and step.workflow_id != workflow_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workflow step {step_id} not found in workflow {workflow_id}",
        )
    db.delete(step)
    db.commit()
    return {"message": f"Workflow step {step_id} deleted successfully"}


# ----------------- WORKFLOW STATE CRUD -----------------

@workflow_router.get("/workflows/{workflow_id}/states", response_model=List[WorkflowStateInDB])
def list_workflow_states(
    workflow_id: str,
    db: Session = Depends(get_db),
):
    """List all states for a workflow."""
    workflow = get_workflow_or_404(workflow_id, db)
    return [format_workflow_state_response(s) for s in workflow.states]


@workflow_router.post("/workflows/{workflow_id}/states", response_model=WorkflowStateInDB, status_code=status.HTTP_201_CREATED)
def create_workflow_state(
    workflow_id: str,
    state_in: WorkflowStateCreate,
    db: Session = Depends(get_db),
):
    """Create a state within a workflow."""
    workflow = get_workflow_or_404(workflow_id, db)

    dup = (
        db.query(WorkflowState)
        .filter(
            WorkflowState.workflow_id == workflow_id,
            WorkflowState.name == state_in.name,
        )
        .first()
    )
    if dup:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"State with name '{state_in.name}' already exists in this workflow",
        )

    state = WorkflowState(
        workflow_id=workflow_id,
        name=state_in.name,
        description=state_in.description,
        is_initial=state_in.is_initial,
        is_terminal=state_in.is_terminal,
    )
    db.add(state)
    db.commit()
    db.refresh(state)
    return format_workflow_state_response(state)


@workflow_router.get("/workflows/{workflow_id}/states/{state_id}", response_model=WorkflowStateInDB)
@workflow_router.get("/workflow-states/{state_id}", response_model=WorkflowStateInDB)
def get_workflow_state(
    state_id: str,
    workflow_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Get a workflow state by ID."""
    state = get_workflow_state_or_404(state_id, db)
    if workflow_id and state.workflow_id != workflow_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workflow state {state_id} not found in workflow {workflow_id}",
        )
    return format_workflow_state_response(state)


@workflow_router.patch("/workflows/{workflow_id}/states/{state_id}", response_model=WorkflowStateInDB)
@workflow_router.patch("/workflow-states/{state_id}", response_model=WorkflowStateInDB)
def update_workflow_state(
    state_id: str,
    state_update: WorkflowStateUpdate,
    workflow_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Update a workflow state."""
    state = get_workflow_state_or_404(state_id, db)
    if workflow_id and state.workflow_id != workflow_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workflow state {state_id} not found in workflow {workflow_id}",
        )

    if state_update.name is not None and state_update.name != state.name:
        dup = (
            db.query(WorkflowState)
            .filter(
                WorkflowState.workflow_id == state.workflow_id,
                WorkflowState.name == state_update.name,
                WorkflowState.id != state.id,
            )
            .first()
        )
        if dup:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"State with name '{state_update.name}' already exists in this workflow",
            )
        state.name = state_update.name

    if state_update.description is not None:
        state.description = state_update.description
    if state_update.is_initial is not None:
        state.is_initial = state_update.is_initial
    if state_update.is_terminal is not None:
        state.is_terminal = state_update.is_terminal

    db.commit()
    db.refresh(state)
    return format_workflow_state_response(state)


@workflow_router.delete("/workflows/{workflow_id}/states/{state_id}")
@workflow_router.delete("/workflow-states/{state_id}")
def delete_workflow_state(
    state_id: str,
    workflow_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Delete a workflow state."""
    state = get_workflow_state_or_404(state_id, db)
    if workflow_id and state.workflow_id != workflow_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workflow state {state_id} not found in workflow {workflow_id}",
        )
    db.delete(state)
    db.commit()
    return {"message": f"Workflow state {state_id} deleted successfully"}


# ----------------- WORKFLOW TRANSITION CRUD -----------------

@workflow_router.get("/workflows/{workflow_id}/transitions", response_model=List[WorkflowTransitionInDB])
def list_workflow_transitions(
    workflow_id: str,
    db: Session = Depends(get_db),
):
    """List all transitions for a workflow."""
    workflow = get_workflow_or_404(workflow_id, db)
    return [format_workflow_transition_response(t) for t in workflow.transitions]


@workflow_router.post("/workflows/{workflow_id}/transitions", response_model=WorkflowTransitionInDB, status_code=status.HTTP_201_CREATED)
def create_workflow_transition(
    workflow_id: str,
    transition_in: WorkflowTransitionCreate,
    db: Session = Depends(get_db),
):
    """Create a transition between states in a workflow."""
    workflow = get_workflow_or_404(workflow_id, db)

    behavior = transition_in.expected_behavior.upper()
    if behavior not in ["ALLOW", "DENY"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="expected_behavior must be ALLOW or DENY",
        )

    # Validate from_state
    from_state = (
        db.query(WorkflowState)
        .filter(WorkflowState.id == transition_in.from_state_id)
        .first()
    )
    if not from_state:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"From state {transition_in.from_state_id} not found",
        )
    if from_state.workflow_id != workflow_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="From state does not belong to this workflow",
        )

    # Validate to_state
    to_state = (
        db.query(WorkflowState)
        .filter(WorkflowState.id == transition_in.to_state_id)
        .first()
    )
    if not to_state:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"To state {transition_in.to_state_id} not found",
        )
    if to_state.workflow_id != workflow_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="To state does not belong to this workflow",
        )

    # Validate step if present
    if transition_in.step_id:
        step = (
            db.query(WorkflowStep)
            .filter(WorkflowStep.id == transition_in.step_id)
            .first()
        )
        if not step:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Workflow step {transition_in.step_id} not found",
            )
        if step.workflow_id != workflow_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Workflow step does not belong to this workflow",
            )

    # Prevent duplicate transitions with identical from_state, to_state, and step
    existing = (
        db.query(WorkflowTransition)
        .filter(
            WorkflowTransition.workflow_id == workflow_id,
            WorkflowTransition.from_state_id == transition_in.from_state_id,
            WorkflowTransition.to_state_id == transition_in.to_state_id,
            WorkflowTransition.step_id == transition_in.step_id,
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Transition with identical from_state, to_state, and step already exists in this workflow",
        )

    trans = WorkflowTransition(
        workflow_id=workflow_id,
        from_state_id=transition_in.from_state_id,
        to_state_id=transition_in.to_state_id,
        step_id=transition_in.step_id,
        expected_behavior=behavior,
        description=transition_in.description,
    )
    db.add(trans)
    db.commit()
    db.refresh(trans)
    return format_workflow_transition_response(trans)


@workflow_router.get("/workflows/{workflow_id}/transitions/{transition_id}", response_model=WorkflowTransitionInDB)
@workflow_router.get("/workflow-transitions/{transition_id}", response_model=WorkflowTransitionInDB)
def get_workflow_transition(
    transition_id: str,
    workflow_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Get a workflow transition by ID."""
    trans = get_workflow_transition_or_404(transition_id, db)
    if workflow_id and trans.workflow_id != workflow_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workflow transition {transition_id} not found in workflow {workflow_id}",
        )
    return format_workflow_transition_response(trans)


@workflow_router.patch("/workflows/{workflow_id}/transitions/{transition_id}", response_model=WorkflowTransitionInDB)
@workflow_router.patch("/workflow-transitions/{transition_id}", response_model=WorkflowTransitionInDB)
def update_workflow_transition(
    transition_id: str,
    transition_update: WorkflowTransitionUpdate,
    workflow_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Update a workflow transition."""
    trans = get_workflow_transition_or_404(transition_id, db)
    if workflow_id and trans.workflow_id != workflow_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workflow transition {transition_id} not found in workflow {workflow_id}",
        )

    target_from = (
        transition_update.from_state_id
        if transition_update.from_state_id is not None
        else trans.from_state_id
    )
    target_to = (
        transition_update.to_state_id
        if transition_update.to_state_id is not None
        else trans.to_state_id
    )
    target_step = (
        transition_update.step_id
        if transition_update.step_id is not None
        else trans.step_id
    )
    if target_step == "":
        target_step = None

    if (
        transition_update.from_state_id is not None
        and transition_update.from_state_id != trans.from_state_id
    ):
        from_st = db.query(WorkflowState).filter(WorkflowState.id == target_from).first()
        if not from_st:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="From state not found"
            )
        if from_st.workflow_id != trans.workflow_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="From state does not belong to this workflow",
            )

    if (
        transition_update.to_state_id is not None
        and transition_update.to_state_id != trans.to_state_id
    ):
        to_st = db.query(WorkflowState).filter(WorkflowState.id == target_to).first()
        if not to_st:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="To state not found"
            )
        if to_st.workflow_id != trans.workflow_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="To state does not belong to this workflow",
            )

    if (
        transition_update.step_id is not None
        and target_step is not None
        and target_step != trans.step_id
    ):
        st = db.query(WorkflowStep).filter(WorkflowStep.id == target_step).first()
        if not st:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Workflow step not found"
            )
        if st.workflow_id != trans.workflow_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Workflow step does not belong to this workflow",
            )

    if (
        target_from != trans.from_state_id
        or target_to != trans.to_state_id
        or target_step != trans.step_id
    ):
        dup = (
            db.query(WorkflowTransition)
            .filter(
                WorkflowTransition.workflow_id == trans.workflow_id,
                WorkflowTransition.from_state_id == target_from,
                WorkflowTransition.to_state_id == target_to,
                WorkflowTransition.step_id == target_step,
                WorkflowTransition.id != trans.id,
            )
            .first()
        )
        if dup:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Transition with identical from_state, to_state, and step already exists",
            )

    if transition_update.expected_behavior is not None:
        behavior = transition_update.expected_behavior.upper()
        if behavior not in ["ALLOW", "DENY"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="expected_behavior must be ALLOW or DENY",
            )
        trans.expected_behavior = behavior

    trans.from_state_id = target_from
    trans.to_state_id = target_to
    trans.step_id = target_step

    if transition_update.description is not None:
        trans.description = transition_update.description

    db.commit()
    db.refresh(trans)
    return format_workflow_transition_response(trans)


@workflow_router.delete("/workflows/{workflow_id}/transitions/{transition_id}")
@workflow_router.delete("/workflow-transitions/{transition_id}")
def delete_workflow_transition(
    transition_id: str,
    workflow_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Delete a workflow transition."""
    trans = get_workflow_transition_or_404(transition_id, db)
    if workflow_id and trans.workflow_id != workflow_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workflow transition {transition_id} not found in workflow {workflow_id}",
        )
    db.delete(trans)
    db.commit()
    return {"message": f"Workflow transition {transition_id} deleted successfully"}


# ----------------- WORKFLOW EXECUTION ENDPOINTS -----------------

@workflow_router.post("/workflows/{workflow_id}/execute", response_model=WorkflowExecutionDetailInDB)
async def execute_workflow_endpoint(
    workflow_id: str,
    db: Session = Depends(get_db),
):
    """Execute an active workflow statefully."""
    workflow = get_workflow_or_404(workflow_id, db)
    from app.main import app as fastapi_app
    from app.services.security_engine.workflow_engine import WorkflowEngine

    engine = WorkflowEngine(db=db, app=fastapi_app)
    execution = await engine.execute_workflow(workflow, triggered_by="MANUAL")
    return format_workflow_execution_detail(execution, db)


@workflow_router.get("/workflows/{workflow_id}/executions", response_model=List[WorkflowExecutionInDB])
def list_workflow_executions(
    workflow_id: str,
    db: Session = Depends(get_db),
):
    """List all executions for a workflow."""
    workflow = get_workflow_or_404(workflow_id, db)
    executions = (
        db.query(WorkflowExecution)
        .filter(WorkflowExecution.workflow_id == workflow.id)
        .order_by(WorkflowExecution.created_at.desc())
        .all()
    )
    return [format_workflow_execution_response(e, db) for e in executions]


@workflow_router.get("/workflow-executions/{execution_id}", response_model=WorkflowExecutionDetailInDB)
def get_workflow_execution(
    execution_id: str,
    db: Session = Depends(get_db),
):
    """Get workflow execution details, including step executions, findings, and evidence."""
    execution = get_workflow_execution_or_404(execution_id, db)
    return format_workflow_execution_detail(execution, db)


@workflow_router.post("/workflow-executions/{execution_id}/replay", response_model=WorkflowExecutionDetailInDB)
async def replay_workflow_execution_endpoint(
    execution_id: str,
    db: Session = Depends(get_db),
):
    """Replay an existing workflow execution."""
    execution = get_workflow_execution_or_404(execution_id, db)
    workflow = execution.workflow
    if not workflow:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Associated workflow not found",
        )

    from app.main import app as fastapi_app
    from app.services.security_engine.workflow_engine import WorkflowEngine

    engine = WorkflowEngine(db=db, app=fastapi_app)
    new_execution = await engine.execute_workflow(workflow, triggered_by="REPLAY")
    return format_workflow_execution_detail(new_execution, db)


# ----------------- WORKFLOW ATTACK SCENARIO ENDPOINTS (STAGE 7.3) -----------------

@workflow_router.post(
    "/workflows/{workflow_id}/generate-attack-scenarios",
    response_model=WorkflowAttackScenarioGenerateResult,
)
def generate_workflow_attack_scenarios(
    workflow_id: str,
    gen_req: Optional[WorkflowAttackScenarioGenerateRequest] = None,
    db: Session = Depends(get_db),
):
    """
    Generate safe adversarial test scenarios for an ACTIVE workflow.
    Generation does NOT execute scenarios.
    """
    workflow = get_workflow_or_404(workflow_id, db)
    project = db.query(Project).filter(Project.id == workflow.project_id).first()
    if not project or project.authorization_status.lower() != "authorized":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Project must be authorized before generating attack scenarios.",
        )
    if workflow.status.upper() != "ACTIVE":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Workflow is in '{workflow.status}' status. Only ACTIVE workflows can generate attack scenarios.",
        )

    from app.services.security_engine.workflow_attack_generator import WorkflowAttackGenerator

    generator = WorkflowAttackGenerator(db=db)
    scenario_types = gen_req.scenario_types if gen_req else None
    try:
        scenarios = generator.generate_scenarios(workflow, scenario_types=scenario_types)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    formatted_scenarios = [
        format_workflow_attack_scenario_response(sc, db) for sc in scenarios
    ]
    return WorkflowAttackScenarioGenerateResult(
        generated_count=len(formatted_scenarios),
        existing_count=0,
        scenarios=formatted_scenarios,
    )


@workflow_router.get(
    "/workflows/{workflow_id}/attack-scenarios",
    response_model=List[WorkflowAttackScenarioDetailInDB],
)
def list_workflow_attack_scenarios(
    workflow_id: str,
    db: Session = Depends(get_db),
):
    """List all attack scenarios for a workflow."""
    workflow = get_workflow_or_404(workflow_id, db)
    scenarios = (
        db.query(WorkflowAttackScenario)
        .filter(WorkflowAttackScenario.workflow_id == workflow.id)
        .order_by(WorkflowAttackScenario.created_at.desc())
        .all()
    )
    return [format_workflow_attack_scenario_detail(sc, db) for sc in scenarios]


@workflow_router.get(
    "/workflow-attack-scenarios/{scenario_id}",
    response_model=WorkflowAttackScenarioDetailInDB,
)
def get_workflow_attack_scenario(
    scenario_id: str,
    db: Session = Depends(get_db),
):
    """Get attack scenario details and steps."""
    scenario = get_attack_scenario_or_404(scenario_id, db)
    return format_workflow_attack_scenario_detail(scenario, db)


@workflow_router.post(
    "/workflow-attack-scenarios/{scenario_id}/execute",
    response_model=WorkflowExecutionDetailInDB,
)
async def execute_workflow_attack_scenario(
    scenario_id: str,
    db: Session = Depends(get_db),
):
    """Execute an adversarial attack scenario safely."""
    scenario = get_attack_scenario_or_404(scenario_id, db)
    from app.main import app as fastapi_app
    from app.services.security_engine.workflow_attack_engine import WorkflowAttackEngine

    engine = WorkflowAttackEngine(db=db, app=fastapi_app)
    execution = await engine.execute_scenario(scenario, triggered_by="MANUAL")
    return format_workflow_execution_detail(execution, db)


@workflow_router.get(
    "/workflow-attack-scenarios/{scenario_id}/executions",
    response_model=List[WorkflowExecutionInDB],
)
def list_attack_scenario_executions(
    scenario_id: str,
    db: Session = Depends(get_db),
):
    """List past executions for a specific attack scenario."""
    scenario = get_attack_scenario_or_404(scenario_id, db)
    executions = (
        db.query(WorkflowExecution)
        .filter(WorkflowExecution.attack_scenario_id == scenario.id)
        .order_by(WorkflowExecution.created_at.desc())
        .all()
    )
    return [format_workflow_execution_response(e, db) for e in executions]


@workflow_router.post(
    "/workflow-attack-scenarios/{scenario_id}/replay",
    response_model=WorkflowExecutionDetailInDB,
)
async def replay_workflow_attack_scenario(
    scenario_id: str,
    db: Session = Depends(get_db),
):
    """Replay an adversarial attack scenario."""
    scenario = get_attack_scenario_or_404(scenario_id, db)
    from app.main import app as fastapi_app
    from app.services.security_engine.workflow_attack_engine import WorkflowAttackEngine

    engine = WorkflowAttackEngine(db=db, app=fastapi_app)
    execution = await engine.execute_scenario(scenario, triggered_by="REPLAY")
    return format_workflow_execution_detail(execution, db)


# --- Stage 8.1 Correlation & Attack Graph Routes ---

correlation_router = APIRouter(tags=["Correlation & Attack Graph"])


def format_correlation_response(corr: FindingCorrelation) -> FindingCorrelationInDB:
    return FindingCorrelationInDB(
        id=corr.id,
        project_id=corr.project_id,
        finding_a_id=corr.finding_a_id,
        finding_b_id=corr.finding_b_id,
        relationship_type=corr.relationship_type,
        confidence=corr.confidence,
        reason=corr.reason,
        created_at=corr.created_at,
        finding_a_title=corr.finding_a.title if corr.finding_a else None,
        finding_b_title=corr.finding_b.title if corr.finding_b else None,
        finding_a_type=corr.finding_a.type if corr.finding_a else None,
        finding_b_type=corr.finding_b.type if corr.finding_b else None,
        finding_a_severity=corr.finding_a.severity if corr.finding_a else None,
        finding_b_severity=corr.finding_b.severity if corr.finding_b else None,
    )


def format_attack_graph_node_response(node: AttackGraphNode) -> AttackGraphNodeInDB:
    return AttackGraphNodeInDB(
        id=node.id,
        graph_id=node.graph_id,
        finding_id=node.finding_id,
        node_type=node.node_type,
        label=node.label,
        metadata=node.node_metadata,
        created_at=node.created_at,
        finding_severity=node.finding.severity if node.finding else None,
        finding_type=node.finding.type if node.finding else None,
    )


def format_attack_graph_edge_response(edge: AttackGraphEdge) -> AttackGraphEdgeInDB:
    return AttackGraphEdgeInDB(
        id=edge.id,
        graph_id=edge.graph_id,
        source_node_id=edge.source_node_id,
        target_node_id=edge.target_node_id,
        relationship_type=edge.relationship_type,
        confidence=edge.confidence,
        reason=edge.reason,
        metadata=edge.edge_metadata,
        created_at=edge.created_at,
        source_label=edge.source_node.label if edge.source_node else None,
        target_label=edge.target_node.label if edge.target_node else None,
    )


def format_attack_graph_response(graph: AttackGraph) -> AttackGraphInDB:
    return AttackGraphInDB(
        id=graph.id,
        project_id=graph.project_id,
        name=graph.name,
        description=graph.description,
        status=graph.status,
        created_at=graph.created_at,
        updated_at=graph.updated_at,
        node_count=len(graph.nodes) if graph.nodes else 0,
        edge_count=len(graph.edges) if graph.edges else 0,
    )


def format_attack_graph_detail_response(graph: AttackGraph) -> AttackGraphDetailInDB:
    return AttackGraphDetailInDB(
        id=graph.id,
        project_id=graph.project_id,
        name=graph.name,
        description=graph.description,
        status=graph.status,
        created_at=graph.created_at,
        updated_at=graph.updated_at,
        node_count=len(graph.nodes) if graph.nodes else 0,
        edge_count=len(graph.edges) if graph.edges else 0,
        nodes=[format_attack_graph_node_response(n) for n in graph.nodes],
        edges=[format_attack_graph_edge_response(e) for e in graph.edges],
    )


@correlation_router.post(
    "/projects/{project_id}/correlation/run",
    response_model=CorrelationRunResponse,
)
def run_project_correlation(
    project_id: int,
    db: Session = Depends(get_db),
):
    """Run deterministic correlation and construct the attack graph."""
    project = get_project_or_404(project_id, db)
    engine = CorrelationEngine(db=db)
    result = engine.run_correlation(project_id=project.id)
    return CorrelationRunResponse(
        project_id=result["project_id"],
        confirmed_findings_count=result["confirmed_findings_count"],
        correlations_count=result["correlations_count"],
        new_correlations_count=result["new_correlations_count"],
        graph_id=result["graph_id"],
        node_count=result["node_count"],
        edge_count=result["edge_count"],
        correlations=[format_correlation_response(c) for c in result["correlations"]],
        graph=format_attack_graph_response(result["graph"]),
    )


@correlation_router.get(
    "/projects/{project_id}/correlations",
    response_model=List[FindingCorrelationInDB],
)
def list_project_correlations(
    project_id: int,
    db: Session = Depends(get_db),
):
    """List deterministic correlations between findings in a project."""
    project = get_project_or_404(project_id, db)
    correlations = (
        db.query(FindingCorrelation)
        .filter(FindingCorrelation.project_id == project.id)
        .order_by(FindingCorrelation.created_at.asc())
        .all()
    )
    return [format_correlation_response(c) for c in correlations]


@correlation_router.get(
    "/projects/{project_id}/attack-graphs",
    response_model=List[AttackGraphInDB],
)
def list_project_attack_graphs(
    project_id: int,
    db: Session = Depends(get_db),
):
    """List attack graphs for a project."""
    project = get_project_or_404(project_id, db)
    graphs = (
        db.query(AttackGraph)
        .filter(AttackGraph.project_id == project.id)
        .order_by(AttackGraph.created_at.desc())
        .all()
    )
    return [format_attack_graph_response(g) for g in graphs]


@correlation_router.get(
    "/attack-graphs/{graph_id}",
    response_model=AttackGraphDetailInDB,
)
def get_attack_graph(
    graph_id: str,
    db: Session = Depends(get_db),
):
    """Get attack graph details with full nodes and edges."""
    graph = db.query(AttackGraph).filter(AttackGraph.id == graph_id).first()
    if not graph:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack graph {graph_id} not found",
        )
    return format_attack_graph_detail_response(graph)


@correlation_router.get(
    "/attack-graphs/{graph_id}/nodes",
    response_model=List[AttackGraphNodeInDB],
)
def get_attack_graph_nodes(
    graph_id: str,
    db: Session = Depends(get_db),
):
    """Get all nodes in an attack graph."""
    graph = db.query(AttackGraph).filter(AttackGraph.id == graph_id).first()
    if not graph:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack graph {graph_id} not found",
        )
    nodes = (
        db.query(AttackGraphNode)
        .filter(AttackGraphNode.graph_id == graph_id)
        .order_by(AttackGraphNode.created_at.asc())
        .all()
    )
    return [format_attack_graph_node_response(n) for n in nodes]


@correlation_router.get(
    "/attack-graphs/{graph_id}/edges",
    response_model=List[AttackGraphEdgeInDB],
)
def get_attack_graph_edges(
    graph_id: str,
    db: Session = Depends(get_db),
):
    """Get all edges in an attack graph."""
    graph = db.query(AttackGraph).filter(AttackGraph.id == graph_id).first()
    if not graph:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack graph {graph_id} not found",
        )
    edges = (
        db.query(AttackGraphEdge)
        .filter(AttackGraphEdge.graph_id == graph_id)
        .order_by(AttackGraphEdge.created_at.asc())
        .all()
    )
    return [format_attack_graph_edge_response(e) for e in edges]


# ==============================================================================
# STAGE 8.2: Deterministic Attack Path Detection Router & Formatters
# ==============================================================================
attack_path_router = APIRouter(tags=["attack-paths"])


def format_attack_path_step_response(step: AttackPathStep) -> AttackPathStepInDB:
    finding = step.finding
    prereq = step.prerequisite_finding
    endpoint_path = finding.endpoint.path if (finding and finding.endpoint) else None
    resource_name = finding.resource.name if (finding and finding.resource) else None
    identity_name = finding.attacker_identity.name if (finding and finding.attacker_identity) else None
    return AttackPathStepInDB(
        id=step.id,
        attack_path_id=step.attack_path_id,
        position=step.position,
        finding_id=step.finding_id,
        prerequisite_finding_id=step.prerequisite_finding_id,
        relationship_type=step.relationship_type,
        reason=step.reason,
        created_at=step.created_at,
        finding_title=finding.title if finding else None,
        finding_type=finding.type if finding else None,
        finding_severity=finding.severity if finding else None,
        prerequisite_finding_title=prereq.title if prereq else None,
        endpoint_path=endpoint_path,
        resource_name=resource_name,
        identity_name=identity_name,
    )


def format_attack_path_response(path: AttackPath) -> AttackPathInDB:
    steps = [format_attack_path_step_response(s) for s in path.steps] if path.steps else []
    return AttackPathInDB(
        id=path.id,
        project_id=path.project_id,
        attack_graph_id=path.attack_graph_id,
        name=path.name,
        description=path.description,
        status=path.status,
        confidence=path.confidence,
        created_at=path.created_at,
        updated_at=path.updated_at,
        step_count=len(steps),
        steps=steps,
    )


def format_attack_path_detail_response(path: AttackPath) -> AttackPathDetailInDB:
    return format_attack_path_response(path)


@attack_path_router.post(
    "/projects/{project_id}/attack-paths/analyze",
    response_model=AttackPathAnalysisResponse,
)
def analyze_project_attack_paths(
    project_id: int,
    db: Session = Depends(get_db),
):
    """
    Run deterministic attack path analysis for a project.
    Completely offline - never executes target APIs.
    """
    project = get_project_or_404(project_id, db)
    # Ensure active AttackGraph exists; if missing, run CorrelationEngine first
    active_graph = (
        db.query(AttackGraph)
        .filter(AttackGraph.project_id == project.id, AttackGraph.status == "ACTIVE")
        .first()
    )
    if not active_graph:
        corr_engine = CorrelationEngine(db=db)
        corr_engine.run_correlation(project_id=project.id)

    engine = AttackPathEngine(db=db)
    result = engine.analyze_project_attack_paths(project_id=project.id)
    return AttackPathAnalysisResponse(
        project_id=result["project_id"],
        attack_graph_id=result["attack_graph_id"],
        paths_count=result["paths_count"],
        paths=[format_attack_path_detail_response(p) for p in result["paths"]],
    )


@attack_path_router.get(
    "/projects/{project_id}/attack-paths",
    response_model=List[AttackPathDetailInDB],
)
def list_project_attack_paths(
    project_id: int,
    db: Session = Depends(get_db),
):
    """List all detected attack paths for a project."""
    project = get_project_or_404(project_id, db)
    paths = (
        db.query(AttackPath)
        .filter(AttackPath.project_id == project.id)
        .order_by(AttackPath.created_at.desc())
        .all()
    )
    return [format_attack_path_detail_response(p) for p in paths]


@attack_path_router.get(
    "/attack-paths/{path_id}",
    response_model=AttackPathDetailInDB,
)
def get_attack_path(
    path_id: str,
    db: Session = Depends(get_db),
):
    """Get single attack path detail with all ordered steps."""
    path = db.query(AttackPath).filter(AttackPath.id == path_id).first()
    if not path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack path {path_id} not found",
        )
    return format_attack_path_detail_response(path)


@attack_path_router.get(
    "/attack-paths/{path_id}/steps",
    response_model=List[AttackPathStepInDB],
)
def get_attack_path_steps(
    path_id: str,
    db: Session = Depends(get_db),
):
    """Get all ordered steps for an attack path."""
    path = db.query(AttackPath).filter(AttackPath.id == path_id).first()
    if not path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack path {path_id} not found",
        )
    steps = (
        db.query(AttackPathStep)
        .filter(AttackPathStep.attack_path_id == path_id)
        .order_by(AttackPathStep.position.asc())
        .all()
    )
    return [format_attack_path_step_response(s) for s in steps]


@attack_path_router.post(
    "/attack-paths/{path_id}/rebuild",
    response_model=AttackPathDetailInDB,
)
def rebuild_attack_path(
    path_id: str,
    db: Session = Depends(get_db),
):
    """
    Rebuild and re-verify an attack path offline.
    Never executes target APIs.
    """
    path = db.query(AttackPath).filter(AttackPath.id == path_id).first()
    if not path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack path {path_id} not found",
        )
    engine = AttackPathEngine(db=db)
    updated_path = engine.rebuild_attack_path(path_id=path.id)
    return format_attack_path_detail_response(updated_path)


# ==============================================================================
# STAGE 8.3: Deterministic Security Impact Analysis Router & Formatters
# ==============================================================================
impact_router = APIRouter(tags=["security-impacts"])


def format_security_impact_response(impact: SecurityImpact, db: Session) -> SecurityImpactDetailInDB:
    path = impact.attack_path or (
        db.query(AttackPath).filter(AttackPath.id == impact.attack_path_id).first()
        if impact.attack_path_id
        else None
    )
    finding = impact.finding or (
        db.query(Finding).filter(Finding.id == impact.finding_id).first()
        if impact.finding_id
        else None
    )

    engine = ImpactEngine(db=db)
    if path:
        eval_res = engine.evaluate_path_impact(path)
    elif finding:
        eval_res = engine.evaluate_finding_impact(finding)
    else:
        eval_res = {
            "identities_involved": [],
            "resources_involved": [],
            "sensitive_properties_reached": [],
            "boundaries_crossed": [],
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

    return SecurityImpactDetailInDB(
        id=impact.id,
        project_id=impact.project_id,
        attack_path_id=impact.attack_path_id,
        finding_id=impact.finding_id,
        initial_access=impact.initial_access,
        authentication_boundary_crossed=impact.authentication_boundary_crossed,
        authorization_boundary_crossed=impact.authorization_boundary_crossed,
        identity_boundary_crossed=impact.identity_boundary_crossed,
        resource_boundary_crossed=impact.resource_boundary_crossed,
        workflow_boundary_crossed=impact.workflow_boundary_crossed,
        property_boundary_crossed=impact.property_boundary_crossed,
        sensitive_data_reached=impact.sensitive_data_reached,
        cross_identity_impact=impact.cross_identity_impact,
        cross_resource_impact=impact.cross_resource_impact,
        terminal_impact=impact.terminal_impact,
        explanation=impact.explanation,
        created_at=impact.created_at,
        updated_at=impact.updated_at,
        attack_path_name=path.name if path else None,
        finding_title=finding.title if finding else None,
        finding_type=finding.type if finding else None,
        identities_involved=eval_res.get("identities_involved", []),
        resources_involved=eval_res.get("resources_involved", []),
        sensitive_properties_reached=eval_res.get("sensitive_properties_reached", []),
        boundaries_crossed=boundaries if boundaries else eval_res.get("boundaries_crossed", []),
    )


@impact_router.post(
    "/projects/{project_id}/impact-analysis/run",
    response_model=SecurityImpactAnalysisResponse,
)
def run_project_impact_analysis(
    project_id: int,
    db: Session = Depends(get_db),
):
    """
    Run deterministic security impact analysis for a project.
    Completely offline - never executes target APIs.
    """
    project = get_project_or_404(project_id, db)
    engine = ImpactEngine(db=db)
    result = engine.run_impact_analysis(project_id=project.id)
    return SecurityImpactAnalysisResponse(
        project_id=result["project_id"],
        impacts_count=result["impacts_count"],
        impacts=[format_security_impact_response(i, db) for i in result["impacts"]],
    )


@impact_router.get(
    "/projects/{project_id}/security-impacts",
    response_model=List[SecurityImpactDetailInDB],
)
def list_project_security_impacts(
    project_id: int,
    db: Session = Depends(get_db),
):
    """List all security impacts analyzed for a project."""
    project = get_project_or_404(project_id, db)
    impacts = (
        db.query(SecurityImpact)
        .filter(SecurityImpact.project_id == project.id)
        .order_by(SecurityImpact.created_at.desc())
        .all()
    )
    return [format_security_impact_response(i, db) for i in impacts]


@impact_router.get(
    "/security-impacts/{impact_id}",
    response_model=SecurityImpactDetailInDB,
)
def get_security_impact(
    impact_id: str,
    db: Session = Depends(get_db),
):
    """Get single security impact analysis detail."""
    impact = db.query(SecurityImpact).filter(SecurityImpact.id == impact_id).first()
    if not impact:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security impact {impact_id} not found",
        )
    return format_security_impact_response(impact, db)


@impact_router.post(
    "/security-impacts/{impact_id}/rebuild",
    response_model=SecurityImpactDetailInDB,
)
def rebuild_security_impact(
    impact_id: str,
    db: Session = Depends(get_db),
):
    """
    Rebuild and re-verify an existing security impact record offline.
    Never executes target APIs.
    """
    impact = db.query(SecurityImpact).filter(SecurityImpact.id == impact_id).first()
    if not impact:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security impact {impact_id} not found",
        )
    engine = ImpactEngine(db=db)
    updated = engine.rebuild_security_impact(impact_id=impact.id)
    return format_security_impact_response(updated, db)


# ==============================================================================
# STAGE 9.1: AI Security Reasoning Routers
# ==============================================================================
ai_router = APIRouter(tags=["AI Security Reasoning"])


def format_ai_analysis_response(analysis: AIAnalysis, db: Session) -> AIAnalysisDetailInDB:
    finding = db.query(Finding).filter(Finding.id == analysis.finding_id).first() if analysis.finding_id else None
    path = db.query(AttackPath).filter(AttackPath.id == analysis.attack_path_id).first() if analysis.attack_path_id else None

    return AIAnalysisDetailInDB(
        id=analysis.id,
        project_id=analysis.project_id,
        attack_path_id=analysis.attack_path_id,
        finding_id=analysis.finding_id,
        analysis_type=analysis.analysis_type,
        status=analysis.status,
        model_provider=analysis.model_provider,
        model_name=analysis.model_name,
        input_context=analysis.input_context or {},
        output=analysis.output,
        error_message=analysis.error_message,
        created_at=analysis.created_at,
        completed_at=analysis.completed_at,
        finding_title=finding.title if finding else None,
        finding_type=finding.type if finding else None,
        attack_path_name=path.name if path else None,
    )


@ai_router.post(
    "/projects/{project_id}/ai/analyze/finding/{finding_id}",
    response_model=AIAnalysisResponse,
)
def analyze_finding_with_ai(
    project_id: int,
    finding_id: str,
    req: Optional[AIAnalyzeRequest] = None,
    db: Session = Depends(get_db),
):
    """
    Run AI security reasoning on a confirmed finding.
    Strictly analytical; never executes target requests or alters findings.
    """
    project = get_project_or_404(project_id, db)
    finding = db.query(Finding).filter(Finding.id == finding_id, Finding.project_id == project.id).first()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding {finding_id} not found in project {project_id}",
        )

    analysis_type = req.analysis_type if (req and req.analysis_type) else AIAnalysisType.FINDING_EXPLANATION.value

    service = AISecurityService(db=db)
    try:
        analysis = service.analyze_finding(finding_id=finding.id, analysis_type=analysis_type)
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )

    return AIAnalysisResponse(analysis=format_ai_analysis_response(analysis, db))


@ai_router.post(
    "/projects/{project_id}/ai/analyze/path/{path_id}",
    response_model=AIAnalysisResponse,
)
def analyze_attack_path_with_ai(
    project_id: int,
    path_id: str,
    req: Optional[AIAnalyzeRequest] = None,
    db: Session = Depends(get_db),
):
    """
    Run AI security reasoning on an active deterministic attack path.
    Synthesizes the chained findings into an explainable narrative.
    """
    project = get_project_or_404(project_id, db)
    path = db.query(AttackPath).filter(AttackPath.id == path_id, AttackPath.project_id == project.id).first()
    if not path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack path {path_id} not found in project {project_id}",
        )

    analysis_type = req.analysis_type if (req and req.analysis_type) else AIAnalysisType.ATTACK_PATH_EXPLANATION.value

    service = AISecurityService(db=db)
    try:
        analysis = service.analyze_attack_path(attack_path_id=path.id, analysis_type=analysis_type)
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )

    return AIAnalysisResponse(analysis=format_ai_analysis_response(analysis, db))


@ai_router.post(
    "/projects/{project_id}/ai/analyze/impact/{impact_id}",
    response_model=AIAnalysisResponse,
)
def analyze_impact_with_ai(
    project_id: int,
    impact_id: str,
    req: Optional[AIAnalyzeRequest] = None,
    db: Session = Depends(get_db),
):
    """
    Run AI security reasoning on a deterministic SecurityImpact record.
    Explains boundary crossing and business implications.
    """
    project = get_project_or_404(project_id, db)
    impact = db.query(SecurityImpact).filter(SecurityImpact.id == impact_id, SecurityImpact.project_id == project.id).first()
    if not impact:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security impact {impact_id} not found in project {project_id}",
        )

    analysis_type = req.analysis_type if (req and req.analysis_type) else AIAnalysisType.IMPACT_EXPLANATION.value

    service = AISecurityService(db=db)
    try:
        analysis = service.analyze_security_impact(impact_id=impact.id, analysis_type=analysis_type)
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )

    return AIAnalysisResponse(analysis=format_ai_analysis_response(analysis, db))


@ai_router.post(
    "/projects/{project_id}/ai/hypotheses/path/{path_id}",
    response_model=AIAnalysisResponse,
)
def generate_attack_path_hypotheses(
    project_id: int,
    path_id: str,
    db: Session = Depends(get_db),
):
    """
    Generate grounded attack hypotheses for an attack path.
    Hypotheses are strictly labeled as requiring human review and are never auto-executed.
    """
    project = get_project_or_404(project_id, db)
    path = db.query(AttackPath).filter(AttackPath.id == path_id, AttackPath.project_id == project.id).first()
    if not path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack path {path_id} not found in project {project_id}",
        )

    service = AISecurityService(db=db)
    try:
        analysis = service.generate_attack_hypotheses(attack_path_id=path.id)
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )

    return AIAnalysisResponse(analysis=format_ai_analysis_response(analysis, db))


@ai_router.post(
    "/projects/{project_id}/ai/recommendations",
    response_model=AIAnalysisResponse,
)
def generate_security_recommendations(
    project_id: int,
    finding_id: Optional[str] = None,
    attack_path_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """
    Generate actionable tactical and architectural recommendations for a finding or attack path.
    """
    project = get_project_or_404(project_id, db)
    if not finding_id and not attack_path_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Must provide either finding_id or attack_path_id",
        )

    service = AISecurityService(db=db)
    try:
        analysis = service.generate_recommendations(
            finding_id=finding_id,
            attack_path_id=attack_path_id,
        )
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )

    return AIAnalysisResponse(analysis=format_ai_analysis_response(analysis, db))


@ai_router.post(
    "/projects/{project_id}/ai/report-summary",
    response_model=AIAnalysisResponse,
)
def generate_project_report_summary(
    project_id: int,
    db: Session = Depends(get_db),
):
    """
    Generate an executive AI security report summary for the project.
    """
    project = get_project_or_404(project_id, db)
    service = AISecurityService(db=db)
    analysis = service.generate_report_summary(project_id=project.id)
    return AIAnalysisResponse(analysis=format_ai_analysis_response(analysis, db))


@ai_router.get(
    "/projects/{project_id}/ai/analyses",
    response_model=AIAnalysesListResponse,
)
def list_project_ai_analyses(
    project_id: int,
    analysis_type: Optional[str] = None,
    finding_id: Optional[str] = None,
    attack_path_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """List historical AI analyses performed for a project."""
    project = get_project_or_404(project_id, db)
    query = db.query(AIAnalysis).filter(AIAnalysis.project_id == project.id)

    if analysis_type:
        query = query.filter(AIAnalysis.analysis_type == analysis_type)
    if finding_id:
        query = query.filter(AIAnalysis.finding_id == finding_id)
    if attack_path_id:
        query = query.filter(AIAnalysis.attack_path_id == attack_path_id)

    analyses = query.order_by(AIAnalysis.created_at.desc()).all()
    formatted = [format_ai_analysis_response(a, db) for a in analyses]

    return AIAnalysesListResponse(
        project_id=project.id,
        count=len(formatted),
        analyses=formatted,
    )


@ai_router.get(
    "/ai/analyses/{analysis_id}",
    response_model=AIAnalysisResponse,
)
def get_ai_analysis(
    analysis_id: str,
    db: Session = Depends(get_db),
):
    """Get single AI analysis by ID."""
    analysis = db.query(AIAnalysis).filter(AIAnalysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AI analysis {analysis_id} not found",
        )
    return AIAnalysisResponse(analysis=format_ai_analysis_response(analysis, db))


# ==============================================================================
# STAGE 9.2: Human-Approved AI Security Testing Endpoints
# ==============================================================================

def format_ai_hypothesis_response(hypo: AIHypothesis, db: Session) -> AIHypothesisDetailInDB:
    finding = db.query(Finding).filter(Finding.id == hypo.finding_id).first() if hypo.finding_id else None
    path = db.query(AttackPath).filter(AttackPath.id == hypo.attack_path_id).first() if hypo.attack_path_id else None
    latest_review = hypo.reviews[0].action if hypo.reviews else None

    return AIHypothesisDetailInDB(
        id=hypo.id,
        project_id=hypo.project_id,
        ai_analysis_id=hypo.ai_analysis_id,
        attack_path_id=hypo.attack_path_id,
        finding_id=hypo.finding_id,
        security_test_id=hypo.security_test_id,
        hypothesis=hypo.hypothesis,
        reason=hypo.reason,
        suggested_test_type=hypo.suggested_test_type,
        required_context=hypo.required_context,
        confidence=hypo.confidence,
        requires_human_review=hypo.requires_human_review,
        status=hypo.status,
        reviewed_at=hypo.reviewed_at,
        reviewed_by=hypo.reviewed_by,
        rejection_reason=hypo.rejection_reason,
        created_at=hypo.created_at,
        updated_at=hypo.updated_at,
        finding_title=finding.title if finding else None,
        attack_path_name=path.name if path else None,
        latest_review_action=latest_review,
    )


@ai_router.get(
    "/projects/{project_id}/ai/hypotheses",
    response_model=AIHypothesisListResponse,
)
def list_project_ai_hypotheses(
    project_id: int,
    status: Optional[str] = None,
    confidence: Optional[str] = None,
    attack_path_id: Optional[str] = None,
    finding_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """List all AI hypotheses generated for a project with optional filters."""
    project = get_project_or_404(project_id, db)
    query = db.query(AIHypothesis).filter(AIHypothesis.project_id == project.id)

    if status:
        query = query.filter(AIHypothesis.status == status)
    if confidence:
        query = query.filter(AIHypothesis.confidence == confidence)
    if attack_path_id:
        query = query.filter(AIHypothesis.attack_path_id == attack_path_id)
    if finding_id:
        query = query.filter(AIHypothesis.finding_id == finding_id)

    hypotheses = query.order_by(AIHypothesis.created_at.desc()).all()
    formatted = [format_ai_hypothesis_response(h, db) for h in hypotheses]

    return AIHypothesisListResponse(
        project_id=project.id,
        count=len(formatted),
        hypotheses=formatted,
    )


@ai_router.get(
    "/ai/hypotheses/{hypothesis_id}",
    response_model=AIHypothesisDetailInDB,
)
def get_ai_hypothesis(
    hypothesis_id: str,
    db: Session = Depends(get_db),
):
    """Get single AI hypothesis by ID."""
    hypo = db.query(AIHypothesis).filter(AIHypothesis.id == hypothesis_id).first()
    if not hypo:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AI hypothesis '{hypothesis_id}' not found",
        )
    return format_ai_hypothesis_response(hypo, db)


@ai_router.post(
    "/ai/hypotheses/{hypothesis_id}/approve",
    response_model=AIHypothesisDetailInDB,
)
def approve_ai_hypothesis(
    hypothesis_id: str,
    req: AIHypothesisApprovalRequest,
    db: Session = Depends(get_db),
):
    """
    Approve an AI security test hypothesis.
    IMPORTANT: Strictly non-executable. Does NOT execute target API requests.
    Creates an immutable audit record and transitions hypothesis status to APPROVED.
    """
    service = HypothesisReviewService(db=db)
    try:
        hypo, _ = service.approve_hypothesis(
            hypothesis_id=hypothesis_id,
            reviewer_reference=req.reviewer_reference,
            reason=req.reason,
        )
    except HypothesisReviewError as hre:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(hre),
        )
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )

    return format_ai_hypothesis_response(hypo, db)


@ai_router.post(
    "/ai/hypotheses/{hypothesis_id}/reject",
    response_model=AIHypothesisDetailInDB,
)
def reject_ai_hypothesis(
    hypothesis_id: str,
    req: AIHypothesisRejectionRequest,
    db: Session = Depends(get_db),
):
    """
    Reject an AI security test hypothesis with a documented reason.
    Creates an immutable audit record and transitions hypothesis status to REJECTED.
    """
    service = HypothesisReviewService(db=db)
    try:
        hypo, _ = service.reject_hypothesis(
            hypothesis_id=hypothesis_id,
            reviewer_reference=req.reviewer_reference,
            reason=req.reason,
        )
    except HypothesisReviewError as hre:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(hre),
        )
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )

    return format_ai_hypothesis_response(hypo, db)


@ai_router.post(
    "/ai/hypotheses/{hypothesis_id}/convert",
    response_model=AIHypothesisConvertResponse,
)
def convert_ai_hypothesis_to_security_test(
    hypothesis_id: str,
    req: Optional[AIHypothesisConvertRequest] = None,
    db: Session = Depends(get_db),
):
    """
    Convert an APPROVED hypothesis into a deterministic SecurityTest configuration.
    IMPORTANT: Strictly non-executable. Does NOT execute target API requests.
    The resulting SecurityTest must be executed separately via the existing security testing engine.
    """
    converter = HypothesisConverter(db=db)
    try:
        hypo, security_test = converter.convert_hypothesis(
            hypothesis_id=hypothesis_id,
            reviewer_reference=req.reviewer_reference if req else None,
        )
    except HypothesisConversionError as hce:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(hce),
        )
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )

    return AIHypothesisConvertResponse(
        hypothesis=format_ai_hypothesis_response(hypo, db),
        security_test_id=security_test.id,
        message=f"Successfully converted hypothesis to deterministic {security_test.test_type} SecurityTest configuration.",
    )


@ai_router.get(
    "/ai/hypotheses/{hypothesis_id}/audit",
    response_model=AIHypothesisAuditResponse,
)
def get_ai_hypothesis_audit(
    hypothesis_id: str,
    db: Session = Depends(get_db),
):
    """
    Get full immutable audit log and lifecycle trace for an AI hypothesis.
    Traces AI creation, human review/approval, conversion, and deterministic engine execution.
    """
    hypo = db.query(AIHypothesis).filter(AIHypothesis.id == hypothesis_id).first()
    if not hypo:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AI hypothesis '{hypothesis_id}' not found",
        )

    # Reviews
    reviews_in_db = [
        AIHypothesisReviewInDB.model_validate(r) for r in hypo.reviews
    ]

    # SecurityTest details (if converted)
    sec_test_data = None
    if hypo.security_test_id and hypo.security_test:
        st = hypo.security_test
        sec_test_data = {
            "id": st.id,
            "test_type": st.test_type,
            "status": st.status,
            "endpoint_id": st.endpoint_id,
            "endpoint_path": st.endpoint.path if st.endpoint else None,
            "endpoint_method": st.endpoint.method if st.endpoint else None,
            "attacker_identity_name": st.attacker_identity.name if st.attacker_identity else None,
            "execution_count": len(st.executions),
            "latest_execution_result": st.executions[-1].result if st.executions else None,
        }

    # Trace Lifecycle Stages
    lifecycle = [
        {
            "stage": "HYPOTHESIS_CREATED",
            "actor": f"AI Reasoner ({hypo.ai_analysis.model_provider} / {hypo.ai_analysis.model_name})" if hypo.ai_analysis else "AI Reasoner",
            "category": "AI ACTION",
            "timestamp": hypo.created_at.isoformat() if hypo.created_at else None,
            "status": "COMPLETED",
            "detail": hypo.hypothesis,
        }
    ]

    # Reviews in chronological order
    sorted_reviews = sorted(hypo.reviews, key=lambda r: r.created_at)
    for r in sorted_reviews:
        lifecycle.append({
            "stage": f"HUMAN_{r.action}",
            "actor": r.reviewer_reference,
            "category": "HUMAN ACTION",
            "timestamp": r.created_at.isoformat() if r.created_at else None,
            "status": "COMPLETED",
            "reason": r.reason,
            "detail": f"Human reviewer marked hypothesis as {r.action}",
        })

    if hypo.status == "CONVERTED" and hypo.security_test_id:
        lifecycle.append({
            "stage": "CONVERTED_TO_SECURITY_TEST",
            "actor": hypo.reviewed_by or "Human Reviewer",
            "category": "HUMAN ACTION",
            "timestamp": hypo.updated_at.isoformat() if hypo.updated_at else None,
            "status": "COMPLETED",
            "security_test_id": hypo.security_test_id,
            "detail": f"Converted into deterministic {hypo.suggested_test_type} SecurityTest without executing target traffic.",
        })

        # Check if executed separately by Deterministic Security Engine
        if hypo.security_test and hypo.security_test.executions:
            for exec_item in hypo.security_test.executions:
                lifecycle.append({
                    "stage": "DETERMINISTIC_ENGINE_EXECUTION",
                    "actor": "Deterministic Security Engine",
                    "category": "DETERMINISTIC ENGINE ACTION",
                    "timestamp": exec_item.created_at.isoformat() if exec_item.created_at else None,
                    "status": exec_item.status,
                    "execution_id": exec_item.id,
                    "result": exec_item.result,
                    "detail": f"Executed via SecurityTest engine: Result {exec_item.result}",
                })

    return AIHypothesisAuditResponse(
        hypothesis=format_ai_hypothesis_response(hypo, db),
        reviews=reviews_in_db,
        security_test=sec_test_data,
        lifecycle_stages=lifecycle,
    )


# ==============================================================================
# STAGE 9.3: Security Investigation Workspace Router
# ==============================================================================

investigation_router = APIRouter(tags=["Security Investigations"])


def format_investigation_response(
    inv: SecurityInvestigation, db: Session
) -> SecurityInvestigationDetailInDB:
    primary_f_title = None
    primary_f_sev = None
    if inv.primary_finding:
        primary_f_title = inv.primary_finding.title
        primary_f_sev = inv.primary_finding.severity

    primary_p_name = None
    if inv.primary_attack_path:
        primary_p_name = inv.primary_attack_path.name

    items_in_db = [
        InvestigationItemInDB(
            id=item.id,
            investigation_id=item.investigation_id,
            item_type=item.item_type,
            item_id=item.item_id,
            position=item.position,
            created_at=item.created_at,
        )
        for item in inv.items
    ]

    return SecurityInvestigationDetailInDB(
        id=inv.id,
        project_id=inv.project_id,
        title=inv.title,
        description=inv.description,
        status=inv.status,
        primary_finding_id=inv.primary_finding_id,
        primary_attack_path_id=inv.primary_attack_path_id,
        primary_finding_title=primary_f_title,
        primary_finding_severity=primary_f_sev,
        primary_attack_path_name=primary_p_name,
        item_count=len(inv.items),
        items=items_in_db,
        created_at=inv.created_at,
        updated_at=inv.updated_at,
        resolved_at=inv.resolved_at,
    )


@investigation_router.post(
    "/projects/{project_id}/investigations",
    response_model=SecurityInvestigationDetailInDB,
    status_code=status.HTTP_201_CREATED,
)
def create_investigation(
    project_id: int,
    req: SecurityInvestigationCreate,
    db: Session = Depends(get_db),
):
    service = InvestigationService(db=db)
    try:
        inv = service.create_investigation(
            project_id=project_id,
            title=req.title,
            description=req.description,
            primary_finding_id=req.primary_finding_id,
            primary_attack_path_id=req.primary_attack_path_id,
        )
    except CrossProjectViolationError as cpe:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(cpe))
    except InvestigationServiceError as ise:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ise))

    return format_investigation_response(inv, db)


@investigation_router.post(
    "/projects/{project_id}/investigations/from-finding/{finding_id}",
    response_model=SecurityInvestigationDetailInDB,
    status_code=status.HTTP_201_CREATED,
)
def create_investigation_from_finding(
    project_id: int,
    finding_id: str,
    title: Optional[str] = None,
    description: Optional[str] = None,
    force_new: bool = False,
    db: Session = Depends(get_db),
):
    service = InvestigationService(db=db)
    try:
        inv = service.create_from_finding(
            project_id=project_id,
            finding_id=finding_id,
            title=title,
            description=description,
            force_new=force_new,
        )
    except InvalidFindingStateError as ifse:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ifse))
    except CrossProjectViolationError as cpe:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(cpe))
    except InvestigationServiceError as ise:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ise))

    return format_investigation_response(inv, db)


@investigation_router.post(
    "/projects/{project_id}/investigations/from-path/{attack_path_id}",
    response_model=SecurityInvestigationDetailInDB,
    status_code=status.HTTP_201_CREATED,
)
def create_investigation_from_attack_path(
    project_id: int,
    attack_path_id: str,
    title: Optional[str] = None,
    description: Optional[str] = None,
    force_new: bool = False,
    db: Session = Depends(get_db),
):
    service = InvestigationService(db=db)
    try:
        inv = service.create_from_attack_path(
            project_id=project_id,
            attack_path_id=attack_path_id,
            title=title,
            description=description,
            force_new=force_new,
        )
    except CrossProjectViolationError as cpe:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(cpe))
    except InvestigationServiceError as ise:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ise))

    return format_investigation_response(inv, db)


@investigation_router.get(
    "/projects/{project_id}/investigations",
    response_model=SecurityInvestigationListResponse,
)
def list_project_investigations(
    project_id: int,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
):
    get_project_or_404(project_id, db)
    query = db.query(SecurityInvestigation).filter(SecurityInvestigation.project_id == project_id)
    if status:
        query = query.filter(SecurityInvestigation.status == status.upper())

    investigations = query.order_by(SecurityInvestigation.created_at.desc()).all()
    formatted = [format_investigation_response(inv, db) for inv in investigations]
    return SecurityInvestigationListResponse(
        project_id=project_id,
        count=len(formatted),
        investigations=formatted,
    )


@investigation_router.get(
    "/investigations/{investigation_id}",
    response_model=SecurityInvestigationDetailInDB,
)
def get_investigation(
    investigation_id: str,
    db: Session = Depends(get_db),
):
    inv = db.query(SecurityInvestigation).filter(SecurityInvestigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found",
        )
    return format_investigation_response(inv, db)


@investigation_router.patch(
    "/investigations/{investigation_id}",
    response_model=SecurityInvestigationDetailInDB,
)
def update_investigation(
    investigation_id: str,
    req: SecurityInvestigationUpdate,
    db: Session = Depends(get_db),
):
    service = InvestigationService(db=db)
    try:
        inv = service.update_investigation(
            investigation_id=investigation_id,
            title=req.title,
            description=req.description,
            status=req.status,
        )
    except InvestigationServiceError as ise:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ise))

    return format_investigation_response(inv, db)


@investigation_router.post(
    "/investigations/{investigation_id}/items",
    response_model=InvestigationItemInDB,
    status_code=status.HTTP_201_CREATED,
)
def attach_investigation_item(
    investigation_id: str,
    req: InvestigationItemCreate,
    db: Session = Depends(get_db),
):
    service = InvestigationService(db=db)
    try:
        item = service.attach_item(
            investigation_id=investigation_id,
            item_type=req.item_type,
            item_id=req.item_id,
            position=req.position,
        )
    except InvalidFindingStateError as ifse:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ifse))
    except CrossProjectViolationError as cpe:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(cpe))
    except InvestigationServiceError as ise:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ise))

    return InvestigationItemInDB.model_validate(item)


@investigation_router.delete(
    "/investigations/{investigation_id}/items/{item_id}",
)
def detach_investigation_item(
    investigation_id: str,
    item_id: str,
    db: Session = Depends(get_db),
):
    service = InvestigationService(db=db)
    detached = service.detach_item(investigation_id=investigation_id, item_id=item_id)
    if not detached:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Item '{item_id}' not found in investigation '{investigation_id}'",
        )
    return {"message": "Item successfully detached from investigation", "item_id": item_id}


@investigation_router.get(
    "/investigations/{investigation_id}/timeline",
    response_model=InvestigationTimelineResponse,
)
def get_investigation_timeline(
    investigation_id: str,
    db: Session = Depends(get_db),
):
    service = InvestigationService(db=db)
    try:
        events = service.get_investigation_timeline(investigation_id=investigation_id)
    except InvestigationServiceError as ise:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ise))

    return InvestigationTimelineResponse(
        investigation_id=investigation_id,
        events=[InvestigationTimelineEvent(**e) for e in events],
    )


@investigation_router.get(
    "/investigations/{investigation_id}/context",
    response_model=InvestigationContextResponse,
)
def get_investigation_context(
    investigation_id: str,
    db: Session = Depends(get_db),
):
    service = InvestigationService(db=db)
    try:
        ctx = service.get_investigation_context(investigation_id=investigation_id)
    except InvestigationServiceError as ise:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ise))

    return InvestigationContextResponse(**ctx)


# ==============================================================================
# STAGE 10.1: Security Test Orchestration & Execution Plans Router
# ==============================================================================

test_suite_router = APIRouter(tags=["Security Test Suites"])
execution_plan_router = APIRouter(tags=["Security Execution Plans"])


def format_suite_response(suite: SecurityTestSuite) -> SecurityTestSuiteInDB:
    items_in_db = [
        SecurityTestSuiteItemInDB(
            id=item.id,
            suite_id=item.suite_id,
            security_test_id=item.security_test_id,
            execution_order=item.execution_order,
            enabled=item.enabled,
            created_at=item.created_at,
            test_type=item.test_type,
            endpoint=item.endpoint,
            attacker_identity=item.attacker_identity,
        )
        for item in suite.items
    ]
    return SecurityTestSuiteInDB(
        id=suite.id,
        project_id=suite.project_id,
        name=suite.name,
        description=suite.description,
        status=suite.status,
        created_at=suite.created_at,
        updated_at=suite.updated_at,
        test_count=len(suite.items),
        items=items_in_db,
    )


def format_plan_response(plan: SecurityExecutionPlan) -> SecurityExecutionPlanInDB:
    items_in_db = [
        SecurityExecutionItemInDB(
            id=item.id,
            execution_plan_id=item.execution_plan_id,
            security_test_id=item.security_test_id,
            execution_order=item.execution_order,
            status=item.status,
            test_execution_id=item.test_execution_id,
            result=item.result,
            started_at=item.started_at,
            completed_at=item.completed_at,
            error_message=item.error_message,
            test_type=item.test_type,
            endpoint=item.endpoint,
            attacker_identity=item.attacker_identity,
        )
        for item in plan.items
    ]
    return SecurityExecutionPlanInDB(
        id=plan.id,
        project_id=plan.project_id,
        suite_id=plan.suite_id,
        profile_id=plan.profile_id,
        profile_name=plan.profile_name,
        source_type=plan.source_type,
        name=plan.name,
        status=plan.status,
        execution_mode=plan.execution_mode,
        total_tests=plan.total_tests,
        completed_tests=plan.completed_tests,
        confirmed_findings=plan.confirmed_findings,
        inconclusive_tests=plan.inconclusive_tests,
        failed_tests=plan.failed_tests,
        created_at=plan.created_at,
        started_at=plan.started_at,
        completed_at=plan.completed_at,
        suite_name=plan.suite_name,
        items=items_in_db,
    )


def format_plan_progress_response(progress: Dict[str, Any]) -> SecurityExecutionProgressResponse:
    items_in_db = [
        SecurityExecutionItemInDB(
            id=item.id,
            execution_plan_id=item.execution_plan_id,
            security_test_id=item.security_test_id,
            execution_order=item.execution_order,
            status=item.status,
            test_execution_id=item.test_execution_id,
            result=item.result,
            started_at=item.started_at,
            completed_at=item.completed_at,
            error_message=item.error_message,
            test_type=item.test_type,
            endpoint=item.endpoint,
            attacker_identity=item.attacker_identity,
        )
        for item in progress["items"]
    ]
    return SecurityExecutionProgressResponse(
        plan_id=progress["plan_id"],
        project_id=progress["project_id"],
        name=progress["name"],
        status=progress["status"],
        execution_mode=progress["execution_mode"],
        total_tests=progress["total_tests"],
        completed_tests=progress["completed_tests"],
        progress_percent=progress["progress_percent"],
        results_summary=progress["results_summary"],
        items=items_in_db,
        started_at=progress["started_at"],
        completed_at=progress["completed_at"],
    )


# --- Test Suite Endpoints ---

@test_suite_router.post(
    "/projects/{project_id}/test-suites",
    response_model=SecurityTestSuiteInDB,
    status_code=status.HTTP_201_CREATED,
)
def create_test_suite(
    project_id: int,
    suite_in: SecurityTestSuiteCreate,
    db: Session = Depends(get_db),
):
    orchestrator = TestOrchestrator(db=db)
    try:
        suite = orchestrator.create_suite(
            project_id=project_id,
            name=suite_in.name,
            description=suite_in.description,
            status=suite_in.status,
        )
    except OrchestratorEntityNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    return format_suite_response(suite)


@test_suite_router.get(
    "/projects/{project_id}/test-suites",
    response_model=SecurityTestSuiteListResponse,
)
def list_test_suites(
    project_id: int,
    db: Session = Depends(get_db),
):
    get_project_or_404(project_id, db)
    orchestrator = TestOrchestrator(db=db)
    suites = orchestrator.list_suites(project_id)
    return SecurityTestSuiteListResponse(
        project_id=project_id,
        count=len(suites),
        test_suites=[format_suite_response(s) for s in suites],
    )


@test_suite_router.get(
    "/test-suites/{suite_id}",
    response_model=SecurityTestSuiteInDB,
)
def get_test_suite(
    suite_id: str,
    db: Session = Depends(get_db),
):
    orchestrator = TestOrchestrator(db=db)
    suite = orchestrator.get_suite(suite_id)
    if not suite:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Test suite with ID {suite_id} not found.",
        )
    return format_suite_response(suite)


@test_suite_router.patch(
    "/test-suites/{suite_id}",
    response_model=SecurityTestSuiteInDB,
)
def update_test_suite(
    suite_id: str,
    suite_in: SecurityTestSuiteUpdate,
    db: Session = Depends(get_db),
):
    orchestrator = TestOrchestrator(db=db)
    try:
        suite = orchestrator.update_suite(
            suite_id=suite_id,
            name=suite_in.name,
            description=suite_in.description,
            status=suite_in.status,
        )
    except OrchestratorEntityNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    return format_suite_response(suite)


@test_suite_router.delete(
    "/test-suites/{suite_id}",
)
def delete_test_suite(
    suite_id: str,
    db: Session = Depends(get_db),
):
    orchestrator = TestOrchestrator(db=db)
    try:
        orchestrator.delete_suite(suite_id)
    except OrchestratorEntityNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    return {"status": "deleted", "suite_id": suite_id}


@test_suite_router.post(
    "/test-suites/{suite_id}/tests",
    response_model=SecurityTestSuiteItemInDB,
    status_code=status.HTTP_201_CREATED,
)
def add_test_to_suite(
    suite_id: str,
    item_in: SecurityTestSuiteItemCreate,
    db: Session = Depends(get_db),
):
    orchestrator = TestOrchestrator(db=db)
    try:
        item = orchestrator.add_test_to_suite(
            suite_id=suite_id,
            security_test_id=item_in.security_test_id,
            execution_order=item_in.execution_order,
            enabled=item_in.enabled,
        )
    except OrchestratorEntityNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except CrossProjectViolationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    return SecurityTestSuiteItemInDB(
        id=item.id,
        suite_id=item.suite_id,
        security_test_id=item.security_test_id,
        execution_order=item.execution_order,
        enabled=item.enabled,
        created_at=item.created_at,
        test_type=item.test_type,
        endpoint=item.endpoint,
        attacker_identity=item.attacker_identity,
    )


@test_suite_router.patch(
    "/test-suites/{suite_id}/tests/{item_id}",
    response_model=SecurityTestSuiteItemInDB,
)
def update_suite_item(
    suite_id: str,
    item_id: str,
    item_in: SecurityTestSuiteItemUpdate,
    db: Session = Depends(get_db),
):
    orchestrator = TestOrchestrator(db=db)
    try:
        item = orchestrator.update_suite_item(
            suite_id=suite_id,
            item_id=item_id,
            execution_order=item_in.execution_order,
            enabled=item_in.enabled,
        )
    except OrchestratorEntityNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    return SecurityTestSuiteItemInDB(
        id=item.id,
        suite_id=item.suite_id,
        security_test_id=item.security_test_id,
        execution_order=item.execution_order,
        enabled=item.enabled,
        created_at=item.created_at,
        test_type=item.test_type,
        endpoint=item.endpoint,
        attacker_identity=item.attacker_identity,
    )


@test_suite_router.delete(
    "/test-suites/{suite_id}/tests/{item_id}",
)
def remove_test_from_suite(
    suite_id: str,
    item_id: str,
    db: Session = Depends(get_db),
):
    orchestrator = TestOrchestrator(db=db)
    try:
        orchestrator.remove_test_from_suite(suite_id, item_id)
    except OrchestratorEntityNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    return {"status": "deleted", "item_id": item_id}


# --- Execution Plan Endpoints ---

@execution_plan_router.post(
    "/projects/{project_id}/execution-plans",
    response_model=SecurityExecutionPlanInDB,
    status_code=status.HTTP_201_CREATED,
)
def create_execution_plan(
    project_id: int,
    plan_in: SecurityExecutionPlanCreate,
    db: Session = Depends(get_db),
):
    get_project_or_404(project_id, db)
    orchestrator = TestOrchestrator(db=db)
    try:
        if plan_in.suite_id:
            plan = orchestrator.create_plan_from_suite(
                project_id=project_id,
                suite_id=plan_in.suite_id,
                name=plan_in.name,
                execution_mode=plan_in.execution_mode,
            )
        elif plan_in.security_test_ids:
            plan = orchestrator.create_plan_from_tests(
                project_id=project_id,
                security_test_ids=plan_in.security_test_ids,
                name=plan_in.name,
                execution_mode=plan_in.execution_mode,
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Either 'suite_id' or 'security_test_ids' must be provided.",
            )
    except (OrchestratorEntityNotFoundError, InvalidSuiteStateError, CrossProjectViolationError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return format_plan_response(plan)


@execution_plan_router.get(
    "/projects/{project_id}/execution-plans",
    response_model=SecurityExecutionPlanListResponse,
)
def list_execution_plans(
    project_id: int,
    db: Session = Depends(get_db),
):
    get_project_or_404(project_id, db)
    orchestrator = TestOrchestrator(db=db)
    plans = orchestrator.list_plans(project_id)
    return SecurityExecutionPlanListResponse(
        project_id=project_id,
        count=len(plans),
        execution_plans=[format_plan_response(p) for p in plans],
    )


@execution_plan_router.get(
    "/execution-plans/{plan_id}",
    response_model=SecurityExecutionPlanInDB,
)
def get_execution_plan(
    plan_id: str,
    db: Session = Depends(get_db),
):
    orchestrator = TestOrchestrator(db=db)
    plan = orchestrator.get_plan(plan_id)
    if not plan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Execution plan with ID {plan_id} not found.",
        )
    return format_plan_response(plan)


@execution_plan_router.post(
    "/execution-plans/{plan_id}/start",
    response_model=SecurityExecutionPlanInDB,
)
async def start_execution_plan(
    plan_id: str,
    db: Session = Depends(get_db),
):
    orchestrator = TestOrchestrator(db=db)
    try:
        plan = await orchestrator.start_plan(plan_id)
    except OrchestratorEntityNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except (PlanStateError, OrchestratorAuthorizationError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    return format_plan_response(plan)


@execution_plan_router.post(
    "/execution-plans/{plan_id}/cancel",
    response_model=SecurityExecutionPlanInDB,
)
def cancel_execution_plan(
    plan_id: str,
    db: Session = Depends(get_db),
):
    orchestrator = TestOrchestrator(db=db)
    try:
        plan = orchestrator.cancel_plan(plan_id)
    except OrchestratorEntityNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    return format_plan_response(plan)


@execution_plan_router.get(
    "/execution-plans/{plan_id}/progress",
    response_model=SecurityExecutionProgressResponse,
)
def get_execution_plan_progress(
    plan_id: str,
    db: Session = Depends(get_db),
):
    orchestrator = TestOrchestrator(db=db)
    try:
        progress = orchestrator.get_plan_progress(plan_id)
    except OrchestratorEntityNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    return format_plan_progress_response(progress)


# ==============================================================================
# STAGE 10.2: Scan Profiles & Security Baselines Routers
# ==============================================================================

scan_profile_router = APIRouter(tags=["Scan Profiles"])
baseline_router = APIRouter(tags=["Security Baselines"])
baseline_comparison_router = APIRouter(tags=["Baseline Comparisons"])


def format_scan_profile_response(profile: ScanProfile) -> ScanProfileInDB:
    return ScanProfileInDB(
        id=profile.id,
        project_id=profile.project_id,
        name=profile.name,
        description=profile.description,
        profile_type=profile.profile_type,
        status=profile.status,
        configuration=profile.configuration or {},
        created_at=profile.created_at,
        updated_at=profile.updated_at,
    )


def format_baseline_response(baseline: SecurityBaseline) -> SecurityBaselineInDB:
    controls = [
        SecurityBaselineControlInDB(
            id=c.id,
            baseline_id=c.baseline_id,
            control_type=c.control_type,
            target_type=c.target_type,
            target_id=c.target_id,
            expected_behavior=c.expected_behavior,
            severity=c.severity,
            enabled=c.enabled,
            configuration=c.configuration or {},
            created_at=c.created_at,
        )
        for c in (baseline.controls or [])
    ]
    return SecurityBaselineInDB(
        id=baseline.id,
        project_id=baseline.project_id,
        name=baseline.name,
        description=baseline.description,
        status=baseline.status,
        source_execution_plan_id=baseline.source_execution_plan_id,
        version=baseline.version,
        control_count=len(controls),
        created_at=baseline.created_at,
        updated_at=baseline.updated_at,
        controls=controls,
    )


def format_comparison_item(item: SecurityBaselineComparisonItem) -> SecurityBaselineComparisonItemInDB:
    return SecurityBaselineComparisonItemInDB(
        id=item.id,
        comparison_id=item.comparison_id,
        control_id=item.control_id,
        security_test_id=item.security_test_id,
        finding_id=item.finding_id,
        result=item.result,
        previous_behavior=item.previous_behavior,
        current_behavior=item.current_behavior,
        explanation=item.explanation,
        evidence_reference=item.evidence_reference or {},
        created_at=item.created_at,
    )


def format_comparison_response(comp: SecurityBaselineComparison) -> SecurityBaselineComparisonInDB:
    items = [format_comparison_item(i) for i in (comp.items or [])]
    return SecurityBaselineComparisonInDB(
        id=comp.id,
        baseline_id=comp.baseline_id,
        execution_plan_id=comp.execution_plan_id,
        status=comp.status,
        summary=comp.summary or {},
        created_at=comp.created_at,
        items=items,
    )


# --- Scan Profile Endpoints ---

@scan_profile_router.post(
    "/projects/{project_id}/scan-profiles",
    response_model=ScanProfileInDB,
    status_code=status.HTTP_201_CREATED,
)
def create_scan_profile(
    project_id: int,
    profile_in: ScanProfileCreate,
    db: Session = Depends(get_db),
):
    get_project_or_404(project_id, db)
    service = ScanProfileService(db=db)
    try:
        profile = service.create_profile(
            project_id=project_id,
            name=profile_in.name,
            profile_type=profile_in.profile_type,
            description=profile_in.description,
            configuration=profile_in.configuration,
            status=profile_in.status,
        )
    except DuplicateProfileError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except ProfileNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    return format_scan_profile_response(profile)


@scan_profile_router.get(
    "/projects/{project_id}/scan-profiles",
    response_model=ScanProfileListResponse,
)
def list_scan_profiles(
    project_id: int,
    status: Optional[str] = None,
    profile_type: Optional[str] = None,
    db: Session = Depends(get_db),
):
    get_project_or_404(project_id, db)
    service = ScanProfileService(db=db)
    profiles = service.list_profiles(project_id, status=status, profile_type=profile_type)
    return ScanProfileListResponse(
        project_id=project_id,
        count=len(profiles),
        profiles=[format_scan_profile_response(p) for p in profiles],
    )


@scan_profile_router.get(
    "/scan-profiles/{profile_id}",
    response_model=ScanProfileInDB,
)
def get_scan_profile(
    profile_id: str,
    db: Session = Depends(get_db),
):
    service = ScanProfileService(db=db)
    profile = service.get_profile(profile_id)
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan profile with ID {profile_id} not found.",
        )
    return format_scan_profile_response(profile)


@scan_profile_router.put(
    "/scan-profiles/{profile_id}",
    response_model=ScanProfileInDB,
)
def update_scan_profile(
    profile_id: str,
    profile_in: ScanProfileUpdate,
    db: Session = Depends(get_db),
):
    service = ScanProfileService(db=db)
    try:
        profile = service.update_profile(
            profile_id=profile_id,
            name=profile_in.name,
            description=profile_in.description,
            profile_type=profile_in.profile_type,
            status=profile_in.status,
            configuration=profile_in.configuration,
        )
    except ProfileNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except DuplicateProfileError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    return format_scan_profile_response(profile)


@scan_profile_router.delete(
    "/scan-profiles/{profile_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_scan_profile(
    profile_id: str,
    db: Session = Depends(get_db),
):
    service = ScanProfileService(db=db)
    try:
        service.delete_profile(profile_id)
    except ProfileNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    return None


@scan_profile_router.get(
    "/scan-profiles/{profile_id}/preview",
    response_model=ScanProfilePreviewResponse,
)
def preview_scan_profile(
    profile_id: str,
    db: Session = Depends(get_db),
):
    service = ScanProfileService(db=db)
    try:
        preview_data = service.preview_profile(profile_id)
    except ProfileNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    return ScanProfilePreviewResponse(
        profile_id=preview_data["profile_id"],
        profile_name=preview_data["profile_name"],
        profile_type=preview_data["profile_type"],
        selected_test_count=preview_data["selected_test_count"],
        selected_tests=[
            TestSelectionReason(
                security_test_id=t["security_test_id"],
                test_type=t["test_type"],
                endpoint=t["endpoint"],
                priority=t["priority"],
                reason=t["reason"],
            )
            for t in preview_data["selected_tests"]
        ],
    )


@scan_profile_router.post(
    "/scan-profiles/{profile_id}/create-plan",
    response_model=SecurityExecutionPlanInDB,
    status_code=status.HTTP_201_CREATED,
)
def create_plan_from_profile(
    profile_id: str,
    plan_in: PlanFromProfileRequest,
    db: Session = Depends(get_db),
):
    service = ScanProfileService(db=db)
    profile = service.get_profile(profile_id)
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan profile with ID {profile_id} not found.",
        )
    try:
        plan = service.create_plan_from_profile(
            project_id=profile.project_id,
            profile_id=profile_id,
            name=plan_in.name,
            execution_mode=plan_in.execution_mode,
        )
    except DisabledProfileError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except ProfileNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    return format_plan_response(plan)


# --- Security Baseline Endpoints ---

@baseline_router.post(
    "/projects/{project_id}/baselines",
    response_model=SecurityBaselineInDB,
    status_code=status.HTTP_201_CREATED,
)
def create_baseline(
    project_id: int,
    baseline_in: SecurityBaselineCreate,
    db: Session = Depends(get_db),
):
    get_project_or_404(project_id, db)
    service = SecurityBaselineService(db=db)
    try:
        baseline = service.create_baseline(
            project_id=project_id,
            name=baseline_in.name,
            description=baseline_in.description,
            source_execution_plan_id=baseline_in.source_execution_plan_id,
            status=baseline_in.status,
        )
    except BaselineNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    return format_baseline_response(baseline)


@baseline_router.post(
    "/projects/{project_id}/baselines/from-plan",
    response_model=SecurityBaselineInDB,
    status_code=status.HTTP_201_CREATED,
)
def create_baseline_from_plan(
    project_id: int,
    req: BaselineFromPlanRequest,
    db: Session = Depends(get_db),
):
    get_project_or_404(project_id, db)
    service = SecurityBaselineService(db=db)
    try:
        baseline = service.create_baseline_from_execution_plan(
            project_id=project_id,
            execution_plan_id=req.execution_plan_id,
            name=req.name,
            description=req.description,
        )
    except BaselineNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except (InvalidBaselinePlanError, CrossProjectViolationError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    return format_baseline_response(baseline)


@baseline_router.get(
    "/projects/{project_id}/baselines",
    response_model=SecurityBaselineListResponse,
)
def list_baselines(
    project_id: int,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
):
    get_project_or_404(project_id, db)
    service = SecurityBaselineService(db=db)
    baselines = service.list_baselines(project_id=project_id, status=status)
    return SecurityBaselineListResponse(
        project_id=project_id,
        count=len(baselines),
        baselines=[format_baseline_response(b) for b in baselines],
    )


@baseline_router.get(
    "/baselines/{baseline_id}",
    response_model=SecurityBaselineInDB,
)
def get_baseline(
    baseline_id: str,
    db: Session = Depends(get_db),
):
    service = SecurityBaselineService(db=db)
    baseline = service.get_baseline(baseline_id)
    if not baseline:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security baseline with ID {baseline_id} not found.",
        )
    return format_baseline_response(baseline)


@baseline_router.put(
    "/baselines/{baseline_id}",
    response_model=SecurityBaselineInDB,
)
def update_baseline(
    baseline_id: str,
    baseline_in: SecurityBaselineUpdate,
    db: Session = Depends(get_db),
):
    service = SecurityBaselineService(db=db)
    try:
        baseline = service.update_baseline(
            baseline_id=baseline_id,
            name=baseline_in.name,
            description=baseline_in.description,
            status=baseline_in.status,
        )
    except BaselineNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    return format_baseline_response(baseline)


@baseline_router.post(
    "/baselines/{baseline_id}/activate",
    response_model=SecurityBaselineInDB,
)
def activate_baseline(
    baseline_id: str,
    db: Session = Depends(get_db),
):
    service = SecurityBaselineService(db=db)
    try:
        baseline = service.activate_baseline(baseline_id)
    except BaselineNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    return format_baseline_response(baseline)


@baseline_router.post(
    "/baselines/{baseline_id}/archive",
    response_model=SecurityBaselineInDB,
)
def archive_baseline(
    baseline_id: str,
    db: Session = Depends(get_db),
):
    service = SecurityBaselineService(db=db)
    try:
        baseline = service.archive_baseline(baseline_id)
    except BaselineNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    return format_baseline_response(baseline)


# --- Baseline Comparison Endpoints ---

@baseline_comparison_router.post(
    "/baselines/{baseline_id}/compare",
    response_model=SecurityBaselineComparisonInDB,
    status_code=status.HTTP_201_CREATED,
)
def compare_baseline_with_plan(
    baseline_id: str,
    req: BaselineFromPlanRequest,
    db: Session = Depends(get_db),
):
    service = BaselineComparisonService(db=db)
    try:
        comparison = service.compare_baseline_with_plan(
            baseline_id=baseline_id,
            execution_plan_id=req.execution_plan_id,
        )
    except BaselineNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except (InvalidBaselinePlanError, CrossProjectViolationError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    return format_comparison_response(comparison)


@baseline_comparison_router.get(
    "/baseline-comparisons/{comparison_id}",
    response_model=SecurityBaselineComparisonDetailResponse,
)
def get_baseline_comparison(
    comparison_id: str,
    db: Session = Depends(get_db),
):
    service = BaselineComparisonService(db=db)
    comparison = service.get_comparison(comparison_id)
    if not comparison:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Baseline comparison with ID {comparison_id} not found.",
        )

    formatted_items = [format_comparison_item(i) for i in (comparison.items or [])]
    regressions = [i for i in formatted_items if i.result == "REGRESSION"]
    new_violations = [i for i in formatted_items if i.result == "NEW_VIOLATION"]
    improvements = [i for i in formatted_items if i.result == "IMPROVED"]
    unchanged = [i for i in formatted_items if i.result == "UNCHANGED"]
    not_applicable = [i for i in formatted_items if i.result == "NOT_APPLICABLE"]

    return SecurityBaselineComparisonDetailResponse(
        comparison=format_comparison_response(comparison),
        baseline_name=comparison.baseline.name if comparison.baseline else "Baseline",
        baseline_version=comparison.baseline.version if comparison.baseline else 1,
        plan_name=comparison.execution_plan.name if comparison.execution_plan else "Plan",
        plan_status=comparison.execution_plan.status if comparison.execution_plan else "COMPLETED",
        regressions=regressions,
        new_violations=new_violations,
        improvements=improvements,
        unchanged=unchanged,
        not_applicable=not_applicable,
    )


@baseline_comparison_router.get(
    "/projects/{project_id}/baseline-comparisons",
    response_model=List[SecurityBaselineComparisonInDB],
)
def list_baseline_comparisons(
    project_id: int,
    baseline_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    get_project_or_404(project_id, db)
    service = BaselineComparisonService(db=db)
    comparisons = service.list_comparisons(project_id=project_id, baseline_id=baseline_id)
    return [format_comparison_response(c) for c in comparisons]


# --- Security Gate Endpoints ---

security_gate_router = APIRouter(tags=["Security Gates"])


def format_gate_response(gate: SecurityGate) -> SecurityGateInDB:
    latest_eval = (
        sorted(gate.evaluations, key=lambda e: e.evaluated_at, reverse=True)[0]
        if gate.evaluations
        else None
    )
    return SecurityGateInDB(
        id=gate.id,
        project_id=gate.project_id,
        name=gate.name,
        description=gate.description,
        status=gate.status,
        baseline_id=gate.baseline_id,
        scan_profile_id=gate.scan_profile_id,
        failure_rules=gate.failure_rules or {},
        warning_rules=gate.warning_rules or {},
        created_at=gate.created_at,
        updated_at=gate.updated_at,
        baseline_name=gate.baseline.name if gate.baseline else None,
        baseline_version=gate.baseline.version if gate.baseline else None,
        scan_profile_name=gate.scan_profile.name if gate.scan_profile else None,
        latest_evaluation_status=latest_eval.status if latest_eval else None,
    )


def format_evaluation_item(item: SecurityGateEvaluationItem) -> SecurityGateEvaluationItemInDB:
    return SecurityGateEvaluationItemInDB(
        id=item.id,
        evaluation_id=item.evaluation_id,
        rule_type=item.rule_type,
        severity=item.severity,
        triggered=item.triggered,
        actual_value=item.actual_value,
        threshold=item.threshold,
        message=item.message,
        finding_id=item.finding_id,
        comparison_item_id=item.comparison_item_id,
        security_test_id=item.security_test_id,
    )


def format_evaluation_response(ev: SecurityGateEvaluation) -> SecurityGateEvaluationInDB:
    return SecurityGateEvaluationInDB(
        id=ev.id,
        gate_id=ev.gate_id,
        project_id=ev.project_id,
        baseline_comparison_id=ev.baseline_comparison_id,
        status=ev.status,
        failure_count=ev.failure_count,
        warning_count=ev.warning_count,
        confirmed_findings=ev.confirmed_findings,
        regressions=ev.regressions,
        new_violations=ev.new_violations,
        failed_tests=ev.failed_tests,
        inconclusive_tests=ev.inconclusive_tests,
        error_tests=ev.error_tests,
        summary=ev.summary or {},
        evaluated_at=ev.evaluated_at,
        gate_name=ev.gate.name if ev.gate else None,
        items=[format_evaluation_item(i) for i in (ev.items or [])],
    )


@security_gate_router.post(
    "/projects/{project_id}/security-gates",
    response_model=SecurityGateInDB,
    status_code=status.HTTP_201_CREATED,
)
def create_security_gate(
    project_id: int,
    gate_in: SecurityGateCreate,
    db: Session = Depends(get_db),
):
    get_project_or_404(project_id, db)
    service = SecurityGateService(db=db)
    try:
        gate = service.create_gate(
            project_id=project_id,
            name=gate_in.name,
            baseline_id=gate_in.baseline_id,
            scan_profile_id=gate_in.scan_profile_id,
            failure_rules=gate_in.failure_rules,
            warning_rules=gate_in.warning_rules,
            description=gate_in.description,
            status=gate_in.status,
        )
    except DuplicateGateError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except GateNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except (InvalidGateRuleError, CrossProjectViolationError, SecurityGateError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    return format_gate_response(gate)


@security_gate_router.get(
    "/projects/{project_id}/security-gates",
    response_model=SecurityGateListResponse,
)
def list_security_gates(
    project_id: int,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
):
    get_project_or_404(project_id, db)
    service = SecurityGateService(db=db)
    gates = service.list_gates(project_id=project_id, status=status)
    return SecurityGateListResponse(
        project_id=project_id,
        count=len(gates),
        gates=[format_gate_response(g) for g in gates],
    )


@security_gate_router.get(
    "/security-gates/{gate_id}",
    response_model=SecurityGateInDB,
)
def get_security_gate(
    gate_id: str,
    db: Session = Depends(get_db),
):
    service = SecurityGateService(db=db)
    gate = service.get_gate(gate_id)
    if not gate:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security gate with ID {gate_id} not found.",
        )
    return format_gate_response(gate)


@security_gate_router.patch(
    "/security-gates/{gate_id}",
    response_model=SecurityGateInDB,
)
def patch_security_gate(
    gate_id: str,
    gate_in: SecurityGateUpdate,
    db: Session = Depends(get_db),
):
    service = SecurityGateService(db=db)
    try:
        gate = service.update_gate(
            gate_id=gate_id,
            name=gate_in.name,
            description=gate_in.description,
            status=gate_in.status,
            baseline_id=gate_in.baseline_id,
            scan_profile_id=gate_in.scan_profile_id,
            failure_rules=gate_in.failure_rules,
            warning_rules=gate_in.warning_rules,
        )
    except GateNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except DuplicateGateError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except (InvalidGateRuleError, CrossProjectViolationError, SecurityGateError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    return format_gate_response(gate)


@security_gate_router.put(
    "/security-gates/{gate_id}",
    response_model=SecurityGateInDB,
)
def put_security_gate(
    gate_id: str,
    gate_in: SecurityGateUpdate,
    db: Session = Depends(get_db),
):
    return patch_security_gate(gate_id=gate_id, gate_in=gate_in, db=db)


@security_gate_router.delete(
    "/security-gates/{gate_id}",
    status_code=status.HTTP_200_OK,
)
def delete_security_gate(
    gate_id: str,
    db: Session = Depends(get_db),
):
    service = SecurityGateService(db=db)
    try:
        service.delete_gate(gate_id)
    except GateNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    return {"message": "Security gate deleted successfully"}


@security_gate_router.post(
    "/security-gates/{gate_id}/evaluate/{comparison_id}",
    response_model=SecurityGateEvaluationInDB,
    status_code=status.HTTP_200_OK,
)
def evaluate_security_gate(
    gate_id: str,
    comparison_id: str,
    db: Session = Depends(get_db),
):
    service = SecurityGateService(db=db)
    try:
        evaluation = service.evaluate_gate(
            gate_id=gate_id,
            baseline_comparison_id=comparison_id,
        )
    except GateNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except (DisabledGateError, InvalidEvaluationStateError, CrossProjectViolationError, SecurityGateError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    return format_evaluation_response(evaluation)


@security_gate_router.post(
    "/security-gates/{gate_id}/evaluate",
    response_model=SecurityGateEvaluationInDB,
    status_code=status.HTTP_200_OK,
)
def evaluate_security_gate_with_body(
    gate_id: str,
    body: Optional[SecurityGateEvaluateRequest] = None,
    comparison_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    target_comp_id = comparison_id
    if not target_comp_id and body:
        target_comp_id = body.comparison_id or body.baseline_comparison_id
    if not target_comp_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="baseline_comparison_id or comparison_id is required.",
        )
    service = SecurityGateService(db=db)
    try:
        evaluation = service.evaluate_gate(
            gate_id=gate_id,
            baseline_comparison_id=target_comp_id,
        )
    except GateNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except (DisabledGateError, InvalidEvaluationStateError, CrossProjectViolationError, SecurityGateError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    return format_evaluation_response(evaluation)


@security_gate_router.get(
    "/security-gate-evaluations/{evaluation_id}",
    response_model=SecurityGateEvaluationInDB,
)
def get_security_gate_evaluation(
    evaluation_id: str,
    db: Session = Depends(get_db),
):
    service = SecurityGateService(db=db)
    evaluation = service.get_evaluation(evaluation_id)
    if not evaluation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security gate evaluation with ID {evaluation_id} not found.",
        )
    return format_evaluation_response(evaluation)


@security_gate_router.get(
    "/security-gate-evaluations/{evaluation_id}/items",
    response_model=List[SecurityGateEvaluationItemInDB],
)
def get_security_gate_evaluation_items(
    evaluation_id: str,
    db: Session = Depends(get_db),
):
    service = SecurityGateService(db=db)
    evaluation = service.get_evaluation(evaluation_id)
    if not evaluation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security gate evaluation with ID {evaluation_id} not found.",
        )
    return [format_evaluation_item(i) for i in (evaluation.items or [])]


@security_gate_router.get(
    "/security-gate-evaluations/{evaluation_id}/result",
    response_model=SecurityGateCIResult,
)
def get_security_gate_ci_result(
    evaluation_id: str,
    db: Session = Depends(get_db),
):
    service = SecurityGateService(db=db)
    try:
        result = service.get_ci_result(evaluation_id)
    except GateNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    return result


@security_gate_router.get(
    "/projects/{project_id}/security-gate-evaluations",
    response_model=SecurityGateEvaluationListResponse,
)
def list_project_security_gate_evaluations(
    project_id: int,
    gate_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    get_project_or_404(project_id, db)
    service = SecurityGateService(db=db)
    evaluations = service.list_evaluations(project_id=project_id, gate_id=gate_id)
    return SecurityGateEvaluationListResponse(
        project_id=project_id,
        count=len(evaluations),
        evaluations=[format_evaluation_response(e) for e in evaluations],
    )


# --- Security Report Endpoints ---

security_report_router = APIRouter(tags=["Security Reports"])


def format_report_response(report: SecurityReport) -> SecurityReportInDB:
    latest_snapshot = report.snapshots[0] if report.snapshots else None
    return SecurityReportInDB(
        id=report.id,
        project_id=report.project_id,
        name=report.name,
        description=report.description,
        status=report.status,
        report_type=report.report_type,
        source_execution_plan_id=report.source_execution_plan_id,
        source_gate_evaluation_id=report.source_gate_evaluation_id,
        source_investigation_id=report.source_investigation_id,
        version=report.version,
        created_at=report.created_at,
        updated_at=report.updated_at,
        generated_at=report.generated_at,
        latest_snapshot_checksum=latest_snapshot.checksum if latest_snapshot else None,
        execution_plan_name=report.execution_plan.name if report.execution_plan else None,
        gate_name=report.gate_evaluation.gate.name if report.gate_evaluation and report.gate_evaluation.gate else None,
        investigation_title=report.investigation.title if report.investigation else None,
    )


def format_snapshot_response(snapshot: SecurityReportSnapshot) -> SecurityReportSnapshotInDB:
    return SecurityReportSnapshotInDB(
        id=snapshot.id,
        report_id=snapshot.report_id,
        version=snapshot.version,
        generated_at=snapshot.generated_at,
        checksum=snapshot.checksum,
        schema_version=snapshot.schema_version,
        report_json=snapshot.report_json,
    )


@security_report_router.post(
    "/projects/{project_id}/security-reports",
    response_model=SecurityReportInDB,
    status_code=status.HTTP_201_CREATED,
)
def create_security_report(
    project_id: int,
    report_in: SecurityReportCreate,
    db: Session = Depends(get_db),
):
    get_project_or_404(project_id, db)
    service = SecurityReportService(db=db)
    try:
        report = service.create_report(
            project_id=project_id,
            name=report_in.name,
            description=report_in.description,
            report_type=report_in.report_type,
            source_execution_plan_id=report_in.source_execution_plan_id,
            source_gate_evaluation_id=report_in.source_gate_evaluation_id,
            source_investigation_id=report_in.source_investigation_id,
        )
    except DuplicateReportError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except (InvalidReportSourceError, CrossProjectViolationError, SecurityReportError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except ReportNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    return format_report_response(report)


@security_report_router.get(
    "/projects/{project_id}/security-reports",
    response_model=SecurityReportListResponse,
)
def list_security_reports(
    project_id: int,
    status: Optional[str] = None,
    report_type: Optional[str] = None,
    db: Session = Depends(get_db),
):
    get_project_or_404(project_id, db)
    service = SecurityReportService(db=db)
    reports = service.list_reports(project_id=project_id, status=status, report_type=report_type)
    return SecurityReportListResponse(
        project_id=project_id,
        count=len(reports),
        reports=[format_report_response(r) for r in reports],
    )


@security_report_router.get(
    "/security-reports/{report_id}",
    response_model=SecurityReportDetailResponse,
)
def get_security_report(
    report_id: str,
    db: Session = Depends(get_db),
):
    service = SecurityReportService(db=db)
    report = service.get_report(report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security report '{report_id}' not found.",
        )

    latest_snapshot = None
    manifest = None
    if report.snapshots:
        latest_snapshot = format_snapshot_response(report.snapshots[0])
        try:
            manifest_dict = service.get_manifest(report_id)
            manifest = SecurityReportManifest(**manifest_dict)
        except Exception:
            pass

    return SecurityReportDetailResponse(
        report=format_report_response(report),
        latest_snapshot=latest_snapshot,
        manifest=manifest,
    )


@security_report_router.patch(
    "/security-reports/{report_id}",
    response_model=SecurityReportInDB,
)
def patch_security_report(
    report_id: str,
    report_in: SecurityReportUpdate,
    db: Session = Depends(get_db),
):
    service = SecurityReportService(db=db)
    try:
        report = service.update_report(
            report_id=report_id,
            name=report_in.name,
            description=report_in.description,
            report_type=report_in.report_type,
            source_execution_plan_id=report_in.source_execution_plan_id,
            source_gate_evaluation_id=report_in.source_gate_evaluation_id,
            source_investigation_id=report_in.source_investigation_id,
        )
    except ReportNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except DuplicateReportError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except (ArchivedReportError, InvalidReportSourceError, CrossProjectViolationError, SecurityReportError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    return format_report_response(report)


@security_report_router.put(
    "/security-reports/{report_id}",
    response_model=SecurityReportInDB,
)
def put_security_report(
    report_id: str,
    report_in: SecurityReportUpdate,
    db: Session = Depends(get_db),
):
    return patch_security_report(report_id=report_id, report_in=report_in, db=db)


@security_report_router.delete(
    "/security-reports/{report_id}",
    status_code=status.HTTP_200_OK,
)
def delete_security_report(
    report_id: str,
    db: Session = Depends(get_db),
):
    service = SecurityReportService(db=db)
    try:
        service.delete_report(report_id)
    except ReportNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    return {"message": "Security report deleted successfully"}


@security_report_router.post(
    "/security-reports/{report_id}/generate",
    response_model=SecurityReportSnapshotInDB,
    status_code=status.HTTP_200_OK,
)
def generate_security_report(
    report_id: str,
    db: Session = Depends(get_db),
):
    service = SecurityReportService(db=db)
    try:
        snapshot = service.generate_report(report_id)
    except ReportNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except (ArchivedReportError, SecurityReportError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    return format_snapshot_response(snapshot)


@security_report_router.post(
    "/security-reports/{report_id}/archive",
    response_model=SecurityReportInDB,
    status_code=status.HTTP_200_OK,
)
def archive_security_report(
    report_id: str,
    db: Session = Depends(get_db),
):
    service = SecurityReportService(db=db)
    try:
        report = service.archive_report(report_id)
    except ReportNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    return format_report_response(report)


@security_report_router.get(
    "/security-reports/{report_id}/json",
)
def get_security_report_json(
    report_id: str,
    version: Optional[int] = None,
    db: Session = Depends(get_db),
):
    service = SecurityReportService(db=db)
    try:
        snapshot = service.get_snapshot(report_id, version=version)
    except ReportNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    return snapshot.report_json


@security_report_router.get(
    "/security-reports/{report_id}/manifest",
    response_model=SecurityReportManifest,
)
def get_security_report_manifest(
    report_id: str,
    version: Optional[int] = None,
    db: Session = Depends(get_db),
):
    service = SecurityReportService(db=db)
    try:
        manifest = service.get_manifest(report_id, version=version)
    except ReportNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    return manifest


@security_report_router.get(
    "/security-reports/{report_id}/package",
)
def get_security_report_evidence_package(
    report_id: str,
    version: Optional[int] = None,
    db: Session = Depends(get_db),
):
    service = SecurityReportService(db=db)
    try:
        package = service.get_evidence_package(report_id, version=version)
    except ReportNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    return package


# Include sub-routers into main router
router.include_router(project_router)
router.include_router(api_router)
router.include_router(endpoint_router)
router.include_router(ingest_router)
router.include_router(role_router)
router.include_router(identity_router)
router.include_router(resource_router)
router.include_router(ownership_router)
router.include_router(endpoint_assoc_router)
router.include_router(security_test_router)
router.include_router(finding_router)
router.include_router(matrix_router)
router.include_router(policy_router)
router.include_router(property_router)
router.include_router(auth_security_router)
router.include_router(workflow_router)
router.include_router(correlation_router)
router.include_router(attack_path_router)
router.include_router(impact_router)
router.include_router(ai_router)
router.include_router(investigation_router)
router.include_router(test_suite_router)
router.include_router(execution_plan_router)
router.include_router(scan_profile_router)
router.include_router(baseline_router)
router.include_router(baseline_comparison_router)
router.include_router(security_gate_router)
router.include_router(security_report_router)