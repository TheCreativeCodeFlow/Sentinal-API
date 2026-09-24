from typing import Optional, List, Any, Dict
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict


# Project schemas
class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=500)
    environment: str = Field("production", min_length=1, max_length=100)
    base_url: Optional[str] = Field(None, max_length=500)
    authorization_status: str = Field("pending", min_length=1, max_length=50)


class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=500)
    environment: Optional[str] = Field(None, min_length=1, max_length=100)
    base_url: Optional[str] = Field(None, max_length=500)
    authorization_status: Optional[str] = Field(None, min_length=1, max_length=50)


class ProjectInDB(ProjectCreate):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# API schemas
class APICreate(BaseModel):
    project_id: int
    name: str = Field(..., min_length=1, max_length=200)
    version: Optional[str] = Field(None, max_length=50)
    title: Optional[str] = Field(None, max_length=200)
    url: Optional[str] = Field(None, max_length=500)


class APIUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    version: Optional[str] = Field(None, max_length=50)
    title: Optional[str] = Field(None, max_length=200)
    url: Optional[str] = Field(None, max_length=500)


class APIInDB(APICreate):
    id: int
    status: str
    format: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# Endpoint schemas
class EndpointCreate(BaseModel):
    api_id: int
    resource_id: Optional[str] = None
    method: str = Field(..., min_length=1, max_length=10)
    path: str = Field(..., min_length=1, max_length=500)
    summary: Optional[str] = Field(None)
    description: Optional[str] = Field(None)
    tags: Optional[List[str]] = Field(None)


class EndpointUpdate(BaseModel):
    resource_id: Optional[str] = None
    summary: Optional[str] = Field(None)
    description: Optional[str] = Field(None)
    tags: Optional[List[str]] = Field(None)


class EndpointInDB(EndpointCreate):
    id: int
    api_id: int
    resource_id: Optional[str] = None
    resource_name: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# OpenAPI ingestion schemas
class OpenAPISpec(BaseModel):
    url: Optional[str] = Field(None, description="URL to fetch OpenAPI spec from")
    content: Optional[str] = Field(None, description="Raw OpenAPI spec content as string")


class OpenAPIUpload(BaseModel):
    spec_content: str = Field(..., description="OpenAPI spec JSON or YAML content")


class EndpointFilter(BaseModel):
    method: Optional[str] = Field(None)
    tag: Optional[str] = Field(None)
    search: Optional[str] = Field(None, description="Search in path, summary, description")


# Authentication scheme schemas
class AuthSchemeCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    type: str = Field(..., min_length=1, max_length=50)
    description: Optional[str] = Field(None, max_length=500)
    in_: Optional[str] = Field(None, max_length=50)
    scheme: Optional[str] = Field(None, max_length=100)
    bearer_format: Optional[str] = Field(None, max_length=100)
    description_raw: Optional[str] = Field(None)


class AuthSchemeInDB(AuthSchemeCreate):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ==============================================================================
# STAGE 2: Identity & Authorization Modeling Schemas
# ==============================================================================

# Role Schemas
class RoleBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)


class RoleCreate(RoleBase):
    pass


class RoleUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)


class RoleInDB(RoleBase):
    id: str
    project_id: int
    created_at: datetime
    updated_at: datetime
    identities_count: Optional[int] = 0

    model_config = ConfigDict(from_attributes=True)


class RoleMember(BaseModel):
    id: str
    name: str
    auth_type: str
    environment: str

    model_config = ConfigDict(from_attributes=True)


class RoleDetail(RoleInDB):
    members: List[RoleMember] = []


# Identity Schemas
class IdentityBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=500)
    role_id: Optional[str] = None
    auth_type: str = Field("bearer_token", min_length=1, max_length=50)
    environment: str = Field("production", min_length=1, max_length=100)
    credential_reference: Optional[str] = Field(None, max_length=255)
    credential_status: str = Field("configured", min_length=1, max_length=50)


class IdentityCreate(IdentityBase):
    # Raw credential input is accepted on create/update for controlled test execution,
    # but is NEVER returned in response schemas.
    credential_value: Optional[str] = Field(None, max_length=2000)


class IdentityUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=500)
    role_id: Optional[str] = None
    auth_type: Optional[str] = Field(None, min_length=1, max_length=50)
    environment: Optional[str] = Field(None, min_length=1, max_length=100)
    credential_reference: Optional[str] = Field(None, max_length=255)
    credential_status: Optional[str] = Field(None, min_length=1, max_length=50)
    credential_value: Optional[str] = Field(None, max_length=2000)


class IdentityRoleAssign(BaseModel):
    role_id: Optional[str] = None


class IdentityInDB(IdentityBase):
    id: str
    project_id: int
    role_name: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IdentityDetail(IdentityInDB):
    owned_resources_count: int = 0


# Resource Schemas
class ResourceBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=500)
    resource_type: str = Field("entity", min_length=1, max_length=100)
    api_id: Optional[int] = None


class ResourceCreate(ResourceBase):
    pass


class ResourceUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=500)
    resource_type: Optional[str] = Field(None, min_length=1, max_length=100)
    api_id: Optional[int] = None


class ResourceInDB(ResourceBase):
    id: str
    project_id: int
    created_at: datetime
    updated_at: datetime
    ownerships_count: Optional[int] = 0
    endpoints_count: Optional[int] = 0

    model_config = ConfigDict(from_attributes=True)


# Resource Ownership Schemas
class ResourceOwnershipCreate(BaseModel):
    identity_id: str
    resource_instance_id: Optional[str] = Field(None, max_length=255)
    ownership_type: str = Field("owner", min_length=1, max_length=50)
    description: Optional[str] = Field(None, max_length=500)


class ResourceOwnershipInDB(BaseModel):
    id: str
    resource_id: str
    identity_id: str
    identity_name: Optional[str] = None
    resource_name: Optional[str] = None
    resource_instance_id: Optional[str] = None
    ownership_type: str
    description: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ResourceDetail(ResourceInDB):
    ownerships: List[ResourceOwnershipInDB] = []
    endpoints: List[EndpointInDB] = []


# Endpoint Resource Association Schemas
class EndpointResourceAssign(BaseModel):
    resource_id: Optional[str] = None


# Authorization Model View Schemas (Identity -> Role -> Resources)
class AuthModelResourceItem(BaseModel):
    resource_id: str
    resource_name: str
    resource_type: str
    instance_id: Optional[str] = None
    ownership_type: str = "owner"
    associated_endpoints: List[str] = []


class AuthModelIdentityNode(BaseModel):
    identity_id: str
    identity_name: str
    role_id: Optional[str] = None
    role_name: str = "Unassigned"
    auth_type: str
    environment: str
    credential_status: str
    resources: List[AuthModelResourceItem] = []


class AuthorizationModelView(BaseModel):
    project_id: int
    project_name: str
    nodes: List[AuthModelIdentityNode] = []
    total_identities: int = 0
    total_roles: int = 0
    total_resources: int = 0


# ==============================================================================
# STAGE 3: Security Testing Engine Schemas (BOLA)
# ==============================================================================

class SecurityTestCreate(BaseModel):
    endpoint_id: int
    test_type: str = Field("BOLA", min_length=1, max_length=50)
    attacker_identity_id: Optional[str] = None
    victim_identity_id: Optional[str] = None
    victim_resource_id: Optional[str] = None
    victim_resource_instance_id: Optional[str] = Field(None, max_length=255)
    attacker_resource_instance_id: Optional[str] = Field(None, max_length=255)
    expected_access: Optional[str] = Field("DENY", max_length=20)
    configuration: Optional[Dict[str, Any]] = None


class SecurityTestInDB(BaseModel):
    id: str
    project_id: int
    endpoint_id: int
    endpoint_method: Optional[str] = None
    endpoint_path: Optional[str] = None
    test_type: str
    attacker_identity_id: Optional[str] = None
    attacker_identity_name: Optional[str] = None
    attacker_role_name: Optional[str] = None
    victim_identity_id: Optional[str] = None
    victim_identity_name: Optional[str] = None
    victim_resource_id: Optional[str] = None
    victim_resource_name: Optional[str] = None
    victim_resource_instance_id: Optional[str] = None
    attacker_resource_instance_id: Optional[str] = None
    expected_access: Optional[str] = "DENY"
    status: str
    configuration: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime
    latest_result: Optional[str] = None
    executions_count: Optional[int] = 0
    findings_count: Optional[int] = 0

    model_config = ConfigDict(from_attributes=True)


class EvidenceInDB(BaseModel):
    id: str
    execution_id: Optional[str] = None
    workflow_execution_id: Optional[str] = None
    workflow_step_execution_id: Optional[str] = None
    attack_scenario_id: Optional[str] = None
    finding_id: Optional[str] = None
    request_metadata: Optional[Dict[str, Any]] = None
    response_metadata: Optional[Dict[str, Any]] = None
    expected_behavior: str
    actual_behavior: str
    redacted_request: Optional[str] = None
    redacted_response: Optional[str] = None
    reproducibility_status: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TestExecutionInDB(BaseModel):
    id: str
    security_test_id: str
    status: str
    result: Optional[str] = None
    result_reason: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    http_status: Optional[int] = None
    duration_ms: Optional[int] = None
    error_category: Optional[str] = None
    created_at: datetime
    evidence: Optional[EvidenceInDB] = None

    model_config = ConfigDict(from_attributes=True)


class FindingInDB(BaseModel):
    id: str
    project_id: int
    security_test_id: Optional[str] = None
    execution_id: Optional[str] = None
    workflow_id: Optional[str] = None
    workflow_execution_id: Optional[str] = None
    workflow_step_id: Optional[str] = None
    attack_scenario_id: Optional[str] = None
    endpoint_id: Optional[int] = None
    attacker_identity_id: Optional[str] = None
    attacker_role_id: Optional[str] = None
    type: str
    severity: str
    confidence: str
    status: str
    title: str
    description: str
    remediation: str
    expected_authorization: Optional[str] = None
    actual_behavior: Optional[str] = None
    created_at: datetime
    updated_at: Optional[datetime] = None
    endpoint_method: Optional[str] = None
    endpoint_path: Optional[str] = None
    resource_id: Optional[str] = None
    exposed_properties: Optional[List[str]] = None
    authentication_mechanism: Optional[str] = None
    attacker_identity_name: Optional[str] = None
    attacker_role_name: Optional[str] = None
    victim_resource_name: Optional[str] = None
    victim_resource_instance_id: Optional[str] = None
    workflow_name: Optional[str] = None
    workflow_step_name: Optional[str] = None
    attack_scenario_name: Optional[str] = None
    attack_scenario_type: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class FindingDetail(FindingInDB):
    evidence: Optional[EvidenceInDB] = None
    expected_behavior: Optional[str] = None


# ==============================================================================
# STAGE 4: Authorization Boundary & Matrix Schemas
# ==============================================================================

class EndpointAuthorizationPolicyBase(BaseModel):
    authentication_required: bool = True
    notes: Optional[str] = Field(None, max_length=1000)


class EndpointAuthorizationPolicyCreate(EndpointAuthorizationPolicyBase):
    allowed_role_ids: Optional[List[str]] = []
    denied_role_ids: Optional[List[str]] = []


class EndpointAuthorizationPolicyUpdate(BaseModel):
    authentication_required: Optional[bool] = None
    notes: Optional[str] = Field(None, max_length=1000)
    allowed_role_ids: Optional[List[str]] = None
    denied_role_ids: Optional[List[str]] = None


class EndpointAuthorizationPolicyInDB(EndpointAuthorizationPolicyBase):
    id: str
    project_id: int
    endpoint_id: int
    endpoint_method: Optional[str] = None
    endpoint_path: Optional[str] = None
    allowed_roles: List[RoleBase] = []
    denied_roles: List[RoleBase] = []
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AuthorizationMatrixRuleCreate(BaseModel):
    endpoint_id: int
    role_id: Optional[str] = None
    identity_id: Optional[str] = None
    http_method: str = Field("GET", min_length=1, max_length=10)
    expected_access: str = Field("UNKNOWN", description="ALLOW, DENY, UNKNOWN")


class AuthorizationMatrixRuleUpdate(BaseModel):
    expected_access: str = Field(..., description="ALLOW, DENY, UNKNOWN")


class AuthorizationMatrixRuleInDB(BaseModel):
    id: str
    project_id: int
    endpoint_id: int
    role_id: Optional[str] = None
    role_name: Optional[str] = None
    identity_id: Optional[str] = None
    identity_name: Optional[str] = None
    http_method: str
    expected_access: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AuthorizationMatrixCell(BaseModel):
    endpoint_id: int
    role_id: Optional[str] = None
    role_name: str
    http_method: str
    expected_access: str = "UNKNOWN"  # ALLOW, DENY, UNKNOWN
    test_status: str = "NOT TESTED"  # NOT TESTED, PASS, CONFIRMED, INCONCLUSIVE
    security_test_id: Optional[str] = None
    latest_execution_id: Optional[str] = None
    latest_result: Optional[str] = None
    finding_id: Optional[str] = None


class AuthorizationMatrixEndpointRow(BaseModel):
    endpoint_id: int
    method: str
    path: str
    summary: Optional[str] = None
    authentication_required: bool = True
    policy_notes: Optional[str] = None
    cells: Dict[str, AuthorizationMatrixCell] = {}  # keyed by role_id (or "anonymous")


class AuthorizationMatrixView(BaseModel):
    project_id: int
    project_name: str
    roles: List[RoleInDB] = []
    endpoints: List[AuthorizationMatrixEndpointRow] = []
    total_cells: int = 0
    confirmed_count: int = 0
    pass_count: int = 0
    untested_count: int = 0


class BFLATestGenerateRequest(BaseModel):
    endpoint_ids: Optional[List[int]] = None  # None means all safe endpoints in project
    target_all_safe_endpoints: bool = True


class BFLATestGenerateResult(BaseModel):
    generated_count: int
    skipped_count: int
    tests: List[SecurityTestInDB] = []


# ==============================================================================
# STAGE 5: Property-Level Security Schemas
# ==============================================================================

class PropertyAuthorizationRuleBase(BaseModel):
    role_id: str
    access: str = Field("UNKNOWN", max_length=20)  # ALLOW, DENY, UNKNOWN


class PropertyAuthorizationRuleCreate(PropertyAuthorizationRuleBase):
    pass


class PropertyAuthorizationRuleInDB(PropertyAuthorizationRuleBase):
    id: str
    resource_property_id: str
    role_name: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ResourcePropertyBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    data_type: str = Field("string", min_length=1, max_length=50)
    sensitivity: str = Field("INTERNAL", min_length=1, max_length=50)  # PUBLIC, INTERNAL, SENSITIVE, SECRET
    description: Optional[str] = Field(None, max_length=1000)


class ResourcePropertyCreate(ResourcePropertyBase):
    initial_rules: Optional[Dict[str, str]] = None  # role_id -> access (ALLOW, DENY, UNKNOWN)


class ResourcePropertyUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    data_type: Optional[str] = Field(None, min_length=1, max_length=50)
    sensitivity: Optional[str] = Field(None, min_length=1, max_length=50)
    description: Optional[str] = Field(None, max_length=1000)


class ResourcePropertyInDB(ResourcePropertyBase):
    id: str
    resource_id: str
    created_at: datetime
    updated_at: datetime
    rules: List[PropertyAuthorizationRuleInDB] = []

    model_config = ConfigDict(from_attributes=True)


class PropertyRuleBulkItem(BaseModel):
    property_id: str
    role_id: str
    access: str = Field("UNKNOWN", max_length=20)  # ALLOW, DENY, UNKNOWN


class PropertyMatrixBulkUpdate(BaseModel):
    rules: List[PropertyRuleBulkItem]


class PropertyMatrixRow(BaseModel):
    id: str
    name: str
    data_type: str
    sensitivity: str
    description: Optional[str] = None
    rules: Dict[str, str] = {}  # role_id -> access ("ALLOW" / "DENY" / "UNKNOWN")


class PropertyMatrixView(BaseModel):
    resource_id: str
    resource_name: str
    project_id: int
    roles: List[RoleInDB] = []
    properties: List[PropertyMatrixRow] = []
    total_properties: int = 0


class CandidateProperty(BaseModel):
    path: str
    data_type: str
    suggested_sensitivity: str  # PUBLIC, INTERNAL, SENSITIVE, SECRET
    matched_heuristic: Optional[str] = None
    sample_value: Optional[str] = None


class PropertyDiscoveryRequest(BaseModel):
    sample_json: Optional[str] = None
    endpoint_id: Optional[int] = None


class PropertyDiscoveryResponse(BaseModel):
    discovered_properties: List[CandidateProperty] = []
    total_discovered: int = 0


# ==============================================================================
# STAGE 6: Authentication Security Schemas
# ==============================================================================

class AuthenticationPolicyBase(BaseModel):
    authentication_required: bool = True
    authentication_scheme: str = Field("bearer_token", max_length=50)  # bearer_token, api_key, basic_auth, cookie_session, none
    expected_denial_status: int = Field(401, ge=100, le=599)  # 401 or 403
    notes: Optional[str] = Field(None, max_length=1000)


class AuthenticationPolicyCreate(AuthenticationPolicyBase):
    project_id: int
    endpoint_id: int


class AuthenticationPolicyUpdate(BaseModel):
    authentication_required: Optional[bool] = None
    authentication_scheme: Optional[str] = Field(None, max_length=50)
    expected_denial_status: Optional[int] = Field(None, ge=100, le=599)
    notes: Optional[str] = Field(None, max_length=1000)


class AuthenticationPolicyInDB(AuthenticationPolicyBase):
    id: str
    project_id: int
    endpoint_id: int
    endpoint_method: Optional[str] = None
    endpoint_path: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AuthTestGenerationResponse(BaseModel):
    project_id: int
    generated_count: int
    skipped_count: int
    test_ids: List[str] = []
    message: str


# ==============================================================================
# STAGE 7.1: Stateful Workflow & Business Logic Security Schemas
# ==============================================================================

class WorkflowBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=2000)
    status: str = Field("DRAFT", description="DRAFT, ACTIVE, DISABLED")


class WorkflowCreate(WorkflowBase):
    pass


class WorkflowUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=2000)
    status: Optional[str] = Field(None, description="DRAFT, ACTIVE, DISABLED")


class WorkflowStepBase(BaseModel):
    step_order: int = Field(..., ge=1)
    endpoint_id: int
    identity_id: Optional[str] = None
    http_method: str = Field("GET", max_length=10)
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=2000)
    request_template: Optional[Dict[str, Any]] = None
    expected_status_codes: List[int] = Field(default_factory=lambda: [200])


class WorkflowStepCreate(WorkflowStepBase):
    pass


class WorkflowStepUpdate(BaseModel):
    step_order: Optional[int] = Field(None, ge=1)
    endpoint_id: Optional[int] = None
    identity_id: Optional[str] = None
    http_method: Optional[str] = Field(None, max_length=10)
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=2000)
    request_template: Optional[Dict[str, Any]] = None
    expected_status_codes: Optional[List[int]] = None


class WorkflowStepInDB(WorkflowStepBase):
    id: str
    workflow_id: str
    endpoint_path: Optional[str] = None
    endpoint_method: Optional[str] = None
    identity_name: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class WorkflowStateBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=2000)
    is_initial: bool = False
    is_terminal: bool = False


class WorkflowStateCreate(WorkflowStateBase):
    pass


class WorkflowStateUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=2000)
    is_initial: Optional[bool] = None
    is_terminal: Optional[bool] = None


class WorkflowStateInDB(WorkflowStateBase):
    id: str
    workflow_id: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class WorkflowTransitionBase(BaseModel):
    from_state_id: str
    to_state_id: str
    step_id: Optional[str] = None
    expected_behavior: str = Field("ALLOW", description="ALLOW, DENY")
    description: Optional[str] = Field(None, max_length=2000)


class WorkflowTransitionCreate(WorkflowTransitionBase):
    pass


class WorkflowTransitionUpdate(BaseModel):
    from_state_id: Optional[str] = None
    to_state_id: Optional[str] = None
    step_id: Optional[str] = None
    expected_behavior: Optional[str] = Field(None, description="ALLOW, DENY")
    description: Optional[str] = Field(None, max_length=2000)


class WorkflowTransitionInDB(WorkflowTransitionBase):
    id: str
    workflow_id: str
    from_state_name: Optional[str] = None
    to_state_name: Optional[str] = None
    step_name: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class WorkflowInDB(WorkflowBase):
    id: str
    project_id: int
    step_count: int = 0
    state_count: int = 0
    transition_count: int = 0
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class WorkflowDetailInDB(WorkflowBase):
    id: str
    project_id: int
    steps: List[WorkflowStepInDB] = []
    states: List[WorkflowStateInDB] = []
    transitions: List[WorkflowTransitionInDB] = []
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ==============================================================================
# STAGE 7.2: Stateful Workflow Execution Schemas
# ==============================================================================

class WorkflowStepExecutionInDB(BaseModel):
    id: str
    workflow_execution_id: str
    step_id: Optional[str] = None
    attack_step_id: Optional[str] = None
    step_order: int
    http_method: Optional[str] = None
    endpoint_path: Optional[str] = None
    action: Optional[str] = None
    identity_id: Optional[str] = None
    identity_name: Optional[str] = None
    status: str  # PASS, CONFIRMED, INCONCLUSIVE, ERROR, SKIPPED
    request_summary: Optional[Dict[str, Any]] = None
    response_summary: Optional[Dict[str, Any]] = None
    status_code: Optional[int] = None
    latency_ms: Optional[int] = None
    state_before: Optional[str] = None
    state_after: Optional[str] = None
    transition_expected: Optional[str] = None
    transition_result: Optional[str] = None
    correlation_id: Optional[str] = None
    error_message: Optional[str] = None
    created_at: datetime
    step_name: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class WorkflowExecutionInDB(BaseModel):
    id: str
    workflow_id: str
    attack_scenario_id: Optional[str] = None
    status: str  # QUEUED, RUNNING, COMPLETED, FAILED
    result: Optional[str] = None  # PASS, CONFIRMED, INCONCLUSIVE, ERROR
    result_reason: Optional[str] = None
    triggered_by: str = "MANUAL"
    current_state_id: Optional[str] = None
    correlation_id: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    created_at: datetime
    step_count: Optional[int] = 0
    findings_count: Optional[int] = 0

    model_config = ConfigDict(from_attributes=True)


class WorkflowExecutionDetailInDB(WorkflowExecutionInDB):
    workflow_name: Optional[str] = None
    current_state_name: Optional[str] = None
    attack_scenario_name: Optional[str] = None
    attack_scenario_type: Optional[str] = None
    step_executions: List[WorkflowStepExecutionInDB] = []
    findings: List[FindingInDB] = []


# ==============================================================================
# STAGE 7.3: Stateful Attack Scenarios Schemas
# ==============================================================================

class WorkflowAttackStepBase(BaseModel):
    position: int = Field(..., ge=1)
    action: str = Field(..., max_length=50)  # EXECUTE, SKIP, REPLAY, SWITCH_IDENTITY
    source_step_id: Optional[str] = None
    identity_id: Optional[str] = None
    expected_behavior: str = Field("DENY", max_length=50)  # ALLOW, DENY
    configuration: Optional[Dict[str, Any]] = None


class WorkflowAttackStepCreate(WorkflowAttackStepBase):
    pass


class WorkflowAttackStepInDB(WorkflowAttackStepBase):
    id: str
    scenario_id: str
    created_at: datetime
    source_step_name: Optional[str] = None
    endpoint_method: Optional[str] = None
    endpoint_path: Optional[str] = None
    identity_name: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class WorkflowAttackScenarioBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=2000)
    scenario_type: str = Field(..., max_length=50)  # INVALID_STATE_TRANSITION, STEP_REPLAY, STEP_SKIP, STEP_REORDER, IDENTITY_SWITCH, CROSS_IDENTITY_CONTINUATION
    status: str = Field("ACTIVE", max_length=50)  # DRAFT, ACTIVE, DISABLED


class WorkflowAttackScenarioCreate(WorkflowAttackScenarioBase):
    steps: Optional[List[WorkflowAttackStepCreate]] = None


class WorkflowAttackScenarioInDB(WorkflowAttackScenarioBase):
    id: str
    workflow_id: str
    created_at: datetime
    updated_at: datetime
    step_count: Optional[int] = 0
    execution_count: Optional[int] = 0
    findings_count: Optional[int] = 0
    latest_result: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class WorkflowAttackScenarioDetailInDB(WorkflowAttackScenarioInDB):
    workflow_name: Optional[str] = None
    steps: List[WorkflowAttackStepInDB] = []
    latest_execution: Optional[WorkflowExecutionInDB] = None


class WorkflowAttackScenarioGenerateRequest(BaseModel):
    scenario_types: Optional[List[str]] = None  # None means all supported scenario types


class WorkflowAttackScenarioGenerateResult(BaseModel):
    generated_count: int
    existing_count: int
    scenarios: List[WorkflowAttackScenarioInDB] = []