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


# ==============================================================================
# STAGE 8.1: Attack Graph & Finding Correlation Schemas
# ==============================================================================

class AttackGraphNodeBase(BaseModel):
    graph_id: str
    node_type: str
    label: str
    finding_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class AttackGraphNodeInDB(AttackGraphNodeBase):
    id: str
    created_at: datetime
    finding_severity: Optional[str] = None
    finding_type: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class AttackGraphEdgeBase(BaseModel):
    graph_id: str
    source_node_id: str
    target_node_id: str
    relationship_type: str
    confidence: str = "HIGH"
    reason: str
    metadata: Optional[Dict[str, Any]] = None


class AttackGraphEdgeInDB(AttackGraphEdgeBase):
    id: str
    created_at: datetime
    source_label: Optional[str] = None
    target_label: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class AttackGraphBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=2000)
    status: str = Field("ACTIVE", max_length=50)


class AttackGraphInDB(AttackGraphBase):
    id: str
    project_id: int
    created_at: datetime
    updated_at: datetime
    node_count: Optional[int] = 0
    edge_count: Optional[int] = 0

    model_config = ConfigDict(from_attributes=True)


class AttackGraphDetailInDB(AttackGraphInDB):
    nodes: List[AttackGraphNodeInDB] = []
    edges: List[AttackGraphEdgeInDB] = []


class FindingCorrelationInDB(BaseModel):
    id: str
    project_id: int
    finding_a_id: str
    finding_b_id: str
    relationship_type: str
    confidence: str
    reason: str
    created_at: datetime
    finding_a_title: Optional[str] = None
    finding_b_title: Optional[str] = None
    finding_a_type: Optional[str] = None
    finding_b_type: Optional[str] = None
    finding_a_severity: Optional[str] = None
    finding_b_severity: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class CorrelationRunResponse(BaseModel):
    project_id: int
    confirmed_findings_count: int
    correlations_count: int
    new_correlations_count: int
    graph_id: str
    node_count: int
    edge_count: int
    correlations: List[FindingCorrelationInDB] = []
    graph: Optional[AttackGraphInDB] = None


# ==============================================================================
# STAGE 8.2: Deterministic Attack Path Detection Schemas
# ==============================================================================

class AttackPathStepBase(BaseModel):
    position: int
    finding_id: str
    prerequisite_finding_id: Optional[str] = None
    relationship_type: str
    reason: str


class AttackPathStepInDB(AttackPathStepBase):
    id: str
    attack_path_id: str
    created_at: datetime
    finding_title: Optional[str] = None
    finding_type: Optional[str] = None
    finding_severity: Optional[str] = None
    prerequisite_finding_title: Optional[str] = None
    endpoint_path: Optional[str] = None
    resource_name: Optional[str] = None
    identity_name: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class AttackPathBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=5000)
    status: str = Field("ACTIVE", max_length=50)
    confidence: str = Field("HIGH", max_length=50)


class AttackPathInDB(AttackPathBase):
    id: str
    project_id: int
    attack_graph_id: str
    created_at: datetime
    updated_at: datetime
    step_count: Optional[int] = 0
    steps: List[AttackPathStepInDB] = []

    model_config = ConfigDict(from_attributes=True)


class AttackPathDetailInDB(AttackPathInDB):
    pass


class AttackPathAnalysisResponse(BaseModel):
    project_id: int
    attack_graph_id: str
    paths_count: int
    paths: List[AttackPathDetailInDB] = []


# ==============================================================================
# STAGE 8.3: Deterministic Security Impact Analysis Schemas
# ==============================================================================

class SecurityImpactBase(BaseModel):
    initial_access: bool = False
    authentication_boundary_crossed: bool = False
    authorization_boundary_crossed: bool = False
    identity_boundary_crossed: bool = False
    resource_boundary_crossed: bool = False
    workflow_boundary_crossed: bool = False
    property_boundary_crossed: bool = False
    sensitive_data_reached: bool = False
    cross_identity_impact: bool = False
    cross_resource_impact: bool = False
    terminal_impact: str = "NONE"
    explanation: str


class SecurityImpactInDB(SecurityImpactBase):
    id: str
    project_id: int
    attack_path_id: Optional[str] = None
    finding_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    attack_path_name: Optional[str] = None
    finding_title: Optional[str] = None
    finding_type: Optional[str] = None
    identities_involved: List[str] = []
    resources_involved: List[str] = []
    sensitive_properties_reached: List[str] = []
    boundaries_crossed: List[str] = []

    model_config = ConfigDict(from_attributes=True)


class SecurityImpactDetailInDB(SecurityImpactInDB):
    pass


class SecurityImpactAnalysisResponse(BaseModel):
    project_id: int
    impacts_count: int
    impacts: List[SecurityImpactDetailInDB] = []


# ==============================================================================
# STAGE 9.1: AI Security Reasoning Schemas
# ==============================================================================

from enum import Enum


class AIAnalysisType(str, Enum):
    FINDING_EXPLANATION = "FINDING_EXPLANATION"
    ATTACK_PATH_EXPLANATION = "ATTACK_PATH_EXPLANATION"
    IMPACT_EXPLANATION = "IMPACT_EXPLANATION"
    SECURITY_RECOMMENDATION = "SECURITY_RECOMMENDATION"
    ATTACK_HYPOTHESIS = "ATTACK_HYPOTHESIS"
    REPORT_SUMMARY = "REPORT_SUMMARY"


class FindingExplanationOutput(BaseModel):
    finding_id: str
    summary: str
    root_cause_analysis: str
    evidence_corroboration: str
    potential_misconfigurations: List[str] = []
    recommended_investigation: str


class AttackPathExplanationOutput(BaseModel):
    attack_path_id: str
    path_narrative: str
    prerequisite_analysis: str
    step_by_step_breakdown: List[Dict[str, Any]] = []
    exploitability_factors: str
    critical_choke_point: str


class ImpactExplanationOutput(BaseModel):
    impact_id: str
    terminal_impact_interpretation: str
    crossed_boundaries_explained: List[Dict[str, str]] = []
    business_risk_translation: str
    data_exposure_implications: str


class SecurityRecommendationOutput(BaseModel):
    target_type: str
    target_id: str
    immediate_mitigations: List[str] = []
    architectural_remediations: List[str] = []
    preventative_controls: List[str] = []
    code_level_guidance: Optional[str] = None


class AttackHypothesisItem(BaseModel):
    hypothesis: str
    reason: str
    required_existing_context: List[str] = []
    suggested_test_type: str
    confidence: str = Field(..., pattern="^(LOW|MEDIUM|HIGH)$")
    requires_human_review: bool = True


class AttackHypothesesOutput(BaseModel):
    attack_path_id: str
    hypotheses: List[AttackHypothesisItem] = []
    caveats: str


class ReportSummaryOutput(BaseModel):
    project_id: int
    executive_summary: str
    key_exposure_themes: List[str] = []
    highest_risk_paths: List[str] = []
    strategic_recommendations: List[str] = []


class AIAnalysisBase(BaseModel):
    project_id: int
    attack_path_id: Optional[str] = None
    finding_id: Optional[str] = None
    analysis_type: str
    status: str = "QUEUED"
    model_provider: str
    model_name: str
    input_context: Dict[str, Any]
    output: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None


class AIAnalysisInDB(AIAnalysisBase):
    id: str
    created_at: datetime
    completed_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class AIAnalysisDetailInDB(AIAnalysisInDB):
    finding_title: Optional[str] = None
    finding_type: Optional[str] = None
    attack_path_name: Optional[str] = None


class AIAnalysisResponse(BaseModel):
    analysis: AIAnalysisDetailInDB


class AIAnalysesListResponse(BaseModel):
    project_id: int
    count: int
    analyses: List[AIAnalysisDetailInDB] = []


class AIAnalyzeRequest(BaseModel):
    analysis_type: Optional[str] = None


# ==============================================================================
# STAGE 9.2: Human-Approved AI Security Testing Schemas
# ==============================================================================

class AIHypothesisStatus(str, Enum):
    PENDING_REVIEW = "PENDING_REVIEW"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    CONVERTED = "CONVERTED"
    EXPIRED = "EXPIRED"


class AIHypothesisReviewAction(str, Enum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"


class AIHypothesisBase(BaseModel):
    hypothesis: str = Field(..., min_length=1, max_length=5000)
    reason: str = Field(..., min_length=1, max_length=5000)
    suggested_test_type: str = Field(..., min_length=1, max_length=50)
    required_context: Optional[Dict[str, Any]] = None
    confidence: str = Field("MEDIUM", pattern="^(LOW|MEDIUM|HIGH)$")
    requires_human_review: bool = True


class AIHypothesisCreate(AIHypothesisBase):
    project_id: int
    ai_analysis_id: str
    attack_path_id: Optional[str] = None
    finding_id: Optional[str] = None


class AIHypothesisInDB(AIHypothesisBase):
    id: str
    project_id: int
    ai_analysis_id: str
    attack_path_id: Optional[str] = None
    finding_id: Optional[str] = None
    security_test_id: Optional[str] = None
    status: str = "PENDING_REVIEW"
    reviewed_at: Optional[datetime] = None
    reviewed_by: Optional[str] = None
    rejection_reason: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AIHypothesisDetailInDB(AIHypothesisInDB):
    finding_title: Optional[str] = None
    attack_path_name: Optional[str] = None
    latest_review_action: Optional[str] = None


class AIHypothesisReviewInDB(BaseModel):
    id: str
    hypothesis_id: str
    action: str
    reviewer_reference: str
    reason: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AIHypothesisApprovalRequest(BaseModel):
    reviewer_reference: str = Field(..., min_length=1, max_length=255)
    reason: Optional[str] = Field(None, max_length=2000)


class AIHypothesisRejectionRequest(BaseModel):
    reviewer_reference: str = Field(..., min_length=1, max_length=255)
    reason: str = Field(..., min_length=1, max_length=2000)


class AIHypothesisConvertRequest(BaseModel):
    reviewer_reference: Optional[str] = Field(None, max_length=255)


class AIHypothesisConvertResponse(BaseModel):
    hypothesis: AIHypothesisDetailInDB
    security_test_id: str
    message: str


class AIHypothesisListResponse(BaseModel):
    project_id: int
    count: int
    hypotheses: List[AIHypothesisDetailInDB] = []


class AIHypothesisAuditResponse(BaseModel):
    hypothesis: AIHypothesisDetailInDB
    reviews: List[AIHypothesisReviewInDB] = []
    security_test: Optional[Dict[str, Any]] = None
    lifecycle_stages: List[Dict[str, Any]] = []


# ==============================================================================
# STAGE 9.3: Security Investigation Workspace Schemas
# ==============================================================================

class SecurityInvestigationStatus(str, Enum):
    OPEN = "OPEN"
    IN_REVIEW = "IN_REVIEW"
    RESOLVED = "RESOLVED"
    ARCHIVED = "ARCHIVED"


class InvestigationItemType(str, Enum):
    FINDING = "FINDING"
    EVIDENCE = "EVIDENCE"
    ATTACK_GRAPH = "ATTACK_GRAPH"
    ATTACK_PATH = "ATTACK_PATH"
    SECURITY_IMPACT = "SECURITY_IMPACT"
    AI_ANALYSIS = "AI_ANALYSIS"
    AI_HYPOTHESIS = "AI_HYPOTHESIS"
    SECURITY_TEST = "SECURITY_TEST"
    WORKFLOW_EXECUTION = "WORKFLOW_EXECUTION"


class InvestigationItemBase(BaseModel):
    item_type: str
    item_id: str
    position: Optional[int] = None


class InvestigationItemCreate(InvestigationItemBase):
    pass


class InvestigationItemInDB(InvestigationItemBase):
    id: str
    investigation_id: str
    position: int
    created_at: datetime
    item_summary: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)


class SecurityInvestigationBase(BaseModel):
    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    status: str = "OPEN"
    primary_finding_id: Optional[str] = None
    primary_attack_path_id: Optional[str] = None


class SecurityInvestigationCreate(SecurityInvestigationBase):
    pass


class SecurityInvestigationUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    status: Optional[str] = None


class SecurityInvestigationInDB(SecurityInvestigationBase):
    id: str
    project_id: int
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class SecurityInvestigationDetailInDB(SecurityInvestigationInDB):
    primary_finding_title: Optional[str] = None
    primary_finding_severity: Optional[str] = None
    primary_attack_path_name: Optional[str] = None
    item_count: int = 0
    items: List[InvestigationItemInDB] = []


class SecurityInvestigationListResponse(BaseModel):
    project_id: int
    count: int
    investigations: List[SecurityInvestigationDetailInDB] = []


class InvestigationTimelineEvent(BaseModel):
    id: str
    event_type: str
    category: str  # VERIFIED, DETERMINISTIC, AI, HUMAN, ENGINE
    timestamp: Optional[str] = None
    title: str
    description: str
    source_type: str
    source_id: str
    metadata: Dict[str, Any] = {}


class InvestigationTimelineResponse(BaseModel):
    investigation_id: str
    events: List[InvestigationTimelineEvent] = []


class InvestigationContextResponse(BaseModel):
    investigation: SecurityInvestigationDetailInDB
    primary_finding: Optional[Dict[str, Any]] = None
    primary_attack_path: Optional[Dict[str, Any]] = None
    evidence: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    attack_graphs: List[Dict[str, Any]] = []
    attack_paths: List[Dict[str, Any]] = []
    security_impacts: List[Dict[str, Any]] = []
    ai_analyses: List[Dict[str, Any]] = []
    ai_hypotheses: List[Dict[str, Any]] = []
    security_tests: List[Dict[str, Any]] = []
    workflow_executions: List[Dict[str, Any]] = []
    summary_counts: Dict[str, int] = {}


# ==============================================================================
# STAGE 10.1: Security Test Orchestration & Execution Plans Schemas
# ==============================================================================

class TestSuiteStatus(str, Enum):
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"


class ExecutionPlanStatus(str, Enum):
    DRAFT = "DRAFT"
    READY = "READY"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ExecutionMode(str, Enum):
    SEQUENTIAL = "SEQUENTIAL"
    FAIL_FAST = "FAIL_FAST"
    CONTINUE_ON_FAILURE = "CONTINUE_ON_FAILURE"


class ExecutionItemStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    CANCELLED = "CANCELLED"


class SecurityTestSuiteItemBase(BaseModel):
    security_test_id: str
    execution_order: Optional[int] = None
    enabled: bool = True


class SecurityTestSuiteItemCreate(SecurityTestSuiteItemBase):
    pass


class SecurityTestSuiteItemUpdate(BaseModel):
    execution_order: Optional[int] = None
    enabled: Optional[bool] = None


class SecurityTestSuiteItemInDB(BaseModel):
    id: str
    suite_id: str
    security_test_id: str
    execution_order: int
    enabled: bool
    created_at: datetime
    test_type: Optional[str] = None
    endpoint: Optional[str] = None
    attacker_identity: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class SecurityTestSuiteBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    status: str = "ACTIVE"


class SecurityTestSuiteCreate(SecurityTestSuiteBase):
    pass


class SecurityTestSuiteUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = None
    status: Optional[str] = None


class SecurityTestSuiteInDB(SecurityTestSuiteBase):
    id: str
    project_id: int
    created_at: datetime
    updated_at: datetime
    test_count: int = 0
    items: List[SecurityTestSuiteItemInDB] = []

    model_config = ConfigDict(from_attributes=True)


class SecurityTestSuiteListResponse(BaseModel):
    project_id: int
    count: int
    test_suites: List[SecurityTestSuiteInDB] = []


class SecurityExecutionItemInDB(BaseModel):
    id: str
    execution_plan_id: str
    security_test_id: str
    execution_order: int
    status: str
    test_execution_id: Optional[str] = None
    result: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    test_type: Optional[str] = None
    endpoint: Optional[str] = None
    attacker_identity: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class SecurityExecutionPlanBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    suite_id: Optional[str] = None
    profile_id: Optional[str] = None
    execution_mode: str = "SEQUENTIAL"


class SecurityExecutionPlanCreate(SecurityExecutionPlanBase):
    security_test_ids: Optional[List[str]] = None


class SecurityExecutionPlanInDB(SecurityExecutionPlanBase):
    id: str
    project_id: int
    status: str
    total_tests: int = 0
    completed_tests: int = 0
    confirmed_findings: int = 0
    inconclusive_tests: int = 0
    failed_tests: int = 0
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    suite_name: Optional[str] = None
    profile_id: Optional[str] = None
    profile_name: Optional[str] = None
    source_type: Optional[str] = "CUSTOM"
    items: List[SecurityExecutionItemInDB] = []

    model_config = ConfigDict(from_attributes=True)


class SecurityExecutionPlanListResponse(BaseModel):
    project_id: int
    count: int
    execution_plans: List[SecurityExecutionPlanInDB] = []


class SecurityExecutionProgressResponse(BaseModel):
    plan_id: str
    project_id: int
    name: str
    status: str
    execution_mode: str
    total_tests: int
    completed_tests: int
    progress_percent: float
    results_summary: Dict[str, int] = {}
    items: List[SecurityExecutionItemInDB] = []
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


# ==============================================================================
# STAGE 10.2: Scan Profiles & Security Baselines Schemas
# ==============================================================================

class ProfileType(str, Enum):
    QUICK = "QUICK"
    STANDARD = "STANDARD"
    DEEP = "DEEP"
    CUSTOM = "CUSTOM"


class ProfileStatus(str, Enum):
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"


class BaselineStatus(str, Enum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    ARCHIVED = "ARCHIVED"


class ComparisonResult(str, Enum):
    NEW_VIOLATION = "NEW_VIOLATION"
    REGRESSION = "REGRESSION"
    UNCHANGED = "UNCHANGED"
    IMPROVED = "IMPROVED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


# Scan Profiles
class ScanProfileBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    profile_type: str = "STANDARD"
    status: str = "ACTIVE"
    configuration: Dict[str, Any] = Field(default_factory=dict)


class ScanProfileCreate(ScanProfileBase):
    project_id: Optional[int] = None


class ScanProfileUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = None
    profile_type: Optional[str] = None
    status: Optional[str] = None
    configuration: Optional[Dict[str, Any]] = None


class ScanProfileInDB(ScanProfileBase):
    id: str
    project_id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanProfileListResponse(BaseModel):
    project_id: int
    count: int
    profiles: List[ScanProfileInDB] = []


class TestSelectionReason(BaseModel):
    security_test_id: str
    test_type: str
    endpoint: Optional[str] = None
    priority: int
    reason: str


class ScanProfilePreviewResponse(BaseModel):
    profile_id: str
    profile_name: str
    profile_type: str
    selected_test_count: int
    selected_tests: List[TestSelectionReason] = []


class PlanFromProfileRequest(BaseModel):
    name: Optional[str] = None
    execution_mode: str = "SEQUENTIAL"


# Security Baselines
class SecurityBaselineControlBase(BaseModel):
    control_type: str
    target_type: str
    target_id: Optional[str] = None
    expected_behavior: str
    severity: str = "MEDIUM"
    enabled: bool = True
    configuration: Dict[str, Any] = Field(default_factory=dict)


class SecurityBaselineControlInDB(SecurityBaselineControlBase):
    id: str
    baseline_id: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SecurityBaselineBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    status: str = "DRAFT"


class SecurityBaselineCreate(SecurityBaselineBase):
    project_id: Optional[int] = None
    source_execution_plan_id: Optional[str] = None


class SecurityBaselineUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = None
    status: Optional[str] = None


class SecurityBaselineInDB(SecurityBaselineBase):
    id: str
    project_id: int
    source_execution_plan_id: Optional[str] = None
    version: int
    control_count: int = 0
    created_at: datetime
    updated_at: datetime
    controls: List[SecurityBaselineControlInDB] = []

    model_config = ConfigDict(from_attributes=True)


class SecurityBaselineListResponse(BaseModel):
    project_id: int
    count: int
    baselines: List[SecurityBaselineInDB] = []


class BaselineFromPlanRequest(BaseModel):
    execution_plan_id: str
    name: Optional[str] = None
    description: Optional[str] = None


# Baseline Comparisons
class SecurityBaselineComparisonItemInDB(BaseModel):
    id: str
    comparison_id: str
    control_id: Optional[str] = None
    security_test_id: Optional[str] = None
    finding_id: Optional[str] = None
    result: str
    previous_behavior: Optional[str] = None
    current_behavior: Optional[str] = None
    explanation: Optional[str] = None
    evidence_reference: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SecurityBaselineComparisonInDB(BaseModel):
    id: str
    baseline_id: str
    execution_plan_id: str
    status: str
    summary: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    items: List[SecurityBaselineComparisonItemInDB] = []

    model_config = ConfigDict(from_attributes=True)


class SecurityBaselineComparisonDetailResponse(BaseModel):
    comparison: SecurityBaselineComparisonInDB
    baseline_name: str
    baseline_version: int
    plan_name: str
    plan_status: str
    regressions: List[SecurityBaselineComparisonItemInDB] = []
    new_violations: List[SecurityBaselineComparisonItemInDB] = []
    improvements: List[SecurityBaselineComparisonItemInDB] = []
    unchanged: List[SecurityBaselineComparisonItemInDB] = []
    not_applicable: List[SecurityBaselineComparisonItemInDB] = []


class ComparePlanWithBaselineRequest(BaseModel):
    baseline_id: str
    execution_plan_id: str


# ==============================================================================
# STAGE 10.3: CI/CD Security Regression Gates Schemas
# ==============================================================================

class GateStatus(str, Enum):
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"


class GateEvaluationStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    ERROR = "ERROR"


class GateSeverity(str, Enum):
    FAILURE = "FAILURE"
    WARNING = "WARNING"
    ERROR = "ERROR"


class SecurityGateFailureRules(BaseModel):
    max_regressions: int = Field(0, ge=0)
    max_new_violations: int = Field(0, ge=0)
    max_confirmed_findings: int = Field(0, ge=0)
    max_failed_tests: int = Field(0, ge=0)

    model_config = ConfigDict(extra="forbid")


class SecurityGateWarningRules(BaseModel):
    max_inconclusive: int = Field(0, ge=0)
    max_errors: int = Field(0, ge=0)
    max_not_applicable: int = Field(999999, ge=0)

    model_config = ConfigDict(extra="forbid")


class SecurityGateBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    status: str = "ACTIVE"
    baseline_id: str
    scan_profile_id: str
    failure_rules: Dict[str, Any] = Field(default_factory=lambda: SecurityGateFailureRules().model_dump())
    warning_rules: Dict[str, Any] = Field(default_factory=lambda: SecurityGateWarningRules().model_dump())


class SecurityGateCreate(SecurityGateBase):
    project_id: Optional[int] = None


class SecurityGateUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = None
    status: Optional[str] = None
    baseline_id: Optional[str] = None
    scan_profile_id: Optional[str] = None
    failure_rules: Optional[Dict[str, Any]] = None
    warning_rules: Optional[Dict[str, Any]] = None


class SecurityGateInDB(SecurityGateBase):
    id: str
    project_id: int
    baseline_name: Optional[str] = None
    baseline_version: Optional[int] = None
    scan_profile_name: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    latest_evaluation_status: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class SecurityGateListResponse(BaseModel):
    project_id: int
    count: int
    gates: List[SecurityGateInDB] = []


class SecurityGateEvaluationItemInDB(BaseModel):
    id: str
    evaluation_id: str
    rule_type: str
    severity: str
    triggered: bool
    actual_value: int
    threshold: int
    message: str
    finding_id: Optional[str] = None
    comparison_item_id: Optional[str] = None
    security_test_id: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class SecurityGateEvaluationInDB(BaseModel):
    id: str
    gate_id: str
    project_id: int
    baseline_comparison_id: str
    status: str
    failure_count: int = 0
    warning_count: int = 0
    confirmed_findings: int = 0
    regressions: int = 0
    new_violations: int = 0
    failed_tests: int = 0
    inconclusive_tests: int = 0
    error_tests: int = 0
    summary: Dict[str, Any] = Field(default_factory=dict)
    evaluated_at: datetime
    gate_name: Optional[str] = None
    items: List[SecurityGateEvaluationItemInDB] = []

    model_config = ConfigDict(from_attributes=True)


class SecurityGateEvaluateRequest(BaseModel):
    comparison_id: Optional[str] = None
    baseline_comparison_id: Optional[str] = None


class SecurityGateEvaluationListResponse(BaseModel):
    project_id: int
    count: int
    evaluations: List[SecurityGateEvaluationInDB] = []


class TriggeredRuleInfo(BaseModel):
    rule_type: str
    actual: int
    threshold: int
    severity: str
    message: str
    finding_ids: List[str] = []
    comparison_item_ids: List[str] = []
    security_test_ids: List[str] = []


class SecurityGateMetrics(BaseModel):
    new_violations: int = 0
    regressions: int = 0
    confirmed_findings: int = 0
    failed_tests: int = 0
    inconclusive_tests: int = 0
    errors: int = 0
    not_applicable: int = 0


class SecurityGateCIResult(BaseModel):
    status: str
    exit_code: int
    gate_id: str
    gate_name: str
    baseline_version: Optional[int] = None
    evaluation_id: str
    metrics: SecurityGateMetrics
    triggered_rules: List[TriggeredRuleInfo] = []
    evaluated_at: datetime


# ==============================================================================
# STAGE 10.4: Security Reporting & Evidence Packages Schemas
# ==============================================================================

class ReportStatus(str, Enum):
    DRAFT = "DRAFT"
    GENERATED = "GENERATED"
    ARCHIVED = "ARCHIVED"


class ReportType(str, Enum):
    EXECUTION = "EXECUTION"
    BASELINE_REGRESSION = "BASELINE_REGRESSION"
    SECURITY_ASSESSMENT = "SECURITY_ASSESSMENT"
    INVESTIGATION = "INVESTIGATION"


class ProvenanceCategory(str, Enum):
    VERIFIED = "VERIFIED"
    DETERMINISTIC = "DETERMINISTIC"
    AI = "AI"
    HUMAN = "HUMAN"
    ENGINE = "ENGINE"


class SecurityReportBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    report_type: str = "SECURITY_ASSESSMENT"
    source_execution_plan_id: Optional[str] = None
    source_gate_evaluation_id: Optional[str] = None
    source_investigation_id: Optional[str] = None


class SecurityReportCreate(SecurityReportBase):
    project_id: Optional[int] = None


class SecurityReportUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = None
    report_type: Optional[str] = None
    source_execution_plan_id: Optional[str] = None
    source_gate_evaluation_id: Optional[str] = None
    source_investigation_id: Optional[str] = None


class SecurityReportInDB(SecurityReportBase):
    id: str
    project_id: int
    status: str
    version: int
    created_at: datetime
    updated_at: datetime
    generated_at: Optional[datetime] = None
    latest_snapshot_checksum: Optional[str] = None
    execution_plan_name: Optional[str] = None
    gate_name: Optional[str] = None
    investigation_title: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class SecurityReportListResponse(BaseModel):
    project_id: int
    count: int
    reports: List[SecurityReportInDB] = []


class SecurityReportSnapshotInDB(BaseModel):
    id: str
    report_id: str
    version: int
    generated_at: datetime
    checksum: str
    schema_version: str
    report_json: Dict[str, Any]

    model_config = ConfigDict(from_attributes=True)


class SecurityReportManifest(BaseModel):
    package_version: str = "1.0"
    schema_version: str = "1.0"
    report_id: str
    report_version: int
    project_id: int
    generated_at: datetime
    object_counts: Dict[str, int]
    checksums: Dict[str, str]
    source_execution_plan_id: Optional[str] = None
    source_gate_evaluation_id: Optional[str] = None
    source_investigation_id: Optional[str] = None
    integrity_status: str = "VERIFIED"


class SecurityReportDetailResponse(BaseModel):
    report: SecurityReportInDB
    latest_snapshot: Optional[SecurityReportSnapshotInDB] = None
    manifest: Optional[SecurityReportManifest] = None