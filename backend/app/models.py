import uuid
from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    DateTime,
    Boolean,
    ForeignKey,
    Index,
    Table,
    JSON,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.db import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False, index=True)
    description = Column(Text, nullable=True)
    environment = Column(String(100), nullable=False, default="production", index=True)
    base_url = Column(Text, nullable=True)
    authorization_status = Column(
        String(50), nullable=False, default="pending", index=True
    )
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    apis = relationship("API", back_populates="project", cascade="all, delete-orphan")
    roles = relationship("Role", back_populates="project", cascade="all, delete-orphan")
    identities = relationship("Identity", back_populates="project", cascade="all, delete-orphan")
    resources = relationship("Resource", back_populates="project", cascade="all, delete-orphan")
    security_tests = relationship("SecurityTest", back_populates="project", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="project", cascade="all, delete-orphan")
    endpoint_policies = relationship("EndpointAuthorizationPolicy", back_populates="project", cascade="all, delete-orphan")
    matrix_rules = relationship("AuthorizationMatrixRule", back_populates="project", cascade="all, delete-orphan")
    auth_policies = relationship("AuthenticationPolicy", back_populates="project", cascade="all, delete-orphan")
    workflows = relationship("Workflow", back_populates="project", cascade="all, delete-orphan")
    attack_graphs = relationship("AttackGraph", back_populates="project", cascade="all, delete-orphan")
    correlations = relationship("FindingCorrelation", back_populates="project", cascade="all, delete-orphan")


class API(Base):
    __tablename__ = "apis"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(200), nullable=False, index=True)
    version = Column(String(50), nullable=True)
    title = Column(String(200), nullable=True)
    url = Column(Text, nullable=True)
    format = Column(String(20), nullable=False, default="openapi3")
    status = Column(String(50), nullable=False, default="pending", index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    project = relationship("Project", back_populates="apis")
    endpoints = relationship("Endpoint", back_populates="api", cascade="all, delete-orphan")
    resources = relationship("Resource", back_populates="api")


class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(Integer, primary_key=True)
    api_id = Column(Integer, ForeignKey("apis.id", ondelete="CASCADE"), nullable=False)
    resource_id = Column(String(36), ForeignKey("resources.id", ondelete="SET NULL"), nullable=True, index=True)
    method = Column(String(10), nullable=False)
    path = Column(String(500), nullable=False)
    summary = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    tags = Column(Text, nullable=True)
    description_raw = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    api = relationship("API", back_populates="endpoints")
    resource = relationship("Resource", back_populates="endpoints")
    policy = relationship("EndpointAuthorizationPolicy", back_populates="endpoint", uselist=False, cascade="all, delete-orphan")
    matrix_rules = relationship("AuthorizationMatrixRule", back_populates="endpoint", cascade="all, delete-orphan")
    auth_policy = relationship("AuthenticationPolicy", back_populates="endpoint", uselist=False, cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_endpoints_api_id", "api_id"),
        Index("ix_endpoints_method_path", "method", "path", unique=True),
    )


class Role(Base):
    __tablename__ = "roles"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(100), nullable=False, index=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    project = relationship("Project", back_populates="roles")
    identities = relationship("Identity", back_populates="role")

    __table_args__ = (
        Index("ix_roles_project_name", "project_id", "name", unique=True),
    )


class Identity(Base):
    __tablename__ = "identities"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    role_id = Column(String(36), ForeignKey("roles.id", ondelete="SET NULL"), nullable=True, index=True)
    name = Column(String(200), nullable=False, index=True)
    description = Column(Text, nullable=True)
    auth_type = Column(String(50), nullable=False, default="bearer_token")
    environment = Column(String(100), nullable=False, default="production", index=True)
    credential_reference = Column(String(255), nullable=True)
    credential_status = Column(String(50), nullable=False, default="configured")
    credential_value = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    project = relationship("Project", back_populates="identities")
    role = relationship("Role", back_populates="identities")
    resource_ownerships = relationship("ResourceOwnership", back_populates="identity", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_identities_project_name", "project_id", "name", unique=True),
    )


class Resource(Base):
    __tablename__ = "resources"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    api_id = Column(Integer, ForeignKey("apis.id", ondelete="SET NULL"), nullable=True, index=True)
    name = Column(String(200), nullable=False, index=True)
    description = Column(Text, nullable=True)
    resource_type = Column(String(100), nullable=False, default="entity")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    project = relationship("Project", back_populates="resources")
    api = relationship("API", back_populates="resources")
    ownerships = relationship("ResourceOwnership", back_populates="resource", cascade="all, delete-orphan")
    endpoints = relationship("Endpoint", back_populates="resource")
    properties = relationship("ResourceProperty", back_populates="resource", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_resources_project_name", "project_id", "name", unique=True),
    )


class ResourceOwnership(Base):
    __tablename__ = "resource_ownerships"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    resource_id = Column(String(36), ForeignKey("resources.id", ondelete="CASCADE"), nullable=False, index=True)
    identity_id = Column(String(36), ForeignKey("identities.id", ondelete="CASCADE"), nullable=False, index=True)
    resource_instance_id = Column(String(255), nullable=True)
    ownership_type = Column(String(50), nullable=False, default="owner")
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    resource = relationship("Resource", back_populates="ownerships")
    identity = relationship("Identity", back_populates="resource_ownerships")

    __table_args__ = (
        Index("ix_ownership_resource_identity", "resource_id", "identity_id"),
    )


class Schema(Base):
    __tablename__ = "schemas"

    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    content = Column(Text, nullable=False)
    format = Column(String(20), nullable=False, default="openapi3")
    source = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    __table_args__ = (
        Index("ix_schemas_name", "name"),
    )


class AuthScheme(Base):
    __tablename__ = "auth_schemes"

    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    type = Column(String(50), nullable=False, index=True)
    description = Column(Text, nullable=True)
    auth_in = Column(String(50), nullable=True)  # query, header, body
    scheme = Column(String(100), nullable=True)  # bearer, basic
    bearer_format = Column(String(100), nullable=True)
    description_raw = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        Index("ix_auth_schemes_name", "name"),
    )


# ==============================================================================
# STAGE 3: Controlled Security Testing Engine (BOLA)
# ==============================================================================

class SecurityTest(Base):
    __tablename__ = "security_tests"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    endpoint_id = Column(Integer, ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True)
    test_type = Column(String(50), nullable=False, default="BOLA", index=True)
    attacker_identity_id = Column(String(36), ForeignKey("identities.id", ondelete="CASCADE"), nullable=True, index=True)
    victim_identity_id = Column(String(36), ForeignKey("identities.id", ondelete="SET NULL"), nullable=True, index=True)
    victim_resource_id = Column(String(36), ForeignKey("resources.id", ondelete="SET NULL"), nullable=True, index=True)
    victim_resource_instance_id = Column(String(255), nullable=True)
    attacker_resource_instance_id = Column(String(255), nullable=True)
    expected_access = Column(String(20), nullable=True, default="DENY")
    status = Column(String(50), nullable=False, default="configured", index=True)
    configuration = Column(Text, nullable=True)  # JSON-encoded test settings
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    project = relationship("Project", back_populates="security_tests")
    endpoint = relationship("Endpoint")
    attacker_identity = relationship("Identity", foreign_keys=[attacker_identity_id])
    victim_identity = relationship("Identity", foreign_keys=[victim_identity_id])
    victim_resource = relationship("Resource", foreign_keys=[victim_resource_id])
    executions = relationship("TestExecution", back_populates="security_test", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="security_test", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_security_tests_proj_type", "project_id", "test_type"),
    )


class TestExecution(Base):
    __tablename__ = "test_executions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    security_test_id = Column(String(36), ForeignKey("security_tests.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String(50), nullable=False, default="PENDING", index=True)  # PENDING, RUNNING, COMPLETED, FAILED
    result = Column(String(50), nullable=True, index=True)  # PASS, CONFIRMED, INCONCLUSIVE, ERROR
    result_reason = Column(Text, nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    http_status = Column(Integer, nullable=True)
    duration_ms = Column(Integer, nullable=True)
    error_category = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    security_test = relationship("SecurityTest", back_populates="executions")
    evidence = relationship("Evidence", back_populates="execution", uselist=False, cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="execution", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_test_executions_test_status", "security_test_id", "status"),
    )


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    security_test_id = Column(String(36), ForeignKey("security_tests.id", ondelete="CASCADE"), nullable=True, index=True)
    execution_id = Column(String(36), ForeignKey("test_executions.id", ondelete="CASCADE"), nullable=True, index=True)
    workflow_id = Column(String(36), ForeignKey("workflows.id", ondelete="CASCADE"), nullable=True, index=True)
    workflow_execution_id = Column(String(36), ForeignKey("workflow_executions.id", ondelete="CASCADE"), nullable=True, index=True)
    workflow_step_id = Column(String(36), ForeignKey("workflow_steps.id", ondelete="SET NULL"), nullable=True, index=True)
    attack_scenario_id = Column(String(36), ForeignKey("workflow_attack_scenarios.id", ondelete="CASCADE"), nullable=True, index=True)
    endpoint_id = Column(Integer, ForeignKey("endpoints.id", ondelete="SET NULL"), nullable=True, index=True)
    attacker_identity_id = Column(String(36), ForeignKey("identities.id", ondelete="SET NULL"), nullable=True, index=True)
    attacker_role_id = Column(String(36), ForeignKey("roles.id", ondelete="SET NULL"), nullable=True, index=True)
    resource_id = Column(String(36), ForeignKey("resources.id", ondelete="SET NULL"), nullable=True, index=True)
    type = Column(String(50), nullable=False, default="BOLA", index=True)  # BOLA, BFLA, PROPERTY_EXPOSURE, INVALID_STATE_TRANSITION, etc.
    severity = Column(String(50), nullable=False, default="HIGH", index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    confidence = Column(String(50), nullable=False, default="HIGH")  # LOW, MEDIUM, HIGH
    status = Column(String(50), nullable=False, default="OPEN", index=True)  # OPEN, RESOLVED, FALSE_POSITIVE
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    expected_authorization = Column(String(50), nullable=True)  # e.g., DENY, ALLOW
    actual_behavior = Column(Text, nullable=True)
    exposed_properties = Column(Text, nullable=True)  # JSON-encoded list of exposed property paths
    authentication_mechanism = Column(String(50), nullable=True)  # bearer_token, api_key, basic_auth, cookie_session
    remediation = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    project = relationship("Project", back_populates="findings")
    security_test = relationship("SecurityTest", back_populates="findings")
    execution = relationship("TestExecution", back_populates="findings")
    workflow = relationship("Workflow", back_populates="findings")
    workflow_execution = relationship("WorkflowExecution", back_populates="findings")
    workflow_step = relationship("WorkflowStep")
    attack_scenario = relationship("WorkflowAttackScenario", back_populates="findings")
    evidence = relationship("Evidence", back_populates="finding", uselist=False)
    endpoint = relationship("Endpoint")
    attacker_identity = relationship("Identity", foreign_keys=[attacker_identity_id])
    attacker_role = relationship("Role", foreign_keys=[attacker_role_id])
    resource = relationship("Resource", foreign_keys=[resource_id])
    graph_nodes = relationship("AttackGraphNode", back_populates="finding")

    __table_args__ = (
        Index("ix_findings_project_severity", "project_id", "severity"),
        Index("ix_findings_project_type", "project_id", "type"),
        Index("ix_findings_project_workflow", "project_id", "workflow_id"),
        Index("ix_findings_attack_scenario", "attack_scenario_id"),
    )


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    execution_id = Column(String(36), ForeignKey("test_executions.id", ondelete="CASCADE"), nullable=True, index=True)
    workflow_execution_id = Column(String(36), ForeignKey("workflow_executions.id", ondelete="CASCADE"), nullable=True, index=True)
    workflow_step_execution_id = Column(String(36), ForeignKey("workflow_step_executions.id", ondelete="CASCADE"), nullable=True, index=True)
    attack_scenario_id = Column(String(36), ForeignKey("workflow_attack_scenarios.id", ondelete="CASCADE"), nullable=True, index=True)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True)
    request_metadata = Column(Text, nullable=True)  # JSON-encoded metadata
    response_metadata = Column(Text, nullable=True)  # JSON-encoded metadata
    expected_behavior = Column(Text, nullable=False)
    actual_behavior = Column(Text, nullable=False)
    redacted_request = Column(Text, nullable=True)
    redacted_response = Column(Text, nullable=True)
    reproducibility_status = Column(String(50), nullable=False, default="REPRODUCIBLE")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    execution = relationship("TestExecution", back_populates="evidence")
    workflow_execution = relationship("WorkflowExecution", back_populates="evidence")
    workflow_step_execution = relationship("WorkflowStepExecution", back_populates="evidence")
    attack_scenario = relationship("WorkflowAttackScenario")
    finding = relationship("Finding", back_populates="evidence")


# ==============================================================================
# STAGE 4: Authorization Boundary Engine (BFLA & Authorization Matrix)
# ==============================================================================

endpoint_policy_allowed_roles = Table(
    "endpoint_policy_allowed_roles",
    Base.metadata,
    Column("policy_id", String(36), ForeignKey("endpoint_authorization_policies.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", String(36), ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
)

endpoint_policy_denied_roles = Table(
    "endpoint_policy_denied_roles",
    Base.metadata,
    Column("policy_id", String(36), ForeignKey("endpoint_authorization_policies.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", String(36), ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
)


class EndpointAuthorizationPolicy(Base):
    __tablename__ = "endpoint_authorization_policies"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    endpoint_id = Column(Integer, ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    authentication_required = Column(Boolean, default=True, nullable=False)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    project = relationship("Project", back_populates="endpoint_policies")
    endpoint = relationship("Endpoint", back_populates="policy")
    allowed_roles = relationship(
        "Role",
        secondary=endpoint_policy_allowed_roles,
        backref="allowed_policies",
    )
    denied_roles = relationship(
        "Role",
        secondary=endpoint_policy_denied_roles,
        backref="denied_policies",
    )


class AuthorizationMatrixRule(Base):
    __tablename__ = "authorization_matrix_rules"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    endpoint_id = Column(Integer, ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True)
    role_id = Column(String(36), ForeignKey("roles.id", ondelete="CASCADE"), nullable=True, index=True)
    identity_id = Column(String(36), ForeignKey("identities.id", ondelete="CASCADE"), nullable=True, index=True)
    http_method = Column(String(10), nullable=False, default="GET")
    expected_access = Column(String(20), nullable=False, default="UNKNOWN")  # ALLOW, DENY, UNKNOWN
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    project = relationship("Project", back_populates="matrix_rules")
    endpoint = relationship("Endpoint", back_populates="matrix_rules")
    role = relationship("Role")
    identity = relationship("Identity")

    __table_args__ = (
        Index("ix_matrix_endpoint_role_method", "endpoint_id", "role_id", "http_method"),
    )


# ==============================================================================
# STAGE 5: Property Security Models
# ==============================================================================

class ResourceProperty(Base):
    __tablename__ = "resource_properties"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    resource_id = Column(String(36), ForeignKey("resources.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    data_type = Column(String(50), nullable=False, default="string")  # string, number, boolean, object, array
    sensitivity = Column(String(50), nullable=False, default="INTERNAL")  # PUBLIC, INTERNAL, SENSITIVE, SECRET
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    resource = relationship("Resource", back_populates="properties")
    rules = relationship("PropertyAuthorizationRule", back_populates="property", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_resource_properties_res_name", "resource_id", "name", unique=True),
        Index("ix_resource_properties_sensitivity", "sensitivity"),
    )


class PropertyAuthorizationRule(Base):
    __tablename__ = "property_authorization_rules"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    resource_property_id = Column(
        String(36), ForeignKey("resource_properties.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role_id = Column(String(36), ForeignKey("roles.id", ondelete="CASCADE"), nullable=False, index=True)
    access = Column(String(20), nullable=False, default="UNKNOWN")  # ALLOW, DENY, UNKNOWN
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    property = relationship("ResourceProperty", back_populates="rules")
    role = relationship("Role")

    __table_args__ = (
        Index("ix_property_rule_prop_role", "resource_property_id", "role_id", unique=True),
    )


# ==============================================================================
# STAGE 6: Authentication Security Models
# ==============================================================================

class AuthenticationPolicy(Base):
    __tablename__ = "authentication_policies"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    endpoint_id = Column(Integer, ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    authentication_required = Column(Boolean, default=True, nullable=False)
    authentication_scheme = Column(String(50), default="bearer_token", nullable=False)  # bearer_token, api_key, basic_auth, cookie_session, none
    expected_denial_status = Column(Integer, default=401, nullable=False)  # 401 or 403
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    project = relationship("Project", back_populates="auth_policies")
    endpoint = relationship("Endpoint", back_populates="auth_policy")

    __table_args__ = (
        Index("ix_auth_policy_proj_scheme", "project_id", "authentication_scheme"),
    )


# ==============================================================================
# STAGE 7.1: Stateful Workflow & Business Logic Security Models
# ==============================================================================

class Workflow(Base):
    __tablename__ = "workflows"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(200), nullable=False, index=True)
    description = Column(Text, nullable=True)
    status = Column(String(50), nullable=False, default="DRAFT", index=True)  # DRAFT, ACTIVE, DISABLED
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    project = relationship("Project", back_populates="workflows")
    steps = relationship(
        "WorkflowStep",
        back_populates="workflow",
        cascade="all, delete-orphan",
        order_by="WorkflowStep.step_order",
    )
    states = relationship(
        "WorkflowState",
        back_populates="workflow",
        cascade="all, delete-orphan",
    )
    transitions = relationship(
        "WorkflowTransition",
        back_populates="workflow",
        cascade="all, delete-orphan",
    )
    executions = relationship(
        "WorkflowExecution",
        back_populates="workflow",
        cascade="all, delete-orphan",
        order_by="WorkflowExecution.created_at.desc()",
    )
    findings = relationship(
        "Finding",
        back_populates="workflow",
        cascade="all, delete-orphan",
    )
    attack_scenarios = relationship(
        "WorkflowAttackScenario",
        back_populates="workflow",
        cascade="all, delete-orphan",
        order_by="WorkflowAttackScenario.created_at.desc()",
    )

    __table_args__ = (
        Index("ix_workflows_project_name", "project_id", "name", unique=True),
    )


class WorkflowStep(Base):
    __tablename__ = "workflow_steps"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workflow_id = Column(String(36), ForeignKey("workflows.id", ondelete="CASCADE"), nullable=False, index=True)
    step_order = Column(Integer, nullable=False)
    endpoint_id = Column(Integer, ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True)
    identity_id = Column(String(36), ForeignKey("identities.id", ondelete="SET NULL"), nullable=True, index=True)
    http_method = Column(String(10), nullable=False, default="GET")  # GET / HEAD only
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    request_template = Column(JSON, nullable=True)
    expected_status_codes = Column(JSON, nullable=False, default=list)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    workflow = relationship("Workflow", back_populates="steps")
    endpoint = relationship("Endpoint")
    identity = relationship("Identity")
    transitions = relationship("WorkflowTransition", back_populates="step")

    __table_args__ = (
        Index("ix_workflow_steps_wf_order", "workflow_id", "step_order", unique=True),
    )


class WorkflowState(Base):
    __tablename__ = "workflow_states"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workflow_id = Column(String(36), ForeignKey("workflows.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    is_initial = Column(Boolean, default=False, nullable=False)
    is_terminal = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    workflow = relationship("Workflow", back_populates="states")
    outgoing_transitions = relationship(
        "WorkflowTransition",
        foreign_keys="[WorkflowTransition.from_state_id]",
        back_populates="from_state",
        cascade="all, delete-orphan",
    )
    incoming_transitions = relationship(
        "WorkflowTransition",
        foreign_keys="[WorkflowTransition.to_state_id]",
        back_populates="to_state",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_workflow_states_wf_name", "workflow_id", "name", unique=True),
    )


class WorkflowTransition(Base):
    __tablename__ = "workflow_transitions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workflow_id = Column(String(36), ForeignKey("workflows.id", ondelete="CASCADE"), nullable=False, index=True)
    from_state_id = Column(String(36), ForeignKey("workflow_states.id", ondelete="CASCADE"), nullable=False, index=True)
    to_state_id = Column(String(36), ForeignKey("workflow_states.id", ondelete="CASCADE"), nullable=False, index=True)
    step_id = Column(String(36), ForeignKey("workflow_steps.id", ondelete="SET NULL"), nullable=True, index=True)
    expected_behavior = Column(String(20), nullable=False, default="ALLOW")  # ALLOW, DENY
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    workflow = relationship("Workflow", back_populates="transitions")
    from_state = relationship("WorkflowState", foreign_keys=[from_state_id], back_populates="outgoing_transitions")
    to_state = relationship("WorkflowState", foreign_keys=[to_state_id], back_populates="incoming_transitions")
    step = relationship("WorkflowStep", back_populates="transitions")

    __table_args__ = (
        Index("ix_workflow_transitions_unique", "workflow_id", "from_state_id", "to_state_id", "step_id", unique=True),
    )


# ==============================================================================
# STAGE 7.2: Stateful Workflow Execution Models
# ==============================================================================

class WorkflowExecution(Base):
    __tablename__ = "workflow_executions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workflow_id = Column(String(36), ForeignKey("workflows.id", ondelete="CASCADE"), nullable=False, index=True)
    attack_scenario_id = Column(String(36), ForeignKey("workflow_attack_scenarios.id", ondelete="CASCADE"), nullable=True, index=True)
    status = Column(String(50), nullable=False, default="QUEUED", index=True)  # QUEUED, RUNNING, COMPLETED, FAILED
    result = Column(String(50), nullable=True, index=True)  # PASS, CONFIRMED, INCONCLUSIVE, ERROR
    result_reason = Column(Text, nullable=True)
    triggered_by = Column(String(50), nullable=False, default="MANUAL")  # MANUAL, REPLAY
    current_state_id = Column(String(36), ForeignKey("workflow_states.id", ondelete="SET NULL"), nullable=True, index=True)
    correlation_id = Column(String(64), nullable=True, index=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    workflow = relationship("Workflow", back_populates="executions")
    attack_scenario = relationship("WorkflowAttackScenario", back_populates="executions")
    current_state = relationship("WorkflowState")
    step_executions = relationship(
        "WorkflowStepExecution",
        back_populates="workflow_execution",
        cascade="all, delete-orphan",
        order_by="WorkflowStepExecution.step_order",
    )
    findings = relationship("Finding", back_populates="workflow_execution", cascade="all, delete-orphan")
    evidence = relationship("Evidence", back_populates="workflow_execution", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_wf_exec_wf_status", "workflow_id", "status"),
        Index("ix_wf_exec_scenario_status", "attack_scenario_id", "status"),
    )


class WorkflowStepExecution(Base):
    __tablename__ = "workflow_step_executions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workflow_execution_id = Column(
        String(36), ForeignKey("workflow_executions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    step_id = Column(String(36), ForeignKey("workflow_steps.id", ondelete="SET NULL"), nullable=True, index=True)
    attack_step_id = Column(String(36), ForeignKey("workflow_attack_steps.id", ondelete="SET NULL"), nullable=True, index=True)
    step_order = Column(Integer, nullable=False)
    http_method = Column(String(10), nullable=True)
    endpoint_path = Column(String(500), nullable=True)
    action = Column(String(50), nullable=True)  # EXECUTE, SKIP, REPLAY, SWITCH_IDENTITY
    identity_id = Column(String(36), ForeignKey("identities.id", ondelete="SET NULL"), nullable=True, index=True)
    identity_name = Column(String(100), nullable=True)
    status = Column(String(50), nullable=False, default="PENDING")  # PASS, CONFIRMED, INCONCLUSIVE, ERROR, SKIPPED
    request_summary = Column(JSON, nullable=True)
    response_summary = Column(JSON, nullable=True)
    status_code = Column(Integer, nullable=True)
    latency_ms = Column(Integer, nullable=True)
    state_before = Column(String(100), nullable=True)
    state_after = Column(String(100), nullable=True)
    transition_expected = Column(String(20), nullable=True)  # ALLOW, DENY
    transition_result = Column(String(50), nullable=True)  # VALID, INVALID_STATE_TRANSITION, UNEXPECTED_STATE
    correlation_id = Column(String(64), nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    workflow_execution = relationship("WorkflowExecution", back_populates="step_executions")
    step = relationship("WorkflowStep")
    attack_step = relationship("WorkflowAttackStep")
    identity = relationship("Identity", foreign_keys=[identity_id])
    evidence = relationship("Evidence", back_populates="workflow_step_execution", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_wf_step_exec_wf_order", "workflow_execution_id", "step_order"),
    )


# ==============================================================================
# STAGE 7.3: Stateful Attack Scenarios Models
# ==============================================================================

class WorkflowAttackScenario(Base):
    __tablename__ = "workflow_attack_scenarios"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workflow_id = Column(String(36), ForeignKey("workflows.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    scenario_type = Column(String(50), nullable=False, index=True)  # INVALID_STATE_TRANSITION, STEP_REPLAY, STEP_SKIP, STEP_REORDER, IDENTITY_SWITCH, CROSS_IDENTITY_CONTINUATION
    status = Column(String(50), nullable=False, default="ACTIVE", index=True)  # DRAFT, ACTIVE, DISABLED
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    workflow = relationship("Workflow", back_populates="attack_scenarios")
    steps = relationship(
        "WorkflowAttackStep",
        back_populates="scenario",
        cascade="all, delete-orphan",
        order_by="WorkflowAttackStep.position",
    )
    executions = relationship(
        "WorkflowExecution",
        back_populates="attack_scenario",
        cascade="all, delete-orphan",
        order_by="WorkflowExecution.created_at.desc()",
    )
    findings = relationship("Finding", back_populates="attack_scenario", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_wf_attack_scenarios_wf_type", "workflow_id", "scenario_type"),
    )


class WorkflowAttackStep(Base):
    __tablename__ = "workflow_attack_steps"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scenario_id = Column(String(36), ForeignKey("workflow_attack_scenarios.id", ondelete="CASCADE"), nullable=False, index=True)
    source_step_id = Column(String(36), ForeignKey("workflow_steps.id", ondelete="SET NULL"), nullable=True, index=True)
    position = Column(Integer, nullable=False)
    action = Column(String(50), nullable=False)  # EXECUTE, SKIP, REPLAY, SWITCH_IDENTITY
    identity_id = Column(String(36), ForeignKey("identities.id", ondelete="SET NULL"), nullable=True, index=True)
    expected_behavior = Column(String(50), nullable=False, default="DENY")  # ALLOW, DENY
    configuration = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    scenario = relationship("WorkflowAttackScenario", back_populates="steps")
    source_step = relationship("WorkflowStep")
    identity = relationship("Identity", foreign_keys=[identity_id])

    __table_args__ = (
        Index("ix_wf_attack_steps_scenario_pos", "scenario_id", "position"),
    )


# ==============================================================================
# STAGE 8.1: Deterministic Finding Correlation & Attack Graph Models
# ==============================================================================

class AttackGraph(Base):
    __tablename__ = "attack_graphs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(50), nullable=False, default="ACTIVE", index=True)  # ACTIVE, ARCHIVED
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    project = relationship("Project", back_populates="attack_graphs")
    nodes = relationship("AttackGraphNode", back_populates="graph", cascade="all, delete-orphan")
    edges = relationship("AttackGraphEdge", back_populates="graph", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_attack_graphs_project_status", "project_id", "status"),
    )


class AttackGraphNode(Base):
    __tablename__ = "attack_graph_nodes"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    graph_id = Column(String(36), ForeignKey("attack_graphs.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True)
    node_type = Column(String(50), nullable=False, index=True)  # FINDING, IDENTITY, ROLE, ENDPOINT, RESOURCE, WORKFLOW, WORKFLOW_EXECUTION, PROPERTY, AUTHENTICATION
    label = Column(String(255), nullable=False)
    node_metadata = Column("metadata_json", JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    graph = relationship("AttackGraph", back_populates="nodes")
    finding = relationship("Finding", back_populates="graph_nodes")
    outgoing_edges = relationship("AttackGraphEdge", foreign_keys="AttackGraphEdge.source_node_id", cascade="all, delete-orphan")
    incoming_edges = relationship("AttackGraphEdge", foreign_keys="AttackGraphEdge.target_node_id", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_attack_graph_nodes_graph_type", "graph_id", "node_type"),
    )


class AttackGraphEdge(Base):
    __tablename__ = "attack_graph_edges"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    graph_id = Column(String(36), ForeignKey("attack_graphs.id", ondelete="CASCADE"), nullable=False, index=True)
    source_node_id = Column(String(36), ForeignKey("attack_graph_nodes.id", ondelete="CASCADE"), nullable=False, index=True)
    target_node_id = Column(String(36), ForeignKey("attack_graph_nodes.id", ondelete="CASCADE"), nullable=False, index=True)
    relationship_type = Column(String(50), nullable=False, index=True)  # SAME_IDENTITY, SAME_ENDPOINT, etc.
    confidence = Column(String(50), nullable=False, default="HIGH")  # HIGH, MEDIUM, LOW
    reason = Column(Text, nullable=False)
    edge_metadata = Column("metadata_json", JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    graph = relationship("AttackGraph", back_populates="edges")
    source_node = relationship("AttackGraphNode", foreign_keys=[source_node_id], back_populates="outgoing_edges")
    target_node = relationship("AttackGraphNode", foreign_keys=[target_node_id], back_populates="incoming_edges")

    __table_args__ = (
        Index("ix_attack_graph_edges_graph_rel", "graph_id", "relationship_type"),
        Index("ix_attack_graph_edges_src_tgt", "graph_id", "source_node_id", "target_node_id", "relationship_type", unique=True),
    )


class FindingCorrelation(Base):
    __tablename__ = "finding_correlations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_a_id = Column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_b_id = Column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    relationship_type = Column(String(50), nullable=False, index=True)
    confidence = Column(String(50), nullable=False, default="HIGH")  # HIGH, MEDIUM, LOW
    reason = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    project = relationship("Project", back_populates="correlations")
    finding_a = relationship("Finding", foreign_keys=[finding_a_id])
    finding_b = relationship("Finding", foreign_keys=[finding_b_id])

    __table_args__ = (
        Index("ix_finding_correlations_pair_rel", "project_id", "finding_a_id", "finding_b_id", "relationship_type", unique=True),
    )