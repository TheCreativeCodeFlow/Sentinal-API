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
    security_test_id = Column(String(36), ForeignKey("security_tests.id", ondelete="CASCADE"), nullable=False, index=True)
    execution_id = Column(String(36), ForeignKey("test_executions.id", ondelete="CASCADE"), nullable=False, index=True)
    endpoint_id = Column(Integer, ForeignKey("endpoints.id", ondelete="SET NULL"), nullable=True, index=True)
    attacker_identity_id = Column(String(36), ForeignKey("identities.id", ondelete="SET NULL"), nullable=True, index=True)
    attacker_role_id = Column(String(36), ForeignKey("roles.id", ondelete="SET NULL"), nullable=True, index=True)
    resource_id = Column(String(36), ForeignKey("resources.id", ondelete="SET NULL"), nullable=True, index=True)
    type = Column(String(50), nullable=False, default="BOLA", index=True)  # BOLA, BFLA, PROPERTY_EXPOSURE
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
    evidence = relationship("Evidence", back_populates="finding", uselist=False)
    endpoint = relationship("Endpoint")
    attacker_identity = relationship("Identity", foreign_keys=[attacker_identity_id])
    attacker_role = relationship("Role", foreign_keys=[attacker_role_id])
    resource = relationship("Resource", foreign_keys=[resource_id])

    __table_args__ = (
        Index("ix_findings_project_severity", "project_id", "severity"),
        Index("ix_findings_project_type", "project_id", "type"),
    )


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    execution_id = Column(String(36), ForeignKey("test_executions.id", ondelete="CASCADE"), nullable=False, index=True)
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