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