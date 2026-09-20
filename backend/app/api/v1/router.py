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


def get_ownership_or_404(ownership_id: str, db: Session) -> ResourceOwnership:
    """Helper to get resource ownership or raise 404."""
    ownership = db.query(ResourceOwnership).filter(ResourceOwnership.id == ownership_id).first()
    if not ownership:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Resource ownership with id {ownership_id} not found",
        )
    return ownership


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


# Main router for API
router = APIRouter(tags=["api"])


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