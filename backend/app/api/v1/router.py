from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form
from sqlalchemy.orm import Session
from typing import List, Optional

from app.core.db import get_db
from app.models import Project, API, Endpoint, Schema
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
    result = ingest_openapi(spec_content, project_id, api_name, api_version)
    
    return result


# Include sub-routers into main router
router.include_router(project_router)
router.include_router(api_router)
router.include_router(endpoint_router)
router.include_router(ingest_router)