from typing import Optional, List, Any, Dict
from datetime import datetime
from pydantic import BaseModel, Field


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

    class Config:
        from_attributes = True


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

    class Config:
        from_attributes = True


# Endpoint schemas
class EndpointCreate(BaseModel):
    api_id: int
    method: str = Field(..., min_length=1, max_length=10)
    path: str = Field(..., min_length=1, max_length=500)
    summary: Optional[str] = Field(None)
    description: Optional[str] = Field(None)
    tags: Optional[List[str]] = Field(None)


class EndpointUpdate(BaseModel):
    summary: Optional[str] = Field(None)
    description: Optional[str] = Field(None)
    tags: Optional[List[str]] = Field(None)


class EndpointInDB(EndpointCreate):
    id: int
    api_id: int
    created_at: datetime

    class Config:
        from_attributes = True


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

    class Config:
        from_attributes = True