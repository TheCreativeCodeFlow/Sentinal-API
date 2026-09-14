import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import yaml
from fastapi import HTTPException, status
from pydantic import ValidationError
from sqlalchemy.orm import sessionmaker

from app.core.db import get_engine, Base
from app.models import Project, API, Endpoint, Schema, AuthScheme
from app.schemas import (
    ProjectCreate,
    ProjectUpdate,
    APICreate,
    APIUpdate,
    EndpointCreate,
    EndpointUpdate,
    OpenAPIUpload,
    EndpointFilter,
    AuthSchemeCreate,
    AuthSchemeInDB,
)


def get_session():
    """Create a new database session."""
    engine = get_engine()
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)()


def sanitize_path(path: str) -> str:
    """Sanitize OpenAPI path to match our endpoint paths."""
    path = re.sub(r"\{([^}]+)\}", r"{\1}", path)
    return path


def parse_openapi_spec(spec_content: str) -> Tuple[Dict[str, Any], str]:
    """Parse OpenAPI 3.x spec from JSON or YAML string."""
    try:
        try:
            spec = json.loads(spec_content)
            fmt = "openapi3"
        except json.JSONDecodeError:
            spec = yaml.safe_load(spec_content)
            fmt = "openapi3"
        
        if not isinstance(spec, dict):
            raise ValueError("Invalid OpenAPI spec: root must be an object")
        
        if "openapi" not in spec and "swagger" not in spec:
            raise ValueError("Invalid OpenAPI spec: missing 'openapi' or 'swagger' field")
        
        return spec, fmt
    
    except (json.JSONDecodeError, yaml.YAMLError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid OpenAPI specification format: {str(e)}",
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


def extract_endpoints(spec: Dict[str, Any], source: str = "openapi_spec") -> List[Dict[str, Any]]:
    """Extract endpoints from a parsed OpenAPI specification."""
    endpoints = []
    paths = spec.get("paths", {})
    
    if not paths:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OpenAPI spec has no 'paths' field",
        )
    
    for path_path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        
        for method, operation in path_item.items():
            if method.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                parameters = operation.get("parameters", [])
                
                request_body = operation.get("requestBody")
                request_schema = None
                if request_body and isinstance(request_body, dict):
                    content = request_body.get("content", {})
                    json_content = content.get("application/json")
                    if json_content and isinstance(json_content, dict):
                        request_schema = json_content.get("schema")
                
                responses = operation.get("responses", {})
                response_schemas = {}
                for resp_code, resp_obj in responses.items():
                    if isinstance(resp_obj, dict):
                        schema = resp_obj.get("content", {})
                        json_schema = schema.get("application/json")
                        if json_schema and isinstance(json_schema, dict):
                            ref = json_schema.get("schema")
                            if ref:
                                response_schemas[resp_code] = ref
                
                tags = operation.get("tags", [])
                if not isinstance(tags, list):
                    tags = [tags] if tags else []
                
                endpoint_data = {
                    "path": path_path,
                    "method": method.upper(),
                    "summary": operation.get("summary"),
                    "description": operation.get("description"),
                    "tags": tags,
                    "parameters": parameters,
                    "request_schema": request_schema,
                    "response_schemas": response_schemas,
                }
                endpoints.append(endpoint_data)
    
    return endpoints


def extract_auth_schemes(spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract authentication schemes from OpenAPI spec security schemes."""
    schemes = []
    components = spec.get("components", {})
    security_schemes = components.get("securitySchemes", {})
    
    if not isinstance(security_schemes, dict):
        security_schemes = {}
    
    for name, scheme in security_schemes.items():
        if not isinstance(scheme, dict):
            continue
        
        scheme_type = scheme.get("type", "")
        scheme_data = {
            "name": name,
            "type": scheme_type,
            "description": scheme.get("description"),
            "in": scheme.get("in"),
            "scheme": scheme.get("scheme"),
            "bearer_format": scheme.get("bearerFormat"),
        }
        schemes.append(scheme_data)
    
    return schemes


def ingest_openapi(spec_content: str, project_id: int, api_name: Optional[str] = None, api_version: Optional[str] = None) -> Dict[str, Any]:
    """Full OpenAPI ingestion pipeline."""
    spec, fmt = parse_openapi_spec(spec_content)
    
    endpoints = extract_endpoints(spec)
    auth_schemes = extract_auth_schemes(spec)
    
    db = get_session()
    try:
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Project with id {project_id} not found",
            )
        
        # Create API record
        info = spec.get("info", {})
        api = API(
            project_id=project_id,
            name=api_name or info.get("title", "Imported API"),
            version=api_version or info.get("version", "1.0.0"),
            title=info.get("title"),
            url=spec.get("servers", [{}])[0].get("url") if spec.get("servers") else None,
            format=fmt,
            status="ingested",
        )
        db.add(api)
        db.flush()  # Get the API ID
        
        import json as _json
        
        paths = spec.get("paths", {})
        for path_path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            
            for method, operation in path_item.items():
                if method.upper() not in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                    continue
                
                parameters = operation.get("parameters", [])
                request_body = operation.get("requestBody")
                request_schema = None
                if request_body and isinstance(request_body, dict):
                    content = request_body.get("content", {})
                    json_content = content.get("application/json")
                    if json_content and isinstance(json_content, dict):
                        request_schema = json_content.get("schema")
                
                responses = operation.get("responses", {})
                response_schemas = {}
                for resp_code, resp_obj in responses.items():
                    if isinstance(resp_obj, dict):
                        schema = resp_obj.get("content", {})
                        json_schema = schema.get("application/json")
                        if json_schema and isinstance(json_schema, dict):
                            ref = json_schema.get("schema")
                            if ref:
                                response_schemas[resp_code] = ref
                
                tags = operation.get("tags", [])
                if not isinstance(tags, list):
                    tags = [tags] if tags else []
                
                request_schema_json = _json.dumps(request_schema) if request_schema else None
                response_schemas_json = _json.dumps(response_schemas) if response_schemas else None
                tags_json = _json.dumps(tags) if tags else None
                
                endpoint = Endpoint(
                    api_id=api.id,
                    method=method.upper(),
                    path=path_path,
                    summary=operation.get("summary"),
                    description=operation.get("description"),
                    tags=tags_json,
                    description_raw=operation.get("description"),
                )
                db.add(endpoint)
                
                if request_schema:
                    schema = Schema(
                        name=f"req_{path_path.replace('/', '_')}_{method.upper()}",
                        content=_json.dumps(request_schema),
                        format=fmt,
                        source="openapi_spec",
                    )
                    db.add(schema)
                
                for resp_code, ref in response_schemas.items():
                    schema = Schema(
                        name=f"resp_{path_path.replace('/', '_')}_{method.upper()}_{resp_code}",
                        content=_json.dumps(ref) if ref else "{}",
                        format=fmt,
                        source="openapi_spec",
                    )
                    db.add(schema)
        
        # Store auth schemes
        for scheme_data in auth_schemes:
            scheme = AuthScheme(
                name=scheme_data.get("name", ""),
                type=scheme_data.get("type", ""),
                description=scheme_data.get("description"),
                auth_in=scheme_data.get("in"),
                scheme=scheme_data.get("scheme"),
                bearer_format=scheme_data.get("bearer_format"),
                description_raw=scheme_data.get("description"),
            )
            db.add(scheme)
        
        db.commit()
        
        return {
            "project_id": project_id,
            "api_id": api.id,
            "format": fmt,
            "endpoints_extracted": len(endpoints),
            "auth_schemes_found": len(auth_schemes),
            "message": "OpenAPI specification ingested successfully",
        }
    
    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to ingest OpenAPI spec: {str(e)}",
        )
    finally:
        db.close()