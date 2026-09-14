import json
import pytest
from fastapi.testclient import TestClient


# Project tests
def test_create_project(client):
    """Test project creation endpoint."""
    project_data = {
        "name": "Test Project",
        "description": "A test project for validation",
        "environment": "production",
        "base_url": "https://api.example.com",
        "authorization_status": "pending",
    }
    response = client.post("/api/v1/projects/", json=project_data)
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Test Project"
    assert data["description"] == "A test project for validation"
    assert data["environment"] == "production"
    assert data["authorization_status"] == "pending"
    assert "id" in data


def test_list_projects(client):
    """Test listing projects."""
    response = client.get("/api/v1/projects/")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


def test_get_project(client):
    """Test getting a single project."""
    project_data = {
        "name": "Get Project Test",
        "description": "Testing get project",
        "environment": "staging",
        "authorization_status": "pending",
    }
    create_resp = client.post("/api/v1/projects/", json=project_data)
    project_id = create_resp.json()["id"]
    
    response = client.get(f"/api/v1/projects/{project_id}/")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Get Project Test"


def test_update_project(client):
    """Test updating a project."""
    project_data = {
        "name": "Update Project Test",
        "description": "Testing update",
        "environment": "development",
        "authorization_status": "pending",
    }
    create_resp = client.post("/api/v1/projects/", json=project_data)
    project_id = create_resp.json()["id"]
    
    update_data = {
        "name": "Updated Project Name",
    }
    response = client.put(f"/api/v1/projects/{project_id}/", json=update_data)
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Updated Project Name"


def test_delete_project(client):
    """Test deleting a project."""
    project_data = {
        "name": "Delete Project Test",
        "description": "Testing delete",
        "environment": "production",
        "authorization_status": "pending",
    }
    create_resp = client.post("/api/v1/projects/", json=project_data)
    project_id = create_resp.json()["id"]
    
    response = client.delete(f"/api/v1/projects/{project_id}/")
    assert response.status_code == 204
    
    get_resp = client.get(f"/api/v1/projects/{project_id}/")
    assert get_resp.status_code == 404


# Ingestion tests
def test_ingest_openapi_valid_json(client):
    """Test OpenAPI ingestion with valid JSON spec."""
    project_data = {
        "name": "JSON Spec Project",
        "description": "Testing JSON spec ingestion",
        "environment": "production",
        "authorization_status": "pending",
    }
    create_resp = client.post("/api/v1/projects/", json=project_data)
    project_id = create_resp.json()["id"]
    
    valid_spec = {
        "openapi": "3.0.0",
        "info": {
            "title": "Test API",
            "version": "1.0.0",
        },
        "paths": {
            "/users": {
                "get": {
                    "summary": "Get users",
                    "description": "Retrieve a list of users",
                    "tags": ["users"],
                    "parameters": [
                        {
                            "name": "page",
                            "in": "query",
                            "required": False,
                            "schema": {"type": "integer"},
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Successful response",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {"$ref": "#/components/schemas/User"}
                                    }
                                }
                            },
                        }
                    },
                }
            }
        },
        "components": {
            "schemas": {
                "User": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "name": {"type": "string"},
                        "email": {"type": "string", "format": "email"},
                    },
                }
            }
        },
    }
    
    response = client.post(
        f"/api/v1/{project_id}/ingest",
        files={"file": ("spec.json", json.dumps(valid_spec), "application/json")},
    )
    assert response.status_code == 202
    data = response.json()
    assert data["endpoints_extracted"] > 0
    assert data["format"] == "openapi3"
    assert "api_id" in data


def test_ingest_openapi_valid_yaml(client):
    """Test OpenAPI ingestion with valid YAML spec."""
    project_data = {
        "name": "YAML Spec Project",
        "description": "Testing YAML spec ingestion",
        "environment": "production",
        "authorization_status": "pending",
    }
    create_resp = client.post("/api/v1/projects/", json=project_data)
    project_id = create_resp.json()["id"]
    
    valid_spec_yaml = """
openapi: 3.0.0
info:
  title: Test API YAML
  version: 1.0.0
paths:
  /pets:
    get:
      summary: List pets
      tags:
        - pets
      responses:
        "200":
          description: Successful response
          content:
            application/json:
              schema:
                type: array
                items:
                  type: object
                  properties:
                    id:
                      type: integer
                    name:
                      type: string
"""
    
    response = client.post(
        f"/api/v1/{project_id}/ingest",
        files={"file": ("spec.yaml", valid_spec_yaml, "text/yaml")},
    )
    assert response.status_code == 202
    data = response.json()
    assert data["endpoints_extracted"] > 0
    assert "api_id" in data


def test_ingest_openapi_invalid_spec(client):
    """Test OpenAPI ingestion with invalid spec."""
    project_data = {
        "name": "Invalid Spec Project",
        "description": "Testing invalid spec",
        "environment": "production",
        "authorization_status": "pending",
    }
    create_resp = client.post("/api/v1/projects/", json=project_data)
    
    # Spec missing required fields
    response = client.post(
        f"/api/v1/1/ingest",
        files={"file": ("spec.txt", "not a spec", "text/plain")},
    )
    assert response.status_code == 400