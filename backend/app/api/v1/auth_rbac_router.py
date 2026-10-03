import uuid
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.models import (
    User, ApiToken, ProjectMembership, Role, Permission, AuditEvent, Project
)
from app.schemas import (
    UserCreate, UserUpdate, UserInDB, UserListResponse,
    ApiTokenCreate, ApiTokenCreatedResponse, ApiTokenInDB, ApiTokenListResponse,
    TokenVerifyResponse, TokenStatusResponse,
    ProjectMembershipCreate, ProjectMembershipUpdate, ProjectMembershipInDB, ProjectMembershipListResponse,
    PermissionInDB, PermissionListResponse, RoleWithPermissionsInDB, RoleAssignPermissions,
    AuditEventInDB, AuditEventListResponse
)
from app.services.auth.permission_service import (
    get_current_actor, Actor, check_project_access, seed_project_roles, seed_permissions
)
from app.services.auth.token_service import token_service
from app.services.auth.audit_service import audit_service


auth_router = APIRouter(prefix="/auth", tags=["auth"])
user_router = APIRouter(prefix="/users", tags=["users"])
token_router = APIRouter(tags=["api-tokens"])
membership_router = APIRouter(prefix="/projects/{project_id}/memberships", tags=["project-memberships"])
permissions_and_roles_router = APIRouter(tags=["permissions-and-roles"])
audit_router = APIRouter(tags=["audit-events"])


# ==============================================================================
# Auth verification & token status
# ==============================================================================

@auth_router.get("/verify", response_model=TokenVerifyResponse)
def verify_auth(actor: Actor = Depends(get_current_actor)):
    user_db = UserInDB.model_validate(actor.user) if actor.user else None
    token_id = actor.token.id if actor.token else None
    token_name = actor.token.name if actor.token else None
    expires_at = actor.token.expires_at if actor.token else None
    return TokenVerifyResponse(
        authenticated=True,
        user=user_db,
        token_id=token_id,
        token_name=token_name,
        expires_at=expires_at,
        is_development_bypass=actor.is_development_bypass,
    )


@auth_router.get("/token-status", response_model=TokenStatusResponse)
def get_token_status(actor: Actor = Depends(get_current_actor)):
    if not actor.token:
        return TokenStatusResponse(
            valid=True,
            status="SYSTEM_BYPASS" if (actor.is_system_admin or actor.is_development_bypass) else "ACTIVE",
            user_id=actor.user_id,
            token_name="System/Dev Token",
        )
    now = datetime.now(timezone.utc)
    days_left = None
    if actor.token.expires_at:
        exp = actor.token.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        diff = (exp - now).days
        days_left = max(0, diff)
    return TokenStatusResponse(
        valid=(actor.token.status == "ACTIVE"),
        status=actor.token.status,
        user_id=actor.token.user_id,
        token_name=actor.token.name,
        expires_at=actor.token.expires_at,
        last_used_at=actor.token.last_used_at,
        days_until_expiration=days_left,
    )


# ==============================================================================
# Users Management
# ==============================================================================

@user_router.post("", response_model=UserInDB, status_code=status.HTTP_201_CREATED)
def create_user(
    user_in: UserCreate,
    request: Request,
    db: Session = Depends(get_db),
    actor: Actor = Depends(get_current_actor),
):
    if not (actor.is_system_admin or actor.is_development_bypass):
        raise HTTPException(status_code=403, detail="Only administrators can create users.")

    existing = db.query(User).filter(User.email == user_in.email).first()
    if existing:
        raise HTTPException(status_code=409, detail="A user with this email already exists.")

    user = User(
        id=str(uuid.uuid4()),
        email=user_in.email,
        display_name=user_in.display_name,
        status="ACTIVE",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    audit_service.record(
        db=db,
        event_type="AUTH",
        action="CREATE",
        resource_type="USER",
        resource_id=user.id,
        actor_user_id=actor.user_id,
        request_id=getattr(request.state, "request_id", None),
        ip_address=request.client.host if request.client else None,
        outcome="SUCCESS",
        metadata={"email": user.email, "display_name": user.display_name},
    )
    return user


@user_router.get("", response_model=UserListResponse)
def list_users(
    db: Session = Depends(get_db),
    actor: Actor = Depends(get_current_actor),
):
    users = db.query(User).all()
    return UserListResponse(count=len(users), users=users)


@user_router.get("/{user_id}", response_model=UserInDB)
def get_user(
    user_id: str,
    db: Session = Depends(get_db),
    actor: Actor = Depends(get_current_actor),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@user_router.put("/{user_id}", response_model=UserInDB)
def update_user(
    user_id: str,
    user_in: UserUpdate,
    db: Session = Depends(get_db),
    actor: Actor = Depends(get_current_actor),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not (actor.is_system_admin or actor.is_development_bypass or actor.user_id == user_id):
        raise HTTPException(status_code=403, detail="Not authorized to update this user.")

    if user_in.display_name is not None:
        user.display_name = user_in.display_name
    if user_in.status is not None:
        if not (actor.is_system_admin or actor.is_development_bypass):
            raise HTTPException(status_code=403, detail="Only administrators can modify user status.")
        user.status = user_in.status
    user.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)
    return user


# ==============================================================================
# API Tokens
# ==============================================================================

@token_router.post("/users/{user_id}/api-tokens", response_model=ApiTokenCreatedResponse, status_code=status.HTTP_201_CREATED)
def create_api_token(
    user_id: str,
    token_in: ApiTokenCreate,
    request: Request,
    db: Session = Depends(get_db),
    actor: Actor = Depends(get_current_actor),
):
    if not (actor.is_system_admin or actor.is_development_bypass or actor.user_id == user_id):
        raise HTTPException(status_code=403, detail="Not authorized to create tokens for this user.")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    token, raw_token = token_service.create_api_token(
        db=db,
        user_id=user_id,
        name=token_in.name,
        expires_in_days=token_in.expires_in_days,
    )

    audit_service.record(
        db=db,
        event_type="AUTH",
        action="CREATE",
        resource_type="API_TOKEN",
        resource_id=token.id,
        actor_user_id=actor.user_id,
        request_id=getattr(request.state, "request_id", None),
        ip_address=request.client.host if request.client else None,
        outcome="SUCCESS",
        metadata={"token_prefix": token.token_prefix, "name": token.name},
    )

    return ApiTokenCreatedResponse(
        id=token.id,
        user_id=token.user_id,
        name=token.name,
        token_prefix=token.token_prefix,
        status=token.status,
        expires_at=token.expires_at,
        last_used_at=token.last_used_at,
        created_at=token.created_at,
        revoked_at=token.revoked_at,
        raw_token=raw_token,
    )


@token_router.get("/users/{user_id}/api-tokens", response_model=ApiTokenListResponse)
def list_user_api_tokens(
    user_id: str,
    db: Session = Depends(get_db),
    actor: Actor = Depends(get_current_actor),
):
    if not (actor.is_system_admin or actor.is_development_bypass or actor.user_id == user_id):
        raise HTTPException(status_code=403, detail="Not authorized to view tokens for this user.")

    tokens = token_service.list_tokens(db, user_id)
    return ApiTokenListResponse(user_id=user_id, count=len(tokens), tokens=tokens)


@token_router.delete("/api-tokens/{token_id}", status_code=status.HTTP_200_OK)
def revoke_api_token(
    token_id: str,
    request: Request,
    db: Session = Depends(get_db),
    actor: Actor = Depends(get_current_actor),
):
    token = db.query(ApiToken).filter(ApiToken.id == token_id).first()
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")

    if not (actor.is_system_admin or actor.is_development_bypass or actor.user_id == token.user_id):
        raise HTTPException(status_code=403, detail="Not authorized to revoke this token.")

    token_service.revoke_token(db, token_id)
    audit_service.record(
        db=db,
        event_type="AUTH",
        action="REVOKE",
        resource_type="API_TOKEN",
        resource_id=token.id,
        actor_user_id=actor.user_id,
        request_id=getattr(request.state, "request_id", None),
        ip_address=request.client.host if request.client else None,
        outcome="SUCCESS",
        metadata={"name": token.name, "token_prefix": token.token_prefix},
    )
    return {"message": "Token revoked successfully"}


# ==============================================================================
# Project Memberships & RBAC
# ==============================================================================

@membership_router.post("", response_model=ProjectMembershipInDB, status_code=status.HTTP_201_CREATED)
def add_project_membership(
    project_id: int,
    membership_in: ProjectMembershipCreate,
    request: Request,
    db: Session = Depends(get_db),
    actor: Actor = Depends(get_current_actor),
):
    check_project_access(db, actor, project_id, "project:admin")

    user = db.query(User).filter(User.id == membership_in.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    role = db.query(Role).filter(Role.id == membership_in.role_id, Role.project_id == project_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found in this project")

    existing = db.query(ProjectMembership).filter(
        ProjectMembership.project_id == project_id,
        ProjectMembership.user_id == membership_in.user_id,
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="User is already a member of this project")

    membership = ProjectMembership(
        id=str(uuid.uuid4()),
        project_id=project_id,
        user_id=membership_in.user_id,
        role_id=membership_in.role_id,
        status="ACTIVE",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(membership)
    db.commit()
    db.refresh(membership)

    audit_service.record(
        db=db,
        event_type="RBAC",
        action="CREATE",
        resource_type="MEMBERSHIP",
        resource_id=membership.id,
        project_id=project_id,
        actor_user_id=actor.user_id,
        request_id=getattr(request.state, "request_id", None),
        outcome="SUCCESS",
        metadata={"user_id": user.id, "role_name": role.name},
    )

    return ProjectMembershipInDB(
        id=membership.id,
        project_id=membership.project_id,
        user_id=membership.user_id,
        role_id=membership.role_id,
        status=membership.status,
        created_at=membership.created_at,
        updated_at=membership.updated_at,
        user_email=user.email,
        user_display_name=user.display_name,
        role_name=role.name,
    )


@membership_router.get("", response_model=ProjectMembershipListResponse)
def list_project_memberships(
    project_id: int,
    db: Session = Depends(get_db),
    actor: Actor = Depends(get_current_actor),
):
    check_project_access(db, actor, project_id, "project:read")

    memberships = db.query(ProjectMembership).filter(ProjectMembership.project_id == project_id).all()
    results = []
    for m in memberships:
        results.append(
            ProjectMembershipInDB(
                id=m.id,
                project_id=m.project_id,
                user_id=m.user_id,
                role_id=m.role_id,
                status=m.status,
                created_at=m.created_at,
                updated_at=m.updated_at,
                user_email=m.user.email if m.user else None,
                user_display_name=m.user.display_name if m.user else None,
                role_name=m.role.name if m.role else None,
            )
        )
    return ProjectMembershipListResponse(project_id=project_id, count=len(results), memberships=results)


@membership_router.delete("/{user_id}", status_code=status.HTTP_200_OK)
def remove_project_membership(
    project_id: int,
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    actor: Actor = Depends(get_current_actor),
):
    check_project_access(db, actor, project_id, "project:admin")

    membership = db.query(ProjectMembership).filter(
        ProjectMembership.project_id == project_id,
        ProjectMembership.user_id == user_id,
    ).first()
    if not membership:
        raise HTTPException(status_code=404, detail="Membership not found")

    db.delete(membership)
    db.commit()

    audit_service.record(
        db=db,
        event_type="RBAC",
        action="DELETE",
        resource_type="MEMBERSHIP",
        resource_id=membership.id,
        project_id=project_id,
        actor_user_id=actor.user_id,
        request_id=getattr(request.state, "request_id", None),
        outcome="SUCCESS",
        metadata={"user_id": user_id},
    )
    return {"message": "Membership removed successfully"}


# ==============================================================================
# Permissions & Roles
# ==============================================================================

@permissions_and_roles_router.get("/permissions", response_model=PermissionListResponse)
def list_permissions(db: Session = Depends(get_db)):
    seed_permissions(db)
    perms = db.query(Permission).order_by(Permission.key.asc()).all()
    return PermissionListResponse(count=len(perms), permissions=perms)


@permissions_and_roles_router.get("/roles/{role_id}/permissions", response_model=RoleWithPermissionsInDB)
def get_role_permissions(
    role_id: str,
    db: Session = Depends(get_db),
    actor: Actor = Depends(get_current_actor),
):
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    check_project_access(db, actor, role.project_id, "project:read")
    return role


@permissions_and_roles_router.post("/roles/{role_id}/permissions", response_model=RoleWithPermissionsInDB)
def assign_role_permissions(
    role_id: str,
    assign_in: RoleAssignPermissions,
    request: Request,
    db: Session = Depends(get_db),
    actor: Actor = Depends(get_current_actor),
):
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    check_project_access(db, actor, role.project_id, "role:manage")

    seed_permissions(db)
    available_perms = {p.key: p for p in db.query(Permission).all()}

    new_perms = []
    for key in assign_in.permission_keys:
        if key in available_perms:
            new_perms.append(available_perms[key])
        else:
            raise HTTPException(status_code=400, detail=f"Unknown permission key: {key}")

    role.permissions = new_perms
    db.commit()
    db.refresh(role)

    audit_service.record(
        db=db,
        event_type="RBAC",
        action="UPDATE",
        resource_type="ROLE_PERMISSIONS",
        resource_id=role.id,
        project_id=role.project_id,
        actor_user_id=actor.user_id,
        request_id=getattr(request.state, "request_id", None),
        outcome="SUCCESS",
        metadata={"role_name": role.name, "permissions": assign_in.permission_keys},
    )
    return role


@permissions_and_roles_router.post("/projects/{project_id}/roles/seed", status_code=status.HTTP_200_OK)
def seed_roles_for_project(
    project_id: int,
    db: Session = Depends(get_db),
    actor: Actor = Depends(get_current_actor),
):
    check_project_access(db, actor, project_id, "role:manage")
    seed_project_roles(db, project_id)
    return {"message": f"Default roles seeded for project {project_id}"}


# ==============================================================================
# Audit Events (Append-only / Immutable)
# ==============================================================================

@audit_router.get("/projects/{project_id}/audit-events", response_model=AuditEventListResponse)
def list_project_audit_events(
    project_id: int,
    event_type: Optional[str] = None,
    action: Optional[str] = None,
    outcome: Optional[str] = None,
    actor_user_id: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
    actor: Actor = Depends(get_current_actor),
):
    check_project_access(db, actor, project_id, "audit:read")

    query = db.query(AuditEvent).filter(AuditEvent.project_id == project_id)
    if event_type:
        query = query.filter(AuditEvent.event_type == event_type)
    if action:
        query = query.filter(AuditEvent.action == action)
    if outcome:
        query = query.filter(AuditEvent.outcome == outcome)
    if actor_user_id:
        query = query.filter(AuditEvent.actor_user_id == actor_user_id)

    total = query.count()
    events = query.order_by(AuditEvent.created_at.desc()).offset(offset).limit(limit).all()

    results = []
    for ev in events:
        results.append(
            AuditEventInDB(
                id=ev.id,
                project_id=ev.project_id,
                actor_user_id=ev.actor_user_id,
                actor_email=ev.actor_user.email if ev.actor_user else None,
                event_type=ev.event_type,
                action=ev.action,
                resource_type=ev.resource_type,
                resource_id=ev.resource_id,
                outcome=ev.outcome,
                request_id=ev.request_id,
                ip_address=ev.ip_address,
                user_agent=ev.user_agent,
                metadata_json=ev.metadata_json,
                created_at=ev.created_at,
            )
        )
    return AuditEventListResponse(project_id=project_id, count=total, events=results)


@audit_router.get("/audit-events", response_model=AuditEventListResponse)
def list_all_audit_events(
    event_type: Optional[str] = None,
    action: Optional[str] = None,
    outcome: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
    actor: Actor = Depends(get_current_actor),
):
    if not (actor.is_system_admin or actor.is_development_bypass):
        raise HTTPException(status_code=403, detail="Only administrators can view global audit events.")

    query = db.query(AuditEvent)
    if event_type:
        query = query.filter(AuditEvent.event_type == event_type)
    if action:
        query = query.filter(AuditEvent.action == action)
    if outcome:
        query = query.filter(AuditEvent.outcome == outcome)

    total = query.count()
    events = query.order_by(AuditEvent.created_at.desc()).offset(offset).limit(limit).all()

    results = []
    for ev in events:
        results.append(
            AuditEventInDB(
                id=ev.id,
                project_id=ev.project_id,
                actor_user_id=ev.actor_user_id,
                actor_email=ev.actor_user.email if ev.actor_user else None,
                event_type=ev.event_type,
                action=ev.action,
                resource_type=ev.resource_type,
                resource_id=ev.resource_id,
                outcome=ev.outcome,
                request_id=ev.request_id,
                ip_address=ev.ip_address,
                user_agent=ev.user_agent,
                metadata_json=ev.metadata_json,
                created_at=ev.created_at,
            )
        )
    return AuditEventListResponse(project_id=None, count=total, events=results)


@audit_router.get("/audit-events/{event_id}", response_model=AuditEventInDB)
def get_audit_event(
    event_id: str,
    db: Session = Depends(get_db),
    actor: Actor = Depends(get_current_actor),
):
    ev = db.query(AuditEvent).filter(AuditEvent.id == event_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Audit event not found")

    if ev.project_id:
        check_project_access(db, actor, ev.project_id, "audit:read")
    elif not (actor.is_system_admin or actor.is_development_bypass):
        raise HTTPException(status_code=403, detail="Not authorized to view this audit event.")

    return AuditEventInDB(
        id=ev.id,
        project_id=ev.project_id,
        actor_user_id=ev.actor_user_id,
        actor_email=ev.actor_user.email if ev.actor_user else None,
        event_type=ev.event_type,
        action=ev.action,
        resource_type=ev.resource_type,
        resource_id=ev.resource_id,
        outcome=ev.outcome,
        request_id=ev.request_id,
        ip_address=ev.ip_address,
        user_agent=ev.user_agent,
        metadata_json=ev.metadata_json,
        created_at=ev.created_at,
    )
