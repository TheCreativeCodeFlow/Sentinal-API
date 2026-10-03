import uuid
from typing import List, Optional, Set
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import get_db
from app.core.security import constant_time_compare
from app.models import (
    Permission, Role, User, ApiToken, ProjectMembership, Project
)
from app.services.auth.token_service import token_service


# Standard Permissions Defined for SentinelAPI
PERMISSIONS = [
    # Project
    ("project:read", "View project details and resources"),
    ("project:write", "Update project configuration"),
    ("project:delete", "Delete a project"),
    ("project:admin", "Manage project members and settings"),
    # Scans & Execution Plans
    ("scan:read", "View scans, profiles, and execution plans"),
    ("scan:execute", "Trigger or start security scans"),
    ("scan:cancel", "Cancel or abort in-progress scans"),
    # Security Gates
    ("gate:read", "View security gates and evaluations"),
    ("gate:evaluate", "Run security gate evaluations"),
    ("gate:write", "Create, update, or delete security gates"),
    # Baselines
    ("baseline:read", "View security baselines and controls"),
    ("baseline:write", "Create or update security baselines"),
    ("baseline:compare", "Run baseline comparisons"),
    # Reports
    ("report:read", "View security reports and evidence"),
    ("report:export", "Export reports and evidence packages"),
    ("report:generate", "Generate new reports and snapshots"),
    # Investigations & AI
    ("investigation:read", "View security investigations and analyses"),
    ("investigation:write", "Review hypotheses and approve investigations"),
    # Schedules
    ("schedule:read", "View scan schedules and execution history"),
    ("schedule:write", "Create, update, or delete scan schedules"),
    ("schedule:execute", "Manually trigger a scheduled scan"),
    # RBAC & Audit
    ("role:manage", "Manage project roles and permissions"),
    ("audit:read", "View immutable audit logs"),
]

ROLE_PERMISSION_MAPPING = {
    "VIEWER": [
        "project:read", "scan:read", "gate:read", "baseline:read",
        "report:read", "report:export", "investigation:read",
        "schedule:read", "audit:read"
    ],
    "SECURITY_ANALYST": [
        "project:read", "scan:read", "gate:read", "baseline:read",
        "report:read", "report:export", "investigation:read",
        "schedule:read", "audit:read",
        # Analyst extras
        "scan:execute", "scan:cancel", "gate:evaluate", "baseline:compare",
        "report:generate", "investigation:write", "schedule:execute"
    ],
    "PROJECT_ADMIN": [
        # All permissions
        p[0] for p in PERMISSIONS
    ]
}


class Actor:
    def __init__(
        self,
        user: Optional[User] = None,
        token: Optional[ApiToken] = None,
        is_system_admin: bool = False,
        is_development_bypass: bool = False,
    ):
        self.user = user
        self.token = token
        self.is_system_admin = is_system_admin
        self.is_development_bypass = is_development_bypass

    @property
    def user_id(self) -> Optional[str]:
        return self.user.id if self.user else None

    @property
    def email(self) -> str:
        if self.user:
            return self.user.email
        if self.is_system_admin:
            return "system@sentinel.local"
        return "anonymous@sentinel.local"


def seed_permissions(db: Session) -> None:
    """Ensure all core permissions are seeded in database."""
    existing = {p.key: p for p in db.query(Permission).all()}
    for key, desc in PERMISSIONS:
        if key not in existing:
            perm = Permission(id=str(uuid.uuid4()), key=key, description=desc)
            db.add(perm)
    db.commit()


def seed_project_roles(db: Session, project_id: int) -> None:
    """Seed default roles and permissions for a project."""
    seed_permissions(db)
    all_perms = {p.key: p for p in db.query(Permission).all()}

    for role_name, perm_keys in ROLE_PERMISSION_MAPPING.items():
        role = db.query(Role).filter(Role.project_id == project_id, Role.name == role_name).first()
        if not role:
            role = Role(
                id=str(uuid.uuid4()),
                project_id=project_id,
                name=role_name,
                description=f"Standard {role_name} role"
            )
            db.add(role)
            db.commit()
            db.refresh(role)

        # Attach permissions
        role_perm_keys = {p.key for p in role.permissions}
        for key in perm_keys:
            if key in all_perms and key not in role_perm_keys:
                role.permissions.append(all_perms[key])
        db.commit()


def get_current_actor(
    request: Request,
    db: Session = Depends(get_db),
) -> Actor:
    """FastAPI dependency to extract and authenticate current actor."""
    auth_header = request.headers.get("Authorization", "")
    api_key_header = request.headers.get("X-API-Key", "")

    token_str = ""
    if auth_header.startswith("Bearer "):
        token_str = auth_header[7:].strip()
    elif api_key_header:
        token_str = api_key_header.strip()

    # 1. System token check
    if settings.SENTINEL_API_TOKEN:
        if token_str and constant_time_compare(token_str, settings.SENTINEL_API_TOKEN):
            return Actor(is_system_admin=True)

    # 2. Database user token check
    if token_str:
        auth_result = token_service.authenticate_token(db, token_str)
        if auth_result:
            user, api_token = auth_result
            return Actor(user=user, token=api_token)
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired API token.",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # 3. No token provided
    if settings.SENTINEL_ENFORCE_AUTH:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Development fallback
    return Actor(is_system_admin=True, is_development_bypass=True)


def has_project_permission(
    db: Session,
    actor: Actor,
    project_id: int,
    required_permission: str,
) -> bool:
    """Check if actor holds a permission within a project."""
    if actor.is_system_admin or actor.is_development_bypass:
        return True

    if not actor.user:
        return False

    membership = db.query(ProjectMembership).filter(
        ProjectMembership.project_id == project_id,
        ProjectMembership.user_id == actor.user.id,
        ProjectMembership.status == "ACTIVE"
    ).first()

    if not membership:
        return False

    role = membership.role
    if not role:
        return False

    if role.name == "PROJECT_ADMIN":
        return True

    return any(p.key == required_permission for p in role.permissions)


def check_project_access(
    db: Session,
    actor: Actor,
    project_id: int,
    required_permission: Optional[str] = None,
) -> None:
    """
    Enforce project-scoped authorization.
    Raises 403 Forbidden if unauthorized.
    """
    if actor.is_system_admin or actor.is_development_bypass:
        return

    # Check project existence
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    if not actor.user:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")

    membership = db.query(ProjectMembership).filter(
        ProjectMembership.project_id == project_id,
        ProjectMembership.user_id == actor.user.id,
        ProjectMembership.status == "ACTIVE"
    ).first()

    if not membership:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access to project {project_id} forbidden: no active membership."
        )

    if required_permission:
        role = membership.role
        if not role:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User has no assigned role.")
        if role.name != "PROJECT_ADMIN":
            has_perm = any(p.key == required_permission for p in role.permissions)
            if not has_perm:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission '{required_permission}' required for this operation."
                )
