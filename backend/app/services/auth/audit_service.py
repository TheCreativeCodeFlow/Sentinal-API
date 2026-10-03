import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from sqlalchemy.orm import Session

from app.models import AuditEvent

logger = logging.getLogger("sentinel.audit")

SENSITIVE_KEYS = {
    "password", "secret", "token", "key", "authorization", "auth",
    "cookie", "credential", "api_token", "access_token", "refresh_token",
    "bearer", "private_key", "certificate"
}


def sanitize_metadata(data: Any) -> Any:
    """Recursively sanitize dictionary or list to redact sensitive information."""
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            if any(sensitive in k_lower for sensitive in SENSITIVE_KEYS):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = sanitize_metadata(v)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_metadata(item) for item in data]
    return data


class AuditService:
    @staticmethod
    def record(
        db: Session,
        event_type: str,
        action: str,
        resource_type: str,
        outcome: str = "SUCCESS",
        project_id: Optional[int] = None,
        actor_user_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        request_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[AuditEvent]:
        """
        Record an immutable audit event in the database.
        Metadata is strictly sanitized before persistence.
        """
        try:
            sanitized_meta = sanitize_metadata(metadata) if metadata else None
            event = AuditEvent(
                id=str(uuid.uuid4()),
                project_id=project_id,
                actor_user_id=actor_user_id,
                event_type=event_type,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                outcome=outcome,
                request_id=request_id,
                ip_address=ip_address,
                user_agent=user_agent,
                metadata_json=sanitized_meta,
                created_at=datetime.now(timezone.utc),
            )
            db.add(event)
            db.commit()
            db.refresh(event)
            return event
        except Exception as e:
            logger.error(f"Failed to record audit event: {e}", exc_info=True)
            db.rollback()
            return None


audit_service = AuditService()
