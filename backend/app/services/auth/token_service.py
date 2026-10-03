import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple
from sqlalchemy.orm import Session

from app.core.security import generate_api_token, hash_token, constant_time_compare
from app.models import ApiToken, User


class TokenService:
    @staticmethod
    def create_api_token(
        db: Session,
        user_id: str,
        name: str,
        expires_in_days: Optional[int] = None,
    ) -> Tuple[ApiToken, str]:
        """
        Create a new API token for a user.
        Returns (ApiToken model, raw_token_string).
        """
        raw_token, token_prefix, token_hash = generate_api_token()
        expires_at = None
        if expires_in_days is not None:
            expires_at = datetime.now(timezone.utc) + timedelta(days=expires_in_days)

        token = ApiToken(
            id=str(uuid.uuid4()),
            user_id=user_id,
            token_hash=token_hash,
            token_prefix=token_prefix,
            name=name,
            status="ACTIVE",
            expires_at=expires_at,
            created_at=datetime.now(timezone.utc),
        )
        db.add(token)
        db.commit()
        db.refresh(token)
        return token, raw_token

    @staticmethod
    def authenticate_token(
        db: Session,
        raw_token: str,
    ) -> Optional[Tuple[User, ApiToken]]:
        """
        Authenticate raw token using constant-time hash lookup and status checks.
        Returns (User, ApiToken) or None.
        """
        if not raw_token:
            return None

        computed_hash = hash_token(raw_token)
        token = db.query(ApiToken).filter(ApiToken.token_hash == computed_hash).first()
        if not token:
            return None

        # Constant time validation
        if not constant_time_compare(token.token_hash, computed_hash):
            return None

        if token.status != "ACTIVE":
            return None

        now = datetime.now(timezone.utc)
        if token.expires_at is not None:
            # Handle timezone awareness
            exp = token.expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp < now:
                return None

        user = db.query(User).filter(User.id == token.user_id, User.status == "ACTIVE").first()
        if not user:
            return None

        # Update last used / authenticated timestamps
        token.last_used_at = now
        user.last_authenticated_at = now
        db.commit()

        return user, token

    @staticmethod
    def revoke_token(db: Session, token_id: str, user_id: Optional[str] = None) -> bool:
        """Revoke an active API token."""
        query = db.query(ApiToken).filter(ApiToken.id == token_id)
        if user_id:
            query = query.filter(ApiToken.user_id == user_id)
        token = query.first()
        if not token:
            return False

        token.status = "REVOKED"
        token.revoked_at = datetime.now(timezone.utc)
        db.commit()
        return True

    @staticmethod
    def list_tokens(db: Session, user_id: str) -> List[ApiToken]:
        """List all tokens for a user."""
        return db.query(ApiToken).filter(ApiToken.user_id == user_id).order_by(ApiToken.created_at.desc()).all()


token_service = TokenService()
