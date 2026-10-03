import hashlib
import secrets
from typing import Tuple


def hash_token(raw_token: str) -> str:
    """Generate SHA-256 hash of raw token."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def generate_api_token() -> Tuple[str, str, str]:
    """
    Generate a cryptographically secure API token.
    Returns:
        (raw_token, token_prefix, token_hash)
    """
    raw_token = f"sent_{secrets.token_urlsafe(32)}"
    token_prefix = raw_token[:12]
    token_hash = hash_token(raw_token)
    return raw_token, token_prefix, token_hash


def verify_token_hash(raw_token: str, stored_hash: str) -> bool:
    """Constant-time verification of token against stored SHA-256 hash."""
    computed_hash = hash_token(raw_token)
    return secrets.compare_digest(computed_hash, stored_hash)


def constant_time_compare(val1: str, val2: str) -> bool:
    """Constant-time comparison between two strings."""
    return secrets.compare_digest(val1, val2)
