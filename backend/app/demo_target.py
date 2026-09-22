"""
==============================================================================
TEST ONLY - SentinelAPI Local Demonstration & Automated Testing Target
DO NOT USE IN PRODUCTION OR AGAINST REAL SYSTEMS
==============================================================================
This module provides an isolated, local FastAPI router intended strictly for
automated test execution and local development verification of Stage 3 BOLA.
"""

from fastapi import APIRouter, Header, HTTPException, Depends
from typing import Optional, Dict, Any

demo_target_router = APIRouter(prefix="/demo-target", tags=["TEST ONLY - Demo Target"])

# In-memory test fixtures
DEMO_USERS = {
    "demo-token-alice": {
        "id": "user_alice_001",
        "name": "Alice Victim",
        "role": "User",
    },
    "demo-token-bob": {
        "id": "user_bob_002",
        "name": "Bob Attacker",
        "role": "User",
    },
    "demo-token-admin": {
        "id": "admin_charlie_003",
        "name": "Charlie Admin",
        "role": "Admin",
    },
}

DEMO_ORDERS: Dict[str, Dict[str, Any]] = {
    "order_alice_101": {
        "order_id": "order_alice_101",
        "owner_id": "user_alice_001",
        "title": "Confidential Security Audit Report",
        "amount": 1499.00,
        "status": "completed",
        "notes": "Internal audit findings for Q3",
    },
    "order_bob_202": {
        "order_id": "order_bob_202",
        "owner_id": "user_bob_002",
        "title": "Public Developer Toolkit",
        "amount": 49.00,
        "status": "completed",
        "notes": "Standard developer package",
    },
}


def get_current_demo_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    """Extract and validate bearer token for demo target."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Authentication required: Missing Authorization header")

    token = authorization.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    user = DEMO_USERS.get(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return user


@demo_target_router.get(
    "/orders/{order_id}",
    summary="[TEST ONLY] Intentionally Vulnerable BOLA Endpoint",
    description="Authenticates the user but DOES NOT verify object ownership. Vulnerable to BOLA.",
)
def get_order_vulnerable(
    order_id: str,
    user: Dict[str, Any] = Depends(get_current_demo_user),
):
    """
    Intentionally vulnerable endpoint:
    Any authenticated user can read any order by ID regardless of owner.
    """
    order = DEMO_ORDERS.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    return order


@demo_target_router.get(
    "/protected-orders/{order_id}",
    summary="[TEST ONLY] Correctly Protected Object-Level Endpoint",
    description="Authenticates the user AND verifies object ownership before returning data.",
)
def get_order_protected(
    order_id: str,
    user: Dict[str, Any] = Depends(get_current_demo_user),
):
    """
    Secure endpoint:
    Validates that the authenticated user is the owner of the requested order.
    """
    order = DEMO_ORDERS.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    if order["owner_id"] != user["id"]:
        raise HTTPException(
            status_code=403,
            detail="Access forbidden: you do not have permission to view this order.",
        )

    return order


@demo_target_router.get(
    "/error-orders/{order_id}",
    summary="[TEST ONLY] Simulated Server Error Endpoint",
    description="Simulates 500 error to test INCONCLUSIVE classification.",
)
def get_order_server_error(
    order_id: str,
    user: Dict[str, Any] = Depends(get_current_demo_user),
):
    """Simulates an internal server error for inconclusive test verification."""
    raise HTTPException(status_code=500, detail="Internal server error")


# ==============================================================================
# STAGE 4: BFLA / Function-Level Test Endpoints
# ==============================================================================

@demo_target_router.get(
    "/admin/system-stats",
    summary="[TEST ONLY] Vulnerable BFLA Admin Endpoint",
    description="Requires authentication but DOES NOT verify Admin role. Any user can access.",
)
def get_system_stats_vulnerable(
    user: Dict[str, Any] = Depends(get_current_demo_user),
):
    """
    Intentionally vulnerable BFLA endpoint:
    Returns privileged administrative metrics to any authenticated user.
    """
    return {
        "status": "healthy",
        "total_users": 1500,
        "active_sessions": 42,
        "admin_keys": ["key_root_prod_001"],
        "secret_token": "cluster_secret_xyz987",
        "requested_by_user": user["name"],
        "caller_role": user["role"],
    }


@demo_target_router.get(
    "/admin/protected-system-stats",
    summary="[TEST ONLY] Properly Protected BFLA Admin Endpoint",
    description="Verifies that the caller has the 'Admin' role before returning data.",
)
def get_system_stats_protected(
    user: Dict[str, Any] = Depends(get_current_demo_user),
):
    """
    Secure endpoint:
    Checks if caller role is Admin.
    """
    if user.get("role") != "Admin":
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Administrative privileges required.",
        )
    return {
        "status": "healthy",
        "total_users": 1500,
        "active_sessions": 42,
        "admin_keys": ["key_root_prod_001"],
    }


@demo_target_router.get(
    "/admin/error-stats",
    summary="[TEST ONLY] Simulated BFLA Server Error Endpoint",
    description="Simulates 500 server error on admin endpoint.",
)
def get_system_stats_error(
    user: Dict[str, Any] = Depends(get_current_demo_user),
):
    """Simulates an internal server error on admin function."""
    raise HTTPException(status_code=500, detail="Administrative service failure")


# ==============================================================================
# STAGE 5: Property-Level Authorization Test Endpoints
# ==============================================================================

DEMO_USER_PROFILES = {
    "user_alice_001": {
        "id": "user_alice_001",
        "name": "Alice Victim",
        "email": "alice@example.com",
        "role": "User",
        "internal_notes": "VIP Customer with privileged SLA",
    },
    "user_bob_002": {
        "id": "user_bob_002",
        "name": "Bob Attacker",
        "email": "bob@example.com",
        "role": "User",
        "internal_notes": "Standard trial account flagged for audit",
    },
}


@demo_target_router.get(
    "/users/{user_id}",
    summary="[TEST ONLY] User Profile Property Exposure Endpoint",
    description="Returns full user object with role and internal_notes. Intended for testing property exposure.",
)
def get_user_profile(
    user_id: str,
    user: Dict[str, Any] = Depends(get_current_demo_user),
):
    """
    Intentionally exposes all fields (id, name, email, role, internal_notes)
    regardless of whether the caller's role is allowed to see role or internal_notes.
    """
    profile = DEMO_USER_PROFILES.get(user_id)
    if not profile:
        profile = {
            "id": user_id,
            "name": f"User {user_id}",
            "email": f"{user_id}@example.com",
            "role": "User",
            "internal_notes": f"Confidential internal notes for {user_id}",
        }
    return profile


@demo_target_router.get(
    "/filtered-users/{user_id}",
    summary="[TEST ONLY] Properly Filtered User Profile Endpoint",
    description="Filters protected properties (role, internal_notes) if caller is not Admin.",
)
def get_user_profile_filtered(
    user_id: str,
    user: Dict[str, Any] = Depends(get_current_demo_user),
):
    """
    Secure endpoint:
    Omits 'role' and 'internal_notes' for non-Admin callers.
    """
    profile = DEMO_USER_PROFILES.get(user_id)
    if not profile:
        profile = {
            "id": user_id,
            "name": f"User {user_id}",
            "email": f"{user_id}@example.com",
            "role": "User",
            "internal_notes": f"Confidential internal notes for {user_id}",
        }

    if user.get("role") != "Admin":
        return {
            "id": profile["id"],
            "name": profile["name"],
            "email": profile["email"],
        }
    return profile

