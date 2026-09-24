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


DEMO_EXPIRED_TOKENS = {"demo-token-expired"}
DEMO_INVALID_TOKENS = {"demo-token-invalid"}


def get_current_demo_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    """Extract and validate bearer token for demo target."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Authentication required: Missing Authorization header")

    token = authorization.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    if token in DEMO_EXPIRED_TOKENS:
        raise HTTPException(status_code=401, detail="Token expired")

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


# ==============================================================================
# STAGE 6: Authentication Security Test Endpoints
# ==============================================================================

@demo_target_router.get(
    "/auth/protected",
    summary="[TEST ONLY] Secure Protected Endpoint",
    description="Correctly rejects missing, invalid, or expired tokens with HTTP 401.",
)
def demo_auth_protected(user: Dict[str, Any] = Depends(get_current_demo_user)):
    """
    Secure endpoint enforcing valid authentication:
    Returns 401 if missing Authorization header, expired token, or invalid token.
    Returns 200 OK with authenticated user context if valid.
    """
    return {
        "status": "authenticated",
        "message": "Access granted to secure protected resource",
        "user_id": user["id"],
        "user_name": user["name"],
        "role": user["role"],
    }


@demo_target_router.get(
    "/auth/vulnerable",
    summary="[TEST ONLY] Authentication Bypass Vulnerable Endpoint",
    description="Flawed endpoint: accepts requests with missing or invalid authentication and returns protected data.",
)
def demo_auth_vulnerable(authorization: Optional[str] = Header(None)):
    """
    Intentionally flawed endpoint:
    Fails to validate authentication credentials and grants access unconditionally,
    returning protected financial records and user details.
    """
    # Flawed: Does not enforce or validate token, returns protected records
    return {
        "status": "success",
        "authenticated": False,
        "access": "granted_unconditionally",
        "data": {
            "records": [
                {"id": "rec_001", "name": "Confidential Security Audit Report", "amount": 1499.00},
                {"id": "rec_002", "name": "Executive Compensation Data", "amount": 120000.00},
            ],
            "note": "Sensitive internal records leaked without authentication",
        },
    }


@demo_target_router.get(
    "/auth/soft-deny",
    summary="[TEST ONLY] Application-Level Soft Denial Endpoint",
    description="Returns HTTP 200 OK but body specifies authenticated: false and Unauthorized error.",
)
def demo_auth_soft_deny(authorization: Optional[str] = Header(None)):
    """
    Returns HTTP 200 OK with an application-level denial payload.
    Used to test that ResponseAnalyzer correctly identifies this as a rejection (PASS)
    rather than a false-positive bypass.
    """
    return {
        "error": "Unauthorized",
        "authenticated": False,
        "message": "Authentication required to access this resource",
        "code": 401,
    }


@demo_target_router.get(
    "/auth/error",
    summary="[TEST ONLY] Malformed Auth Crash Endpoint",
    description="Simulates unhandled backend exception (HTTP 500) when malformed Authorization header is supplied.",
)
def demo_auth_error(authorization: Optional[str] = Header(None)):
    """
    Endpoint that crashes with HTTP 500 when malformed authentication is supplied.
    If valid token is provided, returns 200.
    If header is missing, returns 401.
    If header is malformed (e.g. invalid scheme, garbage format, or missing Bearer prefix),
    raises an unhandled 500 error.
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Authentication required: Missing Authorization header")

    # Malformed check: if not starting with "Bearer " or empty token or contains malformed keyword
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=500, detail="Internal Server Error: Unhandled header format parsing crash")

    token = authorization[7:].strip()
    if not token or "malformed" in token.lower() or " " in token or token == "Bearer":
        raise HTTPException(status_code=500, detail="Internal Server Error: Unhandled token decoding crash on malformed input")

    if token in DEMO_EXPIRED_TOKENS:
        raise HTTPException(status_code=401, detail="Token expired")

    user = DEMO_USERS.get(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return {
        "status": "authenticated",
        "user_id": user["id"],
        "user_name": user["name"],
    }


@demo_target_router.get(
    "/auth/server-error",
    summary="[TEST ONLY] Unconditional Server Error Endpoint",
    description="Simulates 500 error to test INCONCLUSIVE classification in authentication testing.",
)
def demo_auth_server_error():
    raise HTTPException(status_code=500, detail="Internal Server Error: Database connection failure during auth verification")


# ==============================================================================
# STAGE 7.2: Stateful Workflow Test Endpoints (Orders Domain)
# ==============================================================================

DEFAULT_WORKFLOW_ORDERS: Dict[str, Dict[str, Any]] = {
    "order-valid-1": {"state": "CREATED", "vulnerable": False},
    "order-vuln-1": {"state": "CREATED", "vulnerable": True},
    "order-protected-1": {"state": "CANCELLED", "vulnerable": False},
}

DEMO_WORKFLOW_ORDERS: Dict[str, Dict[str, Any]] = {
    k: dict(v) for k, v in DEFAULT_WORKFLOW_ORDERS.items()
}


@demo_target_router.get(
    "/workflow/reset",
    summary="[TEST ONLY] Reset Workflow Test Orders",
    description="Resets the in-memory order states to their initial fixtures.",
)
def demo_workflow_reset():
    global DEMO_WORKFLOW_ORDERS
    DEMO_WORKFLOW_ORDERS = {k: dict(v) for k, v in DEFAULT_WORKFLOW_ORDERS.items()}
    return {"status": "reset", "orders": list(DEMO_WORKFLOW_ORDERS.keys())}


@demo_target_router.get(
    "/workflow/orders/{order_id}/status",
    summary="[TEST ONLY] Get Order Status",
    description="Returns current lifecycle state for an order.",
)
def demo_workflow_order_status(order_id: str):
    order = DEMO_WORKFLOW_ORDERS.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    return {"order_id": order_id, "state": order["state"]}


@demo_target_router.get(
    "/workflow/orders/{order_id}/cancel",
    summary="[TEST ONLY] Cancel Order Endpoint",
    description="Cancels an order if CREATED. If already CANCELLED, returns 409 Conflict (or 200 if vulnerable).",
)
def demo_workflow_order_cancel(order_id: str):
    order = DEMO_WORKFLOW_ORDERS.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    if order["state"] == "CREATED":
        order["state"] = "CANCELLED"
        return {"order_id": order_id, "state": "CANCELLED", "message": "Order cancelled successfully"}

    if order["state"] == "CANCELLED":
        if order.get("vulnerable"):
            return {"order_id": order_id, "state": "CANCELLED", "message": "Order re-cancelled (vulnerable)"}
        raise HTTPException(status_code=409, detail="Order is already cancelled")

    if order.get("vulnerable"):
        order["state"] = "CANCELLED"
        return {"order_id": order_id, "state": "CANCELLED"}
    raise HTTPException(status_code=409, detail=f"Cannot cancel order in state {order['state']}")


@demo_target_router.get(
    "/workflow/orders/{order_id}/refund",
    summary="[TEST ONLY] Refund Order Endpoint",
    description="Refunds an order if PAID. If CREATED/CANCELLED, returns 409 Conflict (or 200 if vulnerable logic flaw).",
)
def demo_workflow_order_refund(order_id: str):
    order = DEMO_WORKFLOW_ORDERS.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    if order["state"] == "PAID":
        order["state"] = "REFUNDED"
        return {"order_id": order_id, "state": "REFUNDED", "message": "Order refunded successfully"}

    # Disallowed transition from CREATED or CANCELLED to REFUNDED
    if order.get("vulnerable"):
        # Flawed logic: allows refund without verifying that the order was paid!
        order["state"] = "REFUNDED"
        return {
            "order_id": order_id,
            "state": "REFUNDED",
            "message": "Order refunded via flawed state validation bypass",
        }

    raise HTTPException(
        status_code=409,
        detail=f"Cannot refund order in state '{order['state']}'. Only PAID orders can be refunded.",
    )




