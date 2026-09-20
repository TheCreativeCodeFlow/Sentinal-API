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
