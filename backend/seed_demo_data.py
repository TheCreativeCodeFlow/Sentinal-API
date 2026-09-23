"""
Seed script to populate a rich demo environment in sentinel.db for manual testing.
Run: python3 seed_demo_data.py
"""

import json
from datetime import datetime, timezone
from app.core.db import get_db, create_tables
from app.models import (
    Project,
    API,
    Endpoint,
    Role,
    Identity,
    Resource,
    ResourceOwnership,
    ResourceProperty,
    PropertyAuthorizationRule,
    AuthorizationMatrixRule,
    EndpointAuthorizationPolicy,
    AuthenticationPolicy,
    SecurityTest,
)


def seed():
    create_tables()
    db = get_db()

    # Check if demo project already exists
    existing = db.query(Project).filter(Project.name == "Demo Target API (Sentinel Local)").first()
    if existing:
        print(f"Demo project already exists with ID: {existing.id}")
        return existing.id

    now = datetime.now(timezone.utc)

    # 1. Project
    project = Project(
        name="Demo Target API (Sentinel Local)",
        description="Comprehensive testbed showcasing BOLA, BFLA, Property Exposure, and Authentication security vulnerabilities.",
        environment="development",
        base_url="http://127.0.0.1:8000",
        authorization_status="authorized",
        created_at=now,
        updated_at=now,
    )
    db.add(project)
    db.flush()

    # 2. API
    api = API(
        project_id=project.id,
        name="Demo Target API",
        title="Sentinel Demo Target API",
        version="1.0.0",
        created_at=now,
        updated_at=now,
    )
    db.add(api)
    db.flush()

    # 3. Roles
    admin_role = Role(
        project_id=project.id,
        name="Admin",
        description="Full administrative access to all system APIs and operations",
        created_at=now,
        updated_at=now,
    )
    user_role = Role(
        project_id=project.id,
        name="User",
        description="Standard end-user with restricted self-service access",
        created_at=now,
        updated_at=now,
    )
    auditor_role = Role(
        project_id=project.id,
        name="Auditor",
        description="Compliance reviewer with read-only audit access",
        created_at=now,
        updated_at=now,
    )
    db.add_all([admin_role, user_role, auditor_role])
    db.flush()

    # 4. Identities
    alice = Identity(
        project_id=project.id,
        role_id=user_role.id,
        name="Alice (Victim User)",
        auth_type="bearer_token",
        credential_value=json.dumps({"token": "demo-token-alice"}),
        created_at=now,
        updated_at=now,
    )
    bob = Identity(
        project_id=project.id,
        role_id=user_role.id,
        name="Bob (Attacker User)",
        auth_type="bearer_token",
        credential_value=json.dumps({"token": "demo-token-bob"}),
        created_at=now,
        updated_at=now,
    )
    charlie = Identity(
        project_id=project.id,
        role_id=admin_role.id,
        name="Charlie (System Admin)",
        auth_type="bearer_token",
        credential_value=json.dumps({"token": "demo-token-admin"}),
        created_at=now,
        updated_at=now,
    )
    db.add_all([alice, bob, charlie])
    db.flush()

    # 5. Resources
    order_res = Resource(
        project_id=project.id,
        name="Order",
        description="Customer purchase orders",
        created_at=now,
        updated_at=now,
    )
    user_res = Resource(
        project_id=project.id,
        name="UserProfile",
        description="User account profiles containing personal data",
        created_at=now,
        updated_at=now,
    )
    db.add_all([order_res, user_res])
    db.flush()

    # Resource Ownerships
    db.add_all([
        ResourceOwnership(
            resource_id=order_res.id,
            identity_id=alice.id,
            resource_instance_id="order_alice_101",
            description="Alice confidential audit order",
            created_at=now,
            updated_at=now,
        ),
        ResourceOwnership(
            resource_id=order_res.id,
            identity_id=bob.id,
            resource_instance_id="order_bob_202",
            description="Bob standard developer order",
            created_at=now,
            updated_at=now,
        ),
        ResourceOwnership(
            resource_id=user_res.id,
            identity_id=alice.id,
            resource_instance_id="user_alice_001",
            description="Alice profile",
            created_at=now,
            updated_at=now,
        ),
        ResourceOwnership(
            resource_id=user_res.id,
            identity_id=bob.id,
            resource_instance_id="user_bob_002",
            description="Bob profile",
            created_at=now,
            updated_at=now,
        ),
    ])

    # Resource Properties for UserProfile
    prop_name = ResourceProperty(
        resource_id=user_res.id,
        name="name",
        data_type="string",
        sensitivity="PUBLIC",
        description="Display name",
        created_at=now,
        updated_at=now,
    )
    prop_email = ResourceProperty(
        resource_id=user_res.id,
        name="email",
        data_type="string",
        sensitivity="INTERNAL",
        description="Email address",
        created_at=now,
        updated_at=now,
    )
    prop_salary = ResourceProperty(
        resource_id=user_res.id,
        name="salary",
        data_type="number",
        sensitivity="SECRET",
        description="Confidential annual salary",
        created_at=now,
        updated_at=now,
    )
    prop_ssn = ResourceProperty(
        resource_id=user_res.id,
        name="ssn",
        data_type="string",
        sensitivity="SECRET",
        description="Social security number",
        created_at=now,
        updated_at=now,
    )
    db.add_all([prop_name, prop_email, prop_salary, prop_ssn])
    db.flush()

    # Property Authorization Rules: Deny salary & SSN to standard User role
    db.add_all([
        PropertyAuthorizationRule(
            resource_property_id=prop_salary.id,
            role_id=user_role.id,
            access="DENY",
            created_at=now,
            updated_at=now,
        ),
        PropertyAuthorizationRule(
            resource_property_id=prop_ssn.id,
            role_id=user_role.id,
            access="DENY",
            created_at=now,
            updated_at=now,
        ),
    ])

    # 6. Endpoints
    ep_bola_vuln = Endpoint(
        api_id=api.id,
        path="/demo-target/orders/{order_id}",
        method="GET",
        summary="[VULNERABLE BOLA] Retrieve order by ID without owner check",
        resource_id=order_res.id,
        created_at=now,
    )
    ep_bola_prot = Endpoint(
        api_id=api.id,
        path="/demo-target/protected-orders/{order_id}",
        method="GET",
        summary="[SECURE] Retrieve order with strict ownership validation",
        resource_id=order_res.id,
        created_at=now,
    )
    ep_bfla_vuln = Endpoint(
        api_id=api.id,
        path="/demo-target/admin/system-stats",
        method="GET",
        summary="[VULNERABLE BFLA] Admin system metrics without role check",
        created_at=now,
    )
    ep_bfla_prot = Endpoint(
        api_id=api.id,
        path="/demo-target/admin/protected-system-stats",
        method="GET",
        summary="[SECURE] Admin metrics with role check",
        created_at=now,
    )
    ep_prop_vuln = Endpoint(
        api_id=api.id,
        path="/demo-target/users/{user_id}",
        method="GET",
        summary="[VULNERABLE PROPERTY] User profile returning salary and SSN",
        resource_id=user_res.id,
        created_at=now,
    )
    ep_auth_prot = Endpoint(
        api_id=api.id,
        path="/demo-target/auth/protected",
        method="GET",
        summary="[SECURE AUTH] Enforces valid Bearer token",
        created_at=now,
    )
    ep_auth_vuln = Endpoint(
        api_id=api.id,
        path="/demo-target/auth/vulnerable",
        method="GET",
        summary="[VULNERABLE AUTH] No authentication guard on protected customer data",
        created_at=now,
    )
    ep_auth_soft = Endpoint(
        api_id=api.id,
        path="/demo-target/auth/soft-deny",
        method="GET",
        summary="[SOFT DENY] Returns HTTP 200 with application denial body",
        created_at=now,
    )
    ep_auth_err = Endpoint(
        api_id=api.id,
        path="/demo-target/auth/error",
        method="GET",
        summary="[CRASH ON MALFORMED] Crashes with 500 when malformed header received",
        created_at=now,
    )

    all_eps = [
        ep_bola_vuln,
        ep_bola_prot,
        ep_bfla_vuln,
        ep_bfla_prot,
        ep_prop_vuln,
        ep_auth_prot,
        ep_auth_vuln,
        ep_auth_soft,
        ep_auth_err,
    ]
    db.add_all(all_eps)
    db.flush()

    # 7. Authorization Matrix & Policies
    db.add(
        AuthorizationMatrixRule(
            project_id=project.id,
            role_id=user_role.id,
            endpoint_id=ep_bfla_vuln.id,
            http_method="GET",
            expected_access="DENY",
            created_at=now,
            updated_at=now,
        )
    )
    db.add(
        AuthorizationMatrixRule(
            project_id=project.id,
            role_id=admin_role.id,
            endpoint_id=ep_bfla_vuln.id,
            http_method="GET",
            expected_access="ALLOW",
            created_at=now,
            updated_at=now,
        )
    )

    # Authentication Policies
    for ep in [ep_auth_prot, ep_auth_vuln, ep_auth_soft, ep_auth_err]:
        db.add(
            AuthenticationPolicy(
                project_id=project.id,
                endpoint_id=ep.id,
                authentication_required=True,
                authentication_scheme="bearer_token",
                expected_denial_status=401,
                notes="Protected demo endpoint requiring Bearer token",
                created_at=now,
                updated_at=now,
            )
        )
    db.flush()

    # 8. Pre-configured Security Tests
    db.add_all([
        SecurityTest(
            project_id=project.id,
            endpoint_id=ep_bola_vuln.id,
            test_type="BOLA",
            attacker_identity_id=bob.id,
            victim_identity_id=alice.id,
            victim_resource_id=order_res.id,
            victim_resource_instance_id="order_alice_101",
            attacker_resource_instance_id="order_bob_202",
            expected_access="DENY",
            status="CONFIGURED",
            created_at=now,
            updated_at=now,
        ),
        SecurityTest(
            project_id=project.id,
            endpoint_id=ep_bfla_vuln.id,
            test_type="BFLA",
            attacker_identity_id=bob.id,
            expected_access="DENY",
            status="CONFIGURED",
            created_at=now,
            updated_at=now,
        ),
        SecurityTest(
            project_id=project.id,
            endpoint_id=ep_prop_vuln.id,
            test_type="PROPERTY_EXPOSURE",
            attacker_identity_id=bob.id,
            victim_resource_id=user_res.id,
            victim_resource_instance_id="user_alice_001",
            expected_access="DENY",
            status="CONFIGURED",
            created_at=now,
            updated_at=now,
        ),
        SecurityTest(
            project_id=project.id,
            endpoint_id=ep_auth_vuln.id,
            test_type="AUTH_MISSING",
            attacker_identity_id=None,
            expected_access="DENY",
            status="CONFIGURED",
            created_at=now,
            updated_at=now,
        ),
        SecurityTest(
            project_id=project.id,
            endpoint_id=ep_auth_err.id,
            test_type="AUTH_MALFORMED",
            attacker_identity_id=bob.id,
            expected_access="DENY",
            status="CONFIGURED",
            created_at=now,
            updated_at=now,
        ),
        SecurityTest(
            project_id=project.id,
            endpoint_id=ep_auth_prot.id,
            test_type="AUTH_MISSING",
            attacker_identity_id=None,
            expected_access="DENY",
            status="CONFIGURED",
            created_at=now,
            updated_at=now,
        ),
    ])

    db.commit()
    print(f"Successfully seeded demo project '{project.name}' (ID: {project.id}) with {len(all_eps)} endpoints, 3 identities, 2 resources, and 6 security tests.")
    return project.id


if __name__ == "__main__":
    seed()
