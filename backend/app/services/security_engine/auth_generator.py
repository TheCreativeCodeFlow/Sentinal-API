import json
from typing import List, Optional, Tuple
from sqlalchemy.orm import Session

from app.models import (
    Project,
    Endpoint,
    Identity,
    SecurityTest,
    AuthenticationPolicy,
)


AUTH_TEST_TYPES = [
    "AUTH_MISSING",
    "AUTH_INVALID",
    "AUTH_MALFORMED",
    "AUTH_EXPIRED",
    "AUTH_SCHEME",
]


class AuthenticationTestGenerator:
    """
    Controlled Authentication Security Test Generator.
    Inspects project endpoints, authentication policies, and OpenAPI security configurations
    to generate comprehensive test suites (AUTH_MISSING, AUTH_INVALID, AUTH_MALFORMED,
    AUTH_EXPIRED, AUTH_SCHEME) using safe GET/HEAD requests.
    """

    @classmethod
    def generate_tests(
        cls,
        db: Session,
        project_id: int,
        endpoint_ids: Optional[List[int]] = None,
    ) -> Tuple[List[SecurityTest], int]:
        """
        Generates safe Authentication SecurityTest records for protected project endpoints.
        Returns: (created_tests: List[SecurityTest], skipped_count: int)
        """
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project or project.authorization_status.lower() != "authorized":
            raise ValueError("Target project is not authorized for security testing.")

        # 1. Fetch safe endpoints (GET and HEAD only)
        endpoint_query = db.query(Endpoint).join(Endpoint.api).filter(
            Endpoint.api.has(project_id=project_id),
            Endpoint.method.in_(["GET", "HEAD"]),
        )
        if endpoint_ids:
            endpoint_query = endpoint_query.filter(Endpoint.id.in_(endpoint_ids))
        safe_endpoints = endpoint_query.all()

        if not safe_endpoints:
            return [], 0

        # 2. Fetch default identity for attribution if present
        default_identity = (
            db.query(Identity)
            .filter(Identity.project_id == project_id)
            .order_by(Identity.created_at.asc())
            .first()
        )
        attacker_id = default_identity.id if default_identity else None

        # 3. Existing tests map to avoid duplicates
        existing_tests = (
            db.query(SecurityTest)
            .filter(
                SecurityTest.project_id == project_id,
                SecurityTest.test_type.in_(AUTH_TEST_TYPES),
            )
            .all()
        )
        existing_keys = {(t.endpoint_id, t.test_type) for t in existing_tests}

        # 4. Fetch all policies for the project
        policies = {
            p.endpoint_id: p
            for p in db.query(AuthenticationPolicy).filter(AuthenticationPolicy.project_id == project_id).all()
        }

        created_tests: List[SecurityTest] = []
        skipped_count = 0

        for ep in safe_endpoints:
            policy = policies.get(ep.id)
            # Check if authentication is required (default is True unless explicitly set False)
            if policy and not policy.authentication_required:
                continue

            auth_scheme = policy.authentication_scheme if policy else "bearer_token"

            for t_type in AUTH_TEST_TYPES:
                key = (ep.id, t_type)
                if key in existing_keys:
                    skipped_count += 1
                    continue

                test_config = {
                    "test_type": t_type,
                    "auth_scheme": auth_scheme,
                    "expected_denial_status": policy.expected_denial_status if policy else 401,
                }
                if t_type == "AUTH_EXPIRED":
                    test_config["expired_token"] = "demo-token-expired"
                elif t_type == "AUTH_INVALID":
                    test_config["invalid_token"] = "invalid-token-forged-9999"

                sec_test = SecurityTest(
                    project_id=project_id,
                    endpoint_id=ep.id,
                    test_type=t_type,
                    attacker_identity_id=attacker_id,
                    expected_access="DENY",
                    status="configured",
                    configuration=json.dumps(test_config),
                )
                db.add(sec_test)
                created_tests.append(sec_test)
                existing_keys.add(key)

        if created_tests:
            db.commit()
            for t in created_tests:
                db.refresh(t)

        return created_tests, skipped_count
