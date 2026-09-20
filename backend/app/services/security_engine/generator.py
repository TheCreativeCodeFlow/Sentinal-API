import json
from typing import List, Optional, Tuple
from sqlalchemy.orm import Session

from app.models import (
    Project,
    Endpoint,
    Identity,
    Role,
    SecurityTest,
    AuthorizationMatrixRule,
    EndpointAuthorizationPolicy,
)


class BFLATestGenerator:
    """
    Controlled BFLA Security Test Generator.
    Analyzes project endpoints, roles, identities, policies, and matrix rules to generate
    meaningful function-level authorization tests using ONLY safe GET/HEAD methods.
    """

    @classmethod
    def generate_tests(
        cls,
        db: Session,
        project_id: int,
        endpoint_ids: Optional[List[int]] = None,
    ) -> Tuple[List[SecurityTest], int]:
        """
        Generates safe BFLA SecurityTest records for candidate authorization boundary combinations.
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

        # 2. Fetch project identities and roles
        identities = db.query(Identity).filter(Identity.project_id == project_id).all()
        roles = db.query(Role).filter(Role.project_id == project_id).all()

        if not identities:
            return [], 0

        # Group identities by role_id
        identities_by_role = {}
        for ident in identities:
            identities_by_role.setdefault(ident.role_id, []).append(ident)

        created_tests: List[SecurityTest] = []
        skipped_count = 0

        # 3. Existing tests set to prevent duplicate generation
        existing_tests = db.query(SecurityTest).filter(
            SecurityTest.project_id == project_id,
            SecurityTest.test_type == "BFLA",
        ).all()
        existing_keys = {
            (t.endpoint_id, t.attacker_identity_id) for t in existing_tests
        }

        # 4. Generate candidate pairs:
        # Strategy A: Explicit DENY matrix rules
        rules = (
            db.query(AuthorizationMatrixRule)
            .filter(
                AuthorizationMatrixRule.project_id == project_id,
                AuthorizationMatrixRule.expected_access == "DENY",
                AuthorizationMatrixRule.http_method.in_(["GET", "HEAD"]),
            )
            .all()
        )

        for rule in rules:
            endpoint = next((ep for ep in safe_endpoints if ep.id == rule.endpoint_id), None)
            if not endpoint:
                continue

            # Find matching identity
            candidate_identities = identities_by_role.get(rule.role_id, [])
            if not candidate_identities:
                continue

            attacker = candidate_identities[0]
            key = (endpoint.id, attacker.id)
            if key in existing_keys:
                skipped_count += 1
                continue

            test = SecurityTest(
                project_id=project_id,
                endpoint_id=endpoint.id,
                test_type="BFLA",
                attacker_identity_id=attacker.id,
                expected_access="DENY",
                status="configured",
                configuration=json.dumps({
                    "generated_by": "bfla_generator",
                    "reason": f"Matrix rule specifies role '{attacker.role.name if attacker.role else 'User'}' is DENIED access.",
                }),
            )
            db.add(test)
            existing_keys.add(key)
            created_tests.append(test)

        # Strategy B: Endpoint Authorization Policy denied roles
        policies = (
            db.query(EndpointAuthorizationPolicy)
            .filter(EndpointAuthorizationPolicy.project_id == project_id)
            .all()
        )

        for policy in policies:
            endpoint = next((ep for ep in safe_endpoints if ep.id == policy.endpoint_id), None)
            if not endpoint:
                continue

            for denied_role in policy.denied_roles:
                candidate_identities = identities_by_role.get(denied_role.id, [])
                if not candidate_identities:
                    continue

                attacker = candidate_identities[0]
                key = (endpoint.id, attacker.id)
                if key in existing_keys:
                    skipped_count += 1
                    continue

                test = SecurityTest(
                    project_id=project_id,
                    endpoint_id=endpoint.id,
                    test_type="BFLA",
                    attacker_identity_id=attacker.id,
                    expected_access="DENY",
                    status="configured",
                    configuration=json.dumps({
                        "generated_by": "bfla_generator",
                        "reason": f"Endpoint policy explicitly denies access to role '{denied_role.name}'.",
                    }),
                )
                db.add(test)
                existing_keys.add(key)
                created_tests.append(test)

        # Strategy C: Privileged/admin endpoint heuristics
        # If an endpoint has '/admin', '/system', '/internal' in path, and we have non-admin identities
        admin_keywords = ["admin", "internal", "system", "management", "config"]
        for endpoint in safe_endpoints:
            path_lower = endpoint.path.lower()
            if any(kw in path_lower for kw in admin_keywords):
                # Pick a non-admin identity
                for ident in identities:
                    role_name = ident.role.name.lower() if ident.role else ""
                    if "admin" not in role_name:
                        key = (endpoint.id, ident.id)
                        if key in existing_keys:
                            skipped_count += 1
                            continue

                        test = SecurityTest(
                            project_id=project_id,
                            endpoint_id=endpoint.id,
                            test_type="BFLA",
                            attacker_identity_id=ident.id,
                            expected_access="DENY",
                            status="configured",
                            configuration=json.dumps({
                                "generated_by": "bfla_generator",
                                "reason": f"Privileged endpoint boundary: low-privilege identity '{ident.name}' accessing administrative function.",
                            }),
                        )
                        db.add(test)
                        existing_keys.add(key)
                        created_tests.append(test)
                        break  # One non-admin per endpoint is sufficient for boundary verification

        if created_tests:
            db.commit()
            for t in created_tests:
                db.refresh(t)

        return created_tests, skipped_count
