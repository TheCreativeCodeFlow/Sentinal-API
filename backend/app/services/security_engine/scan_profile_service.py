"""
Stage 10.2: Scan Profile Service
Author: SentinelAPI Security Architecture Team

Deterministic scan profile management and test selection engine.
Features:
- Project-scoped ScanProfile domain management (QUICK, STANDARD, DEEP, CUSTOM).
- Deterministic test selection from project security models, authorization policies, endpoints, and workflows.
- Strictly read-only preview mode (zero target HTTP execution).
- Seamless creation of SecurityExecutionPlan rows tied to profiles.
- Strict project isolation and duplicate name prevention.
"""

from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.models import (
    Project,
    ScanProfile,
    SecurityTest,
    SecurityExecutionPlan,
    SecurityExecutionItem,
    EndpointAuthorizationPolicy,
    AuthenticationPolicy,
    AuthorizationMatrixRule,
)


class ScanProfileError(Exception):
    """Base exception for scan profile errors."""
    pass


class ProfileNotFoundError(ScanProfileError):
    """Raised when a scan profile is not found."""
    pass


class DuplicateProfileError(ScanProfileError):
    """Raised when a scan profile name conflicts within the same project."""
    pass


class DisabledProfileError(ScanProfileError):
    """Raised when attempting to plan or execute from a disabled profile."""
    pass


class CrossProjectViolationError(ScanProfileError):
    """Raised when accessing a scan profile from an unauthorized project."""
    pass


class ScanProfileService:
    """
    Deterministic management and test selection service for Scan Profiles.
    """
    __test__ = False

    def __init__(self, db: Session):
        self.db = db

    # =========================================================================
    # Scan Profile CRUD
    # =========================================================================

    def create_profile(
        self,
        project_id: int,
        name: str,
        profile_type: str = "STANDARD",
        description: Optional[str] = None,
        configuration: Optional[Dict[str, Any]] = None,
        status: str = "ACTIVE",
    ) -> ScanProfile:
        """Create a new scan profile within a project."""
        project = self.db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise ProfileNotFoundError(f"Project with ID {project_id} not found.")

        p_name = name.strip()
        existing = (
            self.db.query(ScanProfile)
            .filter(ScanProfile.project_id == project_id, ScanProfile.name == p_name)
            .first()
        )
        if existing:
            raise DuplicateProfileError(
                f"A scan profile named '{p_name}' already exists in project {project_id}."
            )

        p_type = profile_type.upper() if profile_type else "STANDARD"
        if p_type not in ("QUICK", "STANDARD", "DEEP", "CUSTOM"):
            p_type = "STANDARD"

        p_status = status.upper() if status else "ACTIVE"
        if p_status not in ("ACTIVE", "DISABLED"):
            p_status = "ACTIVE"

        profile = ScanProfile(
            project_id=project_id,
            name=p_name,
            description=description.strip() if description else None,
            profile_type=p_type,
            status=p_status,
            configuration=configuration or {},
        )
        self.db.add(profile)
        try:
            self.db.commit()
            self.db.refresh(profile)
        except IntegrityError:
            self.db.rollback()
            raise DuplicateProfileError(
                f"A scan profile named '{p_name}' already exists in project {project_id}."
            )

        return profile

    def get_profile(
        self,
        profile_id: str,
        project_id: Optional[int] = None,
    ) -> Optional[ScanProfile]:
        """Fetch a scan profile and verify cross-project isolation if project_id is given."""
        profile = self.db.query(ScanProfile).filter(ScanProfile.id == profile_id).first()
        if not profile:
            return None

        if project_id is not None and profile.project_id != project_id:
            raise CrossProjectViolationError(
                f"Scan profile '{profile_id}' belongs to project {profile.project_id}, not {project_id}."
            )

        return profile

    def list_profiles(
        self,
        project_id: int,
        status: Optional[str] = None,
        profile_type: Optional[str] = None,
    ) -> List[ScanProfile]:
        """List all scan profiles for a project with optional filtering."""
        query = self.db.query(ScanProfile).filter(ScanProfile.project_id == project_id)
        if status:
            query = query.filter(ScanProfile.status == status.upper())
        if profile_type:
            query = query.filter(ScanProfile.profile_type == profile_type.upper())
        return query.order_by(ScanProfile.created_at.desc()).all()

    def update_profile(
        self,
        profile_id: str,
        project_id: Optional[int] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        profile_type: Optional[str] = None,
        status: Optional[str] = None,
        configuration: Optional[Dict[str, Any]] = None,
    ) -> ScanProfile:
        """Update an existing scan profile."""
        profile = self.get_profile(profile_id, project_id=project_id)
        if not profile:
            raise ProfileNotFoundError(f"Scan profile with ID {profile_id} not found.")

        if name is not None:
            clean_name = name.strip()
            if clean_name != profile.name:
                existing = (
                    self.db.query(ScanProfile)
                    .filter(
                        ScanProfile.project_id == profile.project_id,
                        ScanProfile.name == clean_name,
                        ScanProfile.id != profile_id,
                    )
                    .first()
                )
                if existing:
                    raise DuplicateProfileError(
                        f"A scan profile named '{clean_name}' already exists in project {profile.project_id}."
                    )
                profile.name = clean_name

        if description is not None:
            profile.description = description.strip() if description else None

        if profile_type is not None:
            p_type = profile_type.upper()
            if p_type in ("QUICK", "STANDARD", "DEEP", "CUSTOM"):
                profile.profile_type = p_type

        if status is not None:
            p_status = status.upper()
            if p_status in ("ACTIVE", "DISABLED"):
                profile.status = p_status

        if configuration is not None:
            profile.configuration = configuration

        try:
            self.db.commit()
            self.db.refresh(profile)
        except IntegrityError:
            self.db.rollback()
            raise DuplicateProfileError(
                f"A scan profile named '{profile.name}' already exists in project {profile.project_id}."
            )

        return profile

    def delete_profile(
        self,
        profile_id: str,
        project_id: Optional[int] = None,
    ) -> bool:
        """Delete a scan profile."""
        profile = self.get_profile(profile_id, project_id=project_id)
        if not profile:
            raise ProfileNotFoundError(f"Scan profile with ID {profile_id} not found.")

        self.db.delete(profile)
        self.db.commit()
        return True

    # =========================================================================
    # Profile Test Selection Heuristics (Deterministic & Read-Only)
    # =========================================================================

    def select_tests_for_profile(
        self,
        profile: ScanProfile,
    ) -> List[Dict[str, Any]]:
        """
        Deterministically selects SecurityTest configurations for a profile.
        CRITICAL ARCHITECTURAL RULE:
        Zero target HTTP requests. This method is strictly read-only and queries
        the existing project model and security test inventory.
        """
        project_id = profile.project_id
        config = profile.configuration or {}
        p_type = profile.profile_type.upper()

        # Query all security tests in the project
        all_tests = (
            self.db.query(SecurityTest)
            .filter(SecurityTest.project_id == project_id)
            .all()
        )

        selected: List[Dict[str, Any]] = []

        # Categorization helpers
        def is_auth_test(t: SecurityTest) -> bool:
            return (t.test_type or "").startswith("AUTH_")

        def is_access_control_test(t: SecurityTest) -> bool:
            return (t.test_type or "") in ("BOLA", "BFLA")

        def is_property_test(t: SecurityTest) -> bool:
            return (t.test_type or "").startswith("PROPERTY_")

        def is_workflow_test(t: SecurityTest) -> bool:
            return (t.test_type or "").startswith("WORKFLOW_")

        for test in all_tests:
            ep_path = test.endpoint.path if test.endpoint else "Unknown Endpoint"
            res_name = test.victim_resource.name if getattr(test, "victim_resource", None) else "Resource"
            wf_name = "Workflow"

            # 1. QUICK Profile:
            # - Prioritize authentication and authorization (BOLA, BFLA)
            # - Exclude deep property exposures and multi-step workflow attacks
            if p_type == "QUICK":
                if is_auth_test(test):
                    selected.append({
                        "security_test_id": test.id,
                        "test_type": test.test_type,
                        "endpoint": ep_path,
                        "priority": 10,
                        "reason": f"QUICK profile prioritized authentication check on endpoint '{ep_path}'",
                        "test_obj": test,
                    })
                elif is_access_control_test(test):
                    selected.append({
                        "security_test_id": test.id,
                        "test_type": test.test_type,
                        "endpoint": ep_path,
                        "priority": 20,
                        "reason": f"QUICK profile prioritized {test.test_type} authorization check on endpoint '{ep_path}'",
                        "test_obj": test,
                    })

            # 2. STANDARD Profile:
            # - Include QUICK tests
            # - Include property exposure tests
            # - Include standard workflow scenarios (step skip, state bypass)
            # - Exclude complex deep attacks (replay, identity switch)
            elif p_type == "STANDARD":
                if is_auth_test(test):
                    selected.append({
                        "security_test_id": test.id,
                        "test_type": test.test_type,
                        "endpoint": ep_path,
                        "priority": 10,
                        "reason": f"STANDARD profile verified authentication boundary on endpoint '{ep_path}'",
                        "test_obj": test,
                    })
                elif is_access_control_test(test):
                    selected.append({
                        "security_test_id": test.id,
                        "test_type": test.test_type,
                        "endpoint": ep_path,
                        "priority": 20,
                        "reason": f"STANDARD profile verified {test.test_type} access control on endpoint '{ep_path}'",
                        "test_obj": test,
                    })
                elif is_property_test(test):
                    selected.append({
                        "security_test_id": test.id,
                        "test_type": test.test_type,
                        "endpoint": ep_path,
                        "priority": 30,
                        "reason": f"STANDARD profile verified sensitive property protection on resource '{res_name}'",
                        "test_obj": test,
                    })
                elif test.test_type in ("WORKFLOW_STATE_BYPASS", "WORKFLOW_STEP_SKIP"):
                    selected.append({
                        "security_test_id": test.id,
                        "test_type": test.test_type,
                        "endpoint": ep_path,
                        "priority": 40,
                        "reason": f"STANDARD profile verified workflow transition safety on '{wf_name}'",
                        "test_obj": test,
                    })

            # 3. DEEP Profile:
            # - Full coverage across all test types and workflows
            elif p_type == "DEEP":
                if is_auth_test(test):
                    prio, reason = 10, f"DEEP profile comprehensive authentication audit on '{ep_path}'"
                elif test.test_type == "BOLA":
                    prio, reason = 20, f"DEEP profile exhaustive BOLA object-level audit on '{ep_path}'"
                elif test.test_type == "BFLA":
                    prio, reason = 25, f"DEEP profile exhaustive BFLA function-level privilege audit on '{ep_path}'"
                elif is_property_test(test):
                    prio, reason = 30, f"DEEP profile sensitive data & property exposure audit on '{res_name}'"
                elif is_workflow_test(test):
                    prio, reason = 40, f"DEEP profile multi-step business logic attack audit on '{wf_name}'"
                else:
                    prio, reason = 50, f"DEEP profile full surface area security audit ({test.test_type})"

                selected.append({
                    "security_test_id": test.id,
                    "test_type": test.test_type,
                    "endpoint": ep_path,
                    "priority": prio,
                    "reason": reason,
                    "test_obj": test,
                })

            # 4. CUSTOM Profile:
            # - Configuration-driven selection
            elif p_type == "CUSTOM":
                allowed_types = config.get("allowed_test_types")
                endpoint_ids = config.get("endpoint_ids")
                include_workflows = config.get("include_workflows", True)

                # Filter by allowed test types if specified
                if allowed_types and test.test_type not in allowed_types:
                    continue

                # Filter by endpoint_ids if specified
                if endpoint_ids is not None and test.endpoint_id not in endpoint_ids:
                    continue

                # Filter by workflow inclusion
                if not include_workflows and is_workflow_test(test):
                    continue

                selected.append({
                    "security_test_id": test.id,
                    "test_type": test.test_type,
                    "endpoint": ep_path,
                    "priority": 10,
                    "reason": f"CUSTOM profile matched configured rules for {test.test_type}",
                    "test_obj": test,
                })

        # Deterministic sorting: priority asc, test_type asc, endpoint path asc, security_test_id asc
        selected.sort(
            key=lambda x: (
                x["priority"],
                x["test_type"] or "",
                x["endpoint"] or "",
                x["security_test_id"],
            )
        )

        # Apply optional max_tests limit from configuration
        max_tests = config.get("max_tests")
        if isinstance(max_tests, int) and max_tests > 0:
            selected = selected[:max_tests]

        return selected

    def preview_profile(
        self,
        profile_id: str,
        project_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Preview the tests that would be selected by this profile.
        Strictly deterministic and read-only.
        """
        profile = self.get_profile(profile_id, project_id=project_id)
        if not profile:
            raise ProfileNotFoundError(f"Scan profile with ID {profile_id} not found.")

        selected = self.select_tests_for_profile(profile)
        return {
            "profile_id": profile.id,
            "profile_name": profile.name,
            "profile_type": profile.profile_type,
            "selected_test_count": len(selected),
            "selected_tests": [
                {
                    "security_test_id": item["security_test_id"],
                    "test_type": item["test_type"],
                    "endpoint": item["endpoint"],
                    "priority": item["priority"],
                    "reason": item["reason"],
                }
                for item in selected
            ],
        }

    # =========================================================================
    # Execution Plan Generation
    # =========================================================================

    def create_plan_from_profile(
        self,
        project_id: int,
        profile_id: str,
        name: Optional[str] = None,
        execution_mode: str = "SEQUENTIAL",
    ) -> SecurityExecutionPlan:
        """
        Create a SecurityExecutionPlan from an active scan profile.
        Disabled profiles cannot create execution plans.
        """
        profile = self.get_profile(profile_id, project_id=project_id)
        if not profile:
            raise ProfileNotFoundError(f"Scan profile with ID {profile_id} not found.")

        if profile.status == "DISABLED":
            raise DisabledProfileError(
                f"Scan profile '{profile.name}' is DISABLED and cannot be used to create an execution plan."
            )

        selected = self.select_tests_for_profile(profile)

        plan_name = name.strip() if name else f"{profile.name} - Plan"
        mode = execution_mode.upper() if execution_mode else "SEQUENTIAL"
        if mode not in ("SEQUENTIAL", "FAIL_FAST", "CONTINUE_ON_FAILURE"):
            mode = "SEQUENTIAL"

        plan = SecurityExecutionPlan(
            project_id=project_id,
            profile_id=profile.id,
            suite_id=None,
            name=plan_name,
            status="READY" if selected else "DRAFT",
            execution_mode=mode,
            total_tests=len(selected),
            completed_tests=0,
            confirmed_findings=0,
            inconclusive_tests=0,
            failed_tests=0,
        )
        self.db.add(plan)
        self.db.flush()

        for idx, item in enumerate(selected, start=1):
            exec_item = SecurityExecutionItem(
                execution_plan_id=plan.id,
                security_test_id=item["security_test_id"],
                execution_order=idx,
                status="QUEUED",
            )
            self.db.add(exec_item)

        self.db.commit()
        self.db.refresh(plan)
        return plan
