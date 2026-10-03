"""
HTTP Client for SentinelAPI REST API.
Enforces credential redaction, deterministic error mapping, and strictly zero target HTTP calls.
"""

import sys
from typing import Any, Dict, List, Optional
import httpx

from sentinel.config import Config
from sentinel.errors import (
    AuthenticationError,
    ConflictError,
    ConnectionError,
    ForbiddenError,
    NotFoundError,
    SentinelError,
    TimeoutError,
    ValidationError,
)


class SentinelClient:
    """Thin API client over SentinelAPI backend."""

    def __init__(self, config: Config):
        self.config = config
        headers: Dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": "SentinelCLI/1.0",
        }
        if self.config.token:
            headers["Authorization"] = f"Bearer {self.config.token}"
            headers["X-API-Key"] = self.config.token

        self._client = httpx.Client(
            base_url=self.config.api_url,
            headers=headers,
            timeout=self.config.timeout,
        )

    def close(self):
        """Close the underlying HTTP client session."""
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _log_verbose(self, message: str):
        """Log diagnostic messages to stderr only if verbose mode is enabled."""
        if self.config.verbose:
            sys.stderr.write(f"[verbose] {message}\n")
            sys.stderr.flush()

    def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Any] = None,
    ) -> Any:
        """Execute request with centralized error handling and sanitization."""
        url = f"{self.config.api_url.rstrip('/')}/{path.lstrip('/')}"
        self._log_verbose(f"--> {method.upper()} {url}")

        try:
            response = self._client.request(
                method=method,
                url=path,
                params=params,
                json=json_data,
            )
            self._log_verbose(f"<-- {response.status_code} {response.reason_phrase}")
        except httpx.ConnectError as exc:
            self._log_verbose(f"Connection failure: {exc}")
            raise ConnectionError(
                message=f"Failed to connect to SentinelAPI at {self.config.api_url}",
                reason="Backend server may be offline or unreachable.",
            ) from exc
        except httpx.TimeoutException as exc:
            self._log_verbose(f"Request timeout: {exc}")
            raise TimeoutError(
                message="Request to SentinelAPI backend timed out.",
                reason=f"Exceeded timeout threshold of {self.config.timeout} seconds.",
            ) from exc
        except httpx.RequestError as exc:
            self._log_verbose(f"Transport error: {exc}")
            raise SentinelError(
                message="Network transport error communicating with SentinelAPI.",
                reason=str(exc),
            ) from exc

        return self._handle_response(response)

    def _handle_response(self, response: httpx.Response) -> Any:
        """Parse response and map HTTP error status codes to typed exceptions."""
        if response.is_success:
            if response.status_code == 204:
                return None
            try:
                return response.json()
            except Exception:
                return response.text

        # Extract error message cleanly
        detail = ""
        try:
            body = response.json()
            if isinstance(body, dict):
                detail = body.get("detail") or body.get("message") or str(body)
            else:
                detail = str(body)
        except Exception:
            detail = response.text or response.reason_phrase

        status_code = response.status_code

        if status_code == 401:
            raise AuthenticationError(
                message="Authentication failed against SentinelAPI.",
                reason=detail or "Missing or invalid API token.",
            )
        elif status_code == 403:
            raise ForbiddenError(
                message="Access forbidden.",
                reason=detail or "Unauthorized project access.",
            )
        elif status_code == 404:
            raise NotFoundError(
                message="Resource not found.",
                reason=detail or "The requested entity does not exist.",
            )
        elif status_code == 409:
            raise ConflictError(
                message="Resource conflict.",
                reason=detail or "An entity with the same identifier already exists.",
            )
        elif status_code in (400, 422):
            raise ValidationError(
                message="Invalid request.",
                reason=detail or "Validation failure.",
            )
        else:
            raise SentinelError(
                message=f"SentinelAPI backend error (HTTP {status_code}).",
                reason=detail or response.reason_phrase,
            )

    # =========================================================================
    # Auth & Connectivity
    # =========================================================================

    def verify_auth(self) -> Dict[str, Any]:
        """Verify API connectivity and authentication credentials."""
        return self._request("GET", "/api/v1/auth/verify")

    # =========================================================================
    # Projects
    # =========================================================================

    def list_projects(self) -> List[Dict[str, Any]]:
        """List all accessible projects."""
        return self._request("GET", "/api/v1/projects/")

    def get_project(self, project_id: int) -> Dict[str, Any]:
        """Retrieve details for a specific project."""
        return self._request("GET", f"/api/v1/projects/{project_id}")

    # =========================================================================
    # Scan Profiles
    # =========================================================================

    def list_profiles(
        self,
        project_id: int,
        status: Optional[str] = None,
        profile_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List scan profiles for a project."""
        params: Dict[str, Any] = {}
        if status:
            params["status"] = status
        if profile_type:
            params["profile_type"] = profile_type
        data = self._request("GET", f"/api/v1/projects/{project_id}/scan-profiles", params=params)
        if isinstance(data, dict) and "profiles" in data:
            return data["profiles"]
        return data or []

    def get_profile(self, profile_id: str) -> Dict[str, Any]:
        """Retrieve details of a scan profile."""
        return self._request("GET", f"/api/v1/scan-profiles/{profile_id}")

    def preview_profile(self, profile_id: str) -> Dict[str, Any]:
        """Preview deterministic test selection without executing target requests."""
        return self._request("GET", f"/api/v1/scan-profiles/{profile_id}/preview")

    def create_plan_from_profile(
        self,
        profile_id: str,
        name: Optional[str] = None,
        execution_mode: str = "SEQUENTIAL",
    ) -> Dict[str, Any]:
        """Create a new execution plan from a scan profile."""
        payload = {
            "name": name,
            "execution_mode": execution_mode,
        }
        return self._request("POST", f"/api/v1/scan-profiles/{profile_id}/create-plan", json_data=payload)

    # =========================================================================
    # Execution Plans & Scanning
    # =========================================================================

    def start_execution_plan(self, plan_id: str) -> Dict[str, Any]:
        """Start execution of an existing execution plan."""
        return self._request("POST", f"/api/v1/execution-plans/{plan_id}/start")

    def get_execution_plan(self, plan_id: str) -> Dict[str, Any]:
        """Retrieve execution plan status and summary."""
        return self._request("GET", f"/api/v1/execution-plans/{plan_id}")

    def get_execution_progress(self, plan_id: str) -> Dict[str, Any]:
        """Poll progress of a running execution plan."""
        return self._request("GET", f"/api/v1/execution-plans/{plan_id}/progress")

    # =========================================================================
    # Baselines & Comparisons
    # =========================================================================

    def compare_baseline_with_plan(
        self,
        baseline_id: str,
        execution_plan_id: str,
    ) -> Dict[str, Any]:
        """Generate baseline comparison for an execution plan."""
        payload = {"execution_plan_id": execution_plan_id}
        return self._request("POST", f"/api/v1/baselines/{baseline_id}/compare", json_data=payload)

    def get_comparison(self, comparison_id: str) -> Dict[str, Any]:
        """Retrieve details of a baseline comparison."""
        return self._request("GET", f"/api/v1/baseline-comparisons/{comparison_id}")

    # =========================================================================
    # Security Gates
    # =========================================================================

    def list_gates(self, project_id: int) -> List[Dict[str, Any]]:
        """List all security gates for a project."""
        data = self._request("GET", f"/api/v1/projects/{project_id}/security-gates")
        if isinstance(data, dict) and "gates" in data:
            return data["gates"]
        return data or []

    def get_gate(self, gate_id: str) -> Dict[str, Any]:
        """Retrieve details for a specific security gate."""
        return self._request("GET", f"/api/v1/security-gates/{gate_id}")

    def evaluate_gate(
        self,
        gate_id: str,
        comparison_id: str,
    ) -> Dict[str, Any]:
        """Evaluate a security gate against a baseline comparison."""
        return self._request("POST", f"/api/v1/security-gates/{gate_id}/evaluate/{comparison_id}")

    def get_evaluation(self, evaluation_id: str) -> Dict[str, Any]:
        """Retrieve gate evaluation details."""
        return self._request("GET", f"/api/v1/security-gate-evaluations/{evaluation_id}")

    def get_evaluation_result(self, evaluation_id: str) -> Dict[str, Any]:
        """Retrieve standardized CI gate result with metrics and exit code."""
        return self._request("GET", f"/api/v1/security-gate-evaluations/{evaluation_id}/result")

    # =========================================================================
    # Security Reports & Evidence Packages
    # =========================================================================

    def list_reports(self, project_id: int) -> List[Dict[str, Any]]:
        """List security reports for a project."""
        return self._request("GET", f"/api/v1/projects/{project_id}/security-reports")

    def get_report(self, report_id: str) -> Dict[str, Any]:
        """Retrieve details of a security report."""
        return self._request("GET", f"/api/v1/security-reports/{report_id}")

    def get_report_json(self, report_id: str, version: Optional[int] = None) -> Dict[str, Any]:
        """Retrieve canonical JSON snapshot of a security report."""
        params = {"version": version} if version else None
        return self._request("GET", f"/api/v1/security-reports/{report_id}/json", params=params)

    def get_report_manifest(self, report_id: str, version: Optional[int] = None) -> Dict[str, Any]:
        """Retrieve evidence package manifest."""
        params = {"version": version} if version else None
        return self._request("GET", f"/api/v1/security-reports/{report_id}/manifest", params=params)

    def get_report_package(self, report_id: str, version: Optional[int] = None) -> Dict[str, Any]:
        """Retrieve full structured evidence package."""
        params = {"version": version} if version else None
        return self._request("GET", f"/api/v1/security-reports/{report_id}/package", params=params)

    # =========================================================================
    # Scheduled & Continuous Security Scanning
    # =========================================================================

    def list_schedules(self, project_id: int, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List scan schedules for a project."""
        params = {"status": status} if status else None
        data = self._request("GET", f"/api/v1/projects/{project_id}/security-scan-schedules", params=params)
        if isinstance(data, dict) and "schedules" in data:
            return data["schedules"]
        return data or []

    def get_schedule(self, schedule_id: str) -> Dict[str, Any]:
        """Retrieve details of a security scan schedule."""
        return self._request("GET", f"/api/v1/security-scan-schedules/{schedule_id}")

    def preview_schedule(self, schedule_id: str, count: int = 5) -> Dict[str, Any]:
        """Preview next occurrences for a security scan schedule."""
        params = {"count": count}
        return self._request("GET", f"/api/v1/security-scan-schedules/{schedule_id}/preview", params=params)

    def run_schedule(self, schedule_id: str) -> Dict[str, Any]:
        """Trigger an immediate manual run of a security scan schedule."""
        return self._request("POST", f"/api/v1/security-scan-schedules/{schedule_id}/run")

    def enable_schedule(self, schedule_id: str) -> Dict[str, Any]:
        """Enable an inactive security scan schedule."""
        return self._request("POST", f"/api/v1/security-scan-schedules/{schedule_id}/enable")

    def disable_schedule(self, schedule_id: str) -> Dict[str, Any]:
        """Disable an active security scan schedule."""
        return self._request("POST", f"/api/v1/security-scan-schedules/{schedule_id}/disable")

    def list_scheduled_executions(
        self,
        schedule_id: Optional[str] = None,
        project_id: Optional[int] = None,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List historical scheduled executions for a schedule or project."""
        if schedule_id:
            data = self._request("GET", f"/api/v1/security-scan-schedules/{schedule_id}/executions", params={"limit": limit})
        elif project_id:
            params = {"limit": limit}
            if status:
                params["status"] = status
            data = self._request("GET", f"/api/v1/projects/{project_id}/security-scheduled-executions", params=params)
        else:
            return []

        if isinstance(data, dict) and "executions" in data:
            return data["executions"]
        return data or []

    def get_scheduled_execution(self, execution_id: str) -> Dict[str, Any]:
        """Retrieve details of a scheduled execution."""
        return self._request("GET", f"/api/v1/security-scheduled-executions/{execution_id}")

    def verify_auth(self) -> Dict[str, Any]:
        """Verify current authentication token with backend."""
        return self._request("GET", "/api/v1/auth/verify")

    def get_token_status(self) -> Dict[str, Any]:
        """Check status, expiration, and validity of active token."""
        return self._request("GET", "/api/v1/auth/token-status")

    def list_audit_events(
        self,
        project_id: Optional[int] = None,
        event_type: Optional[str] = None,
        action: Optional[str] = None,
        outcome: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List audit events."""
        params: Dict[str, Any] = {"limit": limit}
        if event_type:
            params["event_type"] = event_type
        if action:
            params["action"] = action
        if outcome:
            params["outcome"] = outcome

        if project_id:
            data = self._request("GET", f"/api/v1/projects/{project_id}/audit-events", params=params)
        else:
            data = self._request("GET", "/api/v1/audit-events", params=params)

        if isinstance(data, dict) and "events" in data:
            return data["events"]
        return data or []

    def get_audit_event(self, event_id: str) -> Dict[str, Any]:
        """Retrieve details of a single immutable audit event."""
        return self._request("GET", f"/api/v1/audit-events/{event_id}")


