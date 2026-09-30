"""
SentinelAPI Security Testing Engine package.
Provides modular, controlled authorization testing (Stage 3 BOLA).
"""

from app.services.security_engine.client import AsyncSecurityHttpClient, ExecutionResult
from app.services.security_engine.evaluator import BOLAEngine
from app.services.security_engine.bfla_engine import BFLAEngine
from app.services.security_engine.property_engine import PropertyExposureEngine
from app.services.security_engine.auth_engine import AuthenticationEngine
from app.services.security_engine.auth_generator import AuthenticationTestGenerator
from app.services.security_engine.workflow_engine import WorkflowEngine
from app.services.security_engine.workflow_attack_generator import WorkflowAttackGenerator
from app.services.security_engine.workflow_attack_engine import WorkflowAttackEngine
from app.services.security_engine.correlation_engine import CorrelationEngine
from app.services.security_engine.attack_path_engine import AttackPathEngine
from app.services.security_engine.impact_engine import ImpactEngine
from app.services.security_engine.investigation_service import (
    InvestigationService,
    InvestigationServiceError,
    CrossProjectViolationError,
    InvalidFindingStateError,
)

from app.services.security_engine.redactor import redact_headers, redact_text
from app.services.security_engine.orchestrator import (
    TestOrchestrator,
    OrchestrationError,
    PlanStateError,
    AuthorizationError,
    EntityNotFoundError,
    InvalidSuiteStateError,
)
from app.services.security_engine.scan_profile_service import (
    ScanProfileService,
    ScanProfileError,
    ProfileNotFoundError,
    DuplicateProfileError,
    DisabledProfileError,
)
from app.services.security_engine.baseline_service import (
    SecurityBaselineService,
    BaselineComparisonService,
    BaselineError,
    BaselineNotFoundError,
    ComparisonNotFoundError,
    InvalidBaselinePlanError,
)

from app.services.security_engine.security_gate_service import (
    SecurityGateService,
    SecurityGateError,
    GateNotFoundError,
    DuplicateGateError,
    DisabledGateError,
    InvalidGateRuleError,
    InvalidEvaluationStateError,
    get_gate_exit_code,
)
from app.services.security_engine.report_service import (
    SecurityReportService,
    SecurityReportError,
    ReportNotFoundError,
    DuplicateReportError,
    InvalidReportSourceError,
    ArchivedReportError,
)
from app.services.security_engine.schedule_service import (
    ScheduleService,
    ScheduleError,
    ScheduleNotFoundError,
    DuplicateScheduleError,
    InvalidScheduleError,
    DisabledScheduleError,
)
from app.services.security_engine.scheduled_scan_service import (
    ScheduledScanService,
    ScheduledScanError,
)
from app.services.security_engine.scheduler import (
    SchedulerRunner,
)

__all__ = [
    "AsyncSecurityHttpClient",
    "ExecutionResult",
    "BOLAEngine",
    "BFLAEngine",
    "PropertyExposureEngine",
    "AuthenticationEngine",
    "AuthenticationTestGenerator",
    "WorkflowEngine",
    "WorkflowAttackGenerator",
    "WorkflowAttackEngine",
    "CorrelationEngine",
    "AttackPathEngine",
    "ImpactEngine",
    "InvestigationService",
    "InvestigationServiceError",
    "CrossProjectViolationError",
    "InvalidFindingStateError",
    "TestOrchestrator",
    "OrchestrationError",
    "PlanStateError",
    "AuthorizationError",
    "EntityNotFoundError",
    "InvalidSuiteStateError",
    "ScanProfileService",
    "ScanProfileError",
    "ProfileNotFoundError",
    "DuplicateProfileError",
    "DisabledProfileError",
    "SecurityBaselineService",
    "BaselineComparisonService",
    "BaselineError",
    "BaselineNotFoundError",
    "ComparisonNotFoundError",
    "InvalidBaselinePlanError",
    "SecurityGateService",
    "SecurityGateError",
    "GateNotFoundError",
    "DuplicateGateError",
    "DisabledGateError",
    "InvalidGateRuleError",
    "InvalidEvaluationStateError",
    "get_gate_exit_code",
    "SecurityReportService",
    "SecurityReportError",
    "ReportNotFoundError",
    "DuplicateReportError",
    "InvalidReportSourceError",
    "ArchivedReportError",
    "redact_headers",
    "redact_text",
    "ScheduleService",
    "ScheduleError",
    "ScheduleNotFoundError",
    "DuplicateScheduleError",
    "InvalidScheduleError",
    "DisabledScheduleError",
    "ScheduledScanService",
    "ScheduledScanError",
    "SchedulerRunner",
]


