import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, Any, Optional
import httpx
from app.services.security_engine.redactor import redact_headers, redact_text

# Allowed safe methods for Stage 3
SAFE_HTTP_METHODS = {"GET", "HEAD"}


@dataclass
class ExecutionResult:
    status_code: Optional[int] = None
    headers: Dict[str, str] = field(default_factory=dict)
    redacted_headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    redacted_body: str = ""
    duration_ms: int = 0
    url: str = ""
    method: str = "GET"
    correlation_id: str = ""
    error: Optional[str] = None
    error_category: Optional[str] = None
    request_headers: Dict[str, str] = field(default_factory=dict)
    redacted_request_headers: Dict[str, str] = field(default_factory=dict)


class AsyncSecurityHttpClient:
    """
    Dedicated safe asynchronous security HTTP client.
    Enforces safe methods (GET/HEAD), correlation IDs, controlled redirects,
    timeouts, and strict credential redaction.
    """

    def __init__(
        self,
        timeout: float = 10.0,
        follow_redirects: bool = False,
        app: Optional[Any] = None,
    ):
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        # app allows in-memory test execution with httpx.ASGITransport
        self.app = app

    async def execute(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None,
        sensitive_values: Optional[list] = None,
    ) -> ExecutionResult:
        upper_method = method.upper()
        if upper_method not in SAFE_HTTP_METHODS:
            raise ValueError(
                f"Security testing method '{method}' is not permitted. Only safe methods ({', '.join(SAFE_HTTP_METHODS)}) are allowed in Stage 3."
            )

        cid = correlation_id or str(uuid.uuid4())
        req_headers = dict(headers or {})
        req_headers["X-Correlation-ID"] = cid
        req_cookies = dict(cookies or {})

        redacted_req_headers = redact_headers(req_headers)

        start_time = time.perf_counter()

        transport = None
        if self.app is not None:
            transport = httpx.ASGITransport(app=self.app)

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=self.follow_redirects,
                transport=transport,
            ) as client:
                resp = await client.request(
                    method=upper_method,
                    url=url,
                    headers=req_headers,
                    cookies=req_cookies,
                    params=params,
                )
                duration_ms = int((time.perf_counter() - start_time) * 1000)

                resp_headers = dict(resp.headers)
                redacted_resp_headers = redact_headers(resp_headers)
                raw_body = resp.text
                redacted_body = redact_text(raw_body[:4000], sensitive_values=sensitive_values)

                return ExecutionResult(
                    status_code=resp.status_code,
                    headers=resp_headers,
                    redacted_headers=redacted_resp_headers,
                    body=raw_body,
                    redacted_body=redacted_body,
                    duration_ms=duration_ms,
                    url=url,
                    method=upper_method,
                    correlation_id=cid,
                    error=None,
                    error_category=None,
                    request_headers=req_headers,
                    redacted_request_headers=redacted_req_headers,
                )

        except httpx.TimeoutException as exc:
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            return ExecutionResult(
                status_code=None,
                duration_ms=duration_ms,
                url=url,
                method=upper_method,
                correlation_id=cid,
                error=f"Request timed out after {self.timeout}s: {str(exc)}",
                error_category="timeout",
                request_headers=req_headers,
                redacted_request_headers=redacted_req_headers,
            )
        except httpx.ConnectError as exc:
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            return ExecutionResult(
                status_code=None,
                duration_ms=duration_ms,
                url=url,
                method=upper_method,
                correlation_id=cid,
                error=f"Connection failed: {str(exc)}",
                error_category="network_error",
                request_headers=req_headers,
                redacted_request_headers=redacted_req_headers,
            )
        except Exception as exc:
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            return ExecutionResult(
                status_code=None,
                duration_ms=duration_ms,
                url=url,
                method=upper_method,
                correlation_id=cid,
                error=f"Execution failed: {str(exc)}",
                error_category="client_error",
                request_headers=req_headers,
                redacted_request_headers=redacted_req_headers,
            )
