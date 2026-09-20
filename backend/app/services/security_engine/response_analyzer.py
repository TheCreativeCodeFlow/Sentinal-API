import json
import re
from typing import Any, Dict, List, Optional, Tuple, Union
from pydantic import BaseModel, Field


SENSITIVE_KEY_PATTERNS = [
    re.compile(r"password", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"api[_-]?key", re.IGNORECASE),
    re.compile(r"auth", re.IGNORECASE),
    re.compile(r"ssn", re.IGNORECASE),
    re.compile(r"credit[_-]?card", re.IGNORECASE),
    re.compile(r"card[_-]?number", re.IGNORECASE),
    re.compile(r"is[_-]?admin", re.IGNORECASE),
    re.compile(r"role", re.IGNORECASE),
    re.compile(r"permission", re.IGNORECASE),
    re.compile(r"private[_-]?key", re.IGNORECASE),
]

DENIAL_BODY_PATTERNS = [
    re.compile(r"access\s*denied", re.IGNORECASE),
    re.compile(r"unauthorized", re.IGNORECASE),
    re.compile(r"forbidden", re.IGNORECASE),
    re.compile(r"permission\s*denied", re.IGNORECASE),
    re.compile(r"not\s*allowed", re.IGNORECASE),
    re.compile(r"invalid\s*token", re.IGNORECASE),
    re.compile(r"insufficient\s*permissions", re.IGNORECASE),
]

UUID_REGEX = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
    re.IGNORECASE,
)


class ResponseSignature(BaseModel):
    """
    Structured, reusable summary of an HTTP response for authorization analysis.
    Stores normalized structural metadata and detected indicators without leaking
    sensitive raw response payloads.
    """
    status_code: int
    content_type: str = "text/plain"
    response_size: int = 0
    is_json: bool = False
    is_empty: bool = True
    is_auth_failure: bool = False
    is_server_error: bool = False
    is_client_error: bool = False
    normalized_structure: Optional[Any] = None
    detected_identifiers: List[str] = Field(default_factory=list)
    sensitive_fields_detected: List[str] = Field(default_factory=list)
    denial_indicator: Optional[str] = None


class ResponseAnalyzer:
    """
    Reusable analyzer for HTTP response payloads.
    Generates normalized response signatures and evaluates authorization outcomes.
    """

    @classmethod
    def normalize_structure(cls, data: Any, depth: int = 0, max_depth: int = 4) -> Any:
        """
        Recursively converts a JSON data structure into a schema-like type signature.
        Replaces actual values with their type names to preserve structure without raw data.
        """
        if depth >= max_depth:
            return "..."

        if isinstance(data, dict):
            return {
                k: cls.normalize_structure(v, depth=depth + 1, max_depth=max_depth)
                for k, v in list(data.items())[:20]  # Cap keys to keep compact
            }
        elif isinstance(data, list):
            if not data:
                return []
            # Take the structure of the first item as the list type representation
            return [cls.normalize_structure(data[0], depth=depth + 1, max_depth=max_depth)]
        elif isinstance(data, bool):
            return "boolean"
        elif isinstance(data, int):
            return "integer"
        elif isinstance(data, float):
            return "float"
        elif isinstance(data, str):
            if UUID_REGEX.match(data):
                return "uuid"
            return "string"
        elif data is None:
            return "null"
        return type(data).__name__

    @classmethod
    def extract_identifiers(cls, data: Any, current_depth: int = 0) -> List[str]:
        """
        Collects detected entity identifiers (UUIDs, keys like 'id', 'user_id', etc.)
        from parsed JSON or strings.
        """
        identifiers: List[str] = []
        if current_depth > 4:
            return identifiers

        if isinstance(data, dict):
            for k, v in data.items():
                if k.lower() in ("id", "user_id", "order_id", "account_id", "resource_id"):
                    if isinstance(v, (str, int)) and str(v).strip():
                        identifiers.append(str(v).strip())
                elif isinstance(v, str) and UUID_REGEX.match(v):
                    identifiers.append(v)
                elif isinstance(v, (dict, list)):
                    identifiers.extend(cls.extract_identifiers(v, current_depth + 1))
        elif isinstance(data, list):
            for item in data[:5]:
                identifiers.extend(cls.extract_identifiers(item, current_depth + 1))
        elif isinstance(data, str) and UUID_REGEX.match(data):
            identifiers.append(data)

        # Deduplicate while preserving order
        seen = set()
        deduped = []
        for ident in identifiers:
            if ident not in seen:
                seen.add(ident)
                deduped.append(ident)
        return deduped[:10]

    @classmethod
    def extract_sensitive_fields(cls, data: Any, current_depth: int = 0) -> List[str]:
        """
        Identifies sensitive or privileged property keys present in the response body.
        """
        fields: List[str] = []
        if current_depth > 4:
            return fields

        if isinstance(data, dict):
            for k, v in data.items():
                for pat in SENSITIVE_KEY_PATTERNS:
                    if pat.search(k):
                        fields.append(k)
                        break
                if isinstance(v, (dict, list)):
                    fields.extend(cls.extract_sensitive_fields(v, current_depth + 1))
        elif isinstance(data, list):
            for item in data[:5]:
                fields.extend(cls.extract_sensitive_fields(item, current_depth + 1))

        # Deduplicate
        seen = set()
        deduped = []
        for f in fields:
            if f not in seen:
                seen.add(f)
                deduped.append(f)
        return deduped[:15]

    @classmethod
    def analyze(
        cls,
        status_code: int,
        headers: Dict[str, str],
        body: str,
    ) -> ResponseSignature:
        """
        Analyzes an HTTP response and constructs a reusable ResponseSignature.
        """
        normalized_headers = {k.lower(): v for k, v in headers.items()}
        content_type = normalized_headers.get("content-type", "text/plain").split(";")[0].strip()
        response_size = len(body.encode("utf-8")) if body else 0
        is_empty = response_size == 0 or len(body.strip()) == 0

        is_json = False
        parsed_json: Optional[Any] = None
        normalized_structure: Optional[Any] = None
        detected_identifiers: List[str] = []
        sensitive_fields: List[str] = []

        if not is_empty:
            try:
                parsed_json = json.loads(body)
                is_json = True
                normalized_structure = cls.normalize_structure(parsed_json)
                detected_identifiers = cls.extract_identifiers(parsed_json)
                sensitive_fields = cls.extract_sensitive_fields(parsed_json)
            except Exception:
                # Non-JSON body
                is_json = False
                # Search for UUIDs in text
                uuids = UUID_REGEX.findall(body)
                detected_identifiers = list(dict.fromkeys(uuids))[:5]

        # Check for authorization failure indications
        is_auth_failure = status_code in (401, 403, 404)
        denial_indicator: Optional[str] = None

        if is_auth_failure:
            denial_indicator = f"HTTP {status_code}"
        elif not is_empty:
            # Check if an HTTP 200 payload actually represents an application-level denial
            # e.g., {"error": "Unauthorized", "message": "Access denied"}
            text_to_check = ""
            if isinstance(parsed_json, dict):
                error_val = parsed_json.get("error") or parsed_json.get("message") or parsed_json.get("detail")
                if error_val:
                    text_to_check = str(error_val)
            else:
                text_to_check = body[:500]

            for pat in DENIAL_BODY_PATTERNS:
                if pat.search(text_to_check):
                    is_auth_failure = True
                    denial_indicator = f"Application-level denial message matching '{pat.pattern}'"
                    break

        return ResponseSignature(
            status_code=status_code,
            content_type=content_type,
            response_size=response_size,
            is_json=is_json,
            is_empty=is_empty,
            is_auth_failure=is_auth_failure,
            is_server_error=status_code >= 500,
            is_client_error=400 <= status_code < 500,
            normalized_structure=normalized_structure,
            detected_identifiers=detected_identifiers,
            sensitive_fields_detected=sensitive_fields,
            denial_indicator=denial_indicator,
        )

    @classmethod
    def evaluate_access(
        cls,
        signature: ResponseSignature,
        expected_access: str,
    ) -> Tuple[str, str, Optional[str]]:
        """
        Compares expected authorization policy ('ALLOW' or 'DENY') against actual response signature.
        Returns: (result: PASS | CONFIRMED | INCONCLUSIVE | ERROR, reason: str, error_category: Optional[str])
        """
        exp = expected_access.upper().strip()

        # If expected is DENY:
        if exp == "DENY":
            # 1. Successful denial: HTTP 401, 403, 404 or application-level denial
            if signature.is_auth_failure:
                return (
                    "PASS",
                    f"Access was properly denied with {signature.denial_indicator or f'HTTP {signature.status_code}'}.",
                    None,
                )

            # 2. Server errors: Inconclusive
            if signature.is_server_error:
                return (
                    "INCONCLUSIVE",
                    f"Target returned server error HTTP {signature.status_code}; authorization state cannot be verified.",
                    "server_error",
                )

            # 3. Successful responses: HTTP 200, 201, 204
            if signature.status_code in (200, 201, 204):
                if signature.is_empty and signature.status_code == 200:
                    return (
                        "INCONCLUSIVE",
                        "Received HTTP 200 OK, but response body was empty or indeterminate.",
                        None,
                    )
                # Successful access granted when DENY was expected -> Vulnerability confirmed!
                details = []
                if signature.sensitive_fields_detected:
                    details.append(f"sensitive fields leaked: {', '.join(signature.sensitive_fields_detected[:5])}")
                if signature.detected_identifiers:
                    details.append(f"identifiers exposed: {', '.join(signature.detected_identifiers[:3])}")
                suffix = f" ({'; '.join(details)})" if details else ""

                return (
                    "CONFIRMED",
                    f"Access was granted with HTTP {signature.status_code} despite expected authorization policy being DENY{suffix}.",
                    None,
                )

            # 4. Other client errors (e.g. 400 Bad Request, 405 Method Not Allowed)
            if signature.status_code in (400, 405, 422):
                return (
                    "INCONCLUSIVE",
                    f"Target returned client error HTTP {signature.status_code}; endpoint parameters or format may be invalid.",
                    "client_error",
                )

            return (
                "INCONCLUSIVE",
                f"Target returned unexpected HTTP status {signature.status_code}.",
                "unexpected_status",
            )

        # If expected is ALLOW:
        if exp == "ALLOW":
            if signature.status_code in (200, 201, 204) and not signature.is_auth_failure:
                return (
                    "PASS",
                    f"Access was granted as expected with HTTP {signature.status_code}.",
                    None,
                )

            if signature.is_auth_failure:
                return (
                    "CONFIRMED",
                    f"Access was denied ({signature.denial_indicator or f'HTTP {signature.status_code}'}) although expected policy is ALLOW.",
                    None,
                )

            if signature.is_server_error:
                return (
                    "INCONCLUSIVE",
                    f"Target returned server error HTTP {signature.status_code}.",
                    "server_error",
                )

            return (
                "INCONCLUSIVE",
                f"Target returned unexpected HTTP status {signature.status_code}.",
                "unexpected_status",
            )

        # If UNKNOWN:
        return (
            "INCONCLUSIVE",
            f"Expected authorization policy is '{expected_access}'; unable to evaluate pass/confirmed status.",
            None,
        )
