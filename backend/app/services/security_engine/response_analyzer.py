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

SENSITIVE_HEURISTICS_RULES: List[Tuple[re.Pattern, str, str]] = [
    # (pattern, suggested_sensitivity: SECRET, SENSITIVE, INTERNAL, heuristic_name)
    (re.compile(r"^password(_hash)?$", re.IGNORECASE), "SECRET", "password"),
    (re.compile(r"(access|refresh)[_-]?token", re.IGNORECASE), "SECRET", "access_or_refresh_token"),
    (re.compile(r"api[_-]?key", re.IGNORECASE), "SECRET", "api_key"),
    (re.compile(r"(private[_-]?key|secret)", re.IGNORECASE), "SECRET", "secret_or_private_key"),
    (re.compile(r"(auth|bearer)[_-]?token", re.IGNORECASE), "SECRET", "auth_token"),
    (re.compile(r"^token$", re.IGNORECASE), "SECRET", "token"),
    (re.compile(r"(credit[_-]?card|card[_-]?number|cvv)", re.IGNORECASE), "SENSITIVE", "credit_card"),
    (re.compile(r"^ssn$", re.IGNORECASE), "SENSITIVE", "ssn"),
    (re.compile(r"(salary|compensation|wage)", re.IGNORECASE), "SENSITIVE", "salary"),
    (re.compile(r"internal[_-]?notes?", re.IGNORECASE), "INTERNAL", "internal_notes"),
    (re.compile(r"^(role|roles)$", re.IGNORECASE), "INTERNAL", "role"),
    (re.compile(r"(is[_-]?admin|is[_-]?superuser|permissions?)", re.IGNORECASE), "INTERNAL", "admin_or_permission"),
]


DENIAL_BODY_PATTERNS = [
    re.compile(r"access\s*denied", re.IGNORECASE),
    re.compile(r"unauthorized", re.IGNORECASE),
    re.compile(r"forbidden", re.IGNORECASE),
    re.compile(r"permission\s*denied", re.IGNORECASE),
    re.compile(r"not\s*allowed", re.IGNORECASE),
    re.compile(r"invalid\s*token", re.IGNORECASE),
    re.compile(r"insufficient\s*permissions", re.IGNORECASE),
    re.compile(r"authentication\s*required", re.IGNORECASE),
    re.compile(r"login\s*required", re.IGNORECASE),
    re.compile(r"token\s*expired", re.IGNORECASE),
    re.compile(r"token\s*invalid", re.IGNORECASE),
    re.compile(r"unauthenticated", re.IGNORECASE),
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
    all_property_paths: List[str] = Field(default_factory=list)
    candidate_sensitive_properties: List[Dict[str, Any]] = Field(default_factory=list)
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
    def extract_property_paths(
        cls,
        data: Any,
        prefix: str = "",
        current_depth: int = 0,
        max_depth: int = 6,
    ) -> List[str]:
        """
        Recursively extracts all property paths from parsed JSON data (primitive fields,
        nested objects, and arrays). Normalizes property paths consistently (e.g. user.profile.email,
        user.role, user.internal_notes, items[].id).
        """
        paths: List[str] = []
        if current_depth >= max_depth:
            return paths

        if isinstance(data, dict):
            for k, v in data.items():
                current_path = f"{prefix}.{k}" if prefix else k
                paths.append(current_path)
                if isinstance(v, (dict, list)):
                    paths.extend(
                        cls.extract_property_paths(
                            v, prefix=current_path, current_depth=current_depth + 1, max_depth=max_depth
                        )
                    )
        elif isinstance(data, list):
            for item in data[:3]:
                if isinstance(item, dict):
                    for k, v in item.items():
                        base_path = f"{prefix}.{k}" if prefix else k
                        array_path = f"{prefix}[].{k}" if prefix else f"[].{k}"
                        paths.append(base_path)
                        paths.append(array_path)
                        if isinstance(v, (dict, list)):
                            paths.extend(
                                cls.extract_property_paths(
                                    v, prefix=base_path, current_depth=current_depth + 1, max_depth=max_depth
                                )
                            )
                            paths.extend(
                                cls.extract_property_paths(
                                    v, prefix=array_path, current_depth=current_depth + 1, max_depth=max_depth
                                )
                            )

        # Deduplicate while preserving order
        seen = set()
        deduped = []
        for p in paths:
            if p not in seen:
                seen.add(p)
                deduped.append(p)
        return deduped

    @classmethod
    def classify_property_heuristic(
        cls,
        prop_path: str,
        sample_value: Any = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Applies configurable sensitive property heuristics to a property path.
        Returns candidate classification dict with suggested_sensitivity and matched_heuristic,
        or None if no sensitive heuristic matches.
        """
        leaf_name = prop_path.split(".")[-1].replace("[]", "")
        for pat, suggested_sens, name in SENSITIVE_HEURISTICS_RULES:
            if pat.search(leaf_name) or pat.search(prop_path):
                return {
                    "path": prop_path,
                    "suggested_sensitivity": suggested_sens,
                    "matched_heuristic": name,
                    "sample_value": str(sample_value)[:100] if sample_value is not None else None,
                }
        return None

    @classmethod
    def discover_candidate_sensitive_properties(cls, data: Any) -> List[Dict[str, Any]]:
        """
        Scans parsed JSON for properties matching candidate sensitive heuristics.
        Returns a deduplicated list of candidate property classifications.
        """
        paths = cls.extract_property_paths(data)
        candidates = []
        seen = set()
        for p in paths:
            res = cls.classify_property_heuristic(p)
            if res and p not in seen:
                seen.add(p)
                candidates.append(res)
        return candidates

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
        all_property_paths: List[str] = []
        candidate_sensitive: List[Dict[str, Any]] = []

        if not is_empty:
            try:
                parsed_json = json.loads(body)
                is_json = True
                normalized_structure = cls.normalize_structure(parsed_json)
                detected_identifiers = cls.extract_identifiers(parsed_json)
                sensitive_fields = cls.extract_sensitive_fields(parsed_json)
                all_property_paths = cls.extract_property_paths(parsed_json)
                candidate_sensitive = cls.discover_candidate_sensitive_properties(parsed_json)
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
            # e.g., {"error": "Unauthorized", "message": "Access denied", "authenticated": false}
            if isinstance(parsed_json, dict) and (parsed_json.get("authenticated") is False or parsed_json.get("is_authenticated") is False):
                is_auth_failure = True
                denial_indicator = "JSON payload specifies authenticated: false"
            else:
                text_to_check = ""
                if isinstance(parsed_json, dict):
                    for k in ("error", "message", "detail", "status", "msg"):
                        if k in parsed_json:
                            text_to_check += " " + str(parsed_json[k])
                else:
                    text_to_check = body[:1000]

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
            all_property_paths=all_property_paths,
            candidate_sensitive_properties=candidate_sensitive,
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

    @classmethod
    def matches_property(cls, candidate_path: str, rule_property_name: str) -> bool:
        """
        Determines whether an observed property path matches a configured property rule name.
        Supports exact match, suffix match, terminal property match, and array normalization.
        """
        c = candidate_path.lower().replace("[]", "").strip()
        r = rule_property_name.lower().replace("[]", "").strip()
        if c == r:
            return True
        if c.endswith("." + r):
            return True
        if r.endswith("." + c):
            return True
        if c.split(".")[-1] == r.split(".")[-1]:
            return True
        return False

    @classmethod
    def evaluate_property_exposure(
        cls,
        signature: ResponseSignature,
        property_rules: Dict[str, str],
    ) -> Tuple[str, str, List[str]]:
        """
        Evaluates read-side property exposure security outcome:
        - If protected properties marked DENY are exposed -> CONFIRMED
        - If protected properties are absent or access was denied -> PASS
        - If response cannot be reliably analyzed (server error, non-JSON) -> INCONCLUSIVE
        Returns: (result: PASS | CONFIRMED | INCONCLUSIVE, reason: str, exposed_deny_props: List[str])
        """
        if signature.is_server_error:
            return (
                "INCONCLUSIVE",
                f"Target returned server error HTTP {signature.status_code}; property exposure cannot be evaluated.",
                [],
            )

        if signature.status_code in (401, 403, 404) or signature.is_auth_failure:
            return (
                "PASS",
                f"Endpoint access was denied ({signature.denial_indicator or f'HTTP {signature.status_code}'}); protected properties were not exposed.",
                [],
            )

        if not signature.is_json:
            return (
                "INCONCLUSIVE",
                "Target response was not valid JSON; cannot reliably extract and verify property paths.",
                [],
            )

        # Identify all properties marked DENY
        deny_properties = [prop for prop, acc in property_rules.items() if acc.upper() == "DENY"]

        if not deny_properties:
            return (
                "PASS",
                "No protected properties are configured with DENY policy for this principal.",
                [],
            )

        exposed_deny_props: List[str] = []
        for deny_prop in deny_properties:
            for observed_path in signature.all_property_paths:
                if cls.matches_property(observed_path, deny_prop):
                    if observed_path not in exposed_deny_props:
                        exposed_deny_props.append(observed_path)
                    break

        if exposed_deny_props:
            return (
                "CONFIRMED",
                f"Unauthorized property exposure confirmed: {len(exposed_deny_props)} protected propert(ies) marked DENY were present in response: {', '.join(exposed_deny_props)}.",
                exposed_deny_props,
            )

        return (
            "PASS",
            "All protected properties marked DENY were properly omitted from the response.",
            [],
        )

    @classmethod
    def is_application_denial(
        cls,
        status_code: int,
        parsed_json: Any = None,
        raw_text: str = "",
    ) -> Tuple[bool, Optional[str]]:
        """
        Detects application-level soft-denials where the HTTP status code might be 200 OK
        or 204, but the payload explicitly signifies an authentication or authorization denial.
        """
        if status_code in (401, 403):
            return True, f"HTTP {status_code}"

        # JSON dictionary checks
        if isinstance(parsed_json, dict):
            if parsed_json.get("authenticated") is False or parsed_json.get("is_authenticated") is False:
                return True, "JSON payload specifies authenticated: false"
            if str(parsed_json.get("status", "")).lower() in ("unauthorized", "forbidden", "denied"):
                return True, f"JSON payload status is '{parsed_json.get('status')}'"

            for key in ("error", "message", "detail", "msg", "title"):
                val = str(parsed_json.get(key, ""))
                for pat in DENIAL_BODY_PATTERNS:
                    if pat.search(val):
                        return True, f"JSON field '{key}' matched denial pattern '{pat.pattern}'"

        # Text / HTML checks
        if raw_text:
            text_sample = raw_text[:2000]
            if "<html" in text_sample.lower():
                if re.search(r"<title>[^<]*(login|sign in|unauthorized|access denied)", text_sample, re.IGNORECASE):
                    return True, "HTML page title indicates login or unauthorized"
                if re.search(r"<(?:form|input)[^>]*(login|password|username)", text_sample, re.IGNORECASE):
                    return True, "HTML login form returned instead of protected API data"

            for pat in DENIAL_BODY_PATTERNS:
                if pat.search(text_sample):
                    return True, f"Response text matched denial pattern '{pat.pattern}'"

        return False, None

    @classmethod
    def contains_protected_data(
        cls,
        parsed_json: Any = None,
        raw_text: str = "",
    ) -> Tuple[bool, List[str]]:
        """
        Detects if response actually exposes protected entity records, user information,
        or sensitive attributes despite ambiguous or non-standard status codes.
        """
        indicators: List[str] = []
        if isinstance(parsed_json, dict):
            # Check for data wrapping or direct entity fields
            for k in ("data", "user", "profile", "order", "account", "records", "items", "resource"):
                if k in parsed_json and parsed_json[k]:
                    indicators.append(f"container field '{k}'")

            # Check for direct identity/resource fields
            for key in ("email", "username", "account_number", "ssn", "balance", "role", "permissions"):
                if key in parsed_json and parsed_json[key] is not None:
                    indicators.append(f"entity field '{key}'")

            # Check if identifiers or sensitive properties exist
            ident = cls.extract_identifiers(parsed_json)
            if ident:
                indicators.extend([f"id:{i}" for i in ident[:3]])
            sens = cls.extract_sensitive_fields(parsed_json)
            if sens:
                indicators.extend([f"sensitive:{s}" for s in sens[:3]])

        elif isinstance(parsed_json, list) and len(parsed_json) > 0:
            indicators.append(f"record array with {len(parsed_json)} item(s)")
            if isinstance(parsed_json[0], dict):
                ident = cls.extract_identifiers(parsed_json[0])
                if ident:
                    indicators.extend([f"id:{i}" for i in ident[:2]])

        return (len(indicators) > 0, indicators)

    @classmethod
    def evaluate_authentication_result(
        cls,
        test_type: str,
        signature: ResponseSignature,
        expected_denial_status: int = 401,
        parsed_json: Any = None,
        raw_text: str = "",
    ) -> Tuple[str, str, Optional[str], Optional[str]]:
        """
        Evaluates the security outcome of an authentication test.
        Returns:
            (result: PASS | CONFIRMED | INCONCLUSIVE,
             reason: str,
             finding_type: Optional[str],
             error_category: Optional[str])
        """
        ttype = test_type.upper().strip()

        # 1. Check for unhandled server errors (5xx)
        if signature.is_server_error or signature.status_code >= 500:
            if ttype == "AUTH_MALFORMED":
                return (
                    "CONFIRMED",
                    f"Target crashed with HTTP {signature.status_code} server error on malformed authentication input instead of returning a proper 4xx client rejection.",
                    "MALFORMED_AUTH_HANDLING",
                    None,
                )
            return (
                "INCONCLUSIVE",
                f"Target returned server error HTTP {signature.status_code}; authentication enforcement cannot be verified.",
                None,
                "server_error",
            )

        # 2. Check for soft-denials / application-level denials (e.g. 200 OK + {"error": "Unauthorized"})
        is_denial, denial_desc = cls.is_application_denial(signature.status_code, parsed_json, raw_text)
        has_protected_data, data_indicators = cls.contains_protected_data(parsed_json, raw_text)

        if signature.status_code in (200, 204) and is_denial and not has_protected_data:
            return (
                "PASS",
                f"Access was denied at application level ({denial_desc}) despite HTTP {signature.status_code}. No protected data was returned.",
                None,
                None,
            )

        # 3. Check for standard denials (401 Unauthorized, 403 Forbidden)
        if signature.status_code in (401, 403):
            return (
                "PASS",
                f"Authentication was properly enforced; request was rejected with HTTP {signature.status_code}.",
                None,
                None,
            )

        # 4. Check for HTTP 400 Bad Request (acceptable for malformed auth, scheme mismatch, or invalid auth)
        if signature.status_code == 400:
            if ttype in ("AUTH_MALFORMED", "AUTH_SCHEME", "AUTH_INVALID"):
                return (
                    "PASS",
                    "Target rejected malformed or invalid authentication credential with HTTP 400 Bad Request.",
                    None,
                    None,
                )
            return (
                "INCONCLUSIVE",
                "Target returned HTTP 400 Bad Request; endpoint parameters or request format may be invalid.",
                None,
                "client_error",
            )

        # 5. Check for HTTP redirects to login/authentication (301, 302, 303, 307, 308)
        if signature.status_code in (301, 302, 303, 307, 308):
            return (
                "PASS",
                f"Target returned HTTP {signature.status_code} redirect, directing unauthenticated client to login or authentication gateway.",
                None,
                None,
            )

        # 6. Check for successful responses (HTTP 200, 201, 204)
        if signature.status_code in (200, 201, 204):
            data_suffix = f" (data indicators detected: {', '.join(data_indicators)})" if data_indicators else ""
            if ttype == "AUTH_MISSING":
                return (
                    "CONFIRMED",
                    f"Authentication bypass confirmed: protected endpoint accepted request without authentication headers and returned HTTP {signature.status_code} OK{data_suffix}.",
                    "AUTHENTICATION_BYPASS",
                    None,
                )
            elif ttype == "AUTH_INVALID":
                return (
                    "CONFIRMED",
                    f"Invalid authentication accepted: protected endpoint accepted forged or invalid credentials and returned HTTP {signature.status_code} OK{data_suffix}.",
                    "INVALID_AUTH_ACCEPTED",
                    None,
                )
            elif ttype == "AUTH_MALFORMED":
                return (
                    "CONFIRMED",
                    f"Malformed authentication accepted: protected endpoint accepted malformed authentication headers and returned HTTP {signature.status_code} OK{data_suffix}.",
                    "MALFORMED_AUTH_HANDLING",
                    None,
                )
            elif ttype == "AUTH_EXPIRED":
                return (
                    "CONFIRMED",
                    f"Expired credentials accepted: protected endpoint accepted expired authentication credentials and returned HTTP {signature.status_code} OK{data_suffix}.",
                    "EXPIRED_AUTH_ACCEPTED",
                    None,
                )
            elif ttype == "AUTH_SCHEME":
                return (
                    "CONFIRMED",
                    f"Authentication inconsistency: protected endpoint accepted incorrect authentication scheme and returned HTTP {signature.status_code} OK{data_suffix}.",
                    "AUTHENTICATION_INCONSISTENCY",
                    None,
                )
            else:
                return (
                    "CONFIRMED",
                    f"Protected endpoint granted access with HTTP {signature.status_code} OK{data_suffix}.",
                    "AUTHENTICATION_BYPASS",
                    None,
                )

        # 7. Fallback for other status codes (e.g. 404, 405, 422)
        return (
            "INCONCLUSIVE",
            f"Target returned unexpected HTTP status code {signature.status_code}.",
            None,
            "unexpected_status",
        )


extract_property_paths = ResponseAnalyzer.extract_property_paths
classify_property_heuristic = ResponseAnalyzer.classify_property_heuristic
discover_candidate_sensitive_properties = ResponseAnalyzer.discover_candidate_sensitive_properties
evaluate_authentication_result = ResponseAnalyzer.evaluate_authentication_result
is_application_denial = ResponseAnalyzer.is_application_denial
contains_protected_data = ResponseAnalyzer.contains_protected_data

