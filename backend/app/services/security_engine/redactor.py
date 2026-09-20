import re
from typing import Dict, Any, Optional, List

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "apikey",
    "x-auth-token",
    "proxy-authorization",
    "x-csrf-token",
    "session",
    "token",
}


def redact_headers(headers: Dict[str, Any]) -> Dict[str, str]:
    """
    Return a copy of headers where any sensitive keys have their values masked with [REDACTED].
    """
    redacted: Dict[str, str] = {}
    for key, value in headers.items():
        lower_key = key.lower()
        if lower_key in SENSITIVE_HEADER_NAMES:
            redacted[key] = "[REDACTED]"
        else:
            redacted[key] = str(value)
    return redacted


def redact_text(text: str, sensitive_values: Optional[List[str]] = None) -> str:
    """
    Replace known secret strings and common credential patterns in URLs/text.
    """
    if not text:
        return ""

    result = text
    if sensitive_values:
        for secret in sensitive_values:
            if secret and len(secret) > 2:
                result = result.replace(secret, "[REDACTED]")

    # Redact common token/secret patterns in query strings or json
    result = re.sub(r"(token|key|secret|password|bearer)=([^&\s\"']+)", r"\1=[REDACTED]", result, flags=re.IGNORECASE)
    result = re.sub(r'("(token|key|secret|password|bearer)"\s*:\s*)"([^"]+)"', r'\1"[REDACTED]"', result, flags=re.IGNORECASE)
    return result
