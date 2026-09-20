import base64
from typing import Dict, Tuple, Optional


class AuthAdapter:
    """
    Adapter that injects credentials into HTTP request headers or cookies
    based on identity auth_type.
    """

    @staticmethod
    def apply_auth(
        auth_type: str,
        credential_value: Optional[str],
        headers: Dict[str, str],
        cookies: Dict[str, str],
        config: Optional[dict] = None,
    ) -> Tuple[Dict[str, str], Dict[str, str]]:
        """
        Applies authentication parameters to headers and cookies.
        Returns modified (headers, cookies).
        """
        if not credential_value:
            return headers, cookies

        cfg = config or {}
        val = credential_value.strip()

        if auth_type == "bearer_token":
            # If value doesn't start with Bearer, prepend it
            if not val.lower().startswith("bearer "):
                val = f"Bearer {val}"
            headers["Authorization"] = val

        elif auth_type == "api_key":
            # Default header is X-API-Key or custom from config
            header_name = cfg.get("api_key_header", "X-API-Key")
            headers[header_name] = val

        elif auth_type == "basic_auth":
            # If user already encoded or provided user:pass
            if ":" in val and not val.lower().startswith("basic "):
                encoded = base64.b64encode(val.encode("utf-8")).decode("utf-8")
                headers["Authorization"] = f"Basic {encoded}"
            else:
                if not val.lower().startswith("basic "):
                    val = f"Basic {val}"
                headers["Authorization"] = val

        elif auth_type == "cookie_session":
            # Default cookie name is 'session' or custom
            cookie_name = cfg.get("cookie_name", "session")
            cookies[cookie_name] = val

        return headers, cookies
