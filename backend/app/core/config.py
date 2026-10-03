import os
from typing import List


class Settings:
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./sentinel.db")
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    DEBUG: bool = os.getenv("DEBUG", "true").lower() in ("true", "1", "yes")
    SENTINEL_API_TOKEN: str = os.getenv("SENTINEL_API_TOKEN", "")
    SENTINEL_ENFORCE_AUTH: bool = os.getenv("SENTINEL_ENFORCE_AUTH", "false").lower() in ("true", "1", "yes")
    RATE_LIMIT_ENABLED: bool = os.getenv("RATE_LIMIT_ENABLED", "false").lower() in ("true", "1", "yes")
    
    @property
    def CORS_ORIGINS(self) -> List[str]:
        raw = os.getenv("SENTINEL_CORS_ORIGINS", "")
        if raw:
            return [origin.strip() for origin in raw.split(",") if origin.strip()]
        if self.ENVIRONMENT == "production":
            return ["http://localhost:3000"]
        return ["*"]

    def validate_production_configuration(self) -> List[str]:
        """Validate security settings when running in production."""
        issues = []
        if self.ENVIRONMENT == "production":
            if self.DEBUG:
                issues.append("DEBUG must be disabled in production.")
            if not self.SENTINEL_API_TOKEN and not self.SENTINEL_ENFORCE_AUTH:
                issues.append("Authentication enforcement must be enabled in production.")
            if "*" in self.CORS_ORIGINS:
                issues.append("CORS wildcard origin '*' is forbidden in production.")
        return issues


settings = Settings()
