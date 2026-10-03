import logging
import os
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.router import router
from app.demo_target import demo_target_router
from app.core.config import settings
from app.core.db import create_tables, get_db
from app.core.rate_limit import rate_limiter
from app.core.security import constant_time_compare
from app.services.auth.token_service import token_service
from app.services.auth.permission_service import seed_permissions

logger = logging.getLogger("sentinel.app")


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_tables()
    # Seed standard permissions on startup
    db = get_db()
    try:
        seed_permissions(db)
    except Exception as e:
        logger.warning(f"Permission seeding notice: {e}")
    finally:
        db.close()
    yield


app = FastAPI(
    title="SentinelAPI",
    description="API Security Testing Platform",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_and_auth_middleware(request: Request, call_next):
    # 1. Request correlation ID
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = request_id

    # 2. Rate limiting (if enabled)
    if settings.RATE_LIMIT_ENABLED and request.url.path.startswith("/api/v1/auth"):
        client_ip = request.client.host if request.client else "unknown"
        allowed, remaining, retry_after = rate_limiter.is_allowed(client_ip, limit=30, window_seconds=60)
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Please try again later.", "request_id": request_id},
                headers={"Retry-After": str(retry_after), "X-Request-ID": request_id}
            )

    # 3. Authentication check for API routes
    path = request.url.path
    if path.startswith("/api/v1") and not path.startswith(("/docs", "/redoc", "/openapi.json")):
        auth_header = request.headers.get("Authorization", "")
        api_key_header = request.headers.get("X-API-Key", "")

        token = ""
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
        elif api_key_header:
            token = api_key_header.strip()

        # If a token is provided, authenticate it strictly
        if token:
            valid = False
            # Check system token first
            if settings.SENTINEL_API_TOKEN and constant_time_compare(token, settings.SENTINEL_API_TOKEN):
                valid = True
            else:
                # Check DB-backed user tokens
                db = get_db()
                try:
                    auth_result = token_service.authenticate_token(db, token)
                    if auth_result:
                        valid = True
                        request.state.user = auth_result[0]
                        request.state.token = auth_result[1]
                finally:
                    db.close()

            if not valid:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid or expired API token.", "request_id": request_id},
                    headers={"WWW-Authenticate": "Bearer", "X-Request-ID": request_id},
                )
        elif settings.SENTINEL_ENFORCE_AUTH:
            return JSONResponse(
                status_code=401,
                content={"detail": "Authentication required.", "request_id": request_id},
                headers={"WWW-Authenticate": "Bearer", "X-Request-ID": request_id},
            )

    # 4. Process request
    response = await call_next(request)

    # 5. Security headers
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "1; mode=block"

    return response


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    request_id = getattr(request.state, "request_id", None) or str(uuid.uuid4())
    headers = dict(exc.headers) if exc.headers else {}
    headers["X-Request-ID"] = request_id
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "request_id": request_id},
        headers=headers,
    )


app.include_router(router, prefix="/api/v1")
app.include_router(demo_target_router)


@app.get("/")
async def root():
    return {"message": "SentinelAPI is running"}