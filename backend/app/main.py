from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.router import router
from app.demo_target import demo_target_router
from app.core.db import create_tables


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_tables()
    yield


app = FastAPI(
    title="SentinelAPI",
    description="API Security Testing Platform",
    version="1.0.0",
    lifespan=lifespan,
)

import os
from fastapi import Request
from fastapi.responses import JSONResponse

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def api_token_auth_middleware(request: Request, call_next):
    configured_token = os.environ.get("SENTINEL_API_TOKEN")
    if configured_token:
        path = request.url.path
        if path.startswith("/api/v1") and not path.startswith(("/docs", "/redoc", "/openapi.json")):
            auth_header = request.headers.get("Authorization", "")
            api_key_header = request.headers.get("X-API-Key", "")

            token = ""
            if auth_header.startswith("Bearer "):
                token = auth_header[7:].strip()
            elif api_key_header:
                token = api_key_header.strip()

            if not token or token != configured_token:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid or missing API token."},
                    headers={"WWW-Authenticate": "Bearer"},
                )
    return await call_next(request)


app.include_router(router, prefix="/api/v1")
app.include_router(demo_target_router)


@app.get("/")
async def root():
    return {"message": "SentinelAPI is running"}