from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.router import router
from app.demo_target import demo_target_router

app = FastAPI(
    title="SentinelAPI",
    description="API Security Testing Platform",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api/v1")
app.include_router(demo_target_router)


@app.get("/")
async def root():
    return {"message": "SentinelAPI is running"}