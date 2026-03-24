from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from routes.analytics import router as analytics_router
from routes.attack_runs import router as attack_runs_router
from routes.health import router as health_router
from routes.target_systems import router as target_systems_router

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    summary="ShadowLedger backend API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router)
app.include_router(attack_runs_router)
app.include_router(analytics_router)
app.include_router(target_systems_router)


@app.get("/", tags=["meta"])
async def root() -> dict[str, str]:
    return {"service": settings.app_name, "status": "running"}
