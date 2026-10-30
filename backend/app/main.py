import os

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import get_settings
from app.core.deployment import missing_configuration
from routes.analytics import router as analytics_router
from routes.attack_runs import router as attack_runs_router
from routes.health import router as health_router
from routes.llm_role_settings import router as llm_role_settings_router
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


@app.middleware("http")
async def add_api_security_headers(request: Request, call_next) -> Response:
    if (
        os.getenv("VERCEL") == "1"
        and request.url.path.startswith("/api/v1/")
        and missing_configuration()
    ):
        response = JSONResponse(
            status_code=503,
            content={"data": None, "error": "Service configuration is incomplete.", "meta": {}},
        )
    else:
        response = await call_next(request)
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
    return response


app.include_router(health_router)
app.include_router(attack_runs_router)
app.include_router(analytics_router)
app.include_router(target_systems_router)
app.include_router(llm_role_settings_router)


@app.get("/", tags=["meta"])
async def root() -> dict[str, str]:
    return {"service": settings.app_name, "status": "running"}
