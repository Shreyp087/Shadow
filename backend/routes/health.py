from __future__ import annotations

import os

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db_session
from app.core.deployment import missing_configuration

API_VERSION = "1.0.0"

router = APIRouter(tags=["health"])


@router.get("/api/status")
async def deployment_status() -> dict:
    missing = missing_configuration()
    return {
        "service": "ShadowLedger API",
        "status": "configuration_required" if missing else "configured",
        "version": API_VERSION,
        "missing_configuration": missing,
        "scan_execution": "vercel_workflow" if os.getenv("VERCEL") == "1" else "local_background",
    }


@router.get("/health")
@router.get("/api/health", include_in_schema=False)
async def healthcheck(
    db_session: AsyncSession = Depends(get_db_session),
) -> JSONResponse:
    payload = {
        "status": "ok",
        "version": API_VERSION,
        "db": "connected",
    }

    if os.getenv("VERCEL") == "1" and not os.getenv("DATABASE_URL", "").strip():
        payload.update(status="configuration_required", db="not_configured")
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content=payload)

    try:
        await db_session.execute(text("SELECT 1"))
        return JSONResponse(status_code=status.HTTP_200_OK, content=payload)
    except Exception:
        payload["db"] = "error"
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content=payload)
