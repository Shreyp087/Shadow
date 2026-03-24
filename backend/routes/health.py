from __future__ import annotations

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db_session

API_VERSION = "1.0.0"

router = APIRouter(tags=["health"])


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

    try:
        await db_session.execute(text("SELECT 1"))
        return JSONResponse(status_code=status.HTTP_200_OK, content=payload)
    except Exception:
        payload["db"] = "error"
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content=payload)
