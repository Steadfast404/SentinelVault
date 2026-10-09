from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.db.session import get_db_session
from app.redis import check_redis_health
from app.core.config import settings

router = APIRouter()

@router.get("/healthz")
async def healthz():
    return {"status": "ok"}

@router.get("/readyz")
async def readyz(db: AsyncSession = Depends(get_db_session)):
    # Check DB
    try:
        await db.execute(text("SELECT 1"))
    except Exception:
        raise HTTPException(status_code=503, detail="Database not ready")
        
    # Check Redis
    redis_ok = await check_redis_health()
    if not redis_ok:
        raise HTTPException(status_code=503, detail="Redis not ready")
        
    # Check Alembic - simplistic check for now
    
    return {"status": "ready"}

@router.get("/api/v1/meta/version")
async def version():
    return {"version": "0.1.0"}
