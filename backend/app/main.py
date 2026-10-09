from contextlib import asynccontextmanager
from fastapi import FastAPI
from asgi_correlation_id import CorrelationIdMiddleware
from app.core.config import settings
from app.core.logging import setup_logging, LoggingMiddleware
from app.core.errors import AppError, app_error_handler
from app.core.middleware import SecurityHeadersMiddleware, RequestIdMiddleware, BodySizeLimitMiddleware
from app.api.v1.router import api_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    setup_logging()
    yield
    # Shutdown

def create_app() -> FastAPI:
    app = FastAPI(
        title="SentinelVault",
        docs_url="/docs" if settings.env != "production" else None,
        redoc_url="/redoc" if settings.env != "production" else None,
        openapi_url="/openapi.json" if settings.env != "production" else None,
        lifespan=lifespan
    )
    
    # Exception handlers
    app.add_exception_handler(AppError, app_error_handler)
    
    # Middleware
    app.add_middleware(CorrelationIdMiddleware)
    app.add_middleware(LoggingMiddleware)
    app.add_middleware(BodySizeLimitMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestIdMiddleware)
    
    # Routers
    app.include_router(api_router)
    
    return app

app = create_app()
