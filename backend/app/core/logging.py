import logging
import re
from typing import Any
import structlog
from asgi_correlation_id import correlation_id
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

def redact_sensitive_keys(logger: structlog.types.WrappedLogger, name: str, event_dict: structlog.types.EventDict) -> structlog.types.EventDict:
    """Redact sensitive data."""
    pattern = re.compile(r"(?i)(password|auth_key|token|secret|authorization|cookie|set-cookie|ciphertext|wrapped|recovery|code|key)")
    for key, value in list(event_dict.items()):
        if pattern.search(key):
            event_dict[key] = "[REDACTED]"
        elif isinstance(value, str) and len(value) > 1024:
            event_dict[key] = value[:1024] + "...[TRUNCATED]"
    return event_dict

def setup_logging(log_level: int = logging.INFO):
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            redact_sensitive_keys,
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    logging.basicConfig(format="%(message)s", level=log_level, handlers=[logging.StreamHandler()])
    # Disable uvicorn access logs
    logging.getLogger("uvicorn.access").handlers.clear()
    logging.getLogger("uvicorn.access").propagate = False

class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Any) -> Response:
        structlog.contextvars.bind_contextvars(
            request_id=correlation_id.get(),
            method=request.method,
            path=request.url.path,
        )
        response = await call_next(request)
        logger = structlog.get_logger("api.access")
        logger.info(
            "Request completed",
            status_code=response.status_code,
        )
        return response
