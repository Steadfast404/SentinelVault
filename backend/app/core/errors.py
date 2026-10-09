from fastapi import Request
from fastapi.responses import JSONResponse
from typing import Any, Dict

class AppError(Exception):
    def __init__(self, code: str, status: int, detail: str, extra: Dict[str, Any] = None):
        self.code = code
        self.status = status
        self.detail = detail
        self.extra = extra or {}
        super().__init__(detail)

async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
    content = {
        "type": f"about:blank",
        "title": exc.code,
        "status": exc.status,
        "detail": exc.detail,
        **exc.extra
    }
    return JSONResponse(status_code=exc.status, content=content, headers={"Content-Type": "application/problem+json"})
