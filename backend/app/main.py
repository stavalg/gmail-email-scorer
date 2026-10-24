"""HTTP entry point of the Email Scorer backend."""
import logging
import time

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.auth import require_user
from app.config import get_settings
from app.models import MAX_REQUEST_BYTES, AnalyzeRequest, AnalyzeResponse
from app.pipeline import analyze_email

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
logger = logging.getLogger("email_scorer")

# API docs pages are disabled: there is no reason to publish our API surface.
app = FastAPI(title="Email Scorer", docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    """Refuse oversized requests before reading them. (Requests without a length are still
    bounded by the field limits and by Cloud Run's own 32 MB cap.)"""
    length = request.headers.get("content-length")
    if length is not None and (not length.isdigit() or int(length) > MAX_REQUEST_BYTES):
        return JSONResponse({"error": "request_too_large"}, status_code=413)
    return await call_next(request)


@app.exception_handler(RequestValidationError)
async def invalid_request(request: Request, exc: RequestValidationError) -> JSONResponse:
    # FastAPI's default error message repeats the input back; we never echo email content.
    return JSONResponse({"error": "invalid_request"}, status_code=422)


# Not "/healthz": Cloud Run reserves URL paths ending in "z".
@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/v1/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest, user: str = Depends(require_user)) -> AnalyzeResponse:
    started = time.perf_counter()
    try:
        result = await analyze_email(request, get_settings())
    except Exception as exc:  # noqa: BLE001
        # Never return a score after a failure, and never log content: type name only.
        logger.error("Analysis failed: %s", type(exc).__name__)
        raise HTTPException(status_code=500, detail="internal_error") from None
    logger.info(
        "analyzed verdict=%s score=%d duration_ms=%d coverage=%s",
        result.verdict, result.score, (time.perf_counter() - started) * 1000,
        {name: item.status for name, item in result.coverage.items()},
    )
    return result
