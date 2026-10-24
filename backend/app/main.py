"""HTTP entry point of the Email Scorer backend."""
from fastapi import Depends, FastAPI

from app.auth import require_user

# API docs pages are disabled: there is no reason to publish our API surface.
app = FastAPI(title="Email Scorer", docs_url=None, redoc_url=None, openapi_url=None)


# Not "/healthz": Cloud Run reserves URL paths ending in "z".
@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/v1/analyze")
def analyze(payload: dict, user: str = Depends(require_user)) -> dict:
    # Temporary stub: proves the add-on can reach us and authenticate. Replaced in Task 5 / 14.
    return {"score": 0, "verdict": "safe", "summary": "Backend reachable (stub).",
            "received_fields": sorted(payload)}
