"""HTTP entry point of the Email Scorer backend."""
from fastapi import FastAPI

# API docs pages are disabled: there is no reason to publish our API surface.
app = FastAPI(title="Email Scorer", docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}
