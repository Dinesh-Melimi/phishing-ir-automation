"""Minimal FastAPI service. Auth via X-API-Key header compared in constant time.

Run: PHISHIR_API_KEY=changeme uvicorn phishir.api:app --port 8000
"""

from __future__ import annotations

import hmac
import os

from fastapi import Depends, FastAPI, File, HTTPException, Security, UploadFile, status
from fastapi.security import APIKeyHeader

from . import __version__
from .pipeline import analyze_bytes
from .report import to_markdown

MAX_BYTES = 10 * 1024 * 1024
app = FastAPI(title="phishir", version=__version__, description="Phishing IR triage API")
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_key(key: str | None = Security(api_key_header)) -> None:
    expected = os.getenv("PHISHIR_API_KEY")
    if not expected:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "API key not configured on server")
    if not key or not hmac.compare_digest(key, expected):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or missing API key")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.post("/analyze", dependencies=[Depends(require_key)])
async def analyze(file: UploadFile = File(...)) -> dict:
    data = await file.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "file too large")
    if not data:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "empty file")
    case = analyze_bytes(data)
    return {"case": case.to_dict(), "ticket_markdown": to_markdown(case)}
