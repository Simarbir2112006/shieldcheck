"""FastAPI app exposing the ShieldCheck scan endpoint."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import scanner

app = FastAPI(title="ShieldCheck")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    url: str
    email_text: str | None = None


@app.post("/scan")
async def scan_endpoint(request: ScanRequest):
    return await scanner.scan(request.url, request.email_text)


@app.get("/health")
async def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
