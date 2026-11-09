
import os
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from plumber.orchestrator import PlumberOrchestrator


BOUNCER_URL = os.getenv(
    "BOUNCER_URL",
    "http://127.0.0.1:8002/v1/scan",
)

LIBRARIAN_URL = os.getenv(
    "LIBRARIAN_URL",
    "http://127.0.0.1:8001/investigate",
)

FRONTEND_ORIGINS = [
    origin.strip().rstrip("/")
    for origin in os.getenv(
        "FRONTEND_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if origin.strip()
]

orchestrator = PlumberOrchestrator(
    bouncer_url=BOUNCER_URL,
    librarian_url=LIBRARIAN_URL,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    loaded_count = await orchestrator.startup()
    print(
        f"[Plumber Startup] Loaded {loaded_count} revoked CA "
        "SHA-256 fingerprints into O(1) memory set."
    )
    yield


app = FastAPI(
    title="The Plumber — Layer 2 Deep Protocols & Layer 5 Risk Orchestrator",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class InvestigateRequest(BaseModel):
    url: str = Field(..., examples=["https://example.com"])
    pasted_message: str = Field(
        default="",
        examples=["Urgent action required: verify your account"],
    )


class VerifyReportRequest(BaseModel):
    report_hash: str
    report: Dict[str, Any]


@app.get("/health")
async def health():
    return {"status": "ok", "service": "plumber"}


@app.post("/api/v1/investigate")
async def investigate_target(
    req: InvestigateRequest,
) -> Dict[str, Any]:
    return await orchestrator.investigate(
        url=req.url,
        pasted_message=req.pasted_message,
    )


@app.post("/api/v1/verify-report")
async def verify_report(
    req: VerifyReportRequest,
) -> Dict[str, Any]:
    return orchestrator.verify_report_integrity(
        req.report_hash,
        req.report,
    )
