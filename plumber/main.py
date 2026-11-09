
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from plumber.orchestrator import PlumberOrchestrator


orchestrator = PlumberOrchestrator(
    bouncer_url="http://127.0.0.1:8002/v1/scan",
    librarian_url="http://127.0.0.1:8001/investigate",
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


# Allow requests from the local Vite frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class InvestigateRequest(BaseModel):
    url: str = Field(
        ...,
        examples=["https://example.com"],
    )
    pasted_message: str = Field(
        default="",
        examples=["Urgent action required: verify your account"],
    )


class VerifyReportRequest(BaseModel):
    report_hash: str
    report: Dict[str, Any]


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
