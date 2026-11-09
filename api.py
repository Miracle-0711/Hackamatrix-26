
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl, Field
from librarian import Librarian

app = FastAPI(
    title="Trustsheild AI - Librarian API",
    version="1.1.0"
)

librarian = Librarian()


class InvestigationRequest(BaseModel):
    target_url: HttpUrl
    claimed_brand: str | None = None
    findings: list = Field(default_factory=list)
    pasted_message: str = ""


@app.get("/")
def home():
    return {
        "service": "TRUSTSHEILD_AI",
        "status": "running"
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/investigate")
def investigate(request: InvestigationRequest):
    try:
        report = librarian.inspect_website(
            str(request.target_url),
            claimed_brand=request.claimed_brand,
            pasted_message=request.pasted_message
        )

        risk = report.get("risk_assessment") or {}

        score = risk.get("risk_score")
        evidence = risk.get("evidence", [])

        if not isinstance(evidence, list):
            evidence = []

        findings = [
            {
                "category": item.get("category", "AI_RISK"),
                "strength": item.get("strength", "INFO"),
                "reason": item.get("reason", "Risk evidence detected."),
                "points": item.get("points", 0)
            }
            for item in evidence
            if isinstance(item, dict)
        ]

        return {
            "service": "TRUSTSHEILD_AI",
            "status": report.get("status", "UNKNOWN"),
            "score_delta": (
                max(0, min(100, int(score)))
                if isinstance(score, (int, float))
                else 0
            ),
            "findings": findings,
            "ai_report": report
        }

    except Exception as error:
        print(f"[Librarian API Error] {error}")
        raise HTTPException(
            status_code=500,
            detail="Website investigation failed."
        )
