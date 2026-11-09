
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl, Field
from urllib.parse import urlparse
import requests
import socket
import ipaddress

app = FastAPI(
    title="Trustsheild AI - Librarian API",
    version="2.0.0"
)


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
    return {
        "status": "ok",
        "service": "librarian"
    }


@app.post("/investigate")
def investigate(request: InvestigationRequest):
    url = str(request.target_url)
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise HTTPException(
            status_code=400,
            detail="Invalid URL scheme"
        )

    try:
        addresses = socket.getaddrinfo(parsed.hostname, None)

        for address in addresses:
            ip = ipaddress.ip_address(address[4][0])

            if not ip.is_global:
                raise HTTPException(
                    status_code=400,
                    detail="Private address blocked"
                )

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Could not resolve website"
        )

    findings = list(request.findings)
    score = 0

    suspicious_phrases = [
        "verify your account",
        "urgent action required",
        "send your otp",
        "claim your prize",
        "password immediately"
    ]

    message = request.pasted_message.lower()

    for phrase in suspicious_phrases:
        if phrase in message:
            findings.append({
                "category": "SUSPICIOUS_MESSAGE",
                "strength": "WARNING",
                "reason": f"Suspicious phrase detected: {phrase}",
                "points": 20
            })
            score += 20

    if parsed.scheme == "http":
        findings.append({
            "category": "INSECURE_CONNECTION",
            "strength": "WARNING",
            "reason": "Website does not use HTTPS",
            "points": 15
        })
        score += 15

    try:
        response = requests.get(
            url,
            timeout=8,
            allow_redirects=False,
            verify=True,
            headers={"User-Agent": "TrustsheildAI/1.0"}
        )

        if response.status_code >= 400:
            findings.append({
                "category": "HTTP_ERROR",
                "strength": "INFO",
                "reason": f"Website returned HTTP {response.status_code}",
                "points": 10
            })
            score += 10

    except requests.RequestException:
        findings.append({
            "category": "CONNECTION_ERROR",
            "strength": "WARNING",
            "reason": "Website could not be reached safely",
            "points": 15
        })
        score += 15

    score = min(score, 100)

    risk_level = (
        "HIGH" if score >= 60
        else "MEDIUM" if score >= 30
        else "LOW"
    )

    return {
        "service": "TRUSTSHEILD_AI",
        "status": risk_level,
        "score_delta": score,
        "findings": findings,
        "ai_report": {
            "risk_assessment": {
                "risk_score": score,
                "risk_level": risk_level,
                "evidence": findings
            },
            "message": "Rule-based website investigation completed."
        }
    }
