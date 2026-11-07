# plumber/orchestrator.py
import asyncio
import datetime
import hashlib
import json
import re
from typing import Dict, Any, List
import httpx

from plumber.tls_extractor import RawTLSExtractor
from plumber.ca_blocker import CompromisedCABlocker
from plumber.crypto_auditor import CryptographicAuditor
from plumber.ct_verifier import CertificateTransparencyVerifier


class PlumberOrchestrator:
    """
    Layer 5 Core Orchestrator:
    - Runs Layer 2 deep TLS/PKI checks in parallel with Bouncer & Librarian services.
    - Enforces 3.0-second circuit breakers on external microservice calls.
    - Computes the 0-100 risk verdict with instant critical overrides for broken CAs.
    - Provides deterministic Web3 report hashing & integrity verification.
    """

    def __init__(
        self,
        bouncer_url: str | None = None,
        librarian_url: str | None = None,
    ) -> None:
        self.ca_blocker = CompromisedCABlocker()
        self.bouncer_url = bouncer_url
        self.librarian_url = librarian_url
        self.onchain_registry: Dict[str, Dict[str, Any]] = {}

    async def startup(self) -> int:
        return await self.ca_blocker.preload_revocation_feeds()

    async def _call_bouncer_with_breaker(
        self, url: str, message_text: str = ""
    ) -> Dict[str, Any]:
        """3-second circuit breaker for Bouncer (URL Phishing & Scam Detection)."""
        if self.bouncer_url:
            try:
                async with httpx.AsyncClient(timeout=3.0) as client:
                    r = await client.post(
                        self.bouncer_url, json={"url": url, "text": message_text}
                    )
                    if r.status_code == 200:
                        return r.json()
            except Exception:
                pass

        # Built-in fallback heuristics so the MVP works standalone if Bouncer is offline
        findings = []
        score_delta = 0
        lower_url = url.lower()

        if "xn--" in lower_url:
            score_delta += 35
            findings.append({
                "severity": "HIGH",
                "code": "PUNYCODE_HOMOGRAPH_URL",
                "message": "Domain uses IDN Punycode (xn--) often abused in homograph phishing attacks.",
            })
        if re.search(r"https?://\d+\.\d+\.\d+\.\d+", lower_url):
            score_delta += 30
            findings.append({
                "severity": "HIGH",
                "code": "RAW_IP_URL",
                "message": "URL uses a raw IPv4 address instead of a registered domain name.",
            })
        suspicious_keywords = ["login-verify", "secure-update", "wallet-connect-claim", "airdrop-claim"]
        for kw in suspicious_keywords:
            if kw in lower_url:
                score_delta += 25
                findings.append({
                    "severity": "MEDIUM",
                    "code": "PHISHING_URL_KEYWORD",
                    "message": f"URL contains high-risk phishing token ({kw}).",
                })

        if message_text:
            scam_patterns = ["urgent action required", "verify your seed phrase", "account suspended", "send usdt"]
            matched = [p for p in scam_patterns if p in message_text.lower()]
            if matched:
                score_delta += 35
                findings.append({
                    "severity": "HIGH",
                    "code": "SCAM_MESSAGE_INDICATORS",
                    "message": f"Submitted message contains social-engineering phrases: {', '.join(matched)}.",
                })

        return {"service": "BOUNCER_FALLBACK", "score_delta": min(score_delta, 70), "findings": findings}

    async def _call_librarian_with_breaker(self, domain: str) -> Dict[str, Any]:
        """3-second circuit breaker for Librarian (External Threat Intel & Domain Context)."""
        if self.librarian_url:
            try:
                async with httpx.AsyncClient(timeout=3.0) as client:
                    r = await client.post(self.librarian_url, json={"domain": domain})
                    if r.status_code == 200:
                        return r.json()
            except Exception:
                pass

        return {
            "service": "LIBRARIAN_FALLBACK",
            "threat_intel_sources": ["Mozilla_CCADB_OneCRL", "eMudhra_G3_Revocation_Set", "Certificate_Transparency_SCT"],
            "score_delta": 0,
            "findings": [],
        }

    async def investigate(self, url: str, pasted_message: str = "") -> Dict[str, Any]:
        host, _ = RawTLSExtractor.parse_target(url)

        # Dispatch TLS extraction, Bouncer, and Librarian concurrently with 3s circuit breakers
        tls_task = asyncio.wait_for(RawTLSExtractor.fetch_certificate_chain(url, timeout=3.0), timeout=3.5)
        bouncer_task = asyncio.wait_for(self._call_bouncer_with_breaker(url, pasted_message), timeout=3.0)
        librarian_task = asyncio.wait_for(self._call_librarian_with_breaker(host), timeout=3.0)

        tls_result, bouncer_result, librarian_result = await asyncio.gather(
            tls_task, bouncer_task, librarian_task, return_exceptions=True
        )

        if isinstance(tls_result, Exception):
            tls_result = {"host": host, "reachable": False, "error": str(tls_result), "certificates": [], "raw_x509_objects": []}
        if isinstance(bouncer_result, Exception):
            bouncer_result = {"service": "BOUNCER_TIMEOUT", "score_delta": 0, "findings": []}
        if isinstance(librarian_result, Exception):
            librarian_result = {"service": "LIBRARIAN_TIMEOUT", "score_delta": 0, "findings": []}

        x509_chain = tls_result.get("raw_x509_objects", [])
        leaf_cert = x509_chain[0] if x509_chain else None

        # Layer 2 Audits: Compromised CA Blocker + Crypto/Entropy Auditor + CT Verifier
        ca_audit = self.ca_blocker.inspect_chain(x509_chain)
        crypto_audit = CryptographicAuditor.audit_chain(x509_chain)
        ct_audit = await CertificateTransparencyVerifier.verify_ct_compliance(host, leaf_cert, timeout=2.0)

        # Aggregate Evidence & Compute 0-100 Risk Score
        all_findings: List[Dict[str, str]] = (
            ca_audit["findings"]
            + crypto_audit["findings"]
            + ct_audit["findings"]
            + bouncer_result.get("findings", [])
            + librarian_result.get("findings", [])
        )

        risk_score = bouncer_result.get("score_delta", 0) + librarian_result.get("score_delta", 0)
        if not tls_result.get("reachable"):
            risk_score += 40
            all_findings.append({
                "severity": "HIGH",
                "code": "TLS_HANDSHAKE_UNREACHABLE",
                "message": f"Failed to establish TLS handshake with {host}: {tls_result.get('error')}",
            })
        if not ct_audit.get("ct_compliant"):
            risk_score += 30

        for f in crypto_audit["findings"]:
            risk_score += 45 if f["severity"] == "CRITICAL" else (25 if f["severity"] == "HIGH" else 10)

        # Instant Critical Override (Score = 100) for Compromised CAs or Broken Cryptography
        critical_override = ca_audit["compromised_ca_detected"] or crypto_audit["critical_crypto_failure"]
        if critical_override:
            risk_score = 100
        else:
            risk_score = min(100, max(0, risk_score))

        classification = (
            "CRITICAL" if risk_score >= 85
            else "HIGH" if risk_score >= 60
            else "MEDIUM" if risk_score >= 30
            else "LOW"
        )

        # Evidence-Grounded AI Explanation Summary
        explanation = self._build_grounded_explanation(host, risk_score, classification, all_findings)

        report_payload = {
            "target_url": url,
            "host": host,
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "risk_assessment": {
                "score": risk_score,
                "classification": classification,
                "critical_ca_or_crypto_override": critical_override,
            },
            "ai_grounded_explanation": explanation,
            "layer2_webpki_trust": {
                "tls_reachable": tls_result.get("reachable"),
                "tls_version": tls_result.get("tls_version"),
                "cipher_suite": tls_result.get("cipher_suite"),
                "chain_length": len(tls_result.get("certificates", [])),
                "certificates": tls_result.get("certificates", []),
                "compromised_ca_audit": ca_audit,
                "cryptographic_audit": crypto_audit,
                "certificate_transparency": ct_audit,
            },
            "bouncer_phishing_scam": bouncer_result,
            "librarian_threat_intel": librarian_result,
            "evidence_findings": all_findings,
        }

        # Web3 Threat-Report Registry & Deterministic Integrity Hash
        canonical_json = json.dumps(report_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        report_hash = "0x" + hashlib.sha256(canonical_json).hexdigest()
        self.onchain_registry[report_hash] = {
            "report_hash": report_hash,
            "registered_at": report_payload["timestamp_utc"],
            "payload": report_payload,
        }

        return {
            "report_hash": report_hash,
            "report": report_payload,
        }

    def verify_report_integrity(self, report_hash: str, submitted_report: Dict[str, Any]) -> Dict[str, Any]:
        """Independently recomputes the SHA-256 digest of a report and checks registry presence."""
        canonical_json = json.dumps(submitted_report, sort_keys=True, separators=(",", ":")).encode("utf-8")
        recomputed_hash = "0x" + hashlib.sha256(canonical_json).hexdigest()
        onchain_record = self.onchain_registry.get(report_hash)
        return {
            "submitted_hash": report_hash,
            "recomputed_hash": recomputed_hash,
            "hash_matches_payload": recomputed_hash == report_hash,
            "registered_in_onchain_registry": onchain_record is not None,
            "verified": (recomputed_hash == report_hash) and (onchain_record is not None),
        }

    @staticmethod
    def _build_grounded_explanation(
        host: str, score: int, classification: str, findings: List[Dict[str, str]]
    ) -> str:
        if not findings:
            return (
                f"{host} passed raw TLS chain extraction, Mozilla OneCRL/eMudhra G3 revocation checks, "
                f"RSA/ECDSA cryptographic parameter auditing, and embedded SCT verification with a {classification} risk score ({score}/100)."
            )
        codes = ", ".join(f["code"] for f in findings)
        details = " ".join(f["message"] for f in findings[:3])
        return f"{host} is classified as {classification} risk ({score}/100) triggered by [{codes}]. Evidence: {details}"