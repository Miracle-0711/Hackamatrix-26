
import asyncio
import datetime
import hashlib
import json
import os
import re
import time
from typing import Dict, Any, List

import httpx
import jwt

from plumber.tls_extractor import RawTLSExtractor
from plumber.ca_blocker import CompromisedCABlocker
from plumber.crypto_auditor import CryptographicAuditor
from plumber.ct_verifier import CertificateTransparencyVerifier


class PlumberOrchestrator:

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
        self,
        url: str,
        message_text: str = "",
    ) -> Dict[str, Any]:

        if self.bouncer_url:
            jwt_secret = os.getenv("JWT_SECRET")

            if jwt_secret:
                token = jwt.encode(
                    {
                        "iss": "bouncer-auth",
                        "aud": "bouncer-api",
                        "sub": "plumber-service",
                        "iat": int(time.time()),
                        "exp": int(time.time()) + 60,
                        "scope": "scan:basic",
                    },
                    jwt_secret,
                    algorithm="HS256",
                )

                try:
                    async with httpx.AsyncClient(timeout=8.0) as client:
                        response = await client.post(
                            self.bouncer_url,
                            json={
                                "url": url,
                                "text": message_text,
                                "probe_exposure": False,
                            },
                            headers={
                                "Authorization": f"Bearer {token}"
                            },
                        )

                        if response.status_code == 200:
                            return response.json()

                        print(
                            f"Bouncer rejected request: "
                            f"{response.status_code} - {response.text}"
                        )

                except Exception as exc:
                    print(f"Bouncer connection failed: {exc}")

            else:
                print("Bouncer authentication failed: JWT_SECRET missing.")

        findings = []
        score_delta = 0
        lower_url = url.lower()

        if "xn--" in lower_url:
            score_delta += 35
            findings.append({
                "severity": "HIGH",
                "code": "PUNYCODE_HOMOGRAPH_URL",
                "message": "Domain uses IDN Punycode.",
            })

        if re.search(r"https?://\d+\.\d+\.\d+\.\d+", lower_url):
            score_delta += 30
            findings.append({
                "severity": "HIGH",
                "code": "RAW_IP_URL",
                "message": "URL uses a raw IPv4 address.",
            })

        suspicious_keywords = [
            "login-verify",
            "secure-update",
            "wallet-connect-claim",
            "airdrop-claim",
        ]

        for keyword in suspicious_keywords:
            if keyword in lower_url:
                score_delta += 25
                findings.append({
                    "severity": "MEDIUM",
                    "code": "PHISHING_URL_KEYWORD",
                    "message": f"URL contains suspicious keyword: {keyword}.",
                })

        if message_text:
            scam_patterns = [
                "urgent action required",
                "verify your seed phrase",
                "account suspended",
                "send usdt",
            ]

            matched = [
                pattern for pattern in scam_patterns
                if pattern in message_text.lower()
            ]

            if matched:
                score_delta += 35
                findings.append({
                    "severity": "HIGH",
                    "code": "SCAM_MESSAGE_INDICATORS",
                    "message": (
                        "Submitted message contains suspicious phrases: "
                        + ", ".join(matched)
                    ),
                })

        return {
            "service": "BOUNCER_FALLBACK",
            "score_delta": min(score_delta, 70),
            "findings": findings,
        }

    async def _call_librarian_with_breaker(
        self,
        target_url: str,
        findings: List[Dict[str, Any]],
        pasted_message: str = "",
    ) -> Dict[str, Any]:

        if self.librarian_url:
            try:
                async with httpx.AsyncClient(timeout=20.0) as client:
                    response = await client.post(
                        self.librarian_url,
                        json={
                            "target_url": target_url,
                            "findings": findings,
                            "pasted_message": pasted_message,
                        },
                    )

                    if response.status_code == 200:
                        data = response.json()

                        ai_report = data.get("ai_report", {})
                        ai_risk = ai_report.get(
                            "risk_assessment", {}
                        )

                        raw_score = data.get(
                            "score_delta",
                            ai_risk.get("risk_score", 0),
                        )

                        try:
                            ai_score = int(raw_score or 0)
                        except (TypeError, ValueError):
                            ai_score = 0

                        data["score_delta"] = max(
                            0, min(100, ai_score)
                        )

                        ai_evidence = data.get("findings", [])

                        if not isinstance(ai_evidence, list):
                            ai_evidence = []

                        if not ai_evidence:
                            ai_evidence = ai_risk.get("evidence", [])

                        if not isinstance(ai_evidence, list):
                            ai_evidence = []

                        data["findings"] = [
                            {
                                "severity": item.get(
                                    "strength", "INFO"
                                ),
                                "code": item.get(
                                    "category", "AI_RISK"
                                ),
                                "message": item.get(
                                    "reason",
                                    "AI risk evidence detected.",
                                ),
                            }
                            for item in ai_evidence
                            if isinstance(item, dict)
                        ]

                        return data

                    print(
                        f"Librarian rejected request: "
                        f"{response.status_code} - {response.text}"
                    )

            except Exception as exc:
                print(f"Librarian connection failed: {exc}")

        return {
            "service": "LIBRARIAN_FALLBACK",
            "score_delta": 0,
            "findings": [],
        }

    async def investigate(
        self,
        url: str,
        pasted_message: str = "",
    ) -> Dict[str, Any]:

        host, _ = RawTLSExtractor.parse_target(url)

        tls_task = asyncio.wait_for(
            RawTLSExtractor.fetch_certificate_chain(
                url,
                timeout=3.0,
            ),
            timeout=3.5,
        )

        bouncer_task = asyncio.wait_for(
            self._call_bouncer_with_breaker(
                url,
                pasted_message,
            ),
            timeout=10.0,
        )

        librarian_task = asyncio.wait_for(
            self._call_librarian_with_breaker(
                url,
                [],
                pasted_message,
            ),
            timeout=22.0,
        )

        tls_result, bouncer_result, librarian_result = (
            await asyncio.gather(
                tls_task,
                bouncer_task,
                librarian_task,
                return_exceptions=True,
            )
        )

        if isinstance(tls_result, Exception):
            tls_result = {
                "host": host,
                "reachable": False,
                "error": str(tls_result),
                "certificates": [],
                "raw_x509_objects": [],
            }

        if isinstance(bouncer_result, Exception):
            bouncer_result = {
                "service": "BOUNCER_TIMEOUT",
                "score_delta": 0,
                "findings": [],
            }

        if isinstance(librarian_result, Exception):
            librarian_result = {
                "service": "LIBRARIAN_TIMEOUT",
                "score_delta": 0,
                "findings": [],
            }

        x509_chain = tls_result.get("raw_x509_objects", [])
        leaf_cert = x509_chain[0] if x509_chain else None

        ca_audit = self.ca_blocker.inspect_chain(x509_chain)

        crypto_audit = CryptographicAuditor.audit_chain(
            x509_chain
        )

        ct_audit = (
            await CertificateTransparencyVerifier.verify_ct_compliance(
                host,
                leaf_cert,
                timeout=2.0,
            )
        )

        bouncer_findings = bouncer_result.get("findings", [])
        librarian_findings = librarian_result.get("findings", [])

        all_findings = (
            ca_audit.get("findings", [])
            + crypto_audit.get("findings", [])
            + ct_audit.get("findings", [])
            + bouncer_findings
            + librarian_findings
        )

        risk_score = (
            bouncer_result.get("score_delta", 0)
            + librarian_result.get("score_delta", 0)
        )

        if not tls_result.get("reachable"):
            risk_score += 40

            all_findings.append({
                "severity": "HIGH",
                "code": "TLS_HANDSHAKE_UNREACHABLE",
                "message": (
                    f"Failed to establish TLS handshake with {host}: "
                    f"{tls_result.get('error')}"
                ),
            })

        if not ct_audit.get("ct_compliant"):
            risk_score += 30

        for finding in crypto_audit.get("findings", []):
            severity = str(
                finding.get("severity", "")
            ).upper()

            risk_score += (
                45 if severity == "CRITICAL"
                else 25 if severity == "HIGH"
                else 10
            )

        critical_override = (
            ca_audit.get("compromised_ca_detected", False)
            or crypto_audit.get("critical_crypto_failure", False)
        )

        if critical_override:
            risk_score = 100
        else:
            risk_score = min(100, max(0, risk_score))

        # Bouncer confirmation
        bouncer_verdict = str(
            bouncer_result.get("verdict", "")
        ).lower()

        bouncer_confirmed = (
            bouncer_verdict in {
                "critical",
                "high",
                "suspicious",
            }
            or any(
                str(item.get("severity", "")).upper()
                in {"HIGH", "CRITICAL"}
                for item in bouncer_findings
                if isinstance(item, dict)
            )
        )

        # Ignore weak security-configuration-only evidence.
        meaningful_librarian_findings = [
            item for item in librarian_findings
            if isinstance(item, dict)
            and str(item.get("code", "")).upper()
            not in {
                "SECURITY_HEADERS",
                "MISSING_SECURITY_HEADERS",
            }
            and str(item.get("severity", "")).upper()
            in {"MODERATE", "HIGH", "CRITICAL", "STRONG"}
        ]

        ai_report = librarian_result.get("ai_report", {})
        threat_info = ai_report.get("threat_intelligence", {})

        if not isinstance(threat_info, dict):
            threat_info = {}

        threat_status = str(
            threat_info.get("status", "")
        ).upper()

        librarian_confirmed = (
            librarian_result.get("service") not in {
                "LIBRARIAN_FALLBACK",
                "LIBRARIAN_TIMEOUT",
            }
            and (
                threat_status == "THREAT_FOUND"
                or bool(meaningful_librarian_findings)
            )
        )

        # Final classification
        if critical_override or risk_score >= 85:
            classification = "CRITICAL"

        elif risk_score >= 60:
            classification = "HIGH"

        elif risk_score >= 30:
            classification = "MEDIUM"

        elif bouncer_confirmed or librarian_confirmed:
            classification = "LOW"

        else:
            classification = "UNKNOWN"

        explanation = self._build_grounded_explanation(
            host,
            risk_score,
            classification,
            all_findings,
        )

        report_payload = {
            "target_url": url,
            "host": host,
            "timestamp_utc": datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat(),

            "risk_assessment": {
                "score": risk_score,
                "classification": classification,
                "critical_ca_or_crypto_override": critical_override,
                "assessment_status": (
                    "ASSESSED"
                    if (
                        bouncer_confirmed
                        or librarian_confirmed
                        or critical_override
                    )
                    else "INSUFFICIENT_EVIDENCE"
                ),
            },

            "ai_grounded_explanation": explanation,

            "layer2_webpki_trust": {
                "tls_reachable": tls_result.get("reachable"),
                "tls_version": tls_result.get("tls_version"),
                "cipher_suite": tls_result.get("cipher_suite"),
                "chain_length": len(
                    tls_result.get("certificates", [])
                ),
                "certificates": tls_result.get("certificates", []),
                "compromised_ca_audit": ca_audit,
                "cryptographic_audit": crypto_audit,
                "certificate_transparency": ct_audit,
            },

            "bouncer_phishing_scam": bouncer_result,
            "librarian_threat_intel": librarian_result,
            "evidence_findings": all_findings,

            "limitations": [
                "UNKNOWN means insufficient evidence, not safe.",
                "A valid TLS certificate does not prove website legitimacy.",
                "Heuristic detection cannot guarantee detection of every phishing URL.",
                "No direct Google Safe Browsing API integration is enabled.",
            ],
        }

        canonical_json = json.dumps(
            report_payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        report_hash = (
            "0x" + hashlib.sha256(canonical_json).hexdigest()
        )

        self.onchain_registry[report_hash] = {
            "report_hash": report_hash,
            "registered_at": report_payload["timestamp_utc"],
            "payload": report_payload,
        }

        return {
            "report_hash": report_hash,
            "report": report_payload,
        }

    def verify_report_integrity(
        self,
        report_hash: str,
        submitted_report: Dict[str, Any],
    ) -> Dict[str, Any]:

        canonical_json = json.dumps(
            submitted_report,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        recomputed_hash = (
            "0x" + hashlib.sha256(canonical_json).hexdigest()
        )

        onchain_record = self.onchain_registry.get(report_hash)

        return {
            "submitted_hash": report_hash,
            "recomputed_hash": recomputed_hash,
            "hash_matches_payload": (
                recomputed_hash == report_hash
            ),
            "registered_in_onchain_registry": (
                onchain_record is not None
            ),
            "verified": (
                recomputed_hash == report_hash
                and onchain_record is not None
            ),
        }

    @staticmethod
    def _build_grounded_explanation(
        host: str,
        score: int,
        classification: str,
        findings: List[Dict[str, Any]],
    ) -> str:

        if classification == "UNKNOWN" and not findings:
            return (
                f"{host}: insufficient evidence to determine "
                "whether this website is safe or malicious. "
                "A valid TLS certificate does not prove legitimacy."
            )

        if classification == "UNKNOWN":
            return (
                f"{host}: insufficient reliable evidence to "
                f"confirm malicious activity. Available checks "
                f"produced a score of {score}/100. "
                "This does not mean the website is safe."
            )

        if not findings:
            return (
                f"{host} has no confirmed malicious indicators "
                f"in the available checks. Classification: "
                f"{classification} ({score}/100). "
                "This does not guarantee the website is safe."
            )

        codes = ", ".join(
            finding.get("code", "UNKNOWN")
            for finding in findings
        )

        details = " ".join(
            finding.get("message", "")
            for finding in findings[:3]
        )

        return (
            f"{host} is classified as {classification} risk "
            f"({score}/100) triggered by [{codes}]. "
            f"Evidence: {details}"
        )
