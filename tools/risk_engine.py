

class RiskEngine:

    def calculate_risk(self, report):

        if not isinstance(report, dict):
            return {
                "risk_score": None,
                "risk_level": "UNKNOWN",
                "evidence_count": 0,
                "evidence": [],
                "message": "Invalid investigation report."
            }

        if report.get("status") not in (None, "ANALYZED"):
            return {
                "risk_score": None,
                "risk_level": "UNKNOWN",
                "evidence_count": 0,
                "evidence": [],
                "message": "Website investigation was not completed."
            }

        score = 0
        evidence = []

        def add_evidence(points, category, reason, strength):

            nonlocal score

            score += points

            evidence.append({
                "points": points,
                "category": category,
                "strength": strength,
                "reason": reason
            })

        threat = report.get("threat_intelligence") or {}

        if threat.get("status") == "THREAT_FOUND":

            add_evidence(
                70,
                "THREAT_INTELLIGENCE",
                "Exact URL match found in the OpenPhish feed.",
                "STRONG"
            )

        
        community = report.get("community_threat_ledger") or {}

        if community.get("status") == "THREAT_FOUND":

            add_evidence(
                10,
                "COMMUNITY_REPORT",
                "URL has an unverified community-submitted report.",
                "WEAK"
            )

        
        credential = report.get("credential_inspection") or {}

        for form in credential.get("forms", []):

            warnings = form.get("warnings", [])

            sensitive_fields = any(
                field.get("category") in (
                    "PASSWORD", "OTP", "PAYMENT"
                )
                for field in form.get("fields", [])
            )

            if warnings and sensitive_fields:

                add_evidence(
                    15,
                    "CREDENTIAL_INSPECTION",
                    "Sensitive information may be submitted to a suspicious destination.",
                    "MODERATE"
                )
                break

            elif warnings:

                add_evidence(
                    10,
                    "CREDENTIAL_INSPECTION",
                    "Website form has a suspicious submission destination.",
                    "MODERATE"
                )
                break

       
        brand = report.get("brand_inspection") or {}

        if brand.get("status") == "MISMATCH":

            add_evidence(
                15,
                "BRAND_MISMATCH",
                "Website domain does not match the claimed official brand.",
                "MODERATE"
            )

        
        semantic = report.get("semantic_analysis") or {}

        if semantic.get("status") == "ANALYZED":

            fraud_score = semantic.get("fraud_score", 0)
            spam_score = semantic.get("spam_score", 0)

            if fraud_score >= 0.80:

                add_evidence(
                    20,
                    "AI_FRAUD_ANALYSIS",
                    "AI model detected strong fraud-related signals.",
                    "MODERATE"
                )

            elif spam_score >= 0.80:

                add_evidence(
                    5,
                    "AI_SPAM_ANALYSIS",
                    "AI model detected strong spam-related signals.",
                    "WEAK"
                )

        ssl_result = report.get("ssl_certificate") or {}

        if ssl_result.get("status") == "INVALID_CERTIFICATE":

            add_evidence(
                10,
                "SSL_CERTIFICATE",
                "SSL/TLS certificate verification failed.",
                "MODERATE"
            )

        elif ssl_result.get("status") == "EXPIRING_SOON":

            add_evidence(
                2,
                "SSL_CERTIFICATE",
                "SSL/TLS certificate is approaching expiry.",
                "WEAK"
            )

        elif ssl_result.get("status") == "NOT_HTTPS":

            add_evidence(
                5,
                "HTTPS",
                "Website does not use HTTPS.",
                "WEAK"
            )

        security = report.get("security_assessment") or {}

        missing_count = security.get("missing_count", 0)

        if security.get("status") == "ANALYZED":

            if missing_count >= 4:

                add_evidence(
                    3,
                    "SECURITY_HEADERS",
                    "Several recommended security headers are missing.",
                    "WEAK"
                )

       
        score = min(score, 100)

        if score <= 29:
            risk_level = "LOW"

        elif score <= 59:
            risk_level = "MEDIUM"

        elif score <= 79:
            risk_level = "HIGH"

        else:
            risk_level = "CRITICAL"

        return {
            "risk_score": score,
            "risk_level": risk_level,
            "evidence_count": len(evidence),
            "evidence": evidence,
            "message": (
                "Risk score is a heuristic assessment, "
                "not a probability of fraud. "
                "A LOW score does not guarantee safety."
            )
        }

