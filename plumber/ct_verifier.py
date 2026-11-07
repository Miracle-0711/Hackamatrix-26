# plumber/ct_verifier.py
import httpx
from typing import Dict, Any, List
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

SCT_EXTENSION_OID = ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS  # 1.3.6.1.4.1.11129.2.4.2


class CertificateTransparencyVerifier:
    """
    Step A (0ms Offline): Parses embedded SCTs from OID 1.3.6.1.4.1.11129.2.4.2.
    Step B (Async 2.0s Cap): Queries crt.sh for shadow certificates without hanging live demos.
    """

    @staticmethod
    def extract_embedded_scts(leaf_cert: x509.Certificate) -> Dict[str, Any]:
        try:
            ext = leaf_cert.extensions.get_extension_for_oid(SCT_EXTENSION_OID)
            scts = list(ext.value)
            sct_records = [
                {
                    "version": sct.version.name,
                    "log_id": sct.log_id.hex()[:24] + "...",
                    "timestamp": sct.timestamp.isoformat(),
                }
                for sct in scts
            ]
            return {
                "has_embedded_scts": len(sct_records) > 0,
                "sct_count": len(sct_records),
                "scts": sct_records,
            }
        except x509.ExtensionNotFound:
            return {
                "has_embedded_scts": False,
                "sct_count": 0,
                "scts": [],
            }

    @classmethod
    async def verify_ct_compliance(
        cls, domain: str, leaf_cert: x509.Certificate | None, timeout: float = 2.0
    ) -> Dict[str, Any]:
        findings: List[Dict[str, str]] = []

        # Step A: 0ms Offline X.509 SCT Extension Inspection
        if leaf_cert is None:
            return {
                "ct_compliant": False,
                "embedded_sct_count": 0,
                "crt_sh_status": "SKIPPED_NO_LEAF_CERT",
                "findings": [{
                    "severity": "HIGH",
                    "code": "MISSING_LEAF_CERTIFICATE",
                    "message": "No TLS leaf certificate available for CT inspection.",
                }],
            }

        embedded = cls.extract_embedded_scts(leaf_cert)
        if not embedded["has_embedded_scts"]:
            findings.append({
                "severity": "HIGH",
                "code": "MISSING_EMBEDDED_SCT",
                "message": "Leaf certificate lacks embedded Signed Certificate Timestamps (OID 1.3.6.1.4.1.11129.2.4.2).",
            })

        # Step B: Async crt.sh shadow-certificate query with strict 2.0s circuit breaker
        crt_sh_status = "UNVERIFIED"
        logged_cert_count = 0
        try:
            url = f"https://crt.sh/?q={domain}&output=json"
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    logged_cert_count = len(data) if isinstance(data, list) else 0
                    crt_sh_status = "ONLINE_VERIFIED"
                    if logged_cert_count == 0 and not embedded["has_embedded_scts"]:
                        findings.append({
                            "severity": "CRITICAL",
                            "code": "SHADOW_CERTIFICATE_DETECTED",
                            "message": f"Certificate for {domain} has zero embedded SCTs and is absent from crt.sh logs.",
                        })
                else:
                    crt_sh_status = f"FALLBACK_HTTP_{resp.status_code}"
        except Exception:
            # Never hang the live demo if crt.sh times out or returns 502
            crt_sh_status = "FALLBACK_TO_EMBEDDED_SCT"

        return {
            "ct_compliant": embedded["has_embedded_scts"] or logged_cert_count > 0,
            "embedded_sct_count": embedded["sct_count"],
            "embedded_scts": embedded["scts"],
            "crt_sh_status": crt_sh_status,
            "crt_sh_logged_count": logged_cert_count,
            "findings": findings,
        }