# plumber/tls_extractor.py
import asyncio
import ssl
from typing import List, Dict, Any
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from OpenSSL import SSL

class RawTLSExtractor:
    """
    Opens a raw TCP/TLS connection with host verification disabled so that
    compromised, expired, or self-signed chains can still be extracted and audited.
    """

    @staticmethod
    def parse_target(url_or_domain: str) -> tuple[str, int]:
        if "://" not in url_or_domain:
            url_or_domain = f"https://{url_or_domain}"
        parsed = urlparse(url_or_domain)
        host = parsed.hostname or url_or_domain
        port = parsed.port or 443
        return host, port

    @classmethod
    async def fetch_certificate_chain(
        cls, url_or_domain: str, timeout: float = 3.0
    ) -> Dict[str, Any]:
        host, port = cls.parse_target(url_or_domain)
        loop = asyncio.get_running_loop()

        try:
            chain_der_list, tls_version, cipher_suite = await asyncio.wait_for(
                loop.run_in_executor(None, cls._sync_extract_chain, host, port, timeout),
                timeout=timeout + 0.5,
            )
        except Exception as exc:
            return {
                "host": host,
                "port": port,
                "reachable": False,
                "error": str(exc),
                "certificates": [],
                "raw_x509_objects": [],
            }

        parsed_certs = []
        x509_objects = []

        for idx, der_bytes in enumerate(chain_der_list):
            cert = x509.load_der_x509_certificate(der_bytes)
            x509_objects.append(cert)
            sha256_fp = cert.fingerprint(hashes.SHA256()).hex().upper()
            role = "LEAF" if idx == 0 else ("ROOT" if idx == len(chain_der_list) - 1 and len(chain_der_list) > 2 else "INTERMEDIATE")
            parsed_certs.append({
                "position": idx,
                "role": role,
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "serial_number": hex(cert.serial_number),
                "not_valid_before": cert.not_valid_before_utc.isoformat(),
                "not_valid_after": cert.not_valid_after_utc.isoformat(),
                "sha256_fingerprint": sha256_fp,
            })

        return {
            "host": host,
            "port": port,
            "reachable": True,
            "tls_version": tls_version,
            "cipher_suite": cipher_suite,
            "certificates": parsed_certs,
            "raw_x509_objects": x509_objects,
        }

    @staticmethod
    def _sync_extract_chain(host: str, port: int, timeout: float) -> tuple[List[bytes], str, str]:
        import socket
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                tls_version = ssock.version() or "TLSv1.3"
                cipher_info = ssock.cipher()
                cipher_suite = cipher_info[0] if cipher_info else "UNKNOWN"
                leaf_der = ssock.getpeercert(binary_form=True)
                return ([leaf_der] if leaf_der else []), tls_version, cipher_suite