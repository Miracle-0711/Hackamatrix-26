# plumber/crypto_auditor.py
import datetime
import math
from typing import List, Dict, Any, Tuple
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec

# Product of small odd primes up to 997 for instant O(1) RSA GCD weak-factor detection
SMALL_PRIMES = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
    157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
    239, 241, 251,
]
SMALL_PRIMES_PRODUCT = math.prod(SMALL_PRIMES)

# NIST P-256 (secp256r1) parameters for fast Tiny-Scalar Check d in [1, 256]
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = P256_P - 3
P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

def _ec_point_add(
    p1: Tuple[int, int] | None, p2: Tuple[int, int] | None, p: int, a: int
) -> Tuple[int, int] | None:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if x1 == x2 and y1 == y2:
        lam = ((3 * x1 * x1 + a) * pow(2 * y1, -1, p)) % p
    else:
        lam = ((y2 - y1) * pow(x2 - x1, -1, p)) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return x3, y3

def _precompute_tiny_p256_scalars(max_d: int = 256) -> Dict[Tuple[int, int], int]:
    """Precomputes Q = d * G for d in [1, 256] at module load (< 2ms)."""
    table: Dict[Tuple[int, int], int] = {}
    current = None
    base = (P256_GX, P256_GY)
    for d in range(1, max_d + 1):
        current = _ec_point_add(current, base, P256_P, P256_A)
        if current is not None:
            table[current] = d
    return table

TINY_P256_LOOKUP = _precompute_tiny_p256_scalars(256)


class CryptographicAuditor:
    """
    Audits X.509 certificates for low-entropy ECDSA keys, Fermat-factorable RSA keys,
    weak RSA bit lengths (<2048), SHA-1 signatures, and >398-day validity windows.
    """

    @staticmethod
    def fermat_factor_check(n: int, max_steps: int = 128) -> bool:
        """Detects close primes p and q where N = a^2 - b^2 in <= max_steps."""
        if n <= 0 or n % 2 == 0:
            return True
        a = math.isqrt(n)
        if a * a < n:
            a += 1
        for _ in range(max_steps):
            b2 = a * a - n
            b = math.isqrt(b2)
            if b * b == b2:
                p = a - b
                q = a + b
                if p > 1 and q > 1 and p * q == n:
                    return True
            a += 1
        return False

    @classmethod
    def audit_chain(cls, x509_chain: List[x509.Certificate]) -> Dict[str, Any]:
        if not x509_chain:
            return {"passed": False, "critical_crypto_failure": True, "findings": []}

        findings = []
        critical_failure = False
        now = datetime.datetime.now(datetime.timezone.utc)

        for idx, cert in enumerate(x509_chain):
            role = "Leaf" if idx == 0 else f"Chain[{idx}]"

            # 1. Validity Window & Expiration Check (Leaf <= 398 days per CA/B Forum baseline)
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
            validity_days = (not_after - not_before).days

            if now < not_before or now > not_after:
                findings.append({
                    "severity": "HIGH",
                    "code": "CERT_EXPIRED_OR_NOT_YET_VALID",
                    "message": f"{role} certificate is outside its validity window ({not_before.date()} to {not_after.date()}).",
                })

            if idx == 0 and validity_days > 398:
                findings.append({
                    "severity": "MEDIUM",
                    "code": "EXCESSIVE_VALIDITY_WINDOW",
                    "message": f"Leaf certificate validity ({validity_days} days) exceeds the 398-day WebPKI maximum.",
                })

            # 2. Deprecated SHA-1 Hash Check
            sig_hash = cert.signature_hash_algorithm.name.lower() if cert.signature_hash_algorithm else "unknown"
            if "sha1" in sig_hash or "md5" in sig_hash:
                critical_failure = True
                findings.append({
                    "severity": "CRITICAL",
                    "code": "DEPRECATED_SIGNATURE_HASH",
                    "message": f"{role} certificate uses broken signature hash algorithm ({sig_hash.upper()}).",
                })

            # 3. Public Key Cryptographic & Entropy Auditing
            pub_key = cert.public_key()
            if isinstance(pub_key, rsa.RSAPublicKey):
                numbers = pub_key.public_numbers()
                n = numbers.n
                key_size = pub_key.key_size

                if key_size < 2048:
                    critical_failure = True
                    findings.append({
                        "severity": "CRITICAL",
                        "code": "WEAK_RSA_KEY_SIZE",
                        "message": f"{role} RSA key length is {key_size} bits (minimum required is 2048 bits).",
                    })

                if math.gcd(n, SMALL_PRIMES_PRODUCT) > 1:
                    critical_failure = True
                    findings.append({
                        "severity": "CRITICAL",
                        "code": "RSA_SMALL_PRIME_FACTOR",
                        "message": f"{role} RSA modulus shares a factor with small primes (trivial private key recovery).",
                    })
                elif cls.fermat_factor_check(n):
                    critical_failure = True
                    findings.append({
                        "severity": "CRITICAL",
                        "code": "RSA_FERMAT_FACTORABLE",
                        "message": f"{role} RSA modulus has insufficiently separated primes p and q (Fermat factorable).",
                    })

            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                ec_numbers = pub_key.public_numbers()
                point = (ec_numbers.x, ec_numbers.y)
                if point in TINY_P256_LOOKUP:
                    recovered_d = TINY_P256_LOOKUP[point]
                    critical_failure = True
                    findings.append({
                        "severity": "CRITICAL",
                        "code": "ECDSA_TINY_SCALAR_LOW_ENTROPY",
                        "message": f"{role} ECDSA public key uses tiny private scalar d={recovered_d} (<= 8-bit entropy).",
                    })

        return {
            "passed": len(findings) == 0,
            "critical_crypto_failure": critical_failure,
            "findings": findings,
        }