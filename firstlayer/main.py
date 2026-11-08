import asyncio
import ipaddress
import os
import re
import socket
from http.cookies import SimpleCookie
from urllib.parse import urljoin

import aiohttp
import idna
import jwt
from aiohttp.abc import AbstractResolver
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from yarl import URL


JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ISSUER = "bouncer-auth"
JWT_AUDIENCE = "bouncer-api"

if len(JWT_SECRET.encode()) < 32:
    raise RuntimeError("JWT_SECRET must contain at least 32 bytes")

MAX_BODY = 256 * 1024
MAX_REDIRECTS = 6
REDIRECT_CODES = {301, 302, 303, 307, 308}

# Configure this with brands relevant to your product.
# Similarity is only a signal, never proof of impersonation.
BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
}

# Conservative exclusions for address-translation/transition mechanisms.
BLOCKED_NETWORKS = [
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
    ipaddress.ip_network("2002::/16"),
    ipaddress.ip_network("2001::/32"),
]

app = FastAPI(title="Bouncer", version="0.1.0")
bearer = HTTPBearer()

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=os.getenv("RATE_LIMIT_STORAGE", "memory://"),
)
app.state.limiter = limiter
app.add_exception_handler(
    RateLimitExceeded,
    _rate_limit_exceeded_handler,
)


class ScanInput(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    probe_exposure: bool = False
    text: str = ""


class UnsafeTarget(ValueError):
    pass


def authenticate(
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
):
    try:
        return jwt.decode(
            credentials.credentials,
            JWT_SECRET,
            algorithms=["HS256"],
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            options={
                "require": ["exp", "iss", "aud", "sub"],
            },
        )
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid or expired token")


def public_ip(value: str) -> str:
    address = ipaddress.ip_address(value)

    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            raise UnsafeTarget("IPv4-mapped IPv6 addresses are not allowed")

    if not address.is_global or any(
        address in network for network in BLOCKED_NETWORKS
    ):
        raise UnsafeTarget("Destination is not an allowed public IP")

    return str(address)


def normalize_url(raw: str) -> URL:
    if (
        "\\" in raw
        or any(ord(char) < 32 or ord(char) == 127 for char in raw)
    ):
        raise UnsafeTarget("URL contains forbidden characters")

    try:
        url = URL(raw)

        if url.scheme not in {"http", "https"}:
            raise UnsafeTarget("Only HTTP and HTTPS are allowed")

        if url.user is not None or url.password is not None:
            raise UnsafeTarget("Credentials in URLs are forbidden")

        host = url.host
        if not host or "%" in host:
            raise UnsafeTarget("Missing or invalid hostname")

        host = host.rstrip(".")
        if not host:
            raise UnsafeTarget("Invalid hostname")

        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            host = idna.encode(
                host,
                uts46=True,
                std3_rules=True,
            ).decode("ascii").lower()

            if "." not in host:
                raise UnsafeTarget("Single-label hostnames are forbidden")

            if host.endswith((".localhost", ".local", ".internal")):
                raise UnsafeTarget("Local hostnames are forbidden")
        else:
            host = public_ip(str(address))

        expected_port = 443 if url.scheme == "https" else 80
        if url.port != expected_port:
            raise UnsafeTarget("Only standard HTTP/HTTPS ports are allowed")

        return url.with_host(host).with_fragment(None)

    except UnsafeTarget:
        raise
    except (ValueError, UnicodeError) as exc:
        raise UnsafeTarget("Malformed URL") from exc


class PublicResolver(AbstractResolver):
    """
    The connector uses these exact validated addresses.
    It does not independently resolve the hostname afterward.
    """

    async def resolve(self, host, port=0, family=socket.AF_INET):
        loop = asyncio.get_running_loop()
        records = await asyncio.wait_for(
            loop.getaddrinfo(
                host,
                port,
                family=family,
                type=socket.SOCK_STREAM,
            ),
            timeout=3,
        )

        results = []
        seen = set()

        # Fail closed if ANY returned address is disallowed.
        for address_family, _, proto, _, sockaddr in records:
            address = public_ip(sockaddr[0])

            if address in seen:
                continue
            seen.add(address)

            results.append({
                "hostname": host,
                "host": address,
                "port": port,
                "family": address_family,
                "proto": proto,
                "flags": socket.AI_NUMERICHOST,
            })

        if not results:
            raise UnsafeTarget("Hostname has no usable addresses")

        return results

    async def close(self):
        pass


async def fetch_one(raw_url: str) -> dict:
    url = normalize_url(raw_url)

    connector = aiohttp.TCPConnector(
        resolver=PublicResolver(),
        use_dns_cache=False,
        family=socket.AF_UNSPEC,
        limit=1,
        force_close=True,
        ssl=False,
    )

    timeout = aiohttp.ClientTimeout(
        total=10,
        connect=5,
        sock_read=5,
    )

    # Separate session per hop: no cross-origin cookie propagation.
    async with aiohttp.ClientSession(
        connector=connector,
        timeout=timeout,
        cookie_jar=aiohttp.DummyCookieJar(),
        trust_env=False,
        auto_decompress=False,
        headers={
            "User-Agent": "BouncerScanner/0.1",
            "Accept-Encoding": "identity",
        },
    ) as session:
        async with session.get(
            url,
            allow_redirects=False,
            max_line_size=8190,
            max_field_size=8190,
        ) as response:
            body = bytearray()

            async for chunk in response.content.iter_chunked(8192):
                remaining = MAX_BODY + 1 - len(body)
                body.extend(chunk[:remaining])
                if len(body) > MAX_BODY:
                    break

            return {
                "url": str(url),
                "status": response.status,
                "headers": {
                    key.lower(): value
                    for key, value in response.headers.items()
                },
                "cookies": response.headers.getall("Set-Cookie", []),
                "body": bytes(body[:MAX_BODY]),
                "body_truncated": len(body) > MAX_BODY,
            }


async def follow_redirects(raw_url: str):
    current = str(normalize_url(raw_url))
    seen = set()
    chain = []

    for hop in range(MAX_REDIRECTS + 1):
        if current in seen:
            raise UnsafeTarget("Redirect loop detected")
        seen.add(current)

        result = await fetch_one(current)
        chain.append({
            "url": result["url"],
            "status": result["status"],
        })

        location = result["headers"].get("location")

        if result["status"] not in REDIRECT_CODES or not location:
            return result, chain

        if hop == MAX_REDIRECTS:
            raise UnsafeTarget("Redirect limit exceeded")

        current = str(normalize_url(
            urljoin(result["url"], location)
        ))

    raise UnsafeTarget("Redirect limit exceeded")


def edit_distance(left: str, right: str) -> int:
    previous = list(range(len(right) + 1))

    for row, char_left in enumerate(left, 1):
        current = [row]
        for column, char_right in enumerate(right, 1):
            current.append(min(
                current[-1] + 1,
                previous[column] + 1,
                previous[column - 1] + (char_left != char_right),
            ))
        previous = current

    return previous[-1]


def domain_signals(url: str) -> dict:
    host = normalize_url(url).host
    labels = host.split(".")
    matches = []

    for brand, official in BRAND_DOMAINS.items():
        if host == official or host.endswith("." + official):
            continue

        distance = min(edit_distance(label, brand) for label in labels)
        if distance <= 2:
            matches.append({
                "brand": brand,
                "official_domain": official,
                "minimum_label_edit_distance": distance,
                "interpretation": "Possible similarity; manual review needed",
            })

    return {
        "ascii_hostname": host,
        "contains_punycode": any(
            label.startswith("xn--") for label in labels
        ),
        "brand_similarity_signals": matches,
    }


def inspect_headers(result: dict) -> dict:
    headers = result["headers"]
    https = result["url"].startswith("https://")
    csp = headers.get("content-security-policy", "")

    cookie_results = []

    for raw_cookie in result["cookies"]:
        parsed = SimpleCookie()
        try:
            parsed.load(raw_cookie)

            if not parsed:
                cookie_results.append({"parse_error": True})
                continue

            for name, cookie in parsed.items():
                same_site = str(cookie["samesite"]).lower()
                cookie_results.append({
                    "name": name,
                    "secure": bool(cookie["secure"]),
                    "httponly": bool(cookie["httponly"]),
                    "samesite": same_site or None,
                    "samesite_recognized": same_site in {
                        "lax", "strict", "none"
                    },
                    "none_requires_secure_satisfied": (
                        same_site != "none" or bool(cookie["secure"])
                    ),
                })
        except Exception:
            cookie_results.append({"parse_error": True})

    hsts = headers.get("strict-transport-security", "")
    max_age = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)", hsts, re.I)

    return {
        "transport_https": https,
        "hsts_positive_max_age": bool(
            https and max_age and int(max_age.group(1)) > 0
        ),
        "csp_present": bool(csp),
        "frame_protection_declared": (
            headers.get("x-frame-options", "").upper()
            in {"DENY", "SAMEORIGIN"}
            or "frame-ancestors" in csp.lower()
        ),
        "nosniff": (
            headers.get("x-content-type-options", "").lower()
            == "nosniff"
        ),
        "cookies": cookie_results,
        "server_banner": headers.get("server"),
        "powered_by_banner": headers.get("x-powered-by"),
        "note": (
            "Presence checks are not a full policy audit. "
            "Missing headers do not establish maliciousness."
        ),
    }


async def probe_exposures(final_url: str) -> list:
    origin = str(normalize_url(final_url).origin())
    findings = []

    for path in ("/.env", "/.git/config"):
        result = await fetch_one(origin + path)

        # Do not follow exposure-probe redirects.
        if result["status"] != 200:
            continue

        encoding = result["headers"].get(
            "content-encoding", "identity"
        ).lower()

        if encoding not in {"", "identity"}:
            findings.append({
                "path": path,
                "status": "inconclusive",
                "reason": "Encoded response not inspected",
            })
            continue

        text = result["body"].decode("utf-8", errors="replace")
        content_type = result["headers"].get("content-type", "").lower()

        if "text/html" in content_type or re.search(
            r"<!doctype\s+html|<html\b", text[:2048], re.I
        ):
            continue

        if path == "/.env":
            assignments = re.findall(
                r"(?m)^\s*(?:export\s+)?"
                r"[A-Z_][A-Z0-9_]*\s*=\s*[^\r\n]+",
                text,
            )
            matched = len(assignments) >= 2
        else:
            matched = bool(
                re.search(r"(?m)^\s*\[core\]\s*$", text)
                and re.search(
                    r"(?mi)^\s*(repositoryformatversion|bare)\s*=",
                    text,
                )
            )

        if matched:
            findings.append({
                "path": path,
                "status": "possible_exposure",
                "evidence": "Expected content structure detected",
                "requires_review": True,
            })

        # Never return file bodies or extracted secret values.

    return findings


@app.post("/v1/scan")
@limiter.limit("10/minute")
async def scan(
    request: Request,
    payload: ScanInput,
    claims: dict = Depends(authenticate),
):
    scopes = str(claims.get("scope", "")).split()

    if payload.probe_exposure and "scan:exposure" not in scopes:
        raise HTTPException(
            403,
            "Exposure checks require scan:exposure permission",
        )

    try:
        async with asyncio.timeout(45):
            result, chain = await follow_redirects(payload.url)

            exposure = (
                await probe_exposures(result["url"])
                if payload.probe_exposure
                else []
            )

            # Calculate a basic score_delta and findings based on Bouncer's checks
            score_delta = 0
            findings = []
            
            final_domain_signals = domain_signals(result["url"])
            if final_domain_signals["contains_punycode"]:
                 score_delta += 35
                 findings.append({
                     "severity": "HIGH",
                     "code": "PUNYCODE_HOMOGRAPH_URL",
                     "message": "Domain uses IDN Punycode (xn--) often abused in homograph phishing attacks."
                 })
                 
            if final_domain_signals["brand_similarity_signals"]:
                 score_delta += 25
                 brand = final_domain_signals["brand_similarity_signals"][0]["brand"]
                 findings.append({
                     "severity": "MEDIUM",
                     "code": "BRAND_IMPERSONATION",
                     "message": f"URL exhibits visual similarity to known brand ({brand})."
                 })
            
            if exposure:
                 score_delta += 40
                 findings.append({
                     "severity": "HIGH",
                     "code": "EXPOSED_SECRETS",
                     "message": "Target domain is exposing sensitive configuration files (.env or .git/config)."
                 })

            return {
                "score_delta": score_delta,
                "findings": findings,
                "submitted_url": str(normalize_url(payload.url)),
                "final_url": result["url"],
                "http_status": result["status"],
                "redirect_chain": chain,
                "submitted_domain": domain_signals(payload.url),
                "final_domain": domain_signals(result["url"]),
                "security_headers": inspect_headers(result),
                "exposure_findings": exposure,
                "body_truncated": result["body_truncated"],
                "verdict": "not_assessed",
                "limitations": [
                    "HTTP redirects only; JavaScript is not executed",
                    "No full Unicode-confusable analysis",
                    "No RDAP, WHOIS, SPF, or DMARC lookup yet",
                    "No malware or phishing verdict from these signals alone",
                ],
            }

    except UnsafeTarget as exc:
        raise HTTPException(422, str(exc))
    except (asyncio.TimeoutError, TimeoutError):
        raise HTTPException(504, "Scan time limit exceeded")
    except (aiohttp.ClientError, OSError):
        raise HTTPException(502, "Target could not be fetched safely")
