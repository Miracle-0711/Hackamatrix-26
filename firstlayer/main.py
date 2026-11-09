
import asyncio
import ipaddress
import os
import re
import socket
from html.parser import HTMLParser
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

BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
}

BLOCKED_NETWORKS = [
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
    ipaddress.ip_network("2002::/16"),
    ipaddress.ip_network("2001::/32"),
]

app = FastAPI(title="Bouncer", version="0.4.0")
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
            options={"require": ["exp", "iss", "aud", "sub"]},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid or expired token")


def public_ip(value: str) -> str:
    address = ipaddress.ip_address(value)

    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            raise UnsafeTarget(
                "IPv4-mapped IPv6 addresses are not allowed"
            )

    if not address.is_global or any(
        address in network for network in BLOCKED_NETWORKS
    ):
        raise UnsafeTarget("Destination is not an allowed public IP")

    return str(address)


def normalize_url(raw: str) -> URL:
    if "\\" in raw or any(
        ord(char) < 32 or ord(char) == 127 for char in raw
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
    )

    timeout = aiohttp.ClientTimeout(
        total=10,
        connect=5,
        sock_read=5,
    )

    async with aiohttp.ClientSession(
        connector=connector,
        timeout=timeout,
        cookie_jar=aiohttp.DummyCookieJar(),
        trust_env=False,
        auto_decompress=False,
        headers={
            "User-Agent": "BouncerScanner/0.4",
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

        current = str(
            normalize_url(urljoin(result["url"], location))
        )

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


def inspect_url_risks(raw_url: str) -> list:
    findings = []
    url = normalize_url(raw_url)
    host = url.host.lower()
    path_query = (url.path + "?" + url.query_string).lower()

    suspicious_words = [
        "login", "signin", "verify", "verification",
        "secure", "account", "password", "update",
        "wallet", "banking", "confirm", "credential",
        "recover", "suspended",
    ]

    matched_words = [
        word for word in suspicious_words
        if word in path_query
    ]

    if matched_words:
        findings.append({
            "severity": "INFO",
            "code": "SUSPICIOUS_URL_KEYWORDS",
            "message": (
                "URL contains account-related keywords. "
                "This alone does not prove phishing."
            ),
            "evidence": matched_words,
        })

    if len(host.split(".")) >= 5:
        findings.append({
            "severity": "MEDIUM",
            "code": "EXCESSIVE_SUBDOMAINS",
            "message": "The hostname contains an unusually large number of subdomains.",
        })

    try:
        ipaddress.ip_address(host)
        findings.append({
            "severity": "MEDIUM",
            "code": "IP_ADDRESS_URL",
            "message": "The website uses an IP address instead of a domain name.",
        })
    except ValueError:
        pass

    if len(url.query_string) > 200:
        findings.append({
            "severity": "INFO",
            "code": "LONG_URL_QUERY",
            "message": "The URL contains an unusually long query string.",
        })

    return findings


def domain_signals(url: str) -> dict:
    host = normalize_url(url).host
    labels = host.split(".")
    matches = []

    for brand, official in BRAND_DOMAINS.items():
        if host == official or host.endswith("." + official):
            continue

        distance = min(
            edit_distance(label, brand)
            for label in labels
        )

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
    max_age = re.search(
        r"(?:^|;)\s*max-age\s*=\s*(\d+)",
        hsts,
        re.I,
    )

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


class FormInspector(HTMLParser):
    """Inspect form blocks and inputs without executing page scripts."""

    def __init__(self, page_url: str):
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.page_origin = normalize_url(page_url).origin()
        self.current_form = None
        self.password_form_found = False
        self.external_form_found = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        tag = tag.lower()

        if tag == "form":
            action = attrs.get("action", "").strip()
            action_url = (
                self.page_url if not action
                else urljoin(self.page_url, action)
            )

            try:
                parsed_action = normalize_url(action_url)
                external = parsed_action.origin() != self.page_origin
            except (UnsafeTarget, ValueError):
                external = False

            self.current_form = {
                "external": external,
                "password": False,
            }

        elif tag == "input" and self.current_form is not None:
            if str(attrs.get("type", "")).lower() == "password":
                self.current_form["password"] = True

    def handle_endtag(self, tag):
        if tag.lower() == "form" and self.current_form is not None:
            if self.current_form["password"]:
                self.password_form_found = True

            if self.current_form["external"]:
                self.external_form_found = True

            self.current_form = None


def inspect_phishing_content(result: dict) -> list:
    findings = []

    content_type = result["headers"].get(
        "content-type", ""
    ).lower()

    if "text/html" not in content_type:
        return findings

    html = result["body"].decode("utf-8", errors="replace")
    parser = FormInspector(result["url"])

    try:
        parser.feed(html)
        parser.close()
    except Exception:
        findings.append({
            "severity": "INFO",
            "code": "HTML_PARSE_INCOMPLETE",
            "message": "The HTML could not be fully inspected.",
        })

    if parser.password_form_found:
        findings.append({
            "severity": "INFO",
            "code": "PASSWORD_FORM_DETECTED",
            "message": (
                "A password input was found inside a form. "
                "This alone does not prove phishing."
            ),
        })

    if parser.external_form_found:
        findings.append({
            "severity": "MEDIUM",
            "code": "EXTERNAL_FORM_ACTION",
            "message": (
                "A form submits data to a different origin. "
                "Manual review is required."
            ),
        })

    if parser.password_form_found and parser.external_form_found:
        findings.append({
            "severity": "HIGH",
            "code": "EXTERNAL_CREDENTIAL_SUBMISSION",
            "message": (
                "A password form submits data to an external origin. "
                "This is a strong phishing indicator."
            ),
        })

    return findings


async def probe_exposures(final_url: str) -> list:
    origin = str(normalize_url(final_url).origin())
    findings = []

    for path in ("/.env", "/.git/config"):
        result = await fetch_one(origin + path)

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
        content_type = result["headers"].get(
            "content-type", ""
        ).lower()

        if "text/html" in content_type or re.search(
            r"<!doctype\s+html|<html\b",
            text[:2048],
            re.I,
        ):
            continue

        if path == "/.env":
            assignments = re.findall(
                r"(?m)^\s*(?:export\s+)?[A-Z_][A-Z0-9_]*\s*=\s*[^\r\n]+",
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

    return findings


def calculate_verdict(
    findings: list,
    domain_info: dict,
    exposure: list,
) -> tuple:
    score = 0

    if domain_info["contains_punycode"]:
        score += 20
        findings.append({
            "severity": "MEDIUM",
            "code": "PUNYCODE_DOMAIN",
            "message": "The hostname contains an IDN Punycode label.",
        })

    if domain_info["brand_similarity_signals"]:
        score += 30
        brand = domain_info["brand_similarity_signals"][0]["brand"]
        findings.append({
            "severity": "HIGH",
            "code": "BRAND_IMPERSONATION",
            "message": f"The hostname resembles the brand {brand}.",
        })

    codes = {item["code"] for item in findings}

    if "EXTERNAL_CREDENTIAL_SUBMISSION" in codes:
        score += 50
    elif "EXTERNAL_FORM_ACTION" in codes:
        score += 20

    if "IP_ADDRESS_URL" in codes:
        score += 15

    if "EXCESSIVE_SUBDOMAINS" in codes:
        score += 10

    if exposure:
        score += 40
        findings.append({
            "severity": "HIGH",
            "code": "EXPOSED_CONFIGURATION",
            "message": "A potentially exposed configuration file was detected.",
        })

    score = min(score, 100)

    if score >= 70:
        verdict = "critical"
    elif score >= 40:
        verdict = "suspicious"
    else:
        verdict = "not_assessed"

    return score, verdict, findings


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

            submitted_domain = domain_signals(payload.url)
            final_domain = domain_signals(result["url"])

            findings = inspect_phishing_content(result)

            findings.extend(inspect_url_risks(payload.url))
            findings.extend(inspect_url_risks(result["url"]))

            score_delta, verdict, findings = calculate_verdict(
                findings,
                final_domain,
                exposure,
            )

            return {
                "score_delta": score_delta,
                "findings": findings,
                "submitted_url": str(normalize_url(payload.url)),
                "final_url": result["url"],
                "http_status": result["status"],
                "redirect_chain": chain,
                "submitted_domain": submitted_domain,
                "final_domain": final_domain,
                "security_headers": inspect_headers(result),
                "exposure_findings": exposure,
                "body_truncated": result["body_truncated"],
                "verdict": verdict,
                "detection_note": (
                    "This is a heuristic assessment, not a confirmed "
                    "threat-intelligence verdict. NOT_ASSESSED means "
                    "insufficient evidence; it does not mean safe."
                ),
                "limitations": [
                    "HTTP redirects only; JavaScript is not executed",
                    "No full Unicode-confusable analysis",
                    "No RDAP, WHOIS, SPF, or DMARC lookup yet",
                    "No direct Google Safe Browsing API integration",
                    "No malware verdict from these signals alone",
                    "Heuristic findings require manual review",
                ],
            }

    except UnsafeTarget as exc:
        raise HTTPException(422, str(exc))

    except (asyncio.TimeoutError, TimeoutError):
        raise HTTPException(504, "Scan time limit exceeded")

    except (aiohttp.ClientError, OSError):
        raise HTTPException(502, "Target could not be fetched safely")
