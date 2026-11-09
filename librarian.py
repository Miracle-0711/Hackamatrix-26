
import ipaddress
import socket
from urllib.parse import urlparse
from html.parser import HTMLParser

import requests

from tools.credential_inspector import inspect_html
from tools.brand_mismatch import inspect_brand
from tools.semantic_analyzer import SemanticAnalyzer
from tools.threat_intelligence import ThreatIntelligence
from tools.community_ledger import CommunityThreatLedger
from tools.ssl_validator import SSLValidator
from tools.security_assessor import SecurityAssessor
from tools.risk_engine import RiskEngine


MAX_RESPONSE_SIZE = 1_000_000
REQUEST_TIMEOUT = 10


def is_safe_url(url):
    """Allow only HTTP(S) URLs resolving exclusively to public IP addresses."""

    try:
        parsed = urlparse(url)

        if parsed.scheme.lower() not in ("http", "https"):
            return False

        hostname = parsed.hostname

        if not hostname:
            return False

        if parsed.username or parsed.password:
            return False

        # Reject localhost and local hostnames.
        if hostname.lower() == "localhost" or hostname.lower().endswith(".localhost"):
            return False

        try:
            # Direct IP address.
            addresses = [ipaddress.ip_address(hostname)]
        except ValueError:
            # Resolve domain and validate every returned IP.
            resolved = socket.getaddrinfo(
                hostname,
                parsed.port or (443 if parsed.scheme.lower() == "https" else 80),
                type=socket.SOCK_STREAM
            )

            addresses = [
                ipaddress.ip_address(item[4][0])
                for item in resolved
            ]

        if not addresses:
            return False

        return all(address.is_global for address in addresses)

    except (ValueError, TypeError, socket.gaierror, OSError):
        return False


class WebsiteTextExtractor(HTMLParser):

    def __init__(self):
        super().__init__()
        self.text_parts = []
        self.ignore_tags = set()

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "noscript"):
            self.ignore_tags.add(tag)

    def handle_endtag(self, tag):
        self.ignore_tags.discard(tag)

    def handle_data(self, data):
        if not self.ignore_tags:
            cleaned = data.strip()
            if cleaned:
                self.text_parts.append(cleaned)


class Librarian:

    def __init__(self):

        print("\n[Librarian] Initializing assistants...")

        self.semantic_analyzer = SemanticAnalyzer()
        print("[Librarian] Assistant 3 connected successfully!")

        self.threat_intelligence = ThreatIntelligence()
        print("[Librarian] Assistant 4 connected successfully!")

        self.community_ledger = CommunityThreatLedger()
        print("[Librarian] Assistant 5 connected successfully!")

        self.ssl_validator = SSLValidator()
        print("[Librarian] Assistant 6 connected successfully!")

        self.security_assessor = SecurityAssessor()
        print("[Librarian] Assistant 7 connected successfully!")

        self.risk_engine = RiskEngine()
        print("[Librarian] Risk Engine connected successfully!")

    def investigate_brand(self, url, claimed_brand=None):

        if not claimed_brand or not claimed_brand.strip():
            return None

        return inspect_brand(url, claimed_brand)

    def inspect_website(
        self,
        url,
        claimed_brand=None,
        pasted_message=""
    ):
        """
        Inspect a website and optionally analyse a user-pasted message.

        pasted_message is optional so existing callers remain compatible.
        """

        print("\n[Librarian] Inspecting website...")

        if not is_safe_url(url):
            return {
                "url": url,
                "status": "BLOCKED",
                "message": "URL failed basic safety checks."
            }

        report = {
            "url": url,
            "domain": urlparse(url).hostname,
            "status": "ANALYZING"
        }

        # Analyse pasted text independently of website HTML.
        if isinstance(pasted_message, str) and pasted_message.strip():

            try:
                print("\n[Librarian] Analysing pasted message...")

                report["pasted_message_analysis"] = (
                    self.semantic_analyzer.analyze_text(
                        pasted_message[:10000]
                    )
                )

            except Exception as error:
                report["pasted_message_analysis"] = {
                    "status": "ERROR",
                    "message": "Pasted message analysis could not be completed.",
                    "details": str(error)
                }

        try:

            print("\n[Librarian] Running Assistant 4...")
            threat_result = self.threat_intelligence.check_url(url)

            print("\n[Librarian] Running Assistant 5...")
            community_result = self.community_ledger.check_threat(url)

            print("\n[Librarian] Running Assistant 6...")
            ssl_result = self.ssl_validator.inspect_certificate(url)

            report.update({
                "threat_intelligence": threat_result,
                "community_threat_ledger": community_result,
                "ssl_certificate": ssl_result
            })

            print("\n[Librarian] Fetching website...")

            with requests.get(
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
                headers={
                    "User-Agent": "TrustsheildAI/1.0"
                },
                stream=True
            ) as response:

                if response.is_redirect:
                    report.update({
                        "status": "BLOCKED",
                        "message": "Redirects are not followed for safety."
                    })

                    report["risk_assessment"] = (
                        self.risk_engine.calculate_risk(report)
                    )

                    return report

                print("\n[Librarian] Running Assistant 7...")

                security_result = self.security_assessor.inspect_headers(
                    url,
                    response.headers
                )

                report["security_assessment"] = security_result

                content_type = response.headers.get("Content-Type", "")

                if "text/html" not in content_type.lower():
                    report.update({
                        "status": "UNSUPPORTED",
                        "message": "Website did not return HTML content."
                    })

                    report["risk_assessment"] = (
                        self.risk_engine.calculate_risk(report)
                    )

                    return report

                content_length = response.headers.get("Content-Length")

                if content_length:
                    try:
                        if int(content_length) > MAX_RESPONSE_SIZE:
                            report.update({
                                "status": "BLOCKED",
                                "message": "Website response is too large."
                            })
                            return report

                    except ValueError:
                        report.update({
                            "status": "ERROR",
                            "message": "Invalid response size."
                        })
                        return report

                html_bytes = response.raw.read(
                    MAX_RESPONSE_SIZE + 1,
                    decode_content=True
                )

                encoding = response.encoding or "utf-8"

            if len(html_bytes) > MAX_RESPONSE_SIZE:
                report.update({
                    "status": "BLOCKED",
                    "message": "Website response exceeded the size limit."
                })
                return report

            html = html_bytes.decode(
                encoding,
                errors="replace"
            )

            print("\n[Librarian] Running Assistant 1...")
            credential_result = inspect_html(url, html)

            print("\n[Librarian] Running Assistant 2...")
            brand_result = self.investigate_brand(
                url,
                claimed_brand
            )

            print("\n[Librarian] Running Assistant 3...")

            extractor = WebsiteTextExtractor()
            extractor.feed(html)

            website_text = " ".join(extractor.text_parts)

            semantic_result = self.semantic_analyzer.analyze_text(
                website_text[:10000]
            )

            print("\n[Librarian] Investigation completed.")

            report.update({
                "status": "ANALYZED",
                "credential_inspection": credential_result,
                "brand_inspection": brand_result,
                "semantic_analysis": semantic_result
            })

            print("\n[Librarian] Calculating final risk score...")

            report["risk_assessment"] = (
                self.risk_engine.calculate_risk(report)
            )

            print("[Librarian] Risk assessment completed.")

            return report

        except requests.RequestException as error:

            report.update({
                "status": "ERROR",
                "message": "Unable to fetch the website.",
                "details": str(error)
            })

            return report

        except Exception as error:

            report.update({
                "status": "ERROR",
                "message": "Website investigation could not be completed.",
                "details": str(error)
            })

            return report

