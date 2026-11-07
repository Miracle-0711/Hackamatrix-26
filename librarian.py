
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


def is_safe_url(url):

    try:
        parsed = urlparse(url)

        if parsed.scheme.lower() not in ("http", "https"):
            return False

        hostname = parsed.hostname

        if not hostname:
            return False

        if parsed.username or parsed.password:
            return False

        ip = ipaddress.ip_address(hostname)

        if not ip.is_global:
            return False

    except ValueError:

        try:
            addresses = socket.getaddrinfo(hostname, None)

            if not addresses:
                return False

            for address in addresses:
                ip = ipaddress.ip_address(address[4][0])

                if not ip.is_global:
                    return False

        except (socket.gaierror, ValueError, OSError):
            return False

    return True


class WebsiteTextExtractor(HTMLParser):

    def __init__(self):
        super().__init__()
        self.text_parts = []
        self.ignore_content = False

    def handle_starttag(self, tag, attrs):

        if tag in ("script", "style", "noscript"):
            self.ignore_content = True

    def handle_endtag(self, tag):

        if tag in ("script", "style", "noscript"):
            self.ignore_content = False

    def handle_data(self, data):

        if not self.ignore_content:

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

    def inspect_website(self, url, claimed_brand=None):

        print("\n[Librarian] Inspecting website...")

        if not is_safe_url(url):

            return {
                "url": url,
                "status": "BLOCKED",
                "message": "URL failed basic safety checks."
            }

        try:

            print("\n[Librarian] Running Assistant 4...")
            threat_result = self.threat_intelligence.check_url(url)

            print("\n[Librarian] Running Assistant 5...")
            community_result = self.community_ledger.check_threat(url)

            print("\n[Librarian] Running Assistant 6...")
            ssl_result = self.ssl_validator.inspect_certificate(url)

            response = requests.get(
                url,
                timeout=10,
                allow_redirects=False,
                headers={
                    "User-Agent": "TrustsheildAI/1.0"
                },
                stream=True
            )

            if response.is_redirect:

                response.close()

                report = {
                    "url": url,
                    "status": "BLOCKED",
                    "message": "Redirects are not followed for safety.",
                    "threat_intelligence": threat_result,
                    "community_threat_ledger": community_result,
                    "ssl_certificate": ssl_result
                }

                report["risk_assessment"] = (
                    self.risk_engine.calculate_risk(report)
                )

                return report

            print("\n[Librarian] Running Assistant 7...")
            security_result = self.security_assessor.inspect_headers(
                url,
                response.headers
            )

            content_type = response.headers.get("Content-Type", "")

            if "text/html" not in content_type.lower():

                response.close()

                report = {
                    "url": url,
                    "status": "UNSUPPORTED",
                    "message": "Website did not return HTML content.",
                    "threat_intelligence": threat_result,
                    "community_threat_ledger": community_result,
                    "ssl_certificate": ssl_result,
                    "security_assessment": security_result
                }

                report["risk_assessment"] = (
                    self.risk_engine.calculate_risk(report)
                )

                return report

            content_length = response.headers.get("Content-Length")

            if content_length:

                try:

                    if int(content_length) > 1_000_000:
                        response.close()

                        return {
                            "url": url,
                            "status": "BLOCKED",
                            "message": "Website response is too large."
                        }

                except ValueError:

                    response.close()

                    return {
                        "url": url,
                        "status": "ERROR",
                        "message": "Invalid response size."
                    }

            html = response.raw.read(
                1_000_001,
                decode_content=True
            )

            encoding = response.encoding or "utf-8"

            response.close()

            if len(html) > 1_000_000:

                return {
                    "url": url,
                    "status": "BLOCKED",
                    "message": "Website response exceeded the size limit."
                }

            html = html.decode(encoding, errors="replace")

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
                website_text
            )

            print("\n[Librarian] Investigation completed.")

            report = {
                "url": url,
                "domain": urlparse(url).hostname,
                "status": "ANALYZED",

                "credential_inspection": credential_result,
                "brand_inspection": brand_result,
                "semantic_analysis": semantic_result,
                "threat_intelligence": threat_result,
                "community_threat_ledger": community_result,
                "ssl_certificate": ssl_result,
                "security_assessment": security_result
            }

            print("\n[Librarian] Calculating final risk score...")

            report["risk_assessment"] = (
                self.risk_engine.calculate_risk(report)
            )

            print("[Librarian] Risk assessment completed.")

            return report

        except requests.RequestException as error:

            return {
                "url": url,
                "status": "ERROR",
                "message": "Unable to fetch the website.",
                "details": str(error)
            }
