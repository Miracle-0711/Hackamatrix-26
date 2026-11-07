
import requests
from urllib.parse import urlsplit, urlunsplit


class ThreatIntelligence:

    FEED_URL = "https://openphish.com/feed.txt"

    def __init__(self):
        print("[Assistant 4] Threat Intelligence initialized.")

        self.threat_urls = set()
        self.feed_loaded = False

    def normalize_url(self, url):
        try:
            parsed = urlsplit(url.strip())

            if parsed.scheme.lower() not in ("http", "https"):
                return None

            if not parsed.hostname:
                return None

            hostname = parsed.hostname.lower()

            port = parsed.port
            if port and not (
                (parsed.scheme.lower() == "http" and port == 80)
                or (parsed.scheme.lower() == "https" and port == 443)
            ):
                hostname = f"{hostname}:{port}"

            return urlunsplit((
                parsed.scheme.lower(),
                hostname,
                parsed.path or "/",
                parsed.query,
                ""
            ))

        except ValueError:
            return None

    def load_feed(self):

        print("[Assistant 4] Downloading phishing threat feed...")

        try:
            response = requests.get(
                self.FEED_URL,
                timeout=20,
                headers={
                    "User-Agent": "TrustShieldAI/1.0"
                }
            )

            response.raise_for_status()

            urls = response.text.splitlines()

            self.threat_urls = {
                normalized
                for item in urls
                if (normalized := self.normalize_url(item))
            }

            if not self.threat_urls:
                return False

            self.feed_loaded = True

            print(
                f"[Assistant 4] Loaded "
                f"{len(self.threat_urls)} threat URLs."
            )

            return True

        except requests.RequestException as error:

            print("[Assistant 4] Feed download failed:", error)

            return False

    def check_url(self, website_url):

        normalized_url = self.normalize_url(website_url)

        if not normalized_url:
            return {
                "status": "INVALID_URL",
                "message": "Invalid website URL."
            }

        if not self.feed_loaded:

            if not self.load_feed():

                return {
                    "status": "UNAVAILABLE",
                    "message": "Threat intelligence feed could not be loaded."
                }

        if normalized_url in self.threat_urls:

            return {
                "status": "THREAT_FOUND",
                "source": "OpenPhish Community Feed",
                "threat_type": "PHISHING",
                "message": "This URL appears in the known phishing feed."
            }

        return {
            "status": "NO_MATCH",
            "source": "OpenPhish Community Feed",
            "message": "No match found in the available phishing feed."
        }
