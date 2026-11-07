
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit


class CommunityThreatLedger:

    def __init__(self, database_path=None):

        project_root = Path(__file__).resolve().parent.parent

        if database_path is None:
            database_path = project_root / "community_threats.db"

        self.database_path = str(database_path)

        self.create_database()

        print("[Assistant 5] Community Threat Ledger initialized.")

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

    def create_database(self):

        with sqlite3.connect(self.database_path) as connection:

            connection.execute("""
                CREATE TABLE IF NOT EXISTS community_threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL UNIQUE,
                    threat_type TEXT NOT NULL,
                    reported_by TEXT NOT NULL,
                    reason TEXT,
                    reported_at TEXT NOT NULL
                )
            """)

    def report_threat(
        self,
        url,
        threat_type="PHISHING",
        reported_by="COMMUNITY",
        reason=""
    ):

        normalized_url = self.normalize_url(url)

        if not normalized_url:
            return {
                "status": "INVALID_URL",
                "message": "A valid HTTP or HTTPS URL is required."
            }

        allowed_types = {
            "PHISHING",
            "MALWARE",
            "SCAM",
            "SUSPICIOUS"
        }

        threat_type = threat_type.upper().strip()

        if threat_type not in allowed_types:
            return {
                "status": "INVALID_TYPE",
                "message": "Unsupported threat type."
            }

        reported_at = datetime.now(timezone.utc).isoformat()

        try:

            with sqlite3.connect(self.database_path) as connection:

                connection.execute("""
                    INSERT INTO community_threats
                    (url, threat_type, reported_by, reason, reported_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    normalized_url,
                    threat_type,
                    reported_by.strip() or "COMMUNITY",
                    reason.strip(),
                    reported_at
                ))

            return {
                "status": "REPORTED",
                "url": normalized_url,
                "threat_type": threat_type,
                "message": "Community threat report saved successfully."
            }

        except sqlite3.IntegrityError:

            return {
                "status": "ALREADY_REPORTED",
                "url": normalized_url,
                "message": "This URL already exists in the community ledger."
            }

    def check_threat(self, url):

        normalized_url = self.normalize_url(url)

        if not normalized_url:
            return {
                "status": "INVALID_URL",
                "message": "Invalid website URL."
            }

        with sqlite3.connect(self.database_path) as connection:

            connection.row_factory = sqlite3.Row

            record = connection.execute("""
                SELECT *
                FROM community_threats
                WHERE url = ?
            """, (normalized_url,)).fetchone()

        if record:

            return {
                "status": "THREAT_FOUND",
                "source": "Trustsheild AI Community Ledger",
                "threat_type": record["threat_type"],
                "reported_by": record["reported_by"],
                "reason": record["reason"],
                "reported_at": record["reported_at"],
                "message": "This URL has been reported by the community."
            }

        return {
            "status": "NO_MATCH",
            "source": "Trustsheild AI Community Ledger",
            "message": "No community report found for this exact URL."
        }

    def get_all_reports(self):

        with sqlite3.connect(self.database_path) as connection:

            connection.row_factory = sqlite3.Row

            records = connection.execute("""
                SELECT *
                FROM community_threats
                ORDER BY id DESC
            """).fetchall()

        return [dict(record) for record in records]
