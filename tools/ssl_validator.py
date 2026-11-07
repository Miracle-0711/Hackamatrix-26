
import socket
import ssl
import certifi
from datetime import datetime, timezone
from urllib.parse import urlparse


class SSLValidator:

    def inspect_certificate(self, website_url):

        parsed = urlparse(website_url)
        hostname = parsed.hostname

        if not hostname:
            return {
                "status": "INVALID_URL",
                "message": "Unable to identify website hostname."
            }

        if parsed.scheme.lower() != "https":
            return {
                "status": "NOT_HTTPS",
                "https": False,
                "message": "Website does not use HTTPS."
            }

        try:
            context = ssl.create_default_context(
                cafile=certifi.where()
            )

            with socket.create_connection(
                (hostname, 443),
                timeout=8
            ) as connection:

                with context.wrap_socket(
                    connection,
                    server_hostname=hostname
                ) as secure_connection:

                    certificate = secure_connection.getpeercert()

                    expiry_text = certificate.get("notAfter")

                    expiry_date = datetime.strptime(
                        expiry_text,
                        "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)

                    current_time = datetime.now(timezone.utc)

                    days_remaining = (
                        expiry_date - current_time
                    ).days

                    if days_remaining < 0:
                        certificate_status = "EXPIRED"
                        message = "SSL/TLS certificate has expired."

                    elif days_remaining <= 30:
                        certificate_status = "EXPIRING_SOON"
                        message = "SSL/TLS certificate expires soon."

                    else:
                        certificate_status = "VALID"
                        message = "SSL/TLS certificate is valid."

                    return {
                        "status": certificate_status,
                        "https": True,
                        "certificate_verified": True,
                        "hostname": hostname,
                        "issuer": dict(
                            item[0] for item in
                            certificate.get("issuer", [])
                        ),
                        "expires_at": expiry_date.isoformat(),
                        "days_until_expiry": days_remaining,
                        "message": message
                    }

        except ssl.SSLCertVerificationError as error:

            return {
                "status": "INVALID_CERTIFICATE",
                "https": True,
                "certificate_verified": False,
                "message": str(error)
            }

        except (socket.timeout, TimeoutError):

            return {
                "status": "CONNECTION_TIMEOUT",
                "message": "SSL connection timed out."
            }

        except (OSError, ssl.SSLError, ValueError) as error:

            return {
                "status": "ERROR",
                "message": str(error)
            }
