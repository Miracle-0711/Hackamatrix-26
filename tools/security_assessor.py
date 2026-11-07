
from urllib.parse import urlparse


class SecurityAssessor:

    SECURITY_HEADERS = {
        "strict-transport-security":
            "Protects HTTPS connections against downgrade attacks.",

        "content-security-policy":
            "Helps prevent cross-site scripting and content injection.",

        "x-content-type-options":
            "Helps prevent MIME-type sniffing.",

        "x-frame-options":
            "Helps protect against clickjacking.",

        "referrer-policy":
            "Controls how much referrer information is shared.",

        "permissions-policy":
            "Controls access to browser features."
    }

    def inspect_headers(self, website_url, headers):

        parsed = urlparse(website_url)

        if not parsed.hostname:
            return {
                "status": "INVALID_URL",
                "message": "Unable to identify website hostname."
            }

        normalized_headers = {
            key.lower(): value
            for key, value in headers.items()
        }

        present_headers = []
        missing_headers = []

        for header, description in self.SECURITY_HEADERS.items():

            if header in normalized_headers:

                present_headers.append({
                    "header": header,
                    "value": normalized_headers[header],
                    "message": description
                })

            else:

                missing_headers.append({
                    "header": header,
                    "message": description
                })

        https_enabled = parsed.scheme.lower() == "https"

        if not https_enabled:
            missing_headers.append({
                "header": "HTTPS",
                "message": "Website does not use HTTPS."
            })

        return {
            "status": "ANALYZED",
            "website": website_url,
            "https_enabled": https_enabled,
            "total_security_headers": len(self.SECURITY_HEADERS),
            "present_count": len(present_headers),
            "missing_count": len(missing_headers),
            "present_headers": present_headers,
            "missing_headers": missing_headers,
            "message": "Website security header assessment completed."
        }
