
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
import ipaddress


class CredentialInspector(HTMLParser):

    def __init__(self, website_url):
        super().__init__()
        self.website_url = website_url
        self.forms = []
        self.current_form = None

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)

        if tag == "form":
            action = attributes.get("action", "")
            method = attributes.get("method", "GET").upper()

            destination = urljoin(self.website_url, action)
            parsed_destination = urlparse(destination)

            self.current_form = {
                "destination": destination,
                "method": method,
                "fields": [],
                "warnings": []
            }

            website_domain = urlparse(self.website_url).hostname
            destination_domain = parsed_destination.hostname

            if destination_domain and destination_domain.lower() != (
                website_domain or ""
            ).lower():
                self.current_form["warnings"].append(
                    "Form submits to a different hostname."
                )

            if destination_domain:
                try:
                    ipaddress.ip_address(destination_domain)
                    self.current_form["warnings"].append(
                        "Form submits to a raw IP address."
                    )
                except ValueError:
                    pass

            self.forms.append(self.current_form)

        elif tag == "input" and self.current_form is not None:
            field_type = attributes.get("type", "text").lower()
            field_name = attributes.get("name", "").lower()
            autocomplete = attributes.get("autocomplete", "").lower()

            field_text = f"{field_name} {autocomplete}"

            if field_type == "password" or "password" in field_text:
                category = "PASSWORD"

            elif any(word in field_text for word in [
                "otp", "one-time-code", "verification_code"
            ]):
                category = "OTP"

            elif any(word in field_text for word in [
                "card", "credit", "cvv", "cvc", "payment"
            ]):
                category = "PAYMENT"

            else:
                category = "OTHER"

            self.current_form["fields"].append({
                "name": field_name,
                "type": field_type,
                "category": category
            })

    def handle_endtag(self, tag):
        if tag == "form":
            self.current_form = None

    def get_report(self):
        return {
            "website": self.website_url,
            "total_forms": len(self.forms),
            "forms": self.forms
        }


def inspect_html(website_url, html):
    inspector = CredentialInspector(website_url)
    inspector.feed(html)
    inspector.close()

    return inspector.get_report()
