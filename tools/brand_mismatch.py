
from urllib.parse import urlparse
from difflib import SequenceMatcher


KNOWN_BRANDS = {
    "google": "google.com",
    "microsoft": "microsoft.com",
    "amazon": "amazon.com",
    "facebook": "facebook.com",
    "paypal": "paypal.com",
    "apple": "apple.com",
}


def inspect_brand(website_url, claimed_brand):

    parsed_url = urlparse(website_url)
    hostname = (parsed_url.hostname or "").lower()

    if not hostname:
        return {
            "status": "INVALID",
            "message": "Unable to identify the website domain."
        }

    brand = claimed_brand.lower().strip()

    if brand not in KNOWN_BRANDS:
        return {
            "status": "UNKNOWN_BRAND",
            "brand": claimed_brand,
            "message": "Brand is not available in the known brand database."
        }

    official_domain = KNOWN_BRANDS[brand]

    if hostname == official_domain or hostname.endswith("." + official_domain):
        return {
            "status": "MATCH",
            "brand": claimed_brand,
            "website_domain": hostname,
            "official_domain": official_domain,
            "similarity": 1.0,
            "message": "Website domain matches the known official domain."
        }

    similarity = SequenceMatcher(
        None, hostname, official_domain
    ).ratio()

    return {
        "status": "MISMATCH",
        "brand": claimed_brand,
        "website_domain": hostname,
        "official_domain": official_domain,
        "similarity": round(similarity, 2),
        "message": "Website domain does not match the known official domain."
    }
