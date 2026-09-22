import ipaddress
import re
from urllib.parse import parse_qs, urlsplit

import tldextract


SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "confirm",
    "banking",
    "payment",
    "wallet",
    "free",
    "bonus",
    "claim",
    "winner",
    "gift",
    "signin",
    "password",
    "credential",
}
SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
}


class InvalidURL(ValueError):
    pass


def _hostname_is_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def normalize_url(value: str) -> str:
    candidate = value.strip()
    if not candidate:
        raise InvalidURL("A URL is required.")
    if any(character.isspace() for character in candidate):
        raise InvalidURL("The URL cannot contain spaces.")

    if "://" not in candidate:
        candidate = f"https://{candidate}"
    parts = urlsplit(candidate)
    if parts.scheme.lower() not in {"http", "https"}:
        raise InvalidURL("Only http and https URLs are allowed.")
    if not parts.hostname:
        raise InvalidURL("The URL must include a hostname.")
    hostname = parts.hostname.rstrip(".")
    if hostname.lower() in {"localhost", "localhost.localdomain"}:
        return f"{parts.scheme.lower()}://{hostname}{parts.path or '/'}"
    if not _hostname_is_ip(hostname) and "." not in hostname:
        raise InvalidURL("The URL must include a valid domain name.")

    try:
        port = parts.port
    except ValueError as error:
        raise InvalidURL("The URL contains an invalid port.") from error

    netloc = hostname
    if ":" in hostname and not hostname.startswith("["):
        netloc = f"[{hostname}]"
    if port is not None:
        netloc = f"{netloc}:{port}"
    normalized = f"{parts.scheme.lower()}://{netloc}{parts.path or '/'}"
    if parts.query:
        normalized += f"?{parts.query}"
    return normalized


def extract_url_features(normalized_url: str) -> dict:
    parts = urlsplit(normalized_url)
    hostname = parts.hostname or ""
    extracted = tldextract.extract(hostname)
    registered_domain = extracted.top_domain_under_public_suffix or None
    subdomain = extracted.subdomain or None
    url_text = f"{hostname}{parts.path}{parts.query}"
    keyword_matches = sorted(
        {
            keyword
            for keyword in SUSPICIOUS_KEYWORDS
            if re.search(rf"(?<![a-z]){re.escape(keyword)}(?![a-z])", url_text.lower())
        }
    )
    path = parts.path or "/"
    return {
        "full_url": normalized_url,
        "scheme": parts.scheme.lower(),
        "hostname": hostname,
        "registered_domain": registered_domain,
        "subdomain": subdomain,
        "suffix": extracted.suffix or None,
        "path": path,
        "query": parts.query or None,
        "url_length": len(normalized_url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "query_length": len(parts.query),
        "dot_count": normalized_url.count("."),
        "hyphen_count": normalized_url.count("-"),
        "underscore_count": normalized_url.count("_"),
        "digit_count": sum(character.isdigit() for character in normalized_url),
        "special_character_count": sum(
            not character.isalnum() for character in normalized_url
        ),
        "subdomain_count": len(subdomain.split(".")) if subdomain else 0,
        "has_https": parts.scheme.lower() == "https",
        "has_ip_address": _hostname_is_ip(hostname),
        "has_at_symbol": "@" in normalized_url,
        "has_double_slash_path": "//" in path,
        "has_punycode": any(label.startswith("xn--") for label in hostname.split(".")),
        "suspicious_keyword_count": len(keyword_matches),
        "suspicious_keywords": keyword_matches,
        "is_shortened_url": registered_domain in SHORTENER_DOMAINS
        or hostname.lower() in SHORTENER_DOMAINS,
    }


def analyze_url(value: str) -> dict:
    normalized = normalize_url(value)
    return extract_url_features(normalized)
