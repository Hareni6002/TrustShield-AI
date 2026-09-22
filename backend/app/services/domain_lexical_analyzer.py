import math
import re
from collections import Counter

from app.services.brand_analyzer import analyze_brand


CAUTION_TLDS = {"xyz", "top", "click", "shop", "online", "site", "live", "work", "support"}
PATH_KEYWORDS = {
    "login", "signin", "verify", "verification", "account", "secure", "security", "update",
    "password", "recover", "billing", "payment", "wallet", "confirm", "auth",
    "authentication", "reset", "otp",
}


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return round(-sum((count / length) * math.log2(count / length) for count in counts.values()), 2)


def _randomness_score(label: str) -> int:
    if not label:
        return 0
    score = 0
    digit_ratio = sum(character.isdigit() for character in label) / len(label)
    vowel_ratio = sum(character in "aeiou" for character in label.lower()) / len(label)
    if digit_ratio >= 0.25:
        score += 25
    elif digit_ratio >= 0.12:
        score += 10
    if any(character.isdigit() for character in label) and any(character.isalpha() for character in label):
        score += 15
    if len(label) >= 10:
        score += 10
    if len(label) >= 8 and vowel_ratio <= 0.2:
        score += 25
    elif len(label) >= 8 and vowel_ratio <= 0.3:
        score += 10
    if shannon_entropy(label) >= 3.0:
        score += 15
    return min(100, score)


def analyze_lexical(url_analysis: dict) -> tuple[dict, dict]:
    hostname = url_analysis["hostname"].lower()
    registered_domain = url_analysis["registered_domain"] or ""
    suffix = (url_analysis["suffix"] or "").lower()
    registered_label = registered_domain[: -(len(suffix) + 1)] if suffix and registered_domain.endswith(f".{suffix}") else registered_domain
    brand = analyze_brand(hostname, registered_domain, url_analysis.get("subdomain"))
    domain_entropy = shannon_entropy(registered_label.replace("-", ""))
    tokens = [token for token in re.split(r"[-_]", registered_label) if token]
    digit_count = sum(character.isdigit() for character in registered_label)
    domain_length = len(registered_label) or 1
    suspicious_path_keywords = sorted(
        keyword for keyword in PATH_KEYWORDS
        if re.search(rf"(?<![a-z]){re.escape(keyword)}(?![a-z])", f"{url_analysis['path']}?{url_analysis.get('query') or ''}".lower())
    )
    randomness = _randomness_score(registered_label.replace("-", ""))
    risk = 0
    if brand["possible_brand_impersonation"]:
        risk += 45
    if brand["misleading_subdomain_detected"]:
        risk += 25
    if brand["possible_typosquatting"]:
        risk += 25
    if brand["possible_homoglyph_impersonation"]:
        risk += 25
    if url_analysis["has_punycode"]:
        risk += 10 if brand["possible_brand_impersonation"] else 3
    risk += min(15, len(suspicious_path_keywords) * 4)
    risk += round(randomness * 0.2)
    if suffix in CAUTION_TLDS:
        risk += 5
    if digit_count >= 3:
        risk += 5
    if registered_label.count("-") >= 3 or "--" in registered_label:
        risk += 5
    if url_analysis.get("subdomain_count", 0) >= 3:
        risk += 5
    risk = min(100, risk)
    if risk <= 19:
        level = "MINIMAL"
    elif risk <= 39:
        level = "LOW"
    elif risk <= 59:
        level = "MODERATE"
    elif risk <= 79:
        level = "HIGH"
    else:
        level = "VERY HIGH"
    lexical = {
        "tld": suffix,
        "tld_risk_indicator": "caution" if suffix in CAUTION_TLDS else "normal",
        "domain_entropy": domain_entropy,
        "domain_randomness_score": randomness,
        "domain_digit_count": digit_count,
        "domain_digit_ratio": round(digit_count / domain_length, 3),
        "domain_hyphen_count": registered_label.count("-"),
        "repeated_hyphens": "--" in registered_label,
        "consecutive_digits": bool(re.search(r"\d{2,}", registered_label)),
        "mixed_alpha_numeric_tokens": any(any(character.isdigit() for character in token) and any(character.isalpha() for character in token) for token in tokens),
        "suspicious_path_keywords": suspicious_path_keywords,
        "lexical_risk_score": risk,
        "lexical_risk_level": level,
    }
    return brand, lexical
