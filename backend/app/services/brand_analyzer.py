import json
import re
from difflib import SequenceMatcher
from pathlib import Path

import tldextract


SUBSTITUTIONS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s"})
HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "Α": "a", "Ε": "e", "Ο": "o", "Ρ": "p", "Χ": "x",
}


def _load_brands() -> dict[str, list[str]]:
    source = Path(__file__).resolve().parents[2] / "data" / "known_brands.json"
    with source.open(encoding="utf-8") as file:
        return json.load(file)


KNOWN_BRANDS = _load_brands()


def _similarity(left: str, right: str) -> int:
    direct = SequenceMatcher(None, left, right).ratio()
    substituted = SequenceMatcher(None, left.translate(SUBSTITUTIONS), right).ratio()
    return round(max(direct, substituted) * 100)


def _unicode_domain(hostname: str) -> str | None:
    try:
        return hostname.encode("ascii").decode("idna") if hostname.startswith("xn--") else None
    except UnicodeError:
        return None


def _homoglyph_candidate(hostname: str, brand: str) -> bool:
    if not any(character in HOMOGLYPHS for character in hostname):
        return False
    mapped = "".join(HOMOGLYPHS.get(character, character) for character in hostname).lower()
    return _similarity(mapped, brand) >= 85


def analyze_brand(hostname: str, registered_domain: str | None, subdomain: str | None) -> dict:
    hostname = hostname.lower().rstrip(".")
    registered = (registered_domain or "").lower()
    labels = [label for label in re.split(r"[._-]+", hostname) if label]
    extracted = tldextract.extract(hostname)
    exact_brand = None
    legitimate_domains: list[str] = []
    for brand, domains in KNOWN_BRANDS.items():
        if registered in domains:
            exact_brand = brand
            legitimate_domains = domains
            break

    if exact_brand:
        return {
            "detected_brand": exact_brand,
            "brand_similarity_score": 100,
            "possible_brand_impersonation": False,
            "possible_typosquatting": False,
            "possible_homoglyph_impersonation": False,
            "misleading_subdomain_detected": False,
            "brand_like_subdomain": None,
            "legitimate_domains": legitimate_domains,
            "unicode_domain": _unicode_domain(hostname),
            "explanation": f"The registered domain matches the known legitimate {exact_brand} domain.",
        }

    best_brand = None
    best_score = 0
    possible_typo = False
    for brand in KNOWN_BRANDS:
        for label in labels:
            if len(label) < 4:
                continue
            score = _similarity(label, brand)
            if score > best_score:
                best_brand = brand
                best_score = score
            normalized_label = label.translate(SUBSTITUTIONS)
            if normalized_label == brand and label != brand:
                possible_typo = True

    misleading_brand = None
    brand_like_subdomain = None
    subdomain_value = (subdomain or "").lower()
    for brand, domains in KNOWN_BRANDS.items():
        for legitimate_domain in domains:
            if legitimate_domain in subdomain_value and registered not in domains:
                misleading_brand = brand
                brand_like_subdomain = legitimate_domain
                break
        if misleading_brand:
            break

    homoglyph_brand = next(
        (brand for brand in KNOWN_BRANDS if _homoglyph_candidate(hostname, brand)),
        None,
    )
    possible_typo = possible_typo or bool(best_brand and 82 <= best_score < 100 and not homoglyph_brand)
    detected_brand = (
        misleading_brand
        or homoglyph_brand
        or (best_brand if best_score >= 75 or possible_typo else None)
    )
    impersonation = bool(
        misleading_brand
        or homoglyph_brand
        or (
            best_brand
            and (best_score >= 88 or possible_typo)
            and registered not in KNOWN_BRANDS.get(best_brand, [])
        )
    )
    explanations = []
    if misleading_brand:
        explanations.append(
            f"The URL contains '{brand_like_subdomain}' in the subdomain, but the actual registered domain is '{registered}'."
        )
    if possible_typo and best_brand:
        explanations.append(
            f"The domain contains a character pattern that resembles '{best_brand}' and may indicate typosquatting."
        )
    if homoglyph_brand:
        explanations.append("Possible visual brand impersonation detected.")
    if impersonation and best_brand and not misleading_brand and not homoglyph_brand:
        explanations.append(f"Possible {best_brand} impersonation: the domain closely resembles a known brand.")
    return {
        "detected_brand": detected_brand,
        "brand_similarity_score": best_score if detected_brand else 0,
        "possible_brand_impersonation": impersonation,
        "possible_typosquatting": possible_typo,
        "possible_homoglyph_impersonation": bool(homoglyph_brand),
        "misleading_subdomain_detected": bool(misleading_brand),
        "brand_like_subdomain": brand_like_subdomain,
        "legitimate_domains": KNOWN_BRANDS.get(detected_brand, []) if detected_brand else [],
        "unicode_domain": _unicode_domain(hostname),
        "explanation": " ".join(explanations) if explanations else None,
    }
