from app.services.domain_lexical_analyzer import analyze_lexical
from app.services.url_analyzer import analyze_url


ML_FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "dot_count",
    "hyphen_count",
    "underscore_count",
    "digit_count",
    "special_character_count",
    "subdomain_count",
    "has_https",
    "has_ip_address",
    "has_at_symbol",
    "has_double_slash_path",
    "has_punycode",
    "suspicious_keyword_count",
    "domain_digit_count",
    "domain_digit_ratio",
    "domain_hyphen_count",
    "domain_entropy",
    "domain_randomness_score",
    "suspicious_path_keyword_count",
    "brand_similarity_score",
    "official_brand_domain_match",
    "possible_brand_impersonation",
    "possible_typosquatting",
    "misleading_subdomain_detected",
    "url_shortener_detected",
    "tld_caution_indicator",
]


def extract_feature_record(value: str) -> tuple[dict, dict, dict]:
    url_analysis = analyze_url(value)
    brand_analysis, lexical_analysis = analyze_lexical(url_analysis)
    record = {
        "url_length": url_analysis["url_length"],
        "hostname_length": url_analysis["hostname_length"],
        "path_length": url_analysis["path_length"],
        "query_length": url_analysis["query_length"],
        "dot_count": url_analysis["dot_count"],
        "hyphen_count": url_analysis["hyphen_count"],
        "underscore_count": url_analysis["underscore_count"],
        "digit_count": url_analysis["digit_count"],
        "special_character_count": url_analysis["special_character_count"],
        "subdomain_count": url_analysis["subdomain_count"],
        "has_https": int(url_analysis["has_https"]),
        "has_ip_address": int(url_analysis["has_ip_address"]),
        "has_at_symbol": int(url_analysis["has_at_symbol"]),
        "has_double_slash_path": int(url_analysis["has_double_slash_path"]),
        "has_punycode": int(url_analysis["has_punycode"]),
        "suspicious_keyword_count": url_analysis["suspicious_keyword_count"],
        "domain_digit_count": lexical_analysis["domain_digit_count"],
        "domain_digit_ratio": lexical_analysis["domain_digit_ratio"],
        "domain_hyphen_count": lexical_analysis["domain_hyphen_count"],
        "domain_entropy": lexical_analysis["domain_entropy"],
        "domain_randomness_score": lexical_analysis["domain_randomness_score"],
        "suspicious_path_keyword_count": len(lexical_analysis["suspicious_path_keywords"]),
        "brand_similarity_score": 0 if brand_analysis["detected_brand"] and not brand_analysis["possible_brand_impersonation"] else brand_analysis["brand_similarity_score"],
        "official_brand_domain_match": int(
            bool(brand_analysis["detected_brand"])
            and not brand_analysis["possible_brand_impersonation"]
            and not brand_analysis["possible_typosquatting"]
            and not brand_analysis["misleading_subdomain_detected"]
        ),
        "possible_brand_impersonation": int(brand_analysis["possible_brand_impersonation"]),
        "possible_typosquatting": int(brand_analysis["possible_typosquatting"]),
        "misleading_subdomain_detected": int(brand_analysis["misleading_subdomain_detected"]),
        "url_shortener_detected": int(url_analysis["is_shortened_url"]),
        "tld_caution_indicator": int(lexical_analysis["tld_risk_indicator"] == "caution"),
    }
    return record, url_analysis, lexical_analysis


def extract_feature_vector(value: str) -> list[float]:
    record, _, _ = extract_feature_record(value)
    return [float(record[name]) for name in ML_FEATURE_NAMES]
