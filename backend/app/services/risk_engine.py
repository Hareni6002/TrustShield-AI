def calculate_risk(
    url: dict,
    domain: dict,
    ssl: dict,
    dns: dict,
    http: dict,
    brand: dict | None = None,
    lexical: dict | None = None,
) -> dict:
    risk = 0
    warnings: list[str] = []
    positives: list[str] = []

    def warn(points: int, message: str) -> None:
        nonlocal risk
        risk += points
        warnings.append(message)

    def positive(points: int, message: str) -> None:
        nonlocal risk
        risk -= points
        positives.append(message)

    if url["has_ip_address"]:
        warn(20, "The URL uses an IP address instead of a domain name.")
    if url["subdomain_count"] >= 3:
        warn(8, "The hostname contains many subdomain levels.")
    if url["url_length"] > 120:
        warn(8, "The URL is unusually long.")
    if url["suspicious_keyword_count"]:
        warn(5 + min(url["suspicious_keyword_count"], 3), "The URL contains suspicious terms.")
    if url["is_shortened_url"]:
        warn(8, "The URL uses a shortening service, which hides its final destination.")
    if url["has_at_symbol"]:
        warn(8, "The URL contains an @ symbol, an unusual URL structure.")
    if url["has_double_slash_path"]:
        warn(5, "The URL path contains a double slash.")
    if url["has_punycode"]:
        warn(10, "The hostname contains punycode.")
    if not url["has_https"]:
        warn(5, "The URL does not use HTTPS.")
    elif ssl.get("ssl_valid"):
        positive(10, "The HTTPS certificate is currently valid.")
    elif ssl.get("ssl_available"):
        warn(15, "HTTPS is available but certificate validation did not succeed.")
    else:
        warn(12, "An HTTPS connection could not be established.")

    age = domain.get("domain_age_days")
    if age is not None and age < 30:
        warn(15, "The domain was registered recently.")
    elif age is not None and age < 180:
        warn(8, "The domain is relatively new.")
    elif age is not None and age >= 1825:
        positive(12, "The domain has existed for several years.")
    elif age is not None and age >= 365:
        positive(8, "The domain has existed for at least one year.")

    if dns.get("dns_resolves"):
        positive(3, "The domain has working DNS records.")
    else:
        warn(10, "The domain did not return usable DNS address records.")
    if http.get("redirect_count", 0) > 2:
        warn(5, "The request followed multiple redirects.")
    if http.get("has_password_field"):
        warn(3, "The page contains a password field; this is contextual, not proof of fraud.")
    if http.get("has_payment_keywords"):
        warn(3, "The page contains payment-related terms; this is contextual, not proof of fraud.")
    if lexical:
        risk += round(lexical.get("lexical_risk_score", 0) * 0.6)
        if lexical.get("suspicious_path_keywords"):
            warnings.append(
                "The path contains suspicious terms: "
                + ", ".join(lexical["suspicious_path_keywords"])
                + "."
            )
        if lexical.get("domain_randomness_score", 0) >= 60:
            warnings.append("The registered domain has an unusually random character pattern.")
        if lexical.get("tld_risk_indicator") == "caution":
            warnings.append(f"The .{lexical.get('tld')} TLD is marked for additional caution.")
    if brand:
        if brand.get("explanation"):
            warnings.append(brand["explanation"])
        if brand.get("detected_brand") and not brand.get("possible_brand_impersonation"):
            positives.append(
                f"The registered domain exactly matches a known legitimate {brand['detected_brand']} domain."
            )

    risk = max(0, min(100, risk))
    trust = 100 - risk
    if trust >= 80:
        level = "LOW TECHNICAL RISK"
    elif trust >= 60:
        level = "MODERATE-LOW RISK"
    elif trust >= 40:
        level = "UNCERTAIN"
    elif trust >= 20:
        level = "SUSPICIOUS"
    else:
        level = "HIGH TECHNICAL RISK"
    return {
        "technical_trust_score": trust,
        "technical_risk_score": risk,
        "risk_level": level,
        "positive_signals": positives,
        "warning_signals": warnings,
    }
