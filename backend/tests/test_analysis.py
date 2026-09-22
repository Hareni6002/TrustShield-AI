import pytest

from app.services.risk_engine import calculate_risk
from app.services.domain_lexical_analyzer import analyze_lexical, shannon_entropy
from app.services.url_analyzer import InvalidURL, analyze_url, normalize_url
from app.utils.security import PrivateNetworkError, resolve_public_host


def test_normalizes_domain_without_scheme():
    assert normalize_url("google.com") == "https://google.com/"


def test_rejects_invalid_scheme_and_bare_word():
    with pytest.raises(InvalidURL):
        normalize_url("javascript:alert(1)")
    with pytest.raises(InvalidURL):
        normalize_url("hello")


def test_extracts_ip_and_suspicious_keywords():
    analysis = analyze_url("http://8.8.8.8/login/verify")
    assert analysis["has_ip_address"] is True
    assert analysis["suspicious_keyword_count"] == 2


def test_detects_shortener():
    assert analyze_url("https://bit.ly/example")["is_shortened_url"] is True


@pytest.mark.parametrize("hostname", ["localhost", "127.0.0.1", "10.0.0.1", "192.168.1.1"])
def test_blocks_private_network_targets(hostname):
    with pytest.raises(PrivateNetworkError):
        resolve_public_host(hostname)


def test_risk_score_is_bounded():
    url_analysis = analyze_url("http://8.8.8.8/login/verify/password")
    result = calculate_risk(
        url_analysis,
        {"domain_age_days": 1},
        {"ssl_valid": False, "ssl_available": False},
        {"dns_resolves": False},
        {"redirect_count": 5, "has_password_field": True, "has_payment_keywords": True},
    )
    assert 0 <= result["technical_risk_score"] <= 100
    assert 0 <= result["technical_trust_score"] <= 100


def lexical_result(value):
    return analyze_lexical(analyze_url(value))


def test_known_brand_and_official_subdomain_are_not_impersonation():
    brand, lexical = lexical_result("https://paypal.com")
    subdomain_brand, _ = lexical_result("https://support.paypal.com")
    assert brand["possible_brand_impersonation"] is False
    assert brand["possible_typosquatting"] is False
    assert subdomain_brand["possible_brand_impersonation"] is False
    assert lexical["lexical_risk_score"] == 0


@pytest.mark.parametrize(
    ("value", "expected_brand"),
    [
        ("https://paypa1-login.com", "paypal"),
        ("https://amaz0n-support.xyz", "amazon"),
        ("https://micros0ft-login.net", "microsoft"),
        ("https://netfl1x-billing.xyz", "netflix"),
    ],
)
def test_detects_brand_typosquatting(value, expected_brand):
    brand, _ = lexical_result(value)
    assert brand["detected_brand"] == expected_brand
    assert brand["possible_typosquatting"] is True
    assert brand["possible_brand_impersonation"] is True


@pytest.mark.parametrize(
    ("value", "expected_domain"),
    [
        ("https://paypal.com.fake-login.xyz", "fake-login.xyz"),
        ("https://google.com.verify-account.xyz", "verify-account.xyz"),
    ],
)
def test_detects_misleading_subdomain(value, expected_domain):
    brand, _ = lexical_result(value)
    assert brand["misleading_subdomain_detected"] is True
    assert expected_domain in brand["explanation"]


def test_punycode_entropy_and_randomness_signals():
    punycode_url = analyze_url("https://xn--pple-43d.com")
    assert punycode_url["has_punycode"] is True
    assert shannon_entropy("aaaa") == 0.0
    _, lexical = lexical_result("https://x9q2z7a1k.xyz")
    assert lexical["domain_randomness_score"] >= 60
    assert 0 <= lexical["lexical_risk_score"] <= 100


def test_suspicious_tld_and_path_are_structured_signals():
    _, lexical = lexical_result("https://example.xyz/login/verify/account")
    assert lexical["tld_risk_indicator"] == "caution"
    assert lexical["suspicious_path_keywords"] == ["account", "login", "verify"]
