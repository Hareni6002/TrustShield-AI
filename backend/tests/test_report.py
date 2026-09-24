from app.services.report_generator import build_scan_report


def test_pdf_report_is_generated_without_provider_secrets() -> None:
    scan = {
        "normalized_url": "https://example.com",
        "domain_analysis": {"domain_name": "example.com"},
        "trustshield_score": 82,
        "trustshield_risk_level": "LOW OBSERVED RISK",
        "technical_trust_score": 90,
        "url_analysis": {},
        "ssl_analysis": {},
        "dns_analysis": {},
        "http_analysis": {},
        "brand_analysis": {},
        "lexical_analysis": {},
        "ml_analysis": {},
        "explainability": {},
        "reputation_analysis": {},
        "ai_summary": {"summary": "Fallback summary", "recommended_action": "Review evidence."},
        "positive_signals": ["HTTPS enabled"],
        "warning_signals": [],
    }

    pdf = build_scan_report(scan)

    assert pdf.startswith(b"%PDF")
    assert b"API" not in pdf
