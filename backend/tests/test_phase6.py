from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import delete

from app.db import CommunityReport, DomainEntity, DomainRelationship, ScanHistory, SessionLocal, init_db, save_scan_history
from app.main import app


def _cleanup(domain: str) -> None:
    with SessionLocal() as session:
        session.query(CommunityReport).filter(CommunityReport.domain == domain).delete()
        session.query(ScanHistory).filter(ScanHistory.domain == domain).delete()
        session.query(DomainEntity).filter(DomainEntity.domain == domain).delete()
        session.commit()


def _scan(scan_id: str, domain: str, score: int = 80) -> dict:
    return {
        "scan_id": scan_id, "url": f"https://{domain}", "normalized_url": f"https://{domain}/", "domain_analysis": {"domain_name": domain, "registrar": "Test Registrar", "name_servers": ["ns.test"]},
        "trustshield_score": score, "trustshield_risk_level": "LOW OBSERVED RISK", "ml_analysis": {"phishing_probability": 0.1}, "reputation_analysis": {"reputation_risk_score": 0},
        "dns_analysis": {"ip_addresses": ["203.0.113.10"]}, "ssl_analysis": {"certificate_issuer": "Test CA"}, "http_analysis": {"page_title": "Test"},
    }


def test_history_save_and_retrieval():
    init_db()
    domain = "phase6-history.example"
    _cleanup(domain)
    save_scan_history(_scan("phase6-history-id", domain))
    response = TestClient(app).get("/api/history")
    assert response.status_code == 200
    assert any(item["domain"] == domain for item in response.json()["items"])
    _cleanup(domain)


def test_report_validation_duplicate_and_privacy():
    domain = "phase6-report.example"
    _cleanup(domain)
    client = TestClient(app)
    payload = {"url": f"https://{domain}", "category": "Phishing", "description": "Repeated suspicious login behavior observed.", "reporter_email": "private@example.com"}
    first = client.post("/api/reports", json=payload)
    second = client.post("/api/reports", json=payload)
    assert first.status_code == 201 and second.status_code == 201
    assert second.json()["possible_duplicate"] is True
    assert "reporter_email" not in second.text
    assert client.post("/api/reports", json={**payload, "category": "unknown"}).status_code == 422
    _cleanup(domain)


def test_report_moderation_and_community_score():
    domain = "phase6-moderation.example"
    _cleanup(domain)
    client = TestClient(app)
    created = client.post("/api/reports", json={"url": f"https://{domain}", "category": "malware", "description": "Observed a suspicious download prompt."}).json()
    moderated = client.patch(f"/api/reports/{created['id']}", json={"status": "verified"})
    assert moderated.status_code == 200
    summary = client.get(f"/api/reports/domain/{domain}").json()
    assert summary["verified_reports"] == 1
    assert summary["community_risk_score"] > 0
    _cleanup(domain)


def test_network_uses_observed_metadata_only():
    domain = "phase6-network.example"
    related = "phase6-network-login.example"
    _cleanup(domain)
    _cleanup(related)
    save_scan_history(_scan("phase6-network-id", domain))
    save_scan_history(_scan("phase6-related-id", related, 40))
    result = TestClient(app).get(f"/api/network/{domain}")
    assert result.status_code == 200
    assert any(node["id"] == related for node in result.json()["nodes"])
    assert result.json()["edges"][0]["type"] in {"SAME_IP", "SAME_NAMESERVER", "SAME_REGISTRAR", "SIMILAR_DOMAIN"}
    _cleanup(domain)
    _cleanup(related)
