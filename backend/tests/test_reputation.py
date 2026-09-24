from app.services.reputation import aggregator
from app.services.reputation import cache
from app.services.reputation import google_safe_browsing, urlhaus, virustotal


class FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


def test_virustotal_parses_analysis_stats(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(virustotal.httpx, "get", lambda *args, **kwargs: FakeResponse(200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 72, "undetected": 10}, "last_analysis_date": 123}, "links": {"self": "https://example.test"}}}))
    result = virustotal.lookup("https://example.com/vt-test")
    assert result["status"] == "threat_found"
    assert result["malicious"] == 2
    assert result["suspicious"] == 1


def test_google_parses_clean_response(monkeypatch):
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "test-key")
    monkeypatch.setattr(google_safe_browsing.httpx, "post", lambda *args, **kwargs: FakeResponse(200, {}))
    result = google_safe_browsing.lookup("https://example.com/google-test")
    assert result["status"] == "no_record"
    assert result["threat_detected"] is False


def test_urlhaus_parses_threat_record(monkeypatch):
    monkeypatch.setenv("URLHAUS_ENABLED", "true")
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "test-auth-key")
    monkeypatch.setattr(urlhaus.httpx, "post", lambda *args, **kwargs: FakeResponse(200, {"query_status": "ok", "url_status": "online", "threat": "malware_download", "tags": ["elf"], "date_added": "2026-01-01"}))
    result = urlhaus.lookup("https://example.com/urlhaus-test")
    assert result["status"] == "threat_found"
    assert result["threat"] == "malware_download"


def test_urlhaus_requires_auth_key(monkeypatch):
    monkeypatch.setenv("URLHAUS_ENABLED", "true")
    monkeypatch.delenv("URLHAUS_AUTH_KEY", raising=False)
    result = urlhaus.lookup("https://example.com/urlhaus-no-key")
    assert result["status"] == "not_configured"
    assert result["configured"] is False


def test_urlhaus_maps_auth_failure(monkeypatch):
    monkeypatch.setenv("URLHAUS_ENABLED", "true")
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "bad-key")
    monkeypatch.setattr(urlhaus.httpx, "post", lambda *args, **kwargs: FakeResponse(401, {}))
    result = urlhaus.lookup("https://example.com/urlhaus-auth-failure")
    assert result["status"] == "authentication_failed"


def test_aggregator_handles_partial_provider_results(monkeypatch):
    providers = {
        "virustotal": {"available": True, "status": "threat_found", "malicious": 2, "suspicious": 0},
        "google_safe_browsing": {"available": False, "status": "rate_limited"},
        "urlhaus": {"available": True, "status": "no_record"},
    }
    monkeypatch.setattr(aggregator, "virustotal_lookup", lambda url: providers["virustotal"])
    monkeypatch.setattr(aggregator, "google_lookup", lambda url: providers["google_safe_browsing"])
    monkeypatch.setattr(aggregator, "urlhaus_lookup", lambda url: providers["urlhaus"])
    result = aggregator.analyze_reputation("https://example.com/aggregate-test")
    assert result["providers_checked"] == 3
    assert result["providers_available"] == 2
    assert result["threat_sources"] == 1
    assert 0 <= result["reputation_risk_score"] <= 100


def test_fusion_is_bounded_and_reports_conflict():
    reputation = {"reputation_risk_score": 90, "providers_available": 2, "reputation_trust_score": 10}
    result = aggregator.fuse_trustshield_score(95, 4, 0.08, reputation)
    assert 0 <= result["trustshield_score"] <= 100
    assert result["signal_conflict"] is True


def test_reputation_cache_expires(monkeypatch):
    cache.clear_cache()
    monkeypatch.setattr(cache, "CACHE_TTL_SECONDS", 0)
    cache.set_cached("test", {"value": 1})
    assert cache.get_cached("test") is None


def test_provider_failures_are_sanitized(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(virustotal.httpx, "get", lambda *args, **kwargs: FakeResponse(429, {}))
    result = virustotal.lookup("https://example.com/rate-limit-test")
    assert result["status"] == "rate_limited"
    assert "test-key" not in str(result)
