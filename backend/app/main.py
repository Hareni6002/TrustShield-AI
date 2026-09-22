from urllib.parse import urlsplit

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi import HTTPException

from app.schemas.scan import (
    DNSAnalysis,
    BrandAnalysis,
    DomainAnalysis,
    HTTPAnalysis,
    SSLAnalysis,
    ScanRequest,
    ScanResponse,
    LexicalAnalysis,
    URLAnalysis,
)
from app.services.dns_analyzer import analyze_dns
from app.services.domain_analyzer import analyze_domain
from app.services.http_analyzer import analyze_http
from app.services.domain_lexical_analyzer import analyze_lexical
from app.services.risk_engine import calculate_risk
from app.services.ssl_analyzer import analyze_ssl
from app.services.url_analyzer import InvalidURL, analyze_url
from app.utils.security import PrivateNetworkError, resolve_public_host


app = FastAPI(title="TrustShield AI")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root() -> dict[str, str]:
    return {"project": "TrustShield AI", "status": "running"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "healthy"}


@app.post("/api/scan", response_model=ScanResponse)
def scan(request: ScanRequest) -> ScanResponse:
    try:
        url_analysis = analyze_url(request.url)
        hostname = url_analysis["hostname"]
        resolve_public_host(hostname)
    except InvalidURL as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except PrivateNetworkError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    registered_domain = url_analysis["registered_domain"] or hostname
    domain_analysis = analyze_domain(registered_domain) if url_analysis["registered_domain"] else {
        "domain_name": hostname,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "name_servers": [],
        "domain_age_days": None,
        "registration_remaining_days": None,
        "lookup_status": "not_applicable",
    }
    dns_analysis = analyze_dns(hostname)
    parsed = urlsplit(url_analysis["full_url"])
    ssl_analysis = (
        analyze_ssl(hostname, parsed.port)
        if url_analysis["has_https"]
        else {
            "ssl_available": False,
            "ssl_valid": False,
            "certificate_subject": None,
            "certificate_issuer": None,
            "valid_from": None,
            "valid_until": None,
            "days_until_expiry": None,
            "error": "The URL does not use HTTPS.",
        }
    )
    try:
        http_analysis = analyze_http(url_analysis["full_url"])
    except PrivateNetworkError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    brand_analysis, lexical_analysis = analyze_lexical(url_analysis)
    risk = calculate_risk(
        url_analysis,
        domain_analysis,
        ssl_analysis,
        dns_analysis,
        http_analysis,
        brand_analysis,
        lexical_analysis,
    )
    return ScanResponse(
        url=request.url,
        normalized_url=url_analysis["full_url"],
        technical_trust_score=risk["technical_trust_score"],
        technical_risk_score=risk["technical_risk_score"],
        risk_level=risk["risk_level"],
        url_analysis=URLAnalysis(**url_analysis),
        domain_analysis=DomainAnalysis(**domain_analysis),
        ssl_analysis=SSLAnalysis(**ssl_analysis),
        dns_analysis=DNSAnalysis(**dns_analysis),
        http_analysis=HTTPAnalysis(**http_analysis),
        content_analysis=HTTPAnalysis(**http_analysis),
        brand_analysis=BrandAnalysis(**brand_analysis),
        lexical_analysis=LexicalAnalysis(**lexical_analysis),
        positive_signals=risk["positive_signals"],
        warning_signals=risk["warning_signals"],
    )
