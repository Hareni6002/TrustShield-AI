import os
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi import HTTPException
from fastapi import Query
from fastapi.responses import Response

from app.schemas.scan import (
    DNSAnalysis,
    BrandAnalysis,
    DomainAnalysis,
    HTTPAnalysis,
    MLAnalysis,
    SSLAnalysis,
    ScanRequest,
    ScanResponse,
    ReputationAnalysis,
    AISummary,
    AISummaryRequest,
    AIAskRequest,
    AIAskResponse,
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
from app.ml.predictor import model_info, predict_url
from app.ml.explainer import explain_url
from app.ml.features import extract_feature_vector
from app.services.reputation.aggregator import analyze_reputation, fuse_trustshield_score
from app.services.ai.context_builder import build_context
from app.services.ai.safety import deterministic_summary
from app.services.ai.service import answer_question, generate_summary
from app.services.ai.provider import gemini_status
from app.services.ai.store import get_scan, save_scan
from app.services.report_generator import build_scan_report
from app.core.config import integration_status
from app.db import create_report, delete_history, get_history, get_stored_scan, init_db, list_history, list_reports, moderate_report, network_for, report_summary, save_scan_history
from app.schemas.community import CommunityReportCreate, ReportModeration


init_db()


app = FastAPI(title="TrustShield AI")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in os.getenv("FRONTEND_ORIGIN", "http://localhost:5173,http://127.0.0.1:5173").split(",") if origin.strip()],
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


@app.get("/api/model-info")
def get_model_info() -> dict:
    return model_info()


@app.get("/api/integrations/status")
def get_integrations_status() -> dict:
    status = integration_status()
    status["gemini"] = gemini_status()
    return status


@app.get("/api/history")
def history(page: int = Query(1, ge=1), limit: int = Query(20, ge=1, le=100)) -> dict:
    items, total = list_history((page - 1) * limit, limit)
    return {"items": items, "page": page, "limit": limit, "total": total, "pages": (total + limit - 1) // limit}


@app.get("/api/history/{history_id}")
def history_detail(history_id: int) -> dict:
    value = get_history(history_id)
    if value is None:
        raise HTTPException(status_code=404, detail="History record not found.")
    return value


@app.get("/api/history/{history_id}/result")
def history_result(history_id: int) -> dict:
    value = get_history(history_id)
    if value is None:
        raise HTTPException(status_code=404, detail="History record not found.")
    scan_data = get_scan(value["scan_id"]) or get_stored_scan(value["scan_id"])
    if scan_data is None:
        raise HTTPException(status_code=410, detail="The full scan result is no longer available; run a new scan.")
    return scan_data


@app.get("/api/scans/{scan_id}/report")
def scan_report(scan_id: str) -> Response:
    scan_data = get_scan(scan_id) or get_stored_scan(scan_id)
    if scan_data is None:
        raise HTTPException(status_code=404, detail="The requested scan report is no longer available.")
    try:
        pdf = build_scan_report(scan_data)
    except Exception as error:
        raise HTTPException(status_code=500, detail="The security report could not be generated.") from error
    domain = scan_data.get("domain_analysis", {}).get("domain_name", "scan")
    safe_domain = "".join(character if character.isalnum() or character in {".", "-"} else "-" for character in domain)
    return Response(content=pdf, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="trustshield-{safe_domain}.pdf"'})


@app.delete("/api/history/{history_id}")
def history_delete(history_id: int) -> dict[str, bool]:
    if not delete_history(history_id):
        raise HTTPException(status_code=404, detail="History record not found.")
    return {"deleted": True}


@app.post("/api/reports", status_code=201)
def report_create(request: CommunityReportCreate) -> dict:
    try:
        parsed = analyze_url(request.url)
    except InvalidURL as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    data = request.model_dump()
    data["domain"] = parsed["registered_domain"] or parsed["hostname"]
    return create_report(data)


@app.get("/api/reports/domain/{domain}")
def domain_reports(domain: str) -> dict:
    return report_summary(domain.lower().strip().rstrip("."))


@app.get("/api/reports")
def reports(status: str | None = Query(None), limit: int = Query(100, ge=1, le=200)) -> dict:
    if status and status not in {"pending", "verified", "rejected"}:
        raise HTTPException(status_code=400, detail="Unsupported report status.")
    return {"items": list_reports(status, limit)}


@app.patch("/api/reports/{report_id}")
def report_moderate(report_id: int, request: ReportModeration) -> dict:
    value = moderate_report(report_id, request.status)
    if value is None:
        raise HTTPException(status_code=404, detail="Report not found.")
    return value


@app.get("/api/network/{domain}")
def network(domain: str) -> dict:
    return network_for(domain.lower().strip().rstrip("."))


@app.post("/api/ai/summary", response_model=AISummary)
def ai_summary(request: AISummaryRequest) -> AISummary:
    scan_data = get_scan(request.scan_id)
    if scan_data is None:
        raise HTTPException(status_code=404, detail="The requested scan is no longer available.")
    return AISummary(**generate_summary(scan_data))


@app.post("/api/ai/ask", response_model=AIAskResponse)
def ask_trustshield(request: AIAskRequest) -> AIAskResponse:
    scan_data = get_scan(request.scan_id)
    if scan_data is None:
        raise HTTPException(status_code=404, detail="The requested scan is no longer available.")
    return AIAskResponse(**answer_question(scan_data, request.question.strip()))


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
    feature_vector = extract_feature_vector(url_analysis["full_url"])
    ml_analysis = predict_url(url_analysis["full_url"], feature_vector)
    explainability = explain_url(url_analysis["full_url"], feature_vector)
    reputation_analysis = analyze_reputation(url_analysis["full_url"])
    fusion = fuse_trustshield_score(
        risk["technical_trust_score"],
        lexical_analysis["lexical_risk_score"],
        ml_analysis.get("phishing_probability"),
        reputation_analysis,
    )
    phishing_probability = ml_analysis.get("phishing_probability")
    signal_conflict = bool(
        phishing_probability is not None
        and (
            (risk["technical_trust_score"] >= 80 and phishing_probability >= 0.65)
            or (risk["technical_trust_score"] < 40 and phishing_probability <= 0.35)
        )
    )
    ml_analysis["signal_conflict"] = signal_conflict
    ml_analysis["conflict_message"] = (
        "Technical signals and machine-learning assessment disagree. Additional verification is recommended."
        if signal_conflict
        else None
    )
    scan_response = ScanResponse(
        scan_id=str(uuid4()),
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
        ml_analysis=MLAnalysis(**ml_analysis),
        explainability=explainability,
        reputation_analysis=ReputationAnalysis(**reputation_analysis),
        trustshield_score=fusion["trustshield_score"],
        trustshield_risk_level=fusion["trustshield_risk_level"],
        score_components=fusion["score_components"],
        signal_conflict=fusion["signal_conflict"],
        conflict_message=fusion["conflict_message"],
        ai_summary=AISummary(
            summary="Interpreting the completed scan evidence.",
            recommended_action="Review the technical, ML, and reputation evidence before sharing sensitive information.",
        ),
        positive_signals=risk["positive_signals"],
        warning_signals=risk["warning_signals"],
    )
    scan_data = scan_response.model_dump(mode="json")
    scan_response.ai_summary = AISummary(**deterministic_summary(build_context(scan_data)))
    final_scan_data = scan_response.model_dump(mode="json")
    save_scan(scan_response.scan_id, final_scan_data)
    try:
        save_scan_history(final_scan_data)
    except Exception:
        # History is supplementary; a database problem must not fail a completed scan.
        pass
    return scan_response
