from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from textwrap import wrap
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


DISCLAIMER = (
    "TrustShield AI provides risk indicators based on available technical, machine-learning and "
    "reputation evidence. Results do not guarantee absolute website safety."
)


def _value(value: Any, fallback: str = "Unavailable") -> str:
    if value is None or value == "":
        return fallback
    if isinstance(value, bool):
        return "Yes" if value else "No"
    return str(value)


def _lines(values: list[Any] | None, limit: int = 6) -> str:
    if not values:
        return "None recorded"
    return "\n".join(f"• {_value(item)}" for item in values[:limit])


def _paragraph(text: str, style: ParagraphStyle) -> Paragraph:
    return Paragraph(text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br/>"), style)


def build_scan_report(scan: dict[str, Any]) -> bytes:
    buffer = BytesIO()
    styles = getSampleStyleSheet()
    title = ParagraphStyle("ReportTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=24, leading=28, textColor=colors.HexColor("#181818"), alignment=TA_CENTER, spaceAfter=5)
    subtitle = ParagraphStyle("Subtitle", parent=styles["Normal"], fontName="Helvetica", fontSize=9, textColor=colors.HexColor("#666666"), alignment=TA_CENTER, spaceAfter=16)
    heading = ParagraphStyle("Heading", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=12, leading=15, textColor=colors.HexColor("#8b691f"), spaceBefore=12, spaceAfter=6)
    body = ParagraphStyle("Body", parent=styles["BodyText"], fontName="Helvetica", fontSize=8.5, leading=12, textColor=colors.HexColor("#333333"))
    small = ParagraphStyle("Small", parent=body, fontSize=7.5, leading=10, textColor=colors.HexColor("#666666"))
    score = ParagraphStyle("Score", parent=body, fontName="Helvetica-Bold", fontSize=20, textColor=colors.HexColor("#8b691f"), alignment=TA_CENTER)

    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm, topMargin=15 * mm, bottomMargin=15 * mm, title="TrustShield AI Security Report", author="TrustShield AI")
    story: list[Any] = [Paragraph("TrustShield AI", title), Paragraph("Website Risk Intelligence · Security Assessment", subtitle)]

    scanned_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    identity = [
        [Paragraph("Scan date", body), Paragraph(scanned_at, body)],
        [_paragraph("Scanned URL", body), _paragraph(_value(scan.get("normalized_url")), body)],
        [_paragraph("Domain", body), _paragraph(_value(scan.get("domain_analysis", {}).get("domain_name")), body)],
    ]
    table = Table(identity, colWidths=[35 * mm, 135 * mm])
    table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), .35, colors.HexColor("#dddddd")), ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f3f0e8")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7), ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    story.extend([table, Spacer(1, 8)])

    score_table = Table([[Paragraph("TrustShield Score", body), Paragraph(f"{_value(scan.get('trustshield_score'))}/100", score), Paragraph("Risk level", body), Paragraph(_value(scan.get("trustshield_risk_level")), body)]], colWidths=[38 * mm, 35 * mm, 30 * mm, 67 * mm])
    score_table.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), .7, colors.HexColor("#b2924a")), ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#faf8f1")), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7)]))
    story.extend([score_table, Spacer(1, 8)])

    def section(name: str, rows: list[list[str]]) -> None:
        story.append(Paragraph(name, heading))
        formatted = [[_paragraph(str(label), body), _paragraph(str(value), body)] for label, value in rows]
        section_table = Table(formatted, colWidths=[48 * mm, 122 * mm])
        section_table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), .3, colors.HexColor("#e0e0e0")), ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f7f7f7")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6), ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
        story.append(section_table)

    technical = scan.get("url_analysis", {})
    ssl = scan.get("ssl_analysis", {})
    dns = scan.get("dns_analysis", {})
    domain = scan.get("domain_analysis", {})
    brand = scan.get("brand_analysis", {})
    lexical = scan.get("lexical_analysis", {})
    ml = scan.get("ml_analysis", {})
    reputation = scan.get("reputation_analysis", {})
    explainability = scan.get("explainability", {})
    ai = scan.get("ai_summary", {})

    section("Technical Summary", [["Technical trust", f"{_value(scan.get('technical_trust_score'))}/100"], ["HTTPS", _value(technical.get("has_https"))], ["DNS resolves", _value(dns.get("dns_resolves"))], ["SSL", _value(ssl.get("ssl_valid"))], ["HTTP status", _value(scan.get("http_analysis", {}).get("http_status"))]])
    section("Domain Intelligence", [["Domain age", f"{_value(domain.get('domain_age_days'))} days"], ["Registrar", _value(domain.get("registrar"))], ["Lookup status", _value(domain.get("lookup_status"))]])
    section("Brand Analysis", [["Detected brand", _value(brand.get("detected_brand"))], ["Impersonation", _value(brand.get("possible_brand_impersonation"))], ["Typosquatting", _value(brand.get("possible_typosquatting"))], ["Similarity", f"{_value(brand.get('brand_similarity_score'))}/100"]])
    section("Lexical Risk", [["Risk score", f"{_value(lexical.get('lexical_risk_score'))}/100"], ["Risk level", _value(lexical.get("lexical_risk_level"))], ["Suspicious keywords", _value(lexical.get("suspicious_path_keywords"), "None")]])
    section("ML Prediction", [["Prediction", _value(ml.get("prediction"))], ["Phishing probability", f"{round(ml['phishing_probability'] * 100)}%" if ml.get("phishing_probability") is not None else "Unavailable"], ["Model", _value(ml.get("model_version"))]])
    section("SHAP Top Factors", [["Risk factors", _lines([factor.get("display_name") for factor in explainability.get("top_risk_factors", [])])], ["Trust factors", _lines([factor.get("display_name") for factor in explainability.get("top_trust_factors", [])])]])
    section("Reputation Results", [["Risk score", f"{_value(reputation.get('reputation_risk_score'))}/100"], ["Level", _value(reputation.get("reputation_level"))], ["Confidence", _value(reputation.get("reputation_confidence"))], ["Threat sources", _value(reputation.get("threat_sources"))]])
    section("AI Summary", [["Summary", _value(ai.get("summary"))], ["Recommended action", _value(ai.get("recommended_action"))]])
    section("Signals", [["Positive signals", _lines(scan.get("positive_signals"))], ["Warning signals", _lines(scan.get("warning_signals"))]])

    story.extend([Spacer(1, 12), _paragraph(DISCLAIMER, small)])
    doc.build(story)
    return buffer.getvalue()
