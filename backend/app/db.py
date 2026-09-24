from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text, create_engine, desc, func, inspect, or_, select, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


def _database_url() -> str:
    configured = os.getenv("DATABASE_URL", "").strip()
    if configured and configured.startswith("sqlite:///"):
        return configured
    return f"sqlite:///{Path(__file__).resolve().parents[1] / 'trustshield.db'}"


engine = create_engine(_database_url(), connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class ScanHistory(Base):
    __tablename__ = "scan_history"
    __table_args__ = ({"sqlite_autoincrement": True},)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    url: Mapped[str] = mapped_column(String(4096))
    normalized_url: Mapped[str] = mapped_column(String(4096))
    domain: Mapped[str] = mapped_column(String(255), index=True)
    trustshield_score: Mapped[int] = mapped_column(Integer)
    risk_level: Mapped[str] = mapped_column(String(80))
    ml_probability: Mapped[float | None] = mapped_column(Float, nullable=True)
    reputation_risk_score: Mapped[int] = mapped_column(Integer)
    reportable_metadata: Mapped[str] = mapped_column(Text, default="{}")
    scan_payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class CommunityReport(Base):
    __tablename__ = "community_reports"
    __table_args__ = ({"sqlite_autoincrement": True},)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    url: Mapped[str] = mapped_column(String(4096))
    category: Mapped[str] = mapped_column(String(80), index=True)
    description: Mapped[str] = mapped_column(Text)
    reporter_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    reporter_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    possible_duplicate: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class DomainEntity(Base):
    __tablename__ = "domain_entities"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(255), nullable=True)
    registrar: Mapped[str | None] = mapped_column(String(255), nullable=True)
    name_server: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    ssl_issuer: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class DomainRelationship(Base):
    __tablename__ = "domain_relationships"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_domain: Mapped[str] = mapped_column(String(255), index=True)
    target_domain: Mapped[str] = mapped_column(String(255), index=True)
    relationship_type: Mapped[str] = mapped_column(String(50))
    confidence: Mapped[float] = mapped_column(Float)
    evidence: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


def init_db() -> None:
    Base.metadata.create_all(engine)
    # Keep the demo SQLite database compatible with additive schema changes.
    columns = {column["name"] for column in inspect(engine).get_columns("scan_history")}
    if "scan_payload" not in columns:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE scan_history ADD COLUMN scan_payload TEXT"))


def _json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), default=str)


def save_scan_history(scan: dict[str, Any]) -> int:
    now = datetime.now(timezone.utc)
    domain = scan["domain_analysis"]["domain_name"].lower()
    metadata = {
        "ip_addresses": scan.get("dns_analysis", {}).get("ip_addresses", []),
        "registrar": scan.get("domain_analysis", {}).get("registrar"),
        "name_servers": scan.get("domain_analysis", {}).get("name_servers", []),
        "ssl_issuer": scan.get("ssl_analysis", {}).get("certificate_issuer"),
        "page_title": scan.get("http_analysis", {}).get("page_title"),
        "final_url": scan.get("http_analysis", {}).get("final_url"),
    }
    with SessionLocal() as session:
        row = ScanHistory(
            scan_id=scan["scan_id"], url=scan["url"], normalized_url=scan["normalized_url"], domain=domain,
            trustshield_score=scan["trustshield_score"], risk_level=scan["trustshield_risk_level"],
            ml_probability=scan.get("ml_analysis", {}).get("phishing_probability"),
            reputation_risk_score=scan.get("reputation_analysis", {}).get("reputation_risk_score", 0),
            reportable_metadata=_json(metadata), scan_payload=_json(scan), created_at=now,
        )
        session.add(row)
        entity = session.scalar(select(DomainEntity).where(DomainEntity.domain == domain))
        values = {
            "ip_address": ",".join(metadata["ip_addresses"][:10]) or None,
            "registrar": metadata["registrar"],
            "name_server": ",".join(metadata["name_servers"][:10]) or None,
            "ssl_issuer": metadata["ssl_issuer"],
            "last_seen_at": now,
        }
        if entity is None:
            session.add(DomainEntity(domain=domain, created_at=now, **values))
        else:
            for key, value in values.items():
                setattr(entity, key, value)
        session.commit()
        return row.id


def _history_dict(row: ScanHistory, reports: int = 0) -> dict[str, Any]:
    return {
        "id": row.id, "scan_id": row.scan_id, "url": row.url, "normalized_url": row.normalized_url,
        "domain": row.domain, "trustshield_score": row.trustshield_score, "risk_level": row.risk_level,
        "ml_probability": row.ml_probability, "reputation_risk_score": row.reputation_risk_score,
        "created_at": row.created_at.isoformat(), "community_reports": reports,
    }


def list_history(offset: int, limit: int) -> tuple[list[dict[str, Any]], int]:
    with SessionLocal() as session:
        total = session.scalar(select(func.count()).select_from(ScanHistory)) or 0
        rows = session.scalars(select(ScanHistory).order_by(desc(ScanHistory.created_at)).offset(offset).limit(limit)).all()
        result = []
        for row in rows:
            reports = session.scalar(select(func.count()).select_from(CommunityReport).where(CommunityReport.domain == row.domain)) or 0
            result.append(_history_dict(row, reports))
        return result, total


def get_history(row_id: int) -> dict[str, Any] | None:
    with SessionLocal() as session:
        row = session.get(ScanHistory, row_id)
        if row is None:
            return None
        reports = session.scalar(select(func.count()).select_from(CommunityReport).where(CommunityReport.domain == row.domain)) or 0
        return _history_dict(row, reports)


def get_stored_scan(scan_id: str) -> dict[str, Any] | None:
    with SessionLocal() as session:
        row = session.scalar(select(ScanHistory).where(ScanHistory.scan_id == scan_id))
        if row is None or not row.scan_payload:
            return None
        return json.loads(row.scan_payload)


def delete_history(row_id: int) -> bool:
    with SessionLocal() as session:
        row = session.get(ScanHistory, row_id)
        if row is None:
            return False
        session.delete(row)
        session.commit()
        return True


def _public_report(row: CommunityReport) -> dict[str, Any]:
    return {"id": row.id, "domain": row.domain, "url": row.url, "category": row.category, "description": row.description, "status": row.status, "possible_duplicate": row.possible_duplicate, "created_at": row.created_at.isoformat()}


def create_report(data: dict[str, Any]) -> dict[str, Any]:
    with SessionLocal() as session:
        recent = session.scalar(select(CommunityReport).where(
            CommunityReport.domain == data["domain"], CommunityReport.category == data["category"],
            CommunityReport.description == data["description"],
            CommunityReport.created_at >= datetime.fromtimestamp(datetime.now().timestamp() - 7 * 86400, tz=timezone.utc),
        ).order_by(desc(CommunityReport.created_at)))
        row = CommunityReport(**data, possible_duplicate=recent is not None)
        session.add(row)
        session.commit()
        session.refresh(row)
        return _public_report(row)


def report_summary(domain: str) -> dict[str, Any]:
    with SessionLocal() as session:
        rows = session.scalars(select(CommunityReport).where(CommunityReport.domain == domain).order_by(desc(CommunityReport.created_at))).all()
        verified = [row for row in rows if row.status == "verified"]
        category_breakdown: dict[str, int] = {}
        for row in verified:
            category_breakdown[row.category] = category_breakdown.get(row.category, 0) + 1
        score = min(100, len(verified) * 15 + sum(5 for row in rows if row.status == "pending") + sum(8 for row in verified if row.possible_duplicate))
        return {"domain": domain, "total_reports": len(rows), "verified_reports": len(verified), "pending_reports": sum(row.status == "pending" for row in rows), "community_risk_score": score, "category_breakdown": category_breakdown, "latest_reports": [_public_report(row) for row in rows[:10]]}


def list_reports(status: str | None, limit: int = 100) -> list[dict[str, Any]]:
    with SessionLocal() as session:
        query = select(CommunityReport).order_by(desc(CommunityReport.created_at)).limit(limit)
        if status:
            query = query.where(CommunityReport.status == status)
        return [_public_report(row) for row in session.scalars(query).all()]


def moderate_report(report_id: int, status: str) -> dict[str, Any] | None:
    with SessionLocal() as session:
        row = session.get(CommunityReport, report_id)
        if row is None:
            return None
        row.status = status
        session.commit()
        session.refresh(row)
        return _public_report(row)


def network_for(domain: str) -> dict[str, Any]:
    domain = domain.lower()
    with SessionLocal() as session:
        rows = session.scalars(select(ScanHistory).order_by(desc(ScanHistory.created_at)).limit(200)).all()
        current = next((row for row in rows if row.domain == domain), None)
        if current is None:
            return {"domain": domain, "nodes": [{"id": domain, "risk": 0}], "edges": [], "note": "No stored scan metadata is available for this domain."}
        current_meta = json.loads(current.reportable_metadata or "{}")
        nodes = {domain: {"id": domain, "risk": max(0, min(100, 100 - current.trustshield_score))}}
        edges: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        for row in rows:
            if row.domain == domain or row.domain in nodes:
                continue
            meta = json.loads(row.reportable_metadata or "{}")
            candidates: list[tuple[str, float, str]] = []
            shared_ips = set(current_meta.get("ip_addresses", [])) & set(meta.get("ip_addresses", []))
            shared_ns = set(current_meta.get("name_servers", [])) & set(meta.get("name_servers", []))
            if shared_ips:
                candidates.append(("SAME_IP", 85.0, f"Shared observed IP: {sorted(shared_ips)[0]}"))
            if shared_ns:
                candidates.append(("SAME_NAMESERVER", 70.0, f"Shared observed nameserver: {sorted(shared_ns)[0]}"))
            from difflib import SequenceMatcher
            similarity = SequenceMatcher(None, domain, row.domain).ratio()
            if similarity >= 0.72:
                candidates.append(("SIMILAR_DOMAIN", round(similarity * 100, 1), "Registered-domain string similarity"))
            if current_meta.get("registrar") and current_meta.get("registrar") == meta.get("registrar"):
                candidates.append(("SAME_REGISTRAR", 55.0, "Same observed registrar"))
            if candidates:
                relationship, confidence, evidence = max(candidates, key=lambda item: item[1])
                key = (domain, row.domain, relationship)
                if key in seen:
                    continue
                seen.add(key)
                nodes[row.domain] = {"id": row.domain, "risk": max(0, min(100, 100 - row.trustshield_score))}
                edges.append({"source": domain, "target": row.domain, "type": relationship, "confidence": confidence, "evidence": evidence})
                if len(nodes) >= 30:
                    break
        return {"domain": domain, "nodes": list(nodes.values()), "edges": edges, "note": "Relationships indicate observed infrastructure or lexical similarity, not common ownership."}
