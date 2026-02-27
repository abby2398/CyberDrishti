# backend/app/main.py
from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text, func, desc, or_, cast, String
from datetime import datetime, timezone, timedelta
from fastapi.responses import HTMLResponse
from typing import Optional
import uuid

from app.core.config import settings
from app.core.logging import setup_logging, get_logger
from app.db.database import get_db, check_db_connection
from app.models.models import Domain, Finding, ScanJob, AuditLog, DisclosureEvent
from app.services.corpus_tasks import (
    run_pilot_corpus_refresh, run_corpus_refresh_phase2,
    queue_domains_for_rescan, enrich_domain_fingerprint,
    enumerate_domain_subdomains, add_single_domain,
)
from app.services.scanner_tasks import scan_domain, scan_all_pending
from app.services.phase3_tasks import (
    run_phase3_pipeline, update_risk_scores,
    run_breach_correlation, run_disclosure_workflow,
    run_certin_escalation, run_vendor_correlation,
)

setup_logging(settings.LOG_LEVEL, settings.LOG_FILE)
logger = get_logger("api.main")

app = FastAPI(
    title="CyberDrishti API",
    description="CERT-IN National Cyber Exposure Scanner — साइबर दृष्टि",
    version=settings.VERSION,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup():
    logger.info(f"CyberDrishti v{settings.VERSION} starting up")
    check_db_connection()
    _run_migrations()


def _run_migrations():
    """
    Safe, idempotent schema migrations.
    Adds any columns/indexes that exist in the model but may be missing
    from databases created before those columns were introduced.
    Each ALTER is wrapped in a DO block so it silently skips if already present.
    """
    migrations = [
        # Phase 3 ack webhook columns (added in v3)
        """
        DO $$ BEGIN
            ALTER TABLE disclosure_events ADD COLUMN ack_token VARCHAR(64) UNIQUE;
        EXCEPTION WHEN duplicate_column THEN NULL; END $$;
        """,
        """
        DO $$ BEGIN
            ALTER TABLE disclosure_events ADD COLUMN acknowledged_at TIMESTAMPTZ;
        EXCEPTION WHEN duplicate_column THEN NULL; END $$;
        """,
        # Index on ack_token (safe to re-run — CREATE INDEX IF NOT EXISTS)
        """
        CREATE INDEX IF NOT EXISTS idx_disclosure_ack_token
            ON disclosure_events(ack_token);
        """,
        # acknowledged_at on findings table (Phase 3)
        """
        DO $$ BEGIN
            ALTER TABLE findings ADD COLUMN acknowledged_at TIMESTAMPTZ;
        EXCEPTION WHEN duplicate_column THEN NULL; END $$;
        """,
        # vendor_fingerprint on domains (may be missing on very old DBs)
        """
        DO $$ BEGIN
            ALTER TABLE domains ADD COLUMN vendor_fingerprint VARCHAR(200);
        EXCEPTION WHEN duplicate_column THEN NULL; END $$;
        """,
        # contact_email on domains
        """
        DO $$ BEGIN
            ALTER TABLE domains ADD COLUMN contact_email VARCHAR(255);
        EXCEPTION WHEN duplicate_column THEN NULL; END $$;
        """,
    ]

    from sqlalchemy import text as sa_text
    from app.db.database import engine
    try:
        with engine.begin() as conn:
            for sql in migrations:
                conn.execute(sa_text(sql))
        logger.info("DB migrations: all columns verified / applied")
    except Exception as e:
        logger.error(f"DB migration error: {e}")


# ── Health ────────────────────────────────────────────────────

@app.get("/", tags=["Status"])
def root():
    return {"project": "CyberDrishti", "version": settings.VERSION, "docs": "/api/docs"}


@app.get("/api/health", tags=["Status"])
def health(db: Session = Depends(get_db)):
    db_ok = False
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        pass
    return {
        "status": "healthy" if db_ok else "degraded",
        "database": "connected" if db_ok else "disconnected",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": settings.VERSION,
    }


# ── Dashboard ─────────────────────────────────────────────────

@app.get("/api/dashboard", tags=["Dashboard"])
def get_dashboard(db: Session = Depends(get_db)):
    total_domains  = db.query(func.count(Domain.id)).scalar()
    active_domains = db.query(func.count(Domain.id)).filter(Domain.status == "ACTIVE").scalar()
    total_findings = db.query(func.count(Finding.id)).scalar()

    open_critical = db.query(func.count(Finding.id)).filter(
        Finding.severity == "CRITICAL", Finding.status.notin_(["RESOLVED","FALSE_POSITIVE"])).scalar()
    open_high = db.query(func.count(Finding.id)).filter(
        Finding.severity == "HIGH", Finding.status.notin_(["RESOLVED","FALSE_POSITIVE"])).scalar()
    open_medium = db.query(func.count(Finding.id)).filter(
        Finding.severity == "MEDIUM", Finding.status.notin_(["RESOLVED","FALSE_POSITIVE"])).scalar()
    resolved = db.query(func.count(Finding.id)).filter(Finding.status == "RESOLVED").scalar()

    recent_scans = db.query(ScanJob).order_by(desc(ScanJob.created_at)).limit(5).all()

    sector_findings = db.query(
        Domain.sector, func.count(Finding.id).label("count")
    ).join(Finding, Finding.domain_id == Domain.id).group_by(Domain.sector).all()

    # Findings by severity breakdown (all time)
    sev_breakdown = db.query(
        Finding.severity, func.count(Finding.id).label("count")
    ).group_by(Finding.severity).all()

    return {
        "summary": {
            "total_domains": total_domains,
            "active_domains": active_domains,
            "total_findings": total_findings,
            "open_critical": open_critical,
            "open_high": open_high,
            "open_medium": open_medium,
            "resolved_findings": resolved,
        },
        "recent_scans": [
            {"domain": s.domain_name, "status": s.status,
             "findings": s.findings_count, "duration_ms": s.duration_ms,
             "completed_at": s.completed_at.isoformat() if s.completed_at else None}
            for s in recent_scans
        ],
        "findings_by_sector": {r.sector: r.count for r in sector_findings if r.sector},
        "findings_by_severity": {r.severity: r.count for r in sev_breakdown},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── Domains ───────────────────────────────────────────────────

@app.get("/api/domains", tags=["Domains"])
def list_domains(
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=100),
    search: Optional[str] = None,
    status: Optional[str] = None,
    sector: Optional[str] = None,
    tld: Optional[str] = None,
    min_iocs: int = Query(0, ge=0, le=100),
    has_findings: Optional[bool] = None,
    sort: str = Query("iocs_desc"),
    db: Session = Depends(get_db)
):
    query = db.query(Domain)

    # Search
    if search:
        s = f"%{search.lower()}%"
        query = query.filter(Domain.domain.ilike(s))

    # Filters
    if status:
        query = query.filter(Domain.status == status.upper())
    if sector:
        query = query.filter(Domain.sector == sector.upper())
    if tld:
        query = query.filter(Domain.tld == tld.lower())
    if min_iocs:
        query = query.filter(Domain.iocs_score >= min_iocs)

    # Sort
    sort_map = {
        "iocs_desc": desc(Domain.iocs_score),
        "iocs_asc": Domain.iocs_score,
        "domain_asc": Domain.domain,
        "scanned_desc": desc(Domain.last_scanned_at),
        "created_desc": desc(Domain.created_at),
    }
    query = query.order_by(sort_map.get(sort, desc(Domain.iocs_score)))

    total = query.count()
    domains = query.offset((page - 1) * per_page).limit(per_page).all()

    # Count findings per domain efficiently
    finding_counts = dict(
        db.query(Finding.domain_id, func.count(Finding.id))
        .filter(Finding.domain_id.in_([d.id for d in domains]))
        .group_by(Finding.domain_id).all()
    )

    result = []
    for d in domains:
        fc = finding_counts.get(d.id, 0)
        if has_findings is True and fc == 0:
            continue
        if has_findings is False and fc > 0:
            continue
        result.append({
            "id": str(d.id),
            "domain": d.domain,
            "tld": d.tld,
            "iocs_score": d.iocs_score,
            "status": d.status,
            "sector": d.sector,
            "ip_address": str(d.ip_address) if d.ip_address else None,
            "hosting_provider": d.hosting_provider,
            "asn": d.asn,
            "discovered_via": d.discovered_via,
            "vendor_fingerprint": d.vendor_fingerprint,
            "contact_email": d.contact_email,
            "last_scanned_at": d.last_scanned_at.isoformat() if d.last_scanned_at else None,
            "next_scan_due_at": d.next_scan_due_at.isoformat() if d.next_scan_due_at else None,
            "scan_count": d.scan_count,
            "findings_count": fc,
            "signals": {
                "whois_in": d.signal_whois_in,
                "ip_in": d.signal_ip_in,
                "payment_gw": d.signal_payment_gw,
                "gst_number": d.signal_gst_number,
                "lang_in": d.signal_lang_in,
                "registry": d.signal_registry,
            },
        })

    return {"total": total, "page": page, "per_page": per_page, "domains": result}


@app.post("/api/domains/add", tags=["Domains"])
def add_domain(domain: str, db: Session = Depends(get_db)):
    """Manually add a domain to the corpus. Queues IOCS scoring and fingerprinting."""
    domain = domain.strip().lower().replace("https://","").replace("http://","").rstrip("/")
    task = add_single_domain.delay(domain)
    return {"message": f"Domain '{domain}' submitted", "task_id": task.id}


@app.post("/api/domains/re-fingerprint-all", tags=["Domains"])
def re_fingerprint_all_domains(force: bool = False, db: Session = Depends(get_db)):
    """
    Queue vendor re-fingerprinting for ACTIVE domains.
    force=False (default): only queue domains with no vendor set.
    force=True: re-fingerprint ALL active domains (refreshes version strings).
    """
    from app.services.corpus_tasks import enrich_domain_fingerprint
    query = db.query(Domain).filter(Domain.status == "ACTIVE")
    if not force:
        query = query.filter(Domain.vendor_fingerprint == None)  # noqa: E711
    domains = query.all()
    queued = 0
    for d in domains:
        enrich_domain_fingerprint.delay(str(d.id))
        queued += 1
    return {"queued": queued, "force": force, "message": f"Re-fingerprinting {queued} domains"}


@app.get("/api/domains/{domain_id}", tags=["Domains"])
def get_domain_detail(domain_id: str, db: Session = Depends(get_db)):
    """Full domain detail with all its findings."""
    try:
        domain = db.query(Domain).filter(Domain.id == uuid.UUID(domain_id)).first()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid domain ID")
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    findings = db.query(Finding).filter(Finding.domain_id == domain.id).order_by(
        desc(Finding.severity), desc(Finding.created_at)
    ).all()

    recent_jobs = db.query(ScanJob).filter(ScanJob.domain_id == domain.id).order_by(
        desc(ScanJob.created_at)
    ).limit(10).all()

    sev_counts = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    return {
        "id": str(domain.id),
        "domain": domain.domain,
        "tld": domain.tld,
        "iocs_score": domain.iocs_score,
        "status": domain.status,
        "sector": domain.sector,
        "ip_address": str(domain.ip_address) if domain.ip_address else None,
        "hosting_provider": domain.hosting_provider,
        "asn": domain.asn,
        "cdn_detected": domain.cdn_detected,
        "country_code": domain.country_code,
        "discovered_via": domain.discovered_via,
        "notes": domain.notes,
        "vendor_fingerprint": domain.vendor_fingerprint,
        "contact_email": domain.contact_email,
        "last_scanned_at": domain.last_scanned_at.isoformat() if domain.last_scanned_at else None,
        "next_scan_due_at": domain.next_scan_due_at.isoformat() if domain.next_scan_due_at else None,
        "scan_count": domain.scan_count,
        "created_at": domain.created_at.isoformat(),
        "signals": {
            "whois_in": domain.signal_whois_in,
            "ip_in": domain.signal_ip_in,
            "payment_gw": domain.signal_payment_gw,
            "gst_number": domain.signal_gst_number,
            "lang_in": domain.signal_lang_in,
            "registry": domain.signal_registry,
        },
        "findings_summary": sev_counts,
        "findings": [
            {
                "id": str(f.id),
                "url": f.url,
                "entity_type": f.entity_type,
                "finding_type": f.finding_type,
                "severity": f.severity,
                "status": f.status,
                "confidence": float(f.final_confidence or f.heuristic_confidence or 0),
                "sla_due": f.disclosure_sla_due.isoformat() if f.disclosure_sla_due else None,
                "dark_web_confirmed": f.dark_web_confirmed,
                "detected_at": f.created_at.isoformat(),
                "poc_evidence": f.context_snippet_safe,   # RAW — no redaction
            }
            for f in findings
        ],
        "recent_jobs": [
            {
                "id": str(j.id),
                "type": j.job_type,
                "status": j.status,
                "urls_checked": j.urls_checked,
                "findings_count": j.findings_count,
                "duration_ms": j.duration_ms,
                "completed_at": j.completed_at.isoformat() if j.completed_at else None,
            }
            for j in recent_jobs
        ],
    }


@app.patch("/api/domains/{domain_id}/contact", tags=["Domains"])
def update_domain_contact(domain_id: str, email: str, db: Session = Depends(get_db)):
    """Manually set or update the security contact email for a domain."""
    try:
        domain = db.query(Domain).filter(Domain.id == uuid.UUID(domain_id)).first()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid domain ID")
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    old_email = domain.contact_email
    domain.contact_email = email.strip()
    db.add(AuditLog(
        event_type="CONTACT_EMAIL_UPDATED", actor="ANALYST",
        target_type="domain", target_id=domain.id,
        details={"domain": domain.domain, "old": old_email, "new": domain.contact_email},
    ))
    db.commit()
    return {"domain": domain.domain, "contact_email": domain.contact_email}


@app.post("/api/domains/{domain_id}/lookup-contact", tags=["Domains"])
def lookup_domain_contact(domain_id: str, db: Session = Depends(get_db)):
    """
    Attempt to auto-discover the security contact email for a domain
    via security.txt lookup and standard convention fallbacks.
    Saves result to contact_email if found.
    """
    from app.services.phase3_tasks import resolve_security_contact
    try:
        domain = db.query(Domain).filter(Domain.id == uuid.UUID(domain_id)).first()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid domain ID")
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    result = resolve_security_contact(domain.domain)
    if result["email"]:
        domain.contact_email = result["email"]
        db.add(AuditLog(
            event_type="CONTACT_EMAIL_DISCOVERED", actor="SYSTEM",
            target_type="domain", target_id=domain.id,
            details={"domain": domain.domain, "email": result["email"], "source": result["source"]},
        ))
        db.commit()

    return {
        "domain": domain.domain,
        "contact_email": result["email"],
        "source": result["source"],
        "candidates": result["candidates"],
    }




@app.post("/api/domains/{domain_id}/re-fingerprint", tags=["Domains"])
def re_fingerprint_domain(domain_id: str, db: Session = Depends(get_db)):
    """Re-fingerprint a single domain's tech stack immediately."""
    from app.services.corpus_tasks import enrich_domain_fingerprint
    try:
        domain = db.query(Domain).filter(Domain.id == uuid.UUID(domain_id)).first()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid domain ID")
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    task = enrich_domain_fingerprint.delay(str(domain.id))
    return {"message": f"Re-fingerprinting {domain.domain}", "task_id": task.id}


@app.post("/api/domains/{domain_id}/scan", tags=["Domains"])
def trigger_scan(domain_id: str, db: Session = Depends(get_db)):
    domain = db.query(Domain).filter(Domain.id == uuid.UUID(domain_id)).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    task = scan_domain.delay(domain_id)
    return {"message": f"Scan queued for {domain.domain}", "task_id": task.id, "domain": domain.domain}


@app.delete("/api/domains/{domain_id}", tags=["Domains"])
def delete_domain(domain_id: str, db: Session = Depends(get_db)):
    """Permanently delete a domain and all its findings from the corpus."""
    try:
        domain = db.query(Domain).filter(Domain.id == uuid.UUID(domain_id)).first()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid domain ID")
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    domain_name = domain.domain
    db.add(AuditLog(
        event_type="DOMAIN_DELETED", actor="ANALYST",
        target_type="domain", target_id=domain.id,
        details={"domain": domain_name},
    ))
    db.delete(domain)
    db.commit()
    return {"message": f"Domain '{domain_name}' deleted", "domain": domain_name}


# ── Acknowledgement webhook ────────────────────────────────────

@app.get("/api/ack/{token}", tags=["Disclosure"])
def acknowledge_disclosure(token: str, db: Session = Depends(get_db)):
    """
    One-click acknowledgement link sent inside disclosure emails.
    When the org's security team clicks the link, this marks the finding
    as acknowledged, preventing automatic CERT-In escalation.
    Returns a human-readable confirmation page.
    """
    event = db.query(DisclosureEvent).filter(
        DisclosureEvent.ack_token == token
    ).first()
    if not event:
        return HTMLResponse(content="""
            <html><body style="font-family:sans-serif;max-width:500px;margin:80px auto;text-align:center">
            <h2>❌ Invalid or expired acknowledgement link</h2>
            <p>This link may have already been used or does not exist.</p>
            </body></html>""", status_code=404)

    now = datetime.now(timezone.utc)
    already_acked = event.acknowledged_at is not None

    if not already_acked:
        event.acknowledged_at = now
        # Mark the finding as acknowledged too
        finding = db.query(Finding).filter(Finding.id == event.finding_id).first()
        if finding:
            finding.acknowledged_at = now
            db.add(AuditLog(
                event_type="DISCLOSURE_ACKNOWLEDGED", actor="ORG",
                target_type="finding", target_id=finding.id,
                details={
                    "token": token[:8] + "...",
                    "recipient": event.recipient_email,
                    "finding_type": finding.finding_type,
                },
            ))
        db.commit()

    domain_name = ""
    finding = db.query(Finding).filter(Finding.id == event.finding_id).first()
    if finding:
        domain = db.query(Domain).filter(Domain.id == finding.domain_id).first()
        domain_name = domain.domain if domain else ""

    msg = "already acknowledged" if already_acked else "acknowledged"
    html = f"""
        <html><body style="font-family:sans-serif;max-width:560px;margin:80px auto;text-align:center;background:#f8f9fa;padding:40px;border-radius:8px">
        <div style="font-size:48px;margin-bottom:16px">{"✅" if not already_acked else "ℹ️"}</div>
        <h2 style="color:#1a1a2e">Disclosure {msg.title()}</h2>
        {"<p>Thank you. Your acknowledgement has been recorded.</p>" if not already_acked else "<p>This disclosure was already acknowledged.</p>"}
        <p style="color:#666;font-size:14px">Domain: <strong>{domain_name}</strong></p>
        <p style="color:#666;font-size:14px">Acknowledged at: {now.strftime('%Y-%m-%d %H:%M UTC')}</p>
        <hr style="margin:24px 0;border-color:#ddd">
        <p style="color:#999;font-size:12px">
            Please reply to the original disclosure email with your remediation timeline.<br>
            CVD Reference: {event.subject or "—"}
        </p>
        </body></html>"""
    return HTMLResponse(content=html)


# ── Phase 3 summary for dashboard ─────────────────────────────

@app.get("/api/phase3/summary", tags=["Phase3"])
def phase3_summary(db: Session = Depends(get_db)):
    """Summary stats for the Phase 3 dashboard widget."""
    now = datetime.now(timezone.utc)
    due_window = now + timedelta(hours=24)

    awaiting_critical = db.query(Finding).filter(
        Finding.disclosed_at == None,           # noqa: E711
        Finding.severity == "CRITICAL",
        Finding.status.notin_(["RESOLVED", "FALSE_POSITIVE"]),
    ).count()

    awaiting_sla = db.query(Finding).filter(
        Finding.disclosed_at == None,           # noqa: E711
        Finding.severity != "CRITICAL",
        Finding.status.notin_(["RESOLVED", "FALSE_POSITIVE"]),
        Finding.disclosure_sla_due != None,     # noqa: E711
        Finding.disclosure_sla_due <= due_window,
    ).count()

    escalation_pending = db.query(Finding).filter(
        Finding.severity == "CRITICAL",
        Finding.status == "DISCLOSED",
        Finding.acknowledged_at == None,        # noqa: E711
        Finding.disclosed_at != None,           # noqa: E711
        Finding.disclosed_at < now - timedelta(hours=72),
    ).count()

    no_contact = db.query(Domain).filter(
        Domain.status == "ACTIVE",
        Domain.contact_email == None,           # noqa: E711
    ).count()

    disclosed_total = db.query(Finding).filter(
        Finding.disclosed_at != None,           # noqa: E711
    ).count()

    acknowledged = db.query(Finding).filter(
        Finding.acknowledged_at != None,        # noqa: E711
    ).count()

    return {
        "awaiting_disclosure": awaiting_critical + awaiting_sla,
        "awaiting_critical": awaiting_critical,
        "awaiting_sla": awaiting_sla,
        "escalation_pending": escalation_pending,
        "no_contact_email": no_contact,
        "disclosed_total": disclosed_total,
        "acknowledged": acknowledged,
    }


# ── Findings ──────────────────────────────────────────────────

@app.get("/api/findings", tags=["Findings"])
def list_findings(
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=100),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    entity_type: Optional[str] = None,
    domain_id: Optional[str] = None,
    search: Optional[str] = None,
    dark_web: Optional[bool] = None,
    sort: str = Query("created_desc"),
    db: Session = Depends(get_db)
):
    query = db.query(Finding).join(Domain)

    if severity:
        query = query.filter(Finding.severity == severity.upper())
    if status:
        query = query.filter(Finding.status == status.upper())
    if entity_type:
        query = query.filter(Finding.entity_type == entity_type.upper())
    if domain_id:
        try:
            query = query.filter(Finding.domain_id == uuid.UUID(domain_id))
        except Exception:
            pass
    if search:
        s = f"%{search}%"
        query = query.filter(or_(Finding.url.ilike(s), Finding.finding_type.ilike(s), Domain.domain.ilike(s)))
    if dark_web is True:
        query = query.filter(Finding.dark_web_confirmed == True)

    sort_map = {
        "created_desc": desc(Finding.created_at),
        "severity_desc": desc(Finding.severity),
        "confidence_desc": desc(Finding.final_confidence),
        "sla_asc": Finding.disclosure_sla_due,
    }
    query = query.order_by(sort_map.get(sort, desc(Finding.created_at)))

    total = query.count()
    findings = query.offset((page - 1) * per_page).limit(per_page).all()

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "findings": [
            {
                "id": str(f.id),
                "domain": f.domain.domain,
                "domain_id": str(f.domain_id),
                "url": f.url,
                "entity_type": f.entity_type,
                "finding_type": f.finding_type,
                "severity": f.severity,
                "status": f.status,
                "confidence": float(f.final_confidence or f.heuristic_confidence or 0),
                "sla_due": f.disclosure_sla_due.isoformat() if f.disclosure_sla_due else None,
                "dark_web_confirmed": f.dark_web_confirmed,
                "detected_at": f.created_at.isoformat(),
            }
            for f in findings
        ]
    }


@app.get("/api/findings/{finding_id}", tags=["Findings"])
def get_finding_detail(finding_id: str, db: Session = Depends(get_db)):
    try:
        finding = db.query(Finding).filter(Finding.id == uuid.UUID(finding_id)).first()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid finding ID")
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    f = finding
    return {
        "id": str(f.id),
        "domain": f.domain.domain,
        "domain_id": str(f.domain_id),
        "url": f.url,
        "http_status": f.http_status,
        "entity_type": f.entity_type,
        "finding_type": f.finding_type,
        "severity": f.severity,
        "status": f.status,
        "heuristic_confidence": float(f.heuristic_confidence or 0),
        "final_confidence": float(f.final_confidence or f.heuristic_confidence or 0),
        "value_count_estimate": f.value_count_estimate,
        "content_type": f.content_type,
        "file_size_bytes": f.file_size_bytes,
        "dark_web_confirmed": f.dark_web_confirmed,
        "vendor_fingerprint": f.vendor_fingerprint,
        "poc_evidence": f.context_snippet_safe,  # RAW — no redaction in development
        "disclosure_sla_due": f.disclosure_sla_due.isoformat() if f.disclosure_sla_due else None,
        "disclosed_at": f.disclosed_at.isoformat() if f.disclosed_at else None,
        "resolved_at": f.resolved_at.isoformat() if f.resolved_at else None,
        "escalation_level": f.escalation_level,
        "detected_by": f.detected_by,
        "reviewed_by": f.reviewed_by,
        "reviewed_at": f.reviewed_at.isoformat() if f.reviewed_at else None,
        "false_positive_reason": f.false_positive_reason,
        "detected_at": f.created_at.isoformat(),
        "updated_at": f.updated_at.isoformat() if f.updated_at else None,
    }


@app.patch("/api/findings/{finding_id}/status", tags=["Findings"])
def update_finding_status(
    finding_id: str, new_status: str,
    new_severity: Optional[str] = None,
    reason: Optional[str] = None, analyst: str = "ANALYST",
    db: Session = Depends(get_db)
):
    """
    Update finding status. Optionally change severity at the same time.
    new_severity: CRITICAL | HIGH | MEDIUM | LOW | INFO
    """
    finding = db.query(Finding).filter(Finding.id == uuid.UUID(finding_id)).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    valid_status = ["CONFIRMED", "FALSE_POSITIVE", "RESOLVED", "ESCALATED"]
    if new_status.upper() not in valid_status:
        raise HTTPException(status_code=400, detail=f"Invalid status. Use: {valid_status}")

    old_severity = finding.severity
    finding.status = new_status.upper()
    finding.reviewed_by = analyst
    finding.reviewed_at = datetime.now(timezone.utc)

    if new_severity:
        valid_sev = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        if new_severity.upper() not in valid_sev:
            raise HTTPException(status_code=400, detail=f"Invalid severity. Use: {valid_sev}")
        finding.severity = new_severity.upper()
        # Recalculate SLA from new severity
        from app.services.scanner_tasks import compute_sla
        finding.disclosure_sla_due = compute_sla(new_severity.upper())

    if new_status.upper() == "FALSE_POSITIVE":
        finding.false_positive_reason = reason
    if new_status.upper() == "RESOLVED":
        finding.resolved_at = datetime.now(timezone.utc)

    db.add(AuditLog(
        event_type="FINDING_STATUS_UPDATED", actor=analyst,
        target_type="finding", target_id=finding.id,
        details={
            "new_status": new_status,
            "old_severity": old_severity,
            "new_severity": finding.severity,
            "reason": reason,
        }
    ))
    db.commit()
    return {
        "message": "Updated",
        "finding_id": finding_id,
        "new_status": finding.status,
        "severity": finding.severity,
    }


@app.post("/api/jobs/{job_id}/rescan", tags=["Jobs"])
def rescan_job(job_id: str, db: Session = Depends(get_db)):
    """Re-queue a scan for the domain from a FAILED or SKIPPED job."""
    try:
        job = db.query(ScanJob).filter(ScanJob.id == uuid.UUID(job_id)).first()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid job ID")
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status not in ("FAILED", "SKIPPED", "COMPLETED"):
        raise HTTPException(status_code=400, detail=f"Job status is {job.status} — only FAILED/SKIPPED/COMPLETED jobs can be re-scanned")

    # Re-activate domain if it was marked inactive
    domain = db.query(Domain).filter(Domain.id == job.domain_id).first()
    if domain and domain.status == "INACTIVE":
        domain.status = "ACTIVE"
        db.commit()

    task = scan_domain.delay(str(job.domain_id))
    db.add(AuditLog(
        event_type="RESCAN_TRIGGERED", actor="ANALYST",
        target_type="scan_job", target_id=job.id,
        details={"original_job_id": str(job.id), "domain": job.domain_name, "task_id": task.id}
    ))
    db.commit()
    return {"message": f"Re-scan queued for {job.domain_name}", "task_id": task.id, "domain": job.domain_name}


# ── Scanner ───────────────────────────────────────────────────

@app.post("/api/scanner/pilot-refresh", tags=["Scanner"])
def trigger_pilot_corpus_refresh():
    """Phase 1: refresh .gov.in / .edu.in corpus from CT logs."""
    task = run_pilot_corpus_refresh.delay()
    return {"message": "Pilot corpus refresh started", "task_id": task.id}


@app.post("/api/scanner/phase2-refresh", tags=["Scanner"])
def trigger_phase2_corpus_refresh():
    """
    Phase 2: Full Indian domain corpus refresh.
    Discovers all Indian TLDs using CT logs + IOCS scoring.
    Runs as a background task — may take several minutes.
    """
    task = run_corpus_refresh_phase2.delay()
    return {"message": "Phase 2 corpus refresh started", "task_id": task.id}


@app.post("/api/scanner/trigger-rescan-queue", tags=["Scanner"])
def trigger_rescan_queue():
    """
    Phase 2: Enqueue all domains due for re-scan based on
    per-sector TTLs and differential scan (content hash check).
    """
    task = queue_domains_for_rescan.delay()
    return {"message": "Rescan queue triggered", "task_id": task.id}


@app.post("/api/scanner/enumerate-subdomains", tags=["Scanner"])
def trigger_subdomain_enum(domain: str, include_bruteforce: bool = True):
    """
    Phase 2: On-demand full subdomain enumeration for a root domain.
    Runs all 15 configured sources concurrently:
      Free:  crt.sh, AlienVault, HackerTarget, RapidDNS, BufferOver,
             ThreatCrowd, DNS brute-force
      Keyed: Shodan, Censys, ZoomEye, SecurityTrails, VirusTotal,
             BinaryEdge, WhoisXML, Chaos
    Results are DNS-validated and added to the corpus automatically.
    """
    task = enumerate_domain_subdomains.delay(domain, include_bruteforce)
    return {
        "message": f"Subdomain enumeration started for {domain}",
        "task_id": task.id,
        "domain": domain,
    }


@app.post("/api/scanner/scan-all-pending", tags=["Scanner"])
def trigger_scan_all():
    task = scan_all_pending.delay()
    return {"message": "Batch scan started", "task_id": task.id}


# ── Scan Jobs ─────────────────────────────────────────────────

@app.get("/api/jobs", tags=["Jobs"])
def list_jobs(
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=100),
    status: Optional[str] = None,
    domain: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(ScanJob)
    if status:
        query = query.filter(ScanJob.status == status.upper())
    if domain:
        query = query.filter(ScanJob.domain_name.ilike(f"%{domain}%"))

    total = query.count()
    jobs = query.order_by(desc(ScanJob.created_at)).offset((page - 1) * per_page).limit(per_page).all()

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "jobs": [
            {
                "id": str(j.id),
                "domain": j.domain_name,
                "type": j.job_type,
                "status": j.status,
                "urls_checked": j.urls_checked,
                "findings_count": j.findings_count,
                "errors_count": j.errors_count,
                "duration_ms": j.duration_ms,
                "queued_at": j.queued_at.isoformat() if j.queued_at else None,
                "started_at": j.started_at.isoformat() if j.started_at else None,
                "completed_at": j.completed_at.isoformat() if j.completed_at else None,
                "error_message": j.error_message,
            }
            for j in jobs
        ]
    }


# ── Audit ─────────────────────────────────────────────────────



@app.post("/api/jobs/{job_id}/retry", tags=["Jobs"])
def retry_job(job_id: str, db: Session = Depends(get_db)):
    """Re-queue a FAILED or SKIPPED scan job."""
    try:
        job = db.query(ScanJob).filter(ScanJob.id == uuid.UUID(job_id)).first()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid job ID")
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status not in ("FAILED", "SKIPPED", "COMPLETED"):
        raise HTTPException(status_code=400, detail=f"Cannot retry a job with status {job.status}. Must be FAILED, SKIPPED, or COMPLETED.")

    domain = db.query(Domain).filter(Domain.id == job.domain_id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Associated domain not found")

    task = scan_domain.delay(str(domain.id), job.job_type or "FULL_SCAN")
    db.add(AuditLog(
        event_type="JOB_RETRIED", actor="ANALYST",
        target_type="job", target_id=job.id,
        details={"domain": domain.domain, "original_status": job.status, "new_task_id": task.id}
    ))
    db.commit()
    return {"message": f"Retry queued for {domain.domain}", "task_id": task.id, "domain": domain.domain}

@app.get("/api/audit", tags=["Audit"])
def get_audit_log(
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=200),
    event_type: Optional[str] = None,
    actor: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(AuditLog)
    if event_type:
        query = query.filter(AuditLog.event_type.ilike(f"%{event_type}%"))
    if actor:
        query = query.filter(AuditLog.actor.ilike(f"%{actor}%"))

    total = query.count()
    logs = query.order_by(desc(AuditLog.event_at)).offset((page - 1) * per_page).limit(per_page).all()

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "logs": [
            {
                "id": log.id,
                "event_type": log.event_type,
                "actor": log.actor,
                "target_type": log.target_type,
                "target_id": str(log.target_id) if log.target_id else None,
                "details": log.details,
                "timestamp": log.event_at.isoformat(),
            }
            for log in logs
        ]
    }


# ─────────────────────────────────────────────────────────────
#  PHASE 3 ENDPOINTS
# ─────────────────────────────────────────────────────────────

@app.post("/api/phase3/pipeline", tags=["Phase3"])
def trigger_phase3_pipeline(dry_run: bool = True):
    """
    Run full Phase 3 pipeline: risk scoring → breach correlation →
    vendor correlation → disclosure workflow → CERT-In escalation.
    dry_run=True (default) — emails are logged but not sent.
    """
    task = run_phase3_pipeline.delay(dry_run=dry_run)
    return {
        "message": f"Phase 3 pipeline started (dry_run={dry_run})",
        "task_id": task.id,
    }


@app.post("/api/phase3/risk-scores", tags=["Phase3"])
def trigger_risk_scores():
    """Recalculate composite risk scores for all ACTIVE domains."""
    task = update_risk_scores.delay()
    return {"message": "Risk score update queued", "task_id": task.id}


@app.post("/api/phase3/breach-correlation", tags=["Phase3"])
def trigger_breach_correlation(domain_id: Optional[str] = None):
    """
    Run HIBP + Shodan breach correlation.
    Optionally restrict to a single domain by ID.
    """
    task = run_breach_correlation.delay(domain_id=domain_id)
    return {
        "message": "Breach correlation queued",
        "task_id": task.id,
        "scope": domain_id or "all_active",
    }


@app.post("/api/phase3/vendor-correlation", tags=["Phase3"])
def trigger_vendor_correlation():
    """Cross-correlate findings by CMS/framework vendor across all domains."""
    task = run_vendor_correlation.delay()
    return {"message": "Vendor correlation queued", "task_id": task.id}


@app.post("/api/phase3/disclosure", tags=["Phase3"])
def trigger_disclosure(dry_run: bool = True):
    """
    Run disclosure workflow for all SLA-due findings.
    dry_run=True — emails logged only. Set dry_run=false for production.
    """
    task = run_disclosure_workflow.delay(dry_run=dry_run)
    return {
        "message": f"Disclosure workflow queued (dry_run={dry_run})",
        "task_id": task.id,
    }


@app.post("/api/phase3/escalate", tags=["Phase3"])
def trigger_certin_escalation(dry_run: bool = True):
    """Escalate qualifying findings to CERT-In."""
    task = run_certin_escalation.delay(dry_run=dry_run)
    return {
        "message": f"CERT-In escalation queued (dry_run={dry_run})",
        "task_id": task.id,
    }


@app.get("/api/phase3/risk-overview", tags=["Phase3"])
def get_risk_overview(db: Session = Depends(get_db)):
    """
    Return risk score breakdown across all ACTIVE domains.
    Reads from domain.notes JSON (populated by update_risk_scores task).
    """
    import json as json_mod

    domains = db.query(Domain).filter(Domain.status == "ACTIVE").all()
    rows = []
    for d in domains:
        try:
            notes = json_mod.loads(d.notes or "{}")
        except Exception:
            notes = {}

        rows.append({
            "domain": d.domain,
            "sector": d.sector,
            "vendor": d.vendor_fingerprint,
            "iocs_score": d.iocs_score,
            "risk_score": notes.get("risk_score", 0),
            "open_critical": notes.get("open_critical", 0),
            "open_high": notes.get("open_high", 0),
            "dark_web_hits": notes.get("dark_web_hits", 0),
            "sla_breached": notes.get("sla_breached", 0),
            "last_scored_at": notes.get("last_scored_at"),
        })

    rows.sort(key=lambda r: r["risk_score"], reverse=True)

    return {
        "total": len(rows),
        "domains": rows[:100],  # top 100 by risk
    }


@app.get("/api/phase3/disclosures", tags=["Phase3"])
def list_disclosures(
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=100),
    status: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """List all disclosure events with pagination."""
    q = db.query(DisclosureEvent)
    if status:
        q = q.filter(DisclosureEvent.send_status == status.upper())
    total = q.count()
    events = q.order_by(desc(DisclosureEvent.created_at)).offset((page - 1) * per_page).limit(per_page).all()
    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "disclosures": [
            {
                "id": str(e.id),
                "finding_id": str(e.finding_id),
                "recipient_email": e.recipient_email,
                "recipient_type": e.recipient_type,
                "subject": e.subject,
                "sent_at": e.sent_at.isoformat() if e.sent_at else None,
                "send_status": e.send_status,
                "created_at": e.created_at.isoformat(),
            }
            for e in events
        ],
    }
