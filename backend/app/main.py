# backend/app/main.py
from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text, func, desc, or_, cast, String
from datetime import datetime, timezone
from typing import Optional
import uuid

from app.core.config import settings
from app.core.logging import setup_logging, get_logger
from app.db.database import get_db, check_db_connection
from app.models.models import Domain, Finding, ScanJob, AuditLog
from app.services.corpus_tasks import (
    run_pilot_corpus_refresh, run_corpus_refresh_phase2,
    queue_domains_for_rescan, enrich_domain_fingerprint,
    add_single_domain,
)
from app.services.scanner_tasks import scan_domain, scan_all_pending

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


@app.post("/api/domains/add", tags=["Domains"])
def add_domain(domain: str, db: Session = Depends(get_db)):
    domain = domain.strip().lower().replace("https://","").replace("http://","").rstrip("/")
    task = add_single_domain.delay(domain)
    return {"message": f"Domain '{domain}' submitted", "task_id": task.id}


@app.post("/api/domains/{domain_id}/scan", tags=["Domains"])
def trigger_scan(domain_id: str, db: Session = Depends(get_db)):
    domain = db.query(Domain).filter(Domain.id == uuid.UUID(domain_id)).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    task = scan_domain.delay(domain_id)
    return {"message": f"Scan queued for {domain.domain}", "task_id": task.id, "domain": domain.domain}


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
    reason: Optional[str] = None, analyst: str = "ANALYST",
    db: Session = Depends(get_db)
):
    finding = db.query(Finding).filter(Finding.id == uuid.UUID(finding_id)).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    valid = ["CONFIRMED", "FALSE_POSITIVE", "RESOLVED", "ESCALATED"]
    if new_status.upper() not in valid:
        raise HTTPException(status_code=400, detail=f"Invalid status. Use: {valid}")
    finding.status = new_status.upper()
    finding.reviewed_by = analyst
    finding.reviewed_at = datetime.now(timezone.utc)
    if new_status.upper() == "FALSE_POSITIVE":
        finding.false_positive_reason = reason
    if new_status.upper() == "RESOLVED":
        finding.resolved_at = datetime.now(timezone.utc)
    db.add(AuditLog(
        event_type="FINDING_STATUS_UPDATED", actor=analyst,
        target_type="finding", target_id=finding.id,
        details={"new_status": new_status, "reason": reason}
    ))
    db.commit()
    return {"message": "Status updated", "finding_id": finding_id, "new_status": new_status}


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
