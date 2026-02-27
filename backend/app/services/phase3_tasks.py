# backend/app/services/phase3_tasks.py — Phase 3 (manual-only)
from __future__ import annotations
import re, json, hashlib, hmac, secrets, smtplib, textwrap
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, List, Optional, Tuple
import requests
from requests.exceptions import RequestException
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from app.worker import celery_app
from app.db.database import SessionLocal
from app.models.models import Domain, Finding, AuditLog, DisclosureEvent
from app.core.config import settings
from app.core.logging import get_logger
logger = get_logger("phase3")

SLA_HOURS: Dict[str, int] = {"CRITICAL":72,"HIGH":168,"MEDIUM":720,"LOW":2160,"INFO":8760}
SECTOR_WEIGHT: Dict[str, float] = {"GOVERNMENT":1.5,"HEALTHCARE":1.4,"FINANCE":1.4,"EDUCATION":1.1,"RESEARCH":1.2,"OTHER":1.0}
VENDOR_RISK: Dict[str, float] = {"wordpress":1.3,"joomla":1.3,"drupal":1.1,"nic egov":1.2,"spring boot":1.1}
CERTIN_EMAIL = "incident@cert-in.org.in"
NIC_CERT_EMAIL = "security@nic.in"
GOV_TLDS = {".gov.in", ".nic.in"}
CERTIN_ESCALATION_HOURS = 72

# ─── 1. SECURITY CONTACT RESOLUTION ───────────────────────────

def resolve_security_contact(domain: str) -> Dict:
    candidates = []
    security_txt_email = None
    for url in [f"https://{domain}/.well-known/security.txt", f"https://{domain}/security.txt",
                f"http://{domain}/.well-known/security.txt", f"http://{domain}/security.txt"]:
        try:
            r = requests.get(url, timeout=8,
                headers={"User-Agent": "CyberDrishti/2.0 CERT-IN Security Scanner"},
                verify=False, allow_redirects=True)
            if r.status_code == 200 and r.text:
                emails = _parse_security_txt(r.text)
                if emails:
                    security_txt_email = emails[0]
                    candidates.extend(emails)
                    logger.info(f"[security.txt] {domain}: found {emails}")
                    break
        except RequestException:
            continue

    for e in [f"security@{domain}", f"abuse@{domain}", f"cert@{domain}", f"webmaster@{domain}"]:
        if e not in candidates:
            candidates.append(e)

    best = security_txt_email or (candidates[0] if candidates else None)
    source = "security.txt" if security_txt_email else ("convention" if best else "none")
    return {"email": best, "source": source, "candidates": candidates}


def _parse_security_txt(content: str) -> List[str]:
    emails = []
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("#") or not line: continue
        if line.lower().startswith("contact:"):
            value = line[8:].strip()
            if value.lower().startswith("mailto:"):
                email = value[7:].strip()
                if _is_valid_email(email): emails.append(email)
            elif _is_valid_email(value):
                emails.append(value)
    return emails


def _is_valid_email(s: str) -> bool:
    return bool(re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', s)) and "://" not in s


def _get_contact_email(domain: Domain, db) -> Tuple[str, str]:
    if domain.contact_email:
        return domain.contact_email, "stored"
    result = resolve_security_contact(domain.domain)
    if result["email"]:
        domain.contact_email = result["email"]
        db.add(AuditLog(event_type="CONTACT_EMAIL_DISCOVERED", actor="SYSTEM",
            target_type="domain", target_id=domain.id,
            details={"domain": domain.domain, "email": result["email"], "source": result["source"]}))
        db.flush()
    return result["email"] or f"security@{domain.domain}", result["source"]


# ─── 2. RISK SCORING ──────────────────────────────────────────

def compute_domain_risk_score(domain: Domain, findings: List[Finding]) -> int:
    score = 0.0
    score += min((domain.iocs_score or 0) / 4.0, 25)
    open_s = {"NEW", "CONFIRMED", "ESCALATED"}
    open_f = [f for f in findings if f.status in open_s]
    score += min(len([f for f in open_f if f.severity == "CRITICAL"]) * 15, 30)
    score += min(len([f for f in open_f if f.severity == "HIGH"]) * 8, 24)
    score += min(len([f for f in open_f if f.dark_web_confirmed]) * 10, 20)
    now = datetime.now(timezone.utc)
    score += min(len([f for f in open_f if f.disclosure_sla_due and f.disclosure_sla_due < now]) * 5, 10)
    vendor = (domain.vendor_fingerprint or "").lower()
    vm = max((m for k, m in VENDOR_RISK.items() if k in vendor), default=1.0)
    score *= vm
    score *= SECTOR_WEIGHT.get(domain.sector or "OTHER", 1.0)
    return min(int(score), 100)


@celery_app.task(name="app.services.phase3_tasks.update_risk_scores")
def update_risk_scores():
    db = SessionLocal()
    updated = 0
    try:
        domains = db.query(Domain).filter(Domain.status == "ACTIVE").all()
        for d in domains:
            findings = db.query(Finding).filter(Finding.domain_id == d.id).all()
            risk = compute_domain_risk_score(d, findings)
            now = datetime.now(timezone.utc)
            breakdown = {
                "risk_score": risk,
                "open_critical": len([f for f in findings if f.severity=="CRITICAL" and f.status in{"NEW","CONFIRMED","ESCALATED"}]),
                "open_high": len([f for f in findings if f.severity=="HIGH" and f.status in{"NEW","CONFIRMED","ESCALATED"}]),
                "dark_web_hits": len([f for f in findings if f.dark_web_confirmed]),
                "sla_breached": len([f for f in findings if f.disclosure_sla_due and f.disclosure_sla_due < now and f.status not in{"RESOLVED","FALSE_POSITIVE"}]),
                "vendor": d.vendor_fingerprint, "sector": d.sector,
                "last_scored_at": now.isoformat(),
            }
            try: existing = json.loads(d.notes or "{}")
            except Exception: existing = {}
            existing.update(breakdown)
            d.notes = json.dumps(existing)
            updated += 1
        db.commit()
        logger.info(f"Risk scores updated for {updated} domains")
        return {"updated": updated}
    finally:
        db.close()


# ─── 3. BREACH CORRELATION ────────────────────────────────────

def check_hibp_domain(domain: str) -> List[Dict]:
    if not settings.HIBP_API_KEY: return []
    try:
        r = requests.get(f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}",
            headers={"hibp-api-key": settings.HIBP_API_KEY,
                     "User-Agent": "CyberDrishti CERT-IN Automated Scanner"}, timeout=10)
        if r.status_code == 200:
            data = r.json()
            return [{"breach_count": len(data),
                     "account_count": sum(len(v) if isinstance(v,list) else 1 for v in data.values()),
                     "source": "HIBP", "domain": domain}]
        elif r.status_code == 404: return []
    except RequestException as e:
        logger.debug(f"HIBP failed for {domain}: {e}")
    return []


def check_shodan_host(ip: str) -> Optional[Dict]:
    if not settings.SHODAN_API_KEY or not ip: return None
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": settings.SHODAN_API_KEY}, timeout=10)
        if r.status_code == 200:
            data = r.json()
            vulns = data.get("vulns", [])
            return {"ip": ip, "open_ports": [s.get("port") for s in data.get("data",[])[:20]],
                    "vuln_count": len(vulns), "vulns": list(vulns)[:10],
                    "org": data.get("org"), "source": "SHODAN"}
    except RequestException as e:
        logger.debug(f"Shodan failed for {ip}: {e}")
    return None


def _mark_findings_dark_web(db, domain_id, breach_info: Dict):
    findings = db.query(Finding).filter(
        Finding.domain_id == domain_id,
        Finding.severity.in_(["CRITICAL","HIGH"]),
        Finding.status.notin_(["RESOLVED","FALSE_POSITIVE"])).all()
    safe_note = (f"[BREACH CORRELATION {breach_info.get('source','?')} "
                 f"@ {datetime.now(timezone.utc).strftime('%Y-%m-%d')}] "
                 f"breach_count={breach_info.get('breach_count','?')} "
                 f"vuln_count={breach_info.get('vuln_count','?')}")
    for f in findings:
        f.dark_web_confirmed = True
        existing = f.context_snippet_safe or ""
        if safe_note not in existing:
            f.context_snippet_safe = (existing + "\n" + safe_note).strip()
        if f.escalation_level < 1: f.escalation_level = 1


@celery_app.task(name="app.services.phase3_tasks.run_breach_correlation")
def run_breach_correlation(domain_id: Optional[str] = None):
    db = SessionLocal()
    checked = 0; breached = 0
    try:
        domains = (db.query(Domain).filter(Domain.id == domain_id).all()
                   if domain_id else db.query(Domain).filter(Domain.status=="ACTIVE").all())
        for d in domains:
            checked += 1; domain_breached = False
            for br in check_hibp_domain(d.domain):
                domain_breached = True; _mark_findings_dark_web(db, d.id, br)
            if d.ip_address:
                shodan = check_shodan_host(str(d.ip_address))
                if shodan and shodan.get("vuln_count",0) > 0:
                    domain_breached = True; _mark_findings_dark_web(db, d.id, shodan)
            if domain_breached: breached += 1
        db.commit()
        logger.info(f"Breach correlation: {checked} checked, {breached} with evidence")
        return {"checked": checked, "breached": breached}
    finally:
        db.close()


# ─── 4. DISCLOSURE WORKFLOW ───────────────────────────────────

def _is_gov_domain(domain_name: str) -> bool:
    return any(domain_name.endswith(t.lstrip(".")) for t in GOV_TLDS)


def _gen_cvd_id(domain: str) -> str:
    return hashlib.sha256(domain.encode()).hexdigest()[:12].upper()


def _sla_status_summary(findings: List[Finding]) -> str:
    now = datetime.now(timezone.utc)
    breached = [f for f in findings if f.disclosure_sla_due and f.disclosure_sla_due < now]
    return f"BREACHED ({len(breached)} overdue)" if breached else "Within SLA"


def _format_finding_list(findings: List[Finding]) -> str:
    lines = []
    for i, f in enumerate(findings, 1):
        path = f.url_path or "/"
        if len(path) > 80: path = path[:77] + "..."
        conf = float(f.final_confidence or f.heuristic_confidence or 0)
        lines.append(f"  {i}. [{f.severity}] {f.finding_type} @ {path} (confidence={conf:.0%})")
    return "\n".join(lines) if lines else "  (none)"


def _build_disclosure_email(domain: Domain, findings: List[Finding],
                             recipient_type: str, contact_source: str = "convention",
                             ack_token: str = None) -> Tuple[str, str]:
    sev_order = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
    sc: Dict[str,int] = {}
    for f in findings: sc[f.severity] = sc.get(f.severity, 0) + 1
    sev_summary = ", ".join(f"{sc[s]} {s}" for s in sev_order if s in sc)
    top = next((s for s in sev_order if s in sc), "INFO")
    ftypes = list(dict.fromkeys(f.finding_type for f in findings))[:5]
    cvd = _gen_cvd_id(domain.domain)
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    subject = f"[CyberDrishti CERT-IN] Security Disclosure: {domain.domain} — {top} | CVD-{cvd}"

    if recipient_type == "CERTIN":
        body = textwrap.dedent(f"""
            CERT-In Incident Report
            =======================
            Organisation Domain : {domain.domain}
            Sector              : {domain.sector or 'UNKNOWN'}
            IP Address          : {domain.ip_address or 'UNKNOWN'}
            IOCS Score          : {domain.iocs_score}
            Vendor Fingerprint  : {domain.vendor_fingerprint or 'N/A'}
            Contact Email       : {domain.contact_email or 'Not found'}

            Finding Summary
            ---------------
            Total Findings      : {len(findings)}
            Severity Breakdown  : {sev_summary}
            Finding Types       : {', '.join(ftypes)}
            Dark Web Confirmed  : {'YES' if any(f.dark_web_confirmed for f in findings) else 'NO'}
            SLA Status          : {_sla_status_summary(findings)}

            Affected Paths (sanitised — no raw PII)
            ----------------------------------------
            {_format_finding_list(findings[:10])}

            Reported by CyberDrishti automated threat intelligence platform.
            CVD Reference: CVD-{cvd} | Report Date: {date_str}
        """).strip()
    else:
        nic_note = "\n            Note: This disclosure has been CC'd to NIC-CERT (security@nic.in)." if _is_gov_domain(domain.domain) else ""
        src_note = f"\n            (Contact email resolved via {contact_source})" if contact_source != "stored" else ""
        body = textwrap.dedent(f"""
            Security Disclosure Notice
            ==========================
            Dear Security Team,{src_note}

            CyberDrishti, an automated cyber-threat intelligence platform operated in
            coordination with CERT-In guidelines, has identified potential security
            issues on your domain: {domain.domain}{nic_note}

            Finding Summary
            ---------------
            Severity : {sev_summary}
            Types    : {', '.join(ftypes)}

            Details (sanitised — no raw credential or PII values are shared)
            -----------------------------------------------------------------
            {_format_finding_list(findings[:5])}

            Requested Actions
            -----------------
            1. Acknowledge this disclosure within 48 hours.
            2. Provide a remediation timeline.
            3. Notify CyberDrishti upon resolution for coordinated closure.

            Failure to acknowledge a CRITICAL finding within 72 hours may result
            in direct escalation to CERT-In per the national Coordinated Vulnerability
            Disclosure Policy.

            CVD Reference  : CVD-{cvd}
            Disclosure Date: {date_str}

            ── ACKNOWLEDGE RECEIPT (required within 48 hours) ────────────
            {(getattr(settings,'PLATFORM_BASE_URL','http://localhost:8000')+'/api/ack/'+ack_token) if ack_token else '(acknowledgement link will be provided via secure portal)'}

            CyberDrishti Platform | CERT-In Coordination
        """).strip()

    return subject, body


def _send_email(to: str, subject: str, body: str,
                cc: Optional[List[str]] = None, dry_run: bool = True) -> bool:
    cc = cc or []
    if dry_run:
        cc_str = f" CC: {', '.join(cc)}" if cc else ""
        logger.info(f"[DRY RUN] To: {to}{cc_str}\n  Subject: {subject}\n  Body: {len(body)} chars")
        return True
    if not settings.SMTP_HOST:
        logger.warning("SMTP not configured — cannot send email")
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = settings.DISCLOSURE_FROM_EMAIL
        msg["To"] = to
        if cc: msg["Cc"] = ", ".join(cc)
        msg.attach(MIMEText(body, "plain"))
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as smtp:
            smtp.ehlo(); smtp.starttls()
            if settings.SMTP_USER and settings.SMTP_PASSWORD:
                smtp.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            smtp.sendmail(settings.DISCLOSURE_FROM_EMAIL, [to] + cc, msg.as_string())
        logger.info(f"Disclosure sent to {to}" + (f" CC: {cc}" if cc else ""))
        return True
    except Exception as e:
        logger.error(f"Failed to send to {to}: {e}"); return False


@celery_app.task(name="app.services.phase3_tasks.run_disclosure_workflow")
def run_disclosure_workflow(dry_run: bool = True):
    """
    CRITICAL findings: disclosed IMMEDIATELY (no SLA wait).
    Others: disclosed when SLA is within 24h window or past.
    .gov.in / .nic.in: auto-CC NIC-CERT.
    Contact resolved via security.txt → RFC 2142 fallback.
    """
    db = SessionLocal()
    processed = 0; disclosed = 0; failed = 0; no_email = 0
    try:
        now = datetime.now(timezone.utc)
        due_window = now + timedelta(hours=24)

        criticals = db.query(Finding).filter(
            Finding.disclosed_at == None,           # noqa: E711
            Finding.severity == "CRITICAL",
            Finding.status.notin_(["RESOLVED","FALSE_POSITIVE"])).all()

        sla_due = db.query(Finding).filter(
            Finding.disclosed_at == None,           # noqa: E711
            Finding.severity != "CRITICAL",
            Finding.status.notin_(["RESOLVED","FALSE_POSITIVE"]),
            Finding.disclosure_sla_due != None,     # noqa: E711
            Finding.disclosure_sla_due <= due_window).all()

        all_pending = list({f.id: f for f in criticals + sla_due}.values())

        by_domain: Dict[str, List[Finding]] = {}
        for f in all_pending:
            by_domain.setdefault(str(f.domain_id), []).append(f)

        sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}

        for domain_id, findings in by_domain.items():
            domain = db.query(Domain).filter(Domain.id == domain_id).first()
            if not domain: continue
            processed += 1
            findings.sort(key=lambda f: sev_order.get(f.severity, 9))

            contact_email, contact_source = _get_contact_email(domain, db)
            if not contact_email:
                logger.warning(f"No contact email for {domain.domain} — skipping")
                no_email += 1; continue

            cc_list = [NIC_CERT_EMAIL] if _is_gov_domain(domain.domain) else []
            domain_ack_token = secrets.token_urlsafe(32)
            subject, body = _build_disclosure_email(domain, findings, "ORG", contact_source,
                                                    ack_token=domain_ack_token)
            ok = _send_email(contact_email, subject, body, cc=cc_list, dry_run=dry_run)

            # ack_token goes on the first finding's PRIMARY event only.
            # UNIQUE constraint means subsequent events for the same domain
            # batch must use NULL tokens (they don't need ack functionality).
            first_finding = True
            for f in findings:
                ack_token = (domain_ack_token if ok and first_finding else None)
                first_finding = False
                db.add(DisclosureEvent(finding_id=f.id, recipient_email=contact_email,
                    recipient_type="PRIMARY", subject=subject, sent_at=now,
                    send_status="SENT" if ok else "FAILED",
                    ack_token=ack_token))
                if cc_list and ok:
                    for cc_addr in cc_list:
                        db.add(DisclosureEvent(finding_id=f.id, recipient_email=cc_addr,
                            recipient_type="CC_NIC", subject=subject, sent_at=now, send_status="SENT"))
                if ok:
                    f.disclosed_at = now; f.status = "DISCLOSED"; disclosed += 1
                else:
                    failed += 1

            db.add(AuditLog(event_type="DISCLOSURE_SENT" if ok else "DISCLOSURE_FAILED",
                actor="SYSTEM", target_type="domain", target_id=domain.id,
                details={"domain": domain.domain, "findings_count": len(findings),
                         "recipient": contact_email, "contact_source": contact_source,
                         "cc": cc_list, "dry_run": dry_run,
                         "critical_immediate": len([f for f in findings if f.severity=="CRITICAL"])}))

        db.commit()
        logger.info(f"Disclosure: {processed} domains, {disclosed} disclosed, {failed} failed, {no_email} no-email")
        return {"processed_domains": processed, "disclosed": disclosed,
                "failed": failed, "no_email": no_email, "dry_run": dry_run}
    finally:
        db.close()


# ─── 5. CERT-IN ESCALATION ────────────────────────────────────

@celery_app.task(name="app.services.phase3_tasks.run_certin_escalation")
def run_certin_escalation(dry_run: bool = True):
    db = SessionLocal()
    escalated = 0; now = datetime.now(timezone.utc)
    try:
        overdue = db.query(Finding).filter(
            Finding.severity == "CRITICAL", Finding.status == "DISCLOSED",
            Finding.acknowledged_at == None,    # noqa: E711
            Finding.disclosed_at != None,       # noqa: E711
            Finding.disclosed_at < now - timedelta(hours=CERTIN_ESCALATION_HOURS)).all()

        dark_web = db.query(Finding).filter(
            Finding.dark_web_confirmed == True,  # noqa: E712
            Finding.severity.in_(["CRITICAL","HIGH"]),
            Finding.escalation_level < 3,
            Finding.status.notin_(["RESOLVED","FALSE_POSITIVE"])).all()

        to_escalate = list({f.id: f for f in overdue + dark_web}.values())
        by_domain: Dict[str, List[Finding]] = {}
        for f in to_escalate:
            by_domain.setdefault(str(f.domain_id), []).append(f)

        for domain_id, findings in by_domain.items():
            domain = db.query(Domain).filter(Domain.id == domain_id).first()
            if not domain: continue
            subject, body = _build_disclosure_email(domain, findings, "CERTIN")
            ok = _send_email(CERTIN_EMAIL, subject, body, dry_run=dry_run)
            for f in findings:
                f.escalation_level = 3; f.status = "ESCALATED"
                db.add(DisclosureEvent(finding_id=f.id, recipient_email=CERTIN_EMAIL,
                    recipient_type="CC_NIC", subject=subject, sent_at=now,
                    send_status="SENT" if ok else "FAILED"))
                if ok: escalated += 1
            db.add(AuditLog(event_type="CERTIN_ESCALATION", actor="SYSTEM",
                target_type="domain", target_id=domain.id,
                details={"domain": domain.domain, "findings": len(findings), "dry_run": dry_run,
                         "triggers": list({f.finding_type for f in findings})}))

        db.commit()
        logger.info(f"CERT-In escalation: {escalated} findings (dry_run={dry_run})")
        return {"escalated": escalated, "dry_run": dry_run}
    finally:
        db.close()


# ─── 6. VENDOR CORRELATION ────────────────────────────────────

@celery_app.task(name="app.services.phase3_tasks.run_vendor_correlation")
def run_vendor_correlation():
    db = SessionLocal()
    correlated = 0
    try:
        risky_vendors = (db.query(Finding.vendor_fingerprint)
            .filter(Finding.vendor_fingerprint != None,     # noqa: E711
                    Finding.severity.in_(["CRITICAL","HIGH"]),
                    Finding.status.notin_(["RESOLVED","FALSE_POSITIVE"]))
            .distinct().all())
        risky_vendor_set = {r[0] for r in risky_vendors if r[0]}
        if not risky_vendor_set:
            return {"correlated": 0}

        for vendor in risky_vendor_set:
            prefix = vendor.split()[0].lower()
            affected = (db.query(Domain)
                .filter(Domain.vendor_fingerprint.ilike(f"%{prefix}%"), Domain.status=="ACTIVE").all())
            template = (db.query(Finding)
                .filter(Finding.vendor_fingerprint==vendor,
                        Finding.severity.in_(["CRITICAL","HIGH"]),
                        Finding.status.notin_(["RESOLVED","FALSE_POSITIVE"]))
                .order_by(Finding.severity).first())
            if not template: continue

            for d in affected:
                exists = db.query(Finding).filter(
                    Finding.domain_id==d.id, Finding.finding_type=="VENDOR_CORRELATION",
                    Finding.vendor_fingerprint==vendor).first()
                if exists: continue

                from app.services.scanner_tasks import compute_sla
                db.add(Finding(
                    domain_id=d.id, url=f"https://{d.domain}/", url_path="/",
                    entity_type="OTHER", finding_type="VENDOR_CORRELATION", severity="HIGH",
                    heuristic_confidence=0.75, final_confidence=0.75, vendor_fingerprint=vendor,
                    context_snippet_safe=(
                        f"[VENDOR CORRELATION] {vendor} detected on this domain. "
                        f"A {template.severity} {template.finding_type} was confirmed "
                        f"on another domain with the same CMS/framework. "
                        f"Assess this domain for the same vulnerability."),
                    detected_by="VENDOR_CORRELATION", disclosure_sla_due=compute_sla("HIGH")))
                correlated += 1

        db.commit()
        logger.info(f"Vendor correlation: {correlated} new findings")
        return {"correlated": correlated, "risky_vendors": len(risky_vendor_set)}
    finally:
        db.close()


# ─── 7. PIPELINE ──────────────────────────────────────────────

@celery_app.task(name="app.services.phase3_tasks.run_phase3_pipeline")
def run_phase3_pipeline(dry_run: bool = True):
    logger.info(f"{'='*60}\nPHASE 3 PIPELINE — dry_run={dry_run}\n{'='*60}")
    results = {}
    for name, fn in [
        ("risk_scores",        update_risk_scores),
        ("breach_correlation", run_breach_correlation),
        ("vendor_correlation", run_vendor_correlation),
        ("disclosure",         lambda: run_disclosure_workflow(dry_run=dry_run)),
        ("escalation",         lambda: run_certin_escalation(dry_run=dry_run)),
    ]:
        try:
            results[name] = fn()
            logger.info(f"  [{name}] {results[name]}")
        except Exception as e:
            results[name] = {"error": str(e)}
            logger.error(f"  [{name}] FAILED: {e}")

    db = SessionLocal()
    try:
        db.add(AuditLog(event_type="PHASE3_PIPELINE_COMPLETED", actor="SYSTEM",
            details={"dry_run": dry_run, **{k: str(v) for k, v in results.items()}}))
        db.commit()
    finally:
        db.close()
    return {"status": "completed", "dry_run": dry_run, **results}
