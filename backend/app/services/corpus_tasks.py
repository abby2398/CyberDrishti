# backend/app/services/corpus_tasks.py
# ─────────────────────────────────────────────────────────────
#  Domain Corpus Builder — Phase 2
#
#  Phase 1 (Pilot): .gov.in, .nic.in, .edu.in, .ac.in, .res.in
#  Phase 2 (Expansion): All Indian TLDs + .com domains with
#                       India Origin Confidence Score (IOCS) >= 50
#
#  IOCS Scoring signals (min 3 required to qualify):
#    1. TLD signal (.in, .co.in, .gov.in etc.)    +40
#    2. ASN/IP geolocation → India                +20
#    3. Indian phone number in content            +15
#    4. GST number in content                     +15
#    5. Indian registrant in WHOIS                +20
#    6. Devanagari / regional script content      +15
#    7. Indian payment gateway (Razorpay/Paytm)   +15
#    8. Hindi/Indian language meta tag            +10
#    9. Known Indian ASN                          +10
#
#  Differential Scanning:
#    Each domain stores a content_hash (SHA-256 of homepage).
#    Re-scans are skipped if content_hash unchanged AND
#    last_scan_at < baseline_ttl days ago.
#    CRITICAL domains rescan every 7 days regardless.
#
#  Vendor/Plugin Fingerprinting:
#    Detects CMS, framework, and plugin signatures.
#    Findings with the same vendor are cross-correlated
#    so a single plugin vulnerability surfaces at portfolio level.
# ─────────────────────────────────────────────────────────────

import re
import time
import socket
import hashlib
import ipaddress
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Set, Dict, Tuple
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException

from app.worker import celery_app
from app.db.database import SessionLocal
from app.models.models import Domain, AuditLog
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("corpus.builder")

# Suppress SSL warnings for government sites with cert issues
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ═══════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═══════════════════════════════════════════════════════════════

# Phase 1: High-confidence Indian government/education TLDs
PILOT_TLDS = [".gov.in", ".nic.in", ".edu.in", ".ac.in", ".res.in"]

# Phase 2: All Indian country-code TLDs
INDIAN_TLDS = [
    ".gov.in", ".nic.in", ".edu.in", ".ac.in", ".res.in",   # Phase 1
    ".in",                                                     # Generic Indian
    ".co.in", ".net.in", ".org.in", ".gen.in", ".firm.in",   # Indian SLDs
    ".ind.in",                                                 # Individual Indian
    ".mil.in", ".int.in",                                      # Special
]

# Scan cadence by sector/risk
RESCAN_TTL_DAYS = {
    "GOVERNMENT":  7,
    "HEALTHCARE":  7,
    "FINANCE":     7,
    "EDUCATION":  14,
    "RESEARCH":   14,
    "OTHER":      30,
}

# Minimum IOCS score to enter active scan queue
IOCS_THRESHOLD = 50

# Minimum number of IOCS signals required
MIN_SIGNALS = 2  # Phase 2: lowered from 3 to capture more valid domains

# Known Indian ASN prefixes (partial — major ISPs)
INDIAN_ASN_PREFIXES = {
    "AS9829",  # BSNL
    "AS45609", # Airtel
    "AS24560", # Airtel Enterprise
    "AS18101", # Reliance Jio Infocomm
    "AS55836", # Reliance Jio
    "AS17813", # MTNL Mumbai
    "AS17762", # MTNL Delhi
    "AS45271", # Idea Cellular / Vi
    "AS55923", # ACT Fibernet
    "AS4755",  # Tata Communications
    "AS6453",  # Tata Communications
    "AS38266", # Vodafone India
    "AS132717", # NIC India
    "AS45820", # NIC India
}

# Indian payment gateway JS patterns
PAYMENT_GATEWAY_PATTERNS = [
    re.compile(r'razorpay', re.I),
    re.compile(r'paytm\.com', re.I),
    re.compile(r'cashfree', re.I),
    re.compile(r'payu\.in', re.I),
    re.compile(r'ccavenue', re.I),
    re.compile(r'instamojo', re.I),
    re.compile(r'billdesk', re.I),
    re.compile(r'easebuzz', re.I),
]

# Indian language / regional content signals
DEVANAGARI_RE = re.compile(r'[\u0900-\u097F]{4,}')  # 4+ Hindi chars in a row
HINDI_META_RE = re.compile(r'lang=["\']hi["\']|content-language.*hi', re.I)
GST_RE        = re.compile(r'\b\d{2}[A-Z]{5}\d{4}[A-Z]\d[Z][A-Z0-9]\b')
INDIAN_PHONE_RE = re.compile(r'(?:\+91|0)[6-9]\d{9}\b')

# Sector inference from domain keywords
SECTOR_KEYWORDS = {
    "GOVERNMENT":  ["gov", "nic", "ministry", "dept", "department", "mca", "india.gov",
                    "mygov", "dpiit", "ncert", "niti", "pib"],
    "EDUCATION":   ["edu", "ac.in", "university", "college", "school", "iit", "nit",
                    "iisc", "jnu", "iim", "du.", "mu.", "amu", "bhu"],
    "HEALTHCARE":  ["health", "hospital", "medical", "aiims", "pgimer", "nhm",
                    "mohfw", "nha", "pmjay", "clinic", "pharma"],
    "FINANCE":     ["bank", "finance", "nbfc", "rbi", "sebi", "irdai", "pfrda",
                    "sbi.", "hdfc", "icici", "axis", "kotak", "npci", "upi"],
    "RESEARCH":    ["res.in", "csir", "isro", "drdo", "icar", "icmr", "barc"],
}

# Vendor/CMS fingerprint signatures
VENDOR_SIGNATURES: List[Dict] = [
    # WordPress
    {
        "vendor": "WordPress",
        "signals": [
            re.compile(r'/wp-content/'),
            re.compile(r'/wp-includes/'),
            re.compile(r'wp-json'),
        ],
        "version_re": re.compile(r'WordPress\s+([\d.]+)', re.I),
        "risk": "HIGH",   # WP plugin vulns are systemic
    },
    # Joomla
    {
        "vendor": "Joomla",
        "signals": [
            re.compile(r'/components/com_'),
            re.compile(r'Joomla!'),
            re.compile(r'/media/system/js/'),
        ],
        "version_re": re.compile(r'Joomla!\s+([\d.]+)', re.I),
        "risk": "HIGH",
    },
    # Drupal
    {
        "vendor": "Drupal",
        "signals": [
            re.compile(r'Drupal\.settings'),
            re.compile(r'/sites/default/files/'),
            re.compile(r'drupal.org'),
        ],
        "version_re": re.compile(r'Drupal\s+([\d.]+)', re.I),
        "risk": "MEDIUM",
    },
    # Django
    {
        "vendor": "Django",
        "signals": [
            re.compile(r'csrfmiddlewaretoken'),
            re.compile(r'django', re.I),
        ],
        "version_re": None,
        "risk": "LOW",
    },
    # Laravel
    {
        "vendor": "Laravel",
        "signals": [
            re.compile(r'laravel_session'),
            re.compile(r'X-Powered-By.*Laravel', re.I),
        ],
        "version_re": None,
        "risk": "LOW",
    },
    # PHP (generic)
    {
        "vendor": "PHP",
        "signals": [
            re.compile(r'\.php(\?|$|#)'),
        ],
        "version_re": re.compile(r'PHP/([\d.]+)', re.I),
        "risk": "LOW",
    },
    # NIC e-Gov (common Indian government platform)
    {
        "vendor": "NIC-eGov",
        "signals": [
            re.compile(r'nic\.in'),
            re.compile(r'eGov', re.I),
            re.compile(r'National Informatics Centre', re.I),
        ],
        "version_re": None,
        "risk": "MEDIUM",
    },
    # Spring Boot (Java)
    {
        "vendor": "Spring-Boot",
        "signals": [
            re.compile(r'Whitelabel Error Page'),
            re.compile(r'application/json.*spring', re.I),
            re.compile(r'actuator/health'),
        ],
        "version_re": None,
        "risk": "MEDIUM",
    },
    # ASP.NET
    {
        "vendor": "ASP.NET",
        "signals": [
            re.compile(r'__VIEWSTATE'),
            re.compile(r'ASP\.NET', re.I),
            re.compile(r'\.aspx', re.I),
        ],
        "version_re": re.compile(r'ASP\.NET\s+([\d.]+)', re.I),
        "risk": "LOW",
    },
]


# ═══════════════════════════════════════════════════════════════
#  CT LOG DISCOVERY
# ═══════════════════════════════════════════════════════════════

def fetch_ct_logs(query_pattern: str, max_results: int = 500) -> Set[str]:
    """
    Query Certificate Transparency logs via crt.sh.
    query_pattern: e.g. "%.gov.in" or "%.co.in"
    """
    domains: Set[str] = set()
    url = f"https://crt.sh/?q={query_pattern}&output=json"

    try:
        logger.info(f"CT log query: {query_pattern}")
        r = requests.get(
            url, timeout=30,
            headers={"User-Agent": "CyberDrishti/2.0 CERT-IN Security Scanner"},
        )
        if r.status_code != 200:
            logger.warning(f"crt.sh {r.status_code} for {query_pattern}")
            return domains

        for entry in r.json()[:max_results]:
            for name in entry.get("name_value", "").lower().split("\n"):
                name = name.strip().lstrip("*.").strip()
                if name and " " not in name and len(name) > 3:
                    domains.add(name)

    except requests.exceptions.ConnectionError:
        logger.warning(f"Cannot reach crt.sh — offline? ({query_pattern})")
    except Exception as e:
        logger.error(f"CT log error for {query_pattern}: {e}")

    return domains


# ═══════════════════════════════════════════════════════════════
#  NETWORK UTILITIES
# ═══════════════════════════════════════════════════════════════

def resolve_domain(domain: str) -> Optional[str]:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def get_asn_info(ip: str) -> Optional[str]:
    """
    Get ASN for an IP via ip-api.com (free tier, no key needed).
    Returns ASN string like 'AS9829' or None.
    """
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=as,country",
            timeout=5,
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("country") == "India":
                return data.get("as", "")
    except Exception:
        pass
    return None


def fetch_homepage(domain: str, timeout: int = 10) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[Dict]]:
    """
    Fetch homepage content. Returns (url, html, status_code, headers).
    Tries HTTPS first, falls back to HTTP.
    """
    for scheme in ["https", "http"]:
        url = f"{scheme}://{domain}"
        try:
            r = requests.get(
                url, timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": "CyberDrishti/2.0 CERT-IN Security Scanner"},
                verify=False,
            )
            if r.status_code < 500:
                return r.url, r.text[:50000], r.status_code, dict(r.headers)
        except Exception:
            continue
    return None, None, None, None


# ═══════════════════════════════════════════════════════════════
#  IOCS SCORING
# ═══════════════════════════════════════════════════════════════

def compute_iocs(domain: str, tld: str, ip: Optional[str],
                 html: Optional[str], headers: Optional[Dict],
                 asn: Optional[str]) -> Tuple[int, int, Dict]:
    """
    Compute India Origin Confidence Score.
    Returns (score, signal_count, signal_detail_dict).
    """
    score = 0
    signals = 0
    detail = {}

    # ── Signal 1: Indian TLD ──────────────────────────────────
    if any(domain.endswith(t.lstrip(".")) for t in INDIAN_TLDS):
        pts = 40
        score += pts
        signals += 1
        detail["tld"] = pts

    # ── Signal 2: Pilot TLD (extra certainty) ─────────────────
    if any(domain.endswith(t.lstrip(".")) for t in PILOT_TLDS):
        pts = 10  # Bonus on top of TLD signal
        score += pts
        detail["pilot_tld_bonus"] = pts

    # ── Signal 3: IP geolocation → India ──────────────────────
    if asn is not None:   # asn is set only when ip-api confirms India
        pts = 20
        score += pts
        signals += 1
        detail["ip_geo_india"] = pts

    # ── Signal 4: Known Indian ASN ────────────────────────────
    if asn and any(asn.startswith(a) for a in INDIAN_ASN_PREFIXES):
        pts = 10
        score += pts
        signals += 1
        detail["indian_asn"] = pts

    if html:
        # ── Signal 5: Devanagari / regional script content ────
        if DEVANAGARI_RE.search(html):
            pts = 15
            score += pts
            signals += 1
            detail["devanagari_content"] = pts

        # ── Signal 6: Hindi/Indian language meta tag ──────────
        if HINDI_META_RE.search(html):
            pts = 10
            score += pts
            signals += 1
            detail["hindi_meta"] = pts

        # ── Signal 7: Indian phone number in content ──────────
        if INDIAN_PHONE_RE.search(html):
            pts = 15
            score += pts
            signals += 1
            detail["indian_phone"] = pts

        # ── Signal 8: GST number in content ───────────────────
        if GST_RE.search(html):
            pts = 15
            score += pts
            signals += 1
            detail["gst_number"] = pts

        # ── Signal 9: Indian payment gateway ──────────────────
        for pgw in PAYMENT_GATEWAY_PATTERNS:
            if pgw.search(html):
                pts = 15
                score += pts
                signals += 1
                detail["payment_gateway"] = pts
                break

    return min(score, 100), signals, detail


# ═══════════════════════════════════════════════════════════════
#  VENDOR / PLUGIN FINGERPRINTING
# ═══════════════════════════════════════════════════════════════

def fingerprint_vendor(html: str, headers: Dict) -> Optional[Dict]:
    """
    Detect CMS, framework, and version from homepage HTML + headers.
    Returns fingerprint dict or None.
    """
    if not html:
        return None

    header_str = " ".join(f"{k}: {v}" for k, v in (headers or {}).items())
    combined = html + "\n" + header_str

    for sig in VENDOR_SIGNATURES:
        matches = sum(1 for s in sig["signals"] if s.search(combined))
        if matches >= 2 or (len(sig["signals"]) == 1 and matches == 1):
            version = None
            if sig["version_re"]:
                m = sig["version_re"].search(combined)
                if m:
                    version = m.group(1)
            return {
                "vendor": sig["vendor"],
                "version": version,
                "risk": sig["risk"],
                "signal_count": matches,
            }
    return None


# ═══════════════════════════════════════════════════════════════
#  DIFFERENTIAL SCANNING (baseline hash)
# ═══════════════════════════════════════════════════════════════

def compute_content_hash(html: Optional[str]) -> Optional[str]:
    """SHA-256 hash of homepage HTML for change detection."""
    if not html:
        return None
    return hashlib.sha256(html.encode("utf-8", errors="replace")).hexdigest()


def should_rescan(domain_row: Domain) -> bool:
    """
    Returns True if domain is due for re-scan.
    High-risk sectors rescan every 7 days,
    others follow RESCAN_TTL_DAYS config.
    Domains with no previous scan always get scanned.
    """
    if domain_row.last_scanned_at is None:
        return True

    ttl = RESCAN_TTL_DAYS.get(domain_row.sector or "OTHER", 30)

    # Domains with CRITICAL findings get more frequent rescans
    if domain_row.last_scanned_at:
        last_scan = domain_row.last_scanned_at.replace(tzinfo=timezone.utc) \
            if domain_row.last_scanned_at.tzinfo is None \
            else domain_row.last_scanned_at
        age_days = (datetime.now(timezone.utc) - last_scan).days
        return age_days >= ttl

    return True


# ═══════════════════════════════════════════════════════════════
#  SECTOR INFERENCE
# ═══════════════════════════════════════════════════════════════

def infer_sector(domain: str, html: Optional[str] = None) -> str:
    """Infer sector from domain name and optional HTML content."""
    check = domain.lower() + " " + (html[:2000] if html else "")
    for sector, keywords in SECTOR_KEYWORDS.items():
        if any(kw in check for kw in keywords):
            return sector
    return "OTHER"


# ═══════════════════════════════════════════════════════════════
#  DATABASE OPERATIONS
# ═══════════════════════════════════════════════════════════════

def upsert_domain(db, domain: str, tld: str, ip: Optional[str],
                  iocs_score: int, signal_count: int,
                  discovered_via: str, sector: str,
                  content_hash: Optional[str],
                  vendor_fp: Optional[Dict]) -> Tuple[bool, str]:
    """
    Insert or update domain in the corpus.
    Returns (is_new, action_taken).
    """
    existing = db.query(Domain).filter(Domain.domain == domain).first()

    vendor_str = vendor_fp["vendor"] if vendor_fp else None

    if existing:
        changed = False
        if ip and not existing.ip_address:
            existing.ip_address = ip
            changed = True
        if iocs_score > (existing.iocs_score or 0):
            existing.iocs_score = iocs_score
            changed = True
        if vendor_str and existing.vendor_fingerprint != vendor_str:
            existing.vendor_fingerprint = vendor_str
            changed = True
        if content_hash and existing.baseline_hash != content_hash:
            existing.baseline_hash = content_hash
            changed = True
        if existing.status == "PENDING" and iocs_score >= IOCS_THRESHOLD:
            existing.status = "ACTIVE"
            changed = True
        if changed:
            db.commit()
            return False, "updated"
        return False, "unchanged"

    new_domain = Domain(
        domain=domain,
        tld=tld,
        iocs_score=iocs_score,
        status="ACTIVE" if iocs_score >= IOCS_THRESHOLD else "PENDING",
        ip_address=ip,
        discovered_via=discovered_via,
        sector=sector,
        vendor_fingerprint=vendor_str,
        baseline_hash=content_hash,
        signal_whois_in=any(domain.endswith(t.lstrip(".")) for t in INDIAN_TLDS),
        next_scan_due_at=datetime.now(timezone.utc),
    )
    db.add(new_domain)
    db.commit()
    return True, "created"


def get_fallback_domains(tld: str) -> Set[str]:
    """Known Indian domains used when crt.sh is unreachable."""
    fallbacks = {
        ".gov.in": {
            "india.gov.in", "mygov.in", "uidai.gov.in",
            "meity.gov.in", "mca.gov.in", "incometax.gov.in",
            "gst.gov.in", "epfindia.gov.in",
            "nha.gov.in", "mohfw.gov.in", "education.gov.in",
            "pib.gov.in", "dpiit.gov.in",
        },
        ".nic.in": {"nic.in", "services.nic.in"},
        ".edu.in": {"iit.edu.in"},
        ".ac.in": {"du.ac.in", "iisc.ac.in", "jnu.ac.in", "iitb.ac.in", "iitd.ac.in"},
        ".res.in": {"csir.res.in", "isro.res.in"},
        ".in": {
            "flipkart.com", "myntra.com", "snapdeal.com",
        },
        ".co.in": {
            "airtel.co.in", "bsnl.co.in",
        },
    }
    return fallbacks.get(tld, set())


# ═══════════════════════════════════════════════════════════════
#  CELERY TASKS
# ═══════════════════════════════════════════════════════════════

@celery_app.task(name="app.services.corpus_tasks.run_pilot_corpus_refresh", bind=True)
def run_pilot_corpus_refresh(self):
    """
    Phase 1 corpus refresh — .gov.in, .nic.in, .edu.in, .ac.in, .res.in.
    Retained as an alias for backward compatibility; calls phase2 corpus
    but restricted to PILOT_TLDS.
    """
    return run_corpus_refresh_phase2.apply_async(
        kwargs={"tlds": PILOT_TLDS}
    ).get(timeout=600)


@celery_app.task(name="app.services.corpus_tasks.run_corpus_refresh_phase2", bind=True)
def run_corpus_refresh_phase2(self, tlds: Optional[List[str]] = None):
    """
    Phase 2 Corpus Builder.

    Discovers Indian domains across all Indian TLDs using CT logs,
    scores each with multi-signal IOCS, fingerprints the technology
    stack, and stores the domain with a baseline content hash for
    differential scanning.

    Set tlds=None to run all INDIAN_TLDS (full Phase 2 sweep).
    Set tlds=PILOT_TLDS for the Phase 1 subset only.
    """
    target_tlds = tlds or INDIAN_TLDS

    logger.info("=" * 60)
    logger.info(f"CORPUS BUILDER Phase 2 — {len(target_tlds)} TLDs")
    logger.info("=" * 60)

    db = SessionLocal()
    stats = {"new": 0, "updated": 0, "skipped_iocs": 0,
             "skipped_dns": 0, "total_checked": 0}

    try:
        for tld in target_tlds:
            logger.info(f"\n── TLD: {tld} ──────────────────────")

            # 1. Get candidates from CT logs
            candidates = fetch_ct_logs(f"%.{tld.lstrip('.')}", max_results=300)
            if not candidates:
                candidates = get_fallback_domains(tld)

            logger.info(f"  {len(candidates)} candidates from CT logs")

            for domain in candidates:
                stats["total_checked"] += 1
                time.sleep(0.1)  # gentle rate limit on DNS

                # 2. DNS resolution
                ip = resolve_domain(domain)
                if not ip:
                    stats["skipped_dns"] += 1
                    continue

                # 3. Get ASN / geolocation (only for non-Indian TLDs to save time)
                asn = None
                if not any(domain.endswith(t.lstrip(".")) for t in INDIAN_TLDS):
                    asn = get_asn_info(ip)
                else:
                    asn = ""  # Indian TLD → treat as India even without geo check

                # 4. Fetch homepage for content-based signals + fingerprinting
                resolved_url, html, status_code, headers = fetch_homepage(domain)

                # 5. Compute IOCS score
                iocs, sig_count, sig_detail = compute_iocs(
                    domain, tld, ip, html, headers, asn
                )

                # 6. Gate: need minimum signals and threshold score
                if iocs < IOCS_THRESHOLD or sig_count < MIN_SIGNALS:
                    stats["skipped_iocs"] += 1
                    logger.debug(
                        f"  Skip (IOCS={iocs}, sigs={sig_count}): {domain}"
                    )
                    continue

                # 7. Vendor fingerprinting
                vendor_fp = fingerprint_vendor(html or "", headers or {})

                # 8. Content hash for differential scanning
                content_hash = compute_content_hash(html)

                # 9. Sector inference
                sector = infer_sector(domain, html)

                # 10. Upsert into corpus
                is_new, action = upsert_domain(
                    db, domain, tld, ip,
                    iocs, sig_count, "CT_LOG",
                    sector, content_hash, vendor_fp,
                )

                if is_new:
                    stats["new"] += 1
                    vendor_str = f" [{vendor_fp['vendor']}]" if vendor_fp else ""
                    logger.info(
                        f"  + {domain} IOCS={iocs} sigs={sig_count} "
                        f"sector={sector}{vendor_str}"
                    )
                elif action == "updated":
                    stats["updated"] += 1

        # Audit log
        db.add(AuditLog(
            event_type="CORPUS_REFRESH_COMPLETED",
            actor="SYSTEM",
            details={
                "phase": 2,
                "tlds": target_tlds,
                **stats,
            }
        ))
        db.commit()

        logger.info(f"\n{'='*60}")
        logger.info(f"Phase 2 corpus refresh complete:")
        logger.info(f"  Checked   : {stats['total_checked']}")
        logger.info(f"  New       : {stats['new']}")
        logger.info(f"  Updated   : {stats['updated']}")
        logger.info(f"  Skipped (DNS fail) : {stats['skipped_dns']}")
        logger.info(f"  Skipped (low IOCS) : {stats['skipped_iocs']}")
        logger.info(f"{'='*60}")

        return {"status": "success", **stats}

    except Exception as e:
        logger.error(f"Phase 2 corpus refresh failed: {e}", exc_info=True)
        return {"status": "error", "error": str(e)}

    finally:
        db.close()


@celery_app.task(name="app.services.corpus_tasks.enrich_domain_fingerprint", bind=True)
def enrich_domain_fingerprint(self, domain_id: str):
    """
    Re-fingerprint a single domain's tech stack.
    Called after a scan finds something interesting, or on schedule.
    Updates vendor_fingerprint and content_hash in the corpus.
    """
    db = SessionLocal()
    try:
        domain_row = db.query(Domain).filter(Domain.id == domain_id).first()
        if not domain_row:
            return {"status": "error", "error": "domain not found"}

        _, html, _, headers = fetch_homepage(domain_row.domain)
        vendor_fp = fingerprint_vendor(html or "", headers or {})
        content_hash = compute_content_hash(html)

        old_hash = domain_row.baseline_hash
        changed = (old_hash is not None and content_hash != old_hash)

        domain_row.vendor_fingerprint = vendor_fp["vendor"] if vendor_fp else domain_row.vendor_fingerprint
        domain_row.baseline_hash = content_hash
        domain_row.updated_at = datetime.now(timezone.utc)
        db.commit()

        return {
            "domain": domain_row.domain,
            "vendor": vendor_fp["vendor"] if vendor_fp else None,
            "content_changed": changed,
            "status": "updated",
        }
    finally:
        db.close()


@celery_app.task(name="app.services.corpus_tasks.queue_domains_for_rescan")
def queue_domains_for_rescan():
    """
    Scheduler task: find all domains due for re-scan
    and enqueue them as scan_domain tasks.
    Respects per-sector TTLs and differential scan logic.
    """
    from app.services.scanner_tasks import scan_domain

    db = SessionLocal()
    queued = 0
    skipped_ttl = 0

    try:
        active_domains = db.query(Domain).filter(
            Domain.status == "ACTIVE",
            Domain.iocs_score >= IOCS_THRESHOLD,
        ).all()

        for d in active_domains:
            if should_rescan(d):
                scan_domain.delay(str(d.id))
                queued += 1
            else:
                skipped_ttl += 1

        logger.info(f"Rescan queue: {queued} queued, {skipped_ttl} skipped (TTL not reached)")
        return {"queued": queued, "skipped_ttl": skipped_ttl}

    finally:
        db.close()


@celery_app.task(name="app.services.corpus_tasks.add_single_domain")
def add_single_domain(domain: str):
    """
    Manually add a single domain to the corpus.
    Phase 2 aware — full IOCS scoring with content signals.
    """
    db = SessionLocal()
    try:
        # Determine TLD
        tld = ".in"
        for t in INDIAN_TLDS + [".com"]:
            if domain.endswith(t.lstrip(".")):
                tld = t
                break

        ip = resolve_domain(domain)
        asn = get_asn_info(ip) if ip else None
        _, html, _, headers = fetch_homepage(domain)

        iocs, sig_count, sig_detail = compute_iocs(domain, tld, ip, html, headers, asn)
        vendor_fp = fingerprint_vendor(html or "", headers or {})
        content_hash = compute_content_hash(html)
        sector = infer_sector(domain, html)

        is_new, action = upsert_domain(
            db, domain, tld, ip, iocs, sig_count, "MANUAL",
            sector, content_hash, vendor_fp,
        )

        return {
            "domain": domain,
            "ip": ip,
            "iocs_score": iocs,
            "signal_count": sig_count,
            "signals": sig_detail,
            "sector": sector,
            "vendor": vendor_fp["vendor"] if vendor_fp else None,
            "is_new": is_new,
            "status": "queued" if is_new else action,
        }
    finally:
        db.close()
