# backend/app/services/subdomain_enum.py
# ─────────────────────────────────────────────────────────────
#  CyberDrishti — Multi-Source Subdomain Enumerator
#  Phase 2
#
#  Sources (in priority order):
#
#  PASSIVE (no auth required):
#    1. crt.sh          — Certificate Transparency logs (free)
#    2. AlienVault OTX  — Open Threat Exchange (free API)
#    3. HackerTarget    — DNS lookup API (free tier)
#    4. RapidDNS        — DNS database (free)
#    5. BufferOver.run  — DNS aggregator (free)
#    6. ThreatCrowd     — Threat intel (free)
#
#  WITH API KEYS (high quality, configured in .env):
#    7. Shodan          — SHODAN_API_KEY
#    8. Censys          — CENSYS_API_ID + CENSYS_API_SECRET
#    9. ZoomEye         — ZOOMEYE_API_KEY
#   10. SecurityTrails  — SECURITYTRAILS_API_KEY
#   11. VirusTotal      — VIRUSTOTAL_API_KEY
#   12. BinaryEdge      — BINARYEDGE_API_KEY
#   13. WhoisXML API    — WHOIS_XML_API_KEY (subdomain endpoint)
#   14. Chaos (ProjectDiscovery) — CHAOS_API_KEY
#
#  ACTIVE (DNS brute-force):
#   15. DNS brute-force — wordlist of ~500 common subdomains
#       with concurrent async resolution
#
#  All sources are run concurrently (ThreadPoolExecutor).
#  Results are deduplicated and DNS-validated before return.
#  Each source is wrapped in try/except — one failing source
#  never stops the rest.
# ─────────────────────────────────────────────────────────────

import re
import time
import socket
import concurrent.futures
from typing import Set, Dict, List, Optional, Callable
from dataclasses import dataclass, field

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("subdomain.enum")

# ─────────────────────────────────────────────────────────────
#  DNS brute-force wordlist
#  Focused on Indian government/enterprise patterns +
#  universal common subdomains.
# ─────────────────────────────────────────────────────────────
SUBDOMAIN_WORDLIST: List[str] = [
    # Universal
    "www", "mail", "email", "smtp", "pop", "pop3", "imap", "ftp",
    "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    "api", "api2", "api-v1", "api-v2", "rest", "graphql",
    "app", "apps", "application",
    "dev", "develop", "development", "staging", "stage",
    "test", "testing", "uat", "qa", "demo", "sandbox",
    "beta", "alpha", "rc",
    "prod", "production", "live",
    "admin", "administrator", "cpanel", "plesk", "whm",
    "portal", "dashboard", "console", "panel",
    "login", "auth", "sso", "oauth", "ldap",
    "cdn", "static", "assets", "media", "img", "images",
    "files", "docs", "download", "downloads",
    "blog", "forum", "wiki", "help", "support", "kb",
    "shop", "store", "cart", "checkout", "payment",
    "mobile", "m", "wap", "pwa",
    "vpn", "remote", "citrix", "webmail",
    "git", "gitlab", "github", "svn", "repo", "code",
    "jira", "confluence", "jenkins", "ci", "cd",
    "monitor", "status", "health", "metrics",
    "backup", "bak", "old", "archive", "legacy",
    "sql", "mysql", "phpmyadmin", "pma", "dbadmin",
    "elasticsearch", "kibana", "grafana", "prometheus",
    "redis", "memcache", "rabbitmq",
    "s3", "storage", "bucket", "minio",
    "k8s", "kubernetes", "docker", "registry",
    "cloud", "aws", "azure", "gcp",
    "intranet", "internal", "private",
    "localhost", "local",

    # Indian government patterns
    "eprocure", "tender", "tenders", "etender",
    "eoffice", "efile", "nfile",
    "erp", "hrms", "hris", "payroll",
    "rti", "grievance", "pgportal",
    "csc", "umang", "digilocker",
    "mis", "mpr", "report", "reports",
    "service", "services", "eservice", "eservices",
    "citizen", "citizens",
    "nic", "nic2",
    "certificate", "certs",
    "scholarship", "admit",
    "result", "results", "exam",
    "library", "elib",

    # Common enterprise
    "crm", "salesforce", "zoho",
    "hr", "finance", "accounts",
    "exchange", "owa", "autodiscover",
    "meet", "meeting", "webex", "zoom",
    "helpdesk", "ticket", "tickets", "servicedesk",
    "nagios", "zabbix",
    "proxy", "gateway", "load", "lb",
    "secure", "ssl",
    "extranet",
    "upload", "share",
    "video", "stream",
    "news", "press",
    "careers", "hr",
    "feedback", "survey",
    "search",
    "iot", "scada",
    "staging2", "dev2", "test2",
]

# HTTP session with appropriate defaults
_session = requests.Session()
_session.headers.update({
    "User-Agent": "CyberDrishti/2.0 CERT-IN Security Scanner"
})


# ─────────────────────────────────────────────────────────────
#  Result container
# ─────────────────────────────────────────────────────────────

@dataclass
class SubdomainResult:
    subdomains: Set[str] = field(default_factory=set)
    source_stats: Dict[str, int] = field(default_factory=dict)
    errors: Dict[str, str] = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────
#  PASSIVE SOURCE FUNCTIONS
#  Each returns a set of subdomain strings (no scheme, no path).
# ─────────────────────────────────────────────────────────────

def _source_crtsh(domain: str) -> Set[str]:
    """Certificate Transparency logs — crt.sh. Free, no key."""
    found: Set[str] = set()
    try:
        r = _session.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=30,
        )
        r.raise_for_status()
        for entry in r.json():
            for name in entry.get("name_value", "").lower().split("\n"):
                name = name.strip().lstrip("*.")
                if name.endswith(f".{domain}") or name == domain:
                    found.add(name)
    except Exception as e:
        raise RuntimeError(f"crt.sh: {e}")
    return found


def _source_alienvault(domain: str) -> Set[str]:
    """AlienVault OTX — free, no key needed."""
    found: Set[str] = set()
    try:
        page = 1
        while True:
            r = _session.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                params={"page": page, "limit": 500},
                timeout=20,
            )
            r.raise_for_status()
            data = r.json()
            for entry in data.get("passive_dns", []):
                hostname = entry.get("hostname", "").lower().strip()
                if hostname.endswith(f".{domain}") or hostname == domain:
                    found.add(hostname)
            if not data.get("has_next"):
                break
            page += 1
            if page > 5:  # cap at 2500 results
                break
    except Exception as e:
        raise RuntimeError(f"AlienVault OTX: {e}")
    return found


def _source_hackertarget(domain: str) -> Set[str]:
    """HackerTarget DNS lookup — free tier (100 req/day)."""
    found: Set[str] = set()
    try:
        r = _session.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=15,
        )
        r.raise_for_status()
        for line in r.text.splitlines():
            parts = line.split(",")
            if parts:
                hostname = parts[0].strip().lower()
                if hostname.endswith(f".{domain}") or hostname == domain:
                    found.add(hostname)
    except Exception as e:
        raise RuntimeError(f"HackerTarget: {e}")
    return found


def _source_rapiddns(domain: str) -> Set[str]:
    """RapidDNS — free DNS database."""
    found: Set[str] = set()
    try:
        r = _session.get(
            f"https://rapiddns.io/subdomain/{domain}?full=1",
            timeout=15,
        )
        # Parse table from HTML
        for match in re.finditer(r'<td>([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')</td>', r.text):
            found.add(match.group(1).lower())
    except Exception as e:
        raise RuntimeError(f"RapidDNS: {e}")
    return found


def _source_bufferover(domain: str) -> Set[str]:
    """BufferOver.run — free DNS aggregator."""
    found: Set[str] = set()
    try:
        r = _session.get(
            f"https://tls.bufferover.run/dns?q=.{domain}",
            timeout=15,
        )
        r.raise_for_status()
        data = r.json()
        for entry in data.get("Results", []):
            parts = entry.split(",")
            for p in parts:
                p = p.strip().lower()
                if p.endswith(f".{domain}") or p == domain:
                    found.add(p)
    except Exception as e:
        raise RuntimeError(f"BufferOver: {e}")
    return found


def _source_threatcrowd(domain: str) -> Set[str]:
    """ThreatCrowd — free threat intel."""
    found: Set[str] = set()
    try:
        r = _session.get(
            "https://www.threatcrowd.org/searchApi/v2/domain/report/",
            params={"domain": domain},
            timeout=15,
        )
        r.raise_for_status()
        for sub in r.json().get("subdomains", []):
            sub = sub.strip().lower()
            if sub.endswith(f".{domain}") or sub == domain:
                found.add(sub)
    except Exception as e:
        raise RuntimeError(f"ThreatCrowd: {e}")
    return found


# ─────────────────────────────────────────────────────────────
#  AUTHENTICATED SOURCE FUNCTIONS
# ─────────────────────────────────────────────────────────────

def _source_shodan(domain: str) -> Set[str]:
    """Shodan — requires SHODAN_API_KEY."""
    found: Set[str] = set()
    key = settings.SHODAN_API_KEY
    if not key:
        raise RuntimeError("SHODAN_API_KEY not configured")
    try:
        r = _session.get(
            f"https://api.shodan.io/dns/domain/{domain}",
            params={"key": key},
            timeout=20,
        )
        r.raise_for_status()
        data = r.json()
        for sub in data.get("subdomains", []):
            full = f"{sub}.{domain}".lower()
            found.add(full)
    except Exception as e:
        raise RuntimeError(f"Shodan: {e}")
    return found


def _source_censys(domain: str) -> Set[str]:
    """Censys certificates — requires CENSYS_API_ID + CENSYS_API_SECRET."""
    found: Set[str] = set()
    api_id = settings.CENSYS_API_ID
    api_secret = settings.CENSYS_API_SECRET
    if not api_id or not api_secret:
        raise RuntimeError("CENSYS_API_ID/SECRET not configured")
    try:
        cursor = None
        for _ in range(5):  # max 5 pages
            params = {
                "q": f"parsed.names: {domain}",
                "fields": ["parsed.names"],
                "flatten": True,
            }
            if cursor:
                params["cursor"] = cursor
            r = _session.post(
                "https://search.censys.io/api/v2/certificates/search",
                json=params,
                auth=(api_id, api_secret),
                timeout=20,
            )
            r.raise_for_status()
            data = r.json()
            for hit in data.get("result", {}).get("hits", []):
                for name in hit.get("parsed.names", []):
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(f".{domain}") or name == domain:
                        found.add(name)
            cursor = data.get("result", {}).get("links", {}).get("next")
            if not cursor:
                break
    except Exception as e:
        raise RuntimeError(f"Censys: {e}")
    return found


def _source_zoomeye(domain: str) -> Set[str]:
    """ZoomEye — requires ZOOMEYE_API_KEY."""
    found: Set[str] = set()
    key = getattr(settings, "ZOOMEYE_API_KEY", None)
    if not key:
        raise RuntimeError("ZOOMEYE_API_KEY not configured")
    try:
        # ZoomEye v2 API — subdomain search
        headers = {"API-KEY": key}
        r = _session.get(
            "https://api.zoomeye.org/domain/search",
            params={"q": domain, "type": 1, "s": 100},  # type=1 = subdomains
            headers=headers,
            timeout=20,
        )
        r.raise_for_status()
        data = r.json()
        for item in data.get("list", []):
            name = item.get("name", "").lower().strip()
            if name.endswith(f".{domain}") or name == domain:
                found.add(name)
    except Exception as e:
        raise RuntimeError(f"ZoomEye: {e}")
    return found


def _source_securitytrails(domain: str) -> Set[str]:
    """SecurityTrails — requires SECURITYTRAILS_API_KEY."""
    found: Set[str] = set()
    key = getattr(settings, "SECURITYTRAILS_API_KEY", None)
    if not key:
        raise RuntimeError("SECURITYTRAILS_API_KEY not configured")
    try:
        headers = {"apikey": key}
        r = _session.get(
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
            params={"children_only": "false", "include_inactive": "false"},
            headers=headers,
            timeout=20,
        )
        r.raise_for_status()
        data = r.json()
        for sub in data.get("subdomains", []):
            full = f"{sub}.{domain}".lower()
            found.add(full)
    except Exception as e:
        raise RuntimeError(f"SecurityTrails: {e}")
    return found


def _source_virustotal(domain: str) -> Set[str]:
    """VirusTotal — requires VIRUSTOTAL_API_KEY."""
    found: Set[str] = set()
    key = getattr(settings, "VIRUSTOTAL_API_KEY", None)
    if not key:
        raise RuntimeError("VIRUSTOTAL_API_KEY not configured")
    try:
        headers = {"x-apikey": key}
        cursor = None
        for _ in range(10):  # max 10 pages × 40 = 400 subdomains
            params = {"limit": 40}
            if cursor:
                params["cursor"] = cursor
            r = _session.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains",
                params=params,
                headers=headers,
                timeout=20,
            )
            r.raise_for_status()
            data = r.json()
            for item in data.get("data", []):
                name = item.get("id", "").lower().strip()
                if name.endswith(f".{domain}") or name == domain:
                    found.add(name)
            cursor = data.get("meta", {}).get("cursor")
            if not cursor:
                break
    except Exception as e:
        raise RuntimeError(f"VirusTotal: {e}")
    return found


def _source_binaryedge(domain: str) -> Set[str]:
    """BinaryEdge — requires BINARYEDGE_API_KEY."""
    found: Set[str] = set()
    key = getattr(settings, "BINARYEDGE_API_KEY", None)
    if not key:
        raise RuntimeError("BINARYEDGE_API_KEY not configured")
    try:
        headers = {"X-Key": key}
        r = _session.get(
            f"https://api.binaryedge.io/v2/query/domains/subdomain/{domain}",
            params={"page": 1, "pagesize": 500},
            headers=headers,
            timeout=20,
        )
        r.raise_for_status()
        data = r.json()
        for event in data.get("events", []):
            name = event.lower().strip()
            if name.endswith(f".{domain}") or name == domain:
                found.add(name)
    except Exception as e:
        raise RuntimeError(f"BinaryEdge: {e}")
    return found


def _source_whoisxml(domain: str) -> Set[str]:
    """WhoisXML Subdomains API — requires WHOIS_XML_API_KEY."""
    found: Set[str] = set()
    key = settings.WHOIS_XML_API_KEY
    if not key:
        raise RuntimeError("WHOIS_XML_API_KEY not configured")
    try:
        r = _session.get(
            "https://subdomains.whoisxmlapi.com/api/v1",
            params={
                "apiKey": key,
                "domainName": domain,
                "outputFormat": "JSON",
            },
            timeout=20,
        )
        r.raise_for_status()
        data = r.json()
        for item in data.get("result", {}).get("records", []):
            name = item.get("domain", "").lower().strip()
            if name.endswith(f".{domain}") or name == domain:
                found.add(name)
    except Exception as e:
        raise RuntimeError(f"WhoisXML: {e}")
    return found


def _source_chaos(domain: str) -> Set[str]:
    """ProjectDiscovery Chaos — requires CHAOS_API_KEY."""
    found: Set[str] = set()
    key = getattr(settings, "CHAOS_API_KEY", None)
    if not key:
        raise RuntimeError("CHAOS_API_KEY not configured")
    try:
        headers = {"Authorization": key}
        r = _session.get(
            f"https://dns.projectdiscovery.io/dns/{domain}/subdomains",
            headers=headers,
            timeout=20,
        )
        r.raise_for_status()
        data = r.json()
        for sub in data.get("subdomains", []):
            full = f"{sub}.{domain}".lower()
            found.add(full)
    except Exception as e:
        raise RuntimeError(f"Chaos: {e}")
    return found


# ─────────────────────────────────────────────────────────────
#  ACTIVE — DNS brute-force
# ─────────────────────────────────────────────────────────────

def _resolve_one(sub_domain: str) -> Optional[str]:
    """Resolve a subdomain — returns the full hostname if it resolves."""
    try:
        socket.gethostbyname(sub_domain)
        return sub_domain
    except Exception:
        return None


def _source_bruteforce(domain: str, wordlist: Optional[List[str]] = None) -> Set[str]:
    """
    DNS brute-force using the built-in wordlist.
    Uses ThreadPoolExecutor for concurrent resolution.
    """
    found: Set[str] = set()
    words = wordlist or SUBDOMAIN_WORDLIST
    candidates = [f"{w}.{domain}" for w in words]

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
            futures = {ex.submit(_resolve_one, c): c for c in candidates}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.add(result.lower())
    except Exception as e:
        raise RuntimeError(f"DNS brute-force: {e}")
    return found


# ─────────────────────────────────────────────────────────────
#  SOURCE REGISTRY
#  Controls which sources run and in what order.
#  Passive sources always run. Keyed sources only run if
#  the corresponding key is present in settings.
# ─────────────────────────────────────────────────────────────

@dataclass
class SourceDef:
    name: str
    fn: Callable[[str], Set[str]]
    requires_key: Optional[str] = None  # settings attribute name
    passive: bool = True                # False = active (DNS brute-force)


ALL_SOURCES: List[SourceDef] = [
    # ── Free passive ─────────────────────────────────
    SourceDef("crt.sh",         _source_crtsh),
    SourceDef("AlienVault",     _source_alienvault),
    SourceDef("HackerTarget",   _source_hackertarget),
    SourceDef("RapidDNS",       _source_rapiddns),
    SourceDef("BufferOver",     _source_bufferover),
    SourceDef("ThreatCrowd",    _source_threatcrowd),

    # ── API-key authenticated ─────────────────────────
    SourceDef("Shodan",         _source_shodan,         "SHODAN_API_KEY"),
    SourceDef("Censys",         _source_censys,         "CENSYS_API_ID"),
    SourceDef("ZoomEye",        _source_zoomeye,        "ZOOMEYE_API_KEY"),
    SourceDef("SecurityTrails", _source_securitytrails, "SECURITYTRAILS_API_KEY"),
    SourceDef("VirusTotal",     _source_virustotal,     "VIRUSTOTAL_API_KEY"),
    SourceDef("BinaryEdge",     _source_binaryedge,     "BINARYEDGE_API_KEY"),
    SourceDef("WhoisXML",       _source_whoisxml,       "WHOIS_XML_API_KEY"),
    SourceDef("Chaos",          _source_chaos,          "CHAOS_API_KEY"),

    # ── Active DNS brute-force ────────────────────────
    SourceDef("DNS-Bruteforce", _source_bruteforce,     passive=False),
]


def _source_is_available(src: SourceDef) -> bool:
    """Check if a source can run (key present if needed)."""
    if src.requires_key:
        val = getattr(settings, src.requires_key, None)
        return bool(val)
    return True


# ─────────────────────────────────────────────────────────────
#  MAIN ENUMERATION ENTRY POINT
# ─────────────────────────────────────────────────────────────

def enumerate_subdomains(
    domain: str,
    include_bruteforce: bool = True,
    max_workers: int = 8,
) -> SubdomainResult:
    """
    Run all available subdomain sources concurrently for a domain.

    Returns SubdomainResult with:
      .subdomains     — deduplicated set of all discovered subdomains
      .source_stats   — {source_name: count_found}
      .errors         — {source_name: error_message}

    Sources with unconfigured API keys are skipped gracefully.
    DNS brute-force is run after passive sources complete.
    """
    result = SubdomainResult()
    domain = domain.lower().strip()

    # Determine which sources to run
    passive_sources = [
        s for s in ALL_SOURCES
        if s.passive and _source_is_available(s)
    ]
    active_sources = [
        s for s in ALL_SOURCES
        if not s.passive and include_bruteforce
    ]

    available = passive_sources + active_sources
    skipped = [s.name for s in ALL_SOURCES if not _source_is_available(s)]

    logger.info(f"[{domain}] Subdomain enum: {len(available)} sources active, "
                f"{len(skipped)} skipped (no key): {skipped}")

    # ── Run passive sources concurrently ─────────────
    def run_source(src: SourceDef) -> tuple:
        try:
            found = src.fn(domain)
            logger.info(f"  [{src.name}] → {len(found)} subdomains")
            return src.name, found, None
        except Exception as e:
            logger.warning(f"  [{src.name}] ✗ {e}")
            return src.name, set(), str(e)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(run_source, s) for s in passive_sources]
        for future in concurrent.futures.as_completed(futures):
            name, found, error = future.result()
            result.subdomains.update(found)
            result.source_stats[name] = len(found)
            if error:
                result.errors[name] = error

    # ── Run active DNS brute-force after passive ──────
    for src in active_sources:
        name, found, error = run_source(src)
        result.subdomains.update(found)
        result.source_stats[name] = len(found)
        if error:
            result.errors[name] = error

    # ── Validate: only keep subdomains that resolve ───
    # (already validated in bruteforce; passive sources
    #  sometimes return stale/inactive entries)
    logger.info(f"[{domain}] Validating {len(result.subdomains)} raw subdomains via DNS...")
    validated: Set[str] = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = {
            ex.submit(_resolve_one, sub): sub
            for sub in result.subdomains
        }
        for future in concurrent.futures.as_completed(futures):
            if future.result():
                validated.add(future.result())

    raw_count = len(result.subdomains)
    result.subdomains = validated
    logger.info(
        f"[{domain}] Enum complete: {raw_count} raw → {len(validated)} live "
        f"| sources: {result.source_stats}"
    )
    return result
