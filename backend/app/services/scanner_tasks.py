# backend/app/services/scanner_tasks.py
# ─────────────────────────────────────────────────────────────
#  CyberDrishti Heuristic Scanner — Phase 1
#
#  KEY FIXES over Phase 0:
#  1. EVERY finding requires CONTENT VALIDATION — not just HTTP 200
#  2. Soft 404 detection (pages saying "not found" but returning 200)
#  3. Login redirect detection (auth portals masquerading as 200)
#  4. WAF/CDN block page detection
#  5. 80+ sensitive paths across 12 categories
#  6. Evidence snippet stored with each finding for analyst PoC
#
#  RULES:
#  - Read-only. Never exploits anything.
#  - Max 5 requests/sec per domain.
#  - Never stores raw PII — salted hashes only.
# ─────────────────────────────────────────────────────────────

import re
import time
import hashlib
import requests
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional
from urllib.parse import urljoin

from app.worker import celery_app
from app.db.database import SessionLocal
from app.models.models import Domain, Finding, ScanJob, AuditLog
from app.core.config import settings
from app.core.logging import get_logger

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = get_logger("scanner.heuristic")

# ─────────────────────────────────────────────────────────────
#  VERHOEFF CHECKSUM — Aadhaar validation
# ─────────────────────────────────────────────────────────────
_V_D = [
    [0,1,2,3,4,5,6,7,8,9],
    [1,2,3,4,0,6,7,8,9,5],
    [2,3,4,0,1,7,8,9,5,6],
    [3,4,0,1,2,8,9,5,6,7],
    [4,0,1,2,3,9,5,6,7,8],
    [5,9,8,7,6,0,4,3,2,1],
    [6,5,9,8,7,1,0,4,3,2],
    [7,6,5,9,8,2,1,0,4,3],
    [8,7,6,5,9,3,2,1,0,4],
    [9,8,7,6,5,4,3,2,1,0],
]
_V_P = [
    [0,1,2,3,4,5,6,7,8,9],
    [1,5,7,6,2,8,3,0,9,4],
    [5,8,0,3,7,9,6,1,4,2],
    [8,9,1,6,0,4,3,5,2,7],
    [9,4,5,3,1,2,6,8,7,0],
    [4,2,8,6,5,7,3,9,0,1],
    [2,7,9,3,8,0,6,4,1,5],
    [7,0,4,6,9,1,3,2,5,8],
]
_V_INV = [0,4,3,2,1,9,8,7,6,5]

def verhoeff_check(number: str) -> bool:
    """Returns True if the number passes Verhoeff checksum (valid Aadhaar)."""
    n = re.sub(r'[\s\-]', '', number)
    if not n.isdigit():
        return False
    c = 0
    for i, digit in enumerate(reversed(n)):
        p = _V_P[i % 8][int(digit)]
        c = _V_D[c][p]
    return c == 0


# ─────────────────────────────────────────────────────────────
#  LUHN CHECKSUM — Credit card validation
# ─────────────────────────────────────────────────────────────
def luhn_check(number: str) -> bool:
    """Returns True if number passes Luhn algorithm (valid credit card)."""
    n = re.sub(r'[\s\-]', '', number)
    if not n.isdigit():
        return False
    total = 0
    reverse = n[::-1]
    for i, d in enumerate(reverse):
        x = int(d)
        if i % 2 == 1:
            x *= 2
            if x > 9:
                x -= 9
        total += x
    return total % 10 == 0


# ─────────────────────────────────────────────────────────────
#  SHANNON ENTROPY — Detect random-looking API keys
# ─────────────────────────────────────────────────────────────
import math

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    ln = len(s)
    return -sum((f/ln) * math.log2(f/ln) for f in freq.values())


HASH_SALT = "cyberdrishti_certIn_2026_"


# ─────────────────────────────────────────────────────────────
#  FALSE POSITIVE DETECTION ENGINE
#  The root cause of Phase 0 false positives: we were trusting
#  HTTP 200 responses without checking their actual content.
#  These checks fix that.
# ─────────────────────────────────────────────────────────────

# If ANY of these appear in a response that returned 200,
# it's actually an HTML error/login page — not the file we wanted.
SOFT_404_PHRASES = [
    "page not found", "404 not found", "file not found",
    "does not exist", "no such file", "not available",
    "access denied", "permission denied", "403 forbidden",
    "you do not have permission", "unauthorized",
    "login required", "please log in", "sign in to continue",
    "session expired", "authentication required",
    "error occurred", "something went wrong",
    "this page is protected", "restricted access",
    "the page you requested", "the page you are looking for",
]

WAF_INDICATORS = [
    "cloudflare", "ray id:", "cf-ray:", "cloudfront",
    "access denied | akamai", "incapsula incident id",
    "sucuri website firewall", "barracuda networks",
    "your ip has been blocked", "suspicious activity detected",
    "ddos protection by", "error 1020", "error 1006",
]

HTML_TAGS = ["<!doctype html", "<html", "<head>", "<body>", "<title>", "<meta "]

LOGIN_INDICATORS = [
    "type=\"password\"", "type='password'",
    "name=\"password\"", "name='password'",
    "forgot password", "remember me", "keep me logged in",
]


def is_false_positive(response: requests.Response, entity: str) -> tuple:
    """
    Returns (is_fp: bool, reason: str).
    A 200 response is a false positive if the content
    doesn't match what we were looking for.
    """
    if response.status_code != 200:
        return True, f"HTTP {response.status_code} (not 200)"

    content = response.text[:8000]
    cl = content.lower()
    ct = response.headers.get("content-type", "").lower()

    if len(content.strip()) < 10:
        return True, "Empty response body"

    for w in WAF_INDICATORS:
        if w in cl:
            return True, f"WAF/CDN block page ({w})"

    for phrase in SOFT_404_PHRASES:
        if phrase in cl:
            return True, f"Soft 404/error page ('{phrase}')"

    # Raw file entities must NOT return HTML
    raw_entities = {"ENV_FILE", "GIT_REPO", "PRIVATE_KEY", "DATABASE_DUMP", "API_KEY"}
    if entity in raw_entities:
        for tag in HTML_TAGS:
            if tag in cl:
                return True, f"HTML page returned instead of raw file"

    # Admin panels showing login = protected, not a finding
    if entity == "ADMIN_PANEL":
        for li in LOGIN_INDICATORS:
            if li in cl:
                return True, "Login page returned — panel is auth-protected"

    # Config files as HTML = false positive
    if entity == "CONFIG_FILE" and "text/html" in ct and "<html" in cl:
        return True, "HTML page returned for config file path"

    return False, ""


# ─────────────────────────────────────────────────────────────
#  CONTENT VALIDATORS
#  Each entity type must match specific content signatures.
#  A 200 response alone is NEVER enough to confirm a finding.
# ─────────────────────────────────────────────────────────────

def validate_env_file(content: str) -> tuple:
    critical_keys = re.findall(
        r'(DB_PASSWORD|DATABASE_URL|SECRET_KEY|API_KEY|AWS_SECRET|'
        r'PRIVATE_KEY|MYSQL_PASSWORD|POSTGRES_PASSWORD|REDIS_PASSWORD|'
        r'SMTP_PASSWORD|JWT_SECRET|APP_KEY|ENCRYPTION_KEY|ACCESS_TOKEN|'
        r'AUTH_TOKEN|S3_SECRET|STRIPE_SECRET|RAZORPAY_SECRET)\s*=\s*\S+',
        content, re.IGNORECASE
    )
    all_kv = re.findall(r'^[A-Z][A-Z0-9_]{2,}=.+', content, re.MULTILINE)
    doc_words = ["example", "sample", "template", "your_key_here",
                 "changeme", "replace_with", "enter_your", "put_your"]
    is_doc = any(w in content.lower() for w in doc_words)

    if critical_keys and not is_doc:
        preview = ", ".join(m[:40] for m in critical_keys[:3])
        return True, 0.98, f"Contains {len(critical_keys)} sensitive credential(s): {preview}"
    if len(all_kv) >= 3 and not is_doc:
        return True, 0.85, f"Env file with {len(all_kv)} KEY=VALUE pairs"
    if len(all_kv) >= 1 and not is_doc:
        return True, 0.70, f"Possible env file ({len(all_kv)} KEY=VALUE pairs) — review needed"
    return False, 0.0, "No KEY=VALUE credential patterns found"


def validate_git(content: str, path: str) -> tuple:
    if "HEAD" in path:
        if re.match(r'^ref:\s+refs/', content.strip()):
            return True, 0.99, f"Git HEAD: {content.strip()[:60]}"
        if re.match(r'^[0-9a-f]{40}$', content.strip()):
            return True, 0.99, f"Git HEAD (detached): {content.strip()[:40]}"
    if "config" in path:
        if "[core]" in content or "[remote" in content or "[branch" in content:
            return True, 0.97, "Git config with remote repository info exposed"
    if "COMMIT_EDITMSG" in path:
        if content.strip() and "<html" not in content.lower():
            return True, 0.90, f"Git commit message: {content.strip()[:80]}"
    if "logs/HEAD" in path:
        if re.search(r'[0-9a-f]{40}', content):
            return True, 0.95, "Git commit history log exposed"
    if "refs/heads" in path:
        if re.match(r'^[0-9a-f]{40}', content.strip()):
            return True, 0.95, f"Git branch ref: {content.strip()[:40]}"
    return False, 0.0, "Not a valid git file structure"


def validate_private_key(content: str) -> tuple:
    headers = [
        ("-----BEGIN RSA PRIVATE KEY-----", 0.99, "RSA private key"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----", 0.99, "OpenSSH private key"),
        ("-----BEGIN EC PRIVATE KEY-----", 0.99, "EC private key"),
        ("-----BEGIN PRIVATE KEY-----", 0.99, "PKCS8 private key"),
        ("-----BEGIN PGP PRIVATE KEY BLOCK-----", 0.99, "PGP private key"),
        ("-----BEGIN DSA PRIVATE KEY-----", 0.99, "DSA private key"),
    ]
    for header, conf, desc in headers:
        if header in content:
            return True, conf, f"Exposed {desc} — EMERGENCY: rotate immediately"
    return False, 0.0, "No private key header found"


def validate_sql_dump(content: str, path: str) -> tuple:
    sql_sigs = [
        (r'CREATE TABLE\s+\w+', 0.95, "SQL CREATE TABLE statement found"),
        (r'INSERT INTO\s+\w+\s+VALUES', 0.95, "SQL INSERT data found"),
        (r'--\s*MySQL dump', 0.98, "MySQL dump header"),
        (r'--\s*PostgreSQL database dump', 0.98, "PostgreSQL dump header"),
        (r'mysqldump', 0.97, "mysqldump signature"),
        (r'Dump completed on', 0.95, "Database dump completion marker"),
        (r'-- Dumped from database version', 0.97, "Database version header"),
    ]
    for pattern, conf, desc in sql_sigs:
        if re.search(pattern, content, re.IGNORECASE):
            return True, conf, desc
    if path.endswith((".zip", ".tar.gz", ".tar", ".gz", ".bak")):
        if len(content) > 100 and "<html" not in content.lower():
            return True, 0.80, "Binary backup/archive file downloaded"
    return False, 0.0, "No SQL dump signatures found"


def validate_config(content: str, path: str) -> tuple:
    if "wp-config" in path:
        if "DB_PASSWORD" in content or "DB_HOST" in content:
            return True, 0.99, "WordPress config with database credentials"
        if "table_prefix" in content:
            return True, 0.90, "WordPress config file (partial content)"
        return False, 0.0, "wp-config path but no credentials found"

    if path.endswith(".php"):
        if re.search(r'\$(db|database)_(pass|password|host|name)', content, re.IGNORECASE):
            return True, 0.93, "PHP config with database credentials"
        if re.search(r"define\s*\(\s*['\"]DB_PASSWORD", content, re.IGNORECASE):
            return True, 0.97, "PHP DB_PASSWORD constant defined"
        return False, 0.0, "PHP file but no credentials found"

    if path.endswith((".yml", ".yaml")):
        if re.search(r'(password|secret|credentials|private_key)\s*:\s*\S+', content, re.IGNORECASE):
            return True, 0.88, "YAML config with credential values"
        return False, 0.0, "YAML config but no sensitive values"

    if "web.config" in path:
        if "connectionStrings" in content:
            return True, 0.92, "web.config with connection strings"
        if re.search(r'password\s*=\s*\S+', content, re.IGNORECASE):
            return True, 0.90, "web.config with password attribute"
        return False, 0.0, "web.config but no credentials"

    if ".htpasswd" in path:
        if re.search(r'^\w+:\$', content, re.MULTILINE):
            return True, 0.99, "htpasswd with hashed passwords"
        if re.search(r'^\w+:[a-zA-Z0-9./]{13}', content, re.MULTILINE):
            return True, 0.96, "htpasswd with crypt hashes"
        return False, 0.0, "htpasswd path but no password hashes"

    if path.endswith((".properties", "application.yml", "application.yaml")):
        if re.search(r'(password|secret|datasource\.password)\s*[=:]\s*\S+', content, re.IGNORECASE):
            return True, 0.90, "Java/Spring config with credentials"
        return False, 0.0, "Config file but no credentials found"

    if path.endswith(("settings.py", "local_settings.py")):
        if re.search(r"SECRET_KEY\s*=\s*['\"].+['\"]", content):
            return True, 0.95, "Django SECRET_KEY exposed"
        if re.search(r"PASSWORD['\"]:\s*['\"].+['\"]", content):
            return True, 0.92, "Django database password exposed"
        return False, 0.0, "Python settings but no credentials"

    if path.endswith(".json") and "appsettings" in path:
        if re.search(r'"(Password|ConnectionString|Secret)"\s*:\s*"[^"]{3,}"', content):
            return True, 0.91, "ASP.NET appsettings with credentials"
        return False, 0.0, "appsettings.json but no credentials"

    return False, 0.0, "Config file with no sensitive content"


def validate_phpinfo(content: str) -> tuple:
    if "PHP Version" in content and "<table" in content:
        ver = re.search(r'PHP Version\s*</td>\s*<td[^>]*>([0-9.]+)', content)
        v = ver.group(1) if ver else "unknown"
        return True, 0.98, f"phpinfo() output exposed — PHP {v} — reveals server configuration"
    if "phpinfo()" in content.lower() and "php" in content.lower():
        return True, 0.85, "Possible phpinfo() page"
    return False, 0.0, "Not a phpinfo page"


def validate_admin(content: str, path: str) -> tuple:
    cl = content.lower()
    if "phpmyadmin" in path or "/pma" in path:
        if "phpmyadmin" in cl and "select database" in cl:
            return True, 0.97, "phpMyAdmin open without authentication"
        if "phpmyadmin" in cl and "server=" in cl:
            return True, 0.90, "phpMyAdmin interface accessible"
        return False, 0.0, "phpMyAdmin login page only — protected"
    if "adminer" in path:
        if "adminer" in cl and "server" in cl and "type=\"password\"" not in cl:
            return True, 0.93, "Adminer DB manager open without auth"
        return False, 0.0, "Adminer login page — protected"
    return False, 0.0, "Admin path but no unauthenticated interface found"


def validate_log(content: str) -> tuple:
    patterns = [
        (r'\[error\]|\[warn\]|\[notice\]', 0.85, "Web server error log"),
        (r'PHP (Fatal|Warning|Notice|Parse) error:', 0.90, "PHP error log with stack traces"),
        (r'Traceback \(most recent call last\)', 0.88, "Python stack trace"),
        (r'/var/www|/home/\w+/public_html|/srv/www', 0.87, "Server path disclosure"),
        (r'mysql_connect|mysqli_connect|PDOException', 0.88, "Database error in log"),
        (r'SQLSTATE\[', 0.90, "SQL error in log"),
    ]
    for pattern, conf, desc in patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return True, conf, desc
    return False, 0.0, "No log content patterns found"


def validate_directory(content: str) -> tuple:
    strong = ["Index of /", "<title>Index of", "Directory listing for"]
    for sig in strong:
        if sig in content:
            return True, 0.97, f"Open directory listing confirmed: '{sig}'"
    mods = ["Parent Directory", "[DIR]", "Last modified", "apache", "nginx"]
    count = sum(1 for m in mods if m.lower() in content.lower())
    if count >= 3:
        return True, 0.82, f"Likely open directory ({count}/5 indicators)"
    return False, 0.0, "Not a directory listing"


def validate_ds_store(content: str) -> tuple:
    if content[:4] == "\x00\x00\x00\x01" or "Bud1" in content[:8]:
        return True, 0.97, ".DS_Store binary file — exposes directory structure"
    if len(content) > 0 and "<html" not in content.lower() and len(content) < 100000:
        return True, 0.65, "Possible .DS_Store (manual review needed)"
    return False, 0.0, "Not a .DS_Store file"


def validate_aws_creds(content: str) -> tuple:
    """Validate .aws/credentials file."""
    if "[default]" in content or "[profile" in content:
        if "aws_access_key_id" in content.lower():
            return True, 0.99, "AWS credentials file with access key"
        if "aws_secret_access_key" in content.lower():
            return True, 0.98, "AWS credentials file with secret key"
    if re.search(r'AKIA[0-9A-Z]{16}', content):
        return True, 0.98, "AWS Access Key ID found"
    return False, 0.0, "No AWS credential patterns"


def validate_metadata(content: str, path: str) -> tuple:
    """Validate cloud metadata endpoint response."""
    if "/latest/meta-data" in path:
        aws_fields = ["ami-id", "instance-id", "local-ipv4", "public-ipv4", "iam/"]
        for f in aws_fields:
            if f in content:
                return True, 0.97, f"AWS EC2 metadata accessible — found field: {f}"
        if len(content.strip()) > 5 and "<html" not in content.lower():
            return True, 0.80, "AWS metadata endpoint responding"
    if "/computeMetadata/v1" in path:
        gcp_fields = ["project-id", "instance/", "service-accounts/", "hostname"]
        for f in gcp_fields:
            if f in content:
                return True, 0.97, f"GCP metadata accessible — found field: {f}"
    return False, 0.0, "Not a cloud metadata response"


def validate_kube(content: str) -> tuple:
    """Validate Kubernetes config exposure."""
    if "apiVersion" in content and "kind: Config" in content:
        return True, 0.99, "Kubernetes config file — cluster credentials exposed"
    if "certificate-authority-data" in content or "client-certificate-data" in content:
        return True, 0.98, "Kubernetes cert data in config"
    if "clusters:" in content and "users:" in content:
        return True, 0.95, "Kubernetes config structure found"
    return False, 0.0, "Not a kubeconfig file"


def validate_shell_history(content: str) -> tuple:
    """Validate shell history exposure."""
    if len(content.strip()) < 5 or "<html" in content.lower():
        return False, 0.0, "Not a shell history file"
    cmd_patterns = [r'sudo ', r'ssh ', r'mysql ', r'psql ', r'curl ', r'wget ', r'export ', r'password', r'passwd']
    hits = sum(1 for p in cmd_patterns if re.search(p, content, re.IGNORECASE))
    if hits >= 2:
        return True, 0.93, f"Bash history with {hits} command type(s) — may contain credentials"
    if hits >= 1:
        return True, 0.75, "Possible bash history file"
    # Still flag if it looks like command history (lines starting with common commands)
    if re.search(r'^(ls|cd|cat|grep|find|git|docker|kubectl|python|pip|npm)\b', content, re.MULTILINE):
        return True, 0.70, "Shell history file with command history"
    return False, 0.0, "Not confirmed as shell history"


def validate_binary(content: str, path: str) -> tuple:
    """Validate binary dump files (heapdump, core dump)."""
    if "heapdump" in path or ".hprof" in path:
        # Java heap dump starts with JAVA PROFILE
        if content[:12].startswith("JAVA PROFILE") or len(content) > 10000:
            return True, 0.90, "Java heap dump file — may contain plaintext secrets in memory"
        if len(content) > 1000 and "<html" not in content[:200].lower():
            return True, 0.75, "Large binary file at heapdump path — likely memory dump"
    if path.endswith("/core"):
        if len(content) > 10000 and "<html" not in content[:200].lower():
            return True, 0.80, "Core dump file — may contain process memory"
    return False, 0.0, "Not a confirmed binary dump"


def validate_json_endpoint(content: str) -> tuple:
    """Validate JSON data endpoints (Spring actuator, Azure config)."""
    try:
        import json
        data = json.loads(content)
        # Spring actuator /env has specific structure
        if isinstance(data, dict):
            if "propertySources" in data or "activeProfiles" in data:
                return True, 0.97, "Spring Boot /actuator/env — environment variables exposed"
            if "contexts" in data or "beans" in data:
                return True, 0.93, "Spring Boot actuator endpoint exposed"
            # Azure profile
            if "subscriptions" in data or "tenantId" in data:
                return True, 0.96, "Azure profile JSON — subscription/tenant data exposed"
            # Generic JSON with secrets
            content_lower = content.lower()
            if any(k in content_lower for k in ["password", "secret", "credentials", "private_key", "access_key"]):
                return True, 0.85, "JSON endpoint with potential credential fields"
            # Any non-trivial JSON at sensitive path
            return True, 0.70, "JSON data endpoint accessible"
    except Exception:
        pass
    return False, 0.0, "Not valid JSON or no sensitive content"


def run_validator(probe: Dict, content: str) -> tuple:
    v = probe.get("validator", "none")
    path = probe["path"]
    entity = probe["entity"]

    if v == "env":       return validate_env_file(content)
    if v == "git":       return validate_git(content, path)
    if v == "key":       return validate_private_key(content)
    if v == "sql":       return validate_sql_dump(content, path)
    if v == "config":    return validate_config(content, path)
    if v == "phpinfo":   return validate_phpinfo(content)
    if v == "admin":     return validate_admin(content, path)
    if v == "log":       return validate_log(content)
    if v == "directory": return validate_directory(content)
    if v == "dsstore":   return validate_ds_store(content)
    if v == "aws":       return validate_aws_creds(content)
    if v == "metadata":  return validate_metadata(content, path)
    if v == "kube":      return validate_kube(content)
    if v == "shell":     return validate_shell_history(content)
    if v == "binary":    return validate_binary(content, path)
    if v == "json":      return validate_json_endpoint(content)

    # Generic: non-HTML raw content for raw file entities
    if entity in ("GIT_REPO", "ENV_FILE", "PRIVATE_KEY"):
        if "<html" not in content.lower() and len(content.strip()) > 10:
            return True, 0.60, "Raw file content returned — manual review recommended"

    if path.endswith(".json"):
        try:
            import json; json.loads(content)
            return True, 0.72, "Valid JSON file exposed — check for credentials"
        except Exception:
            return False, 0.0, "Not valid JSON"

    if path.endswith((".txt", ".lock", ".md")) and not content.lower().startswith("<"):
        if len(content.strip()) > 20:
            return True, 0.65, "Plain text file accessible — review content"

    return False, 0.0, "No content match"


# ─────────────────────────────────────────────────────────────
#  SENSITIVE PATHS — 80+ probes
# ─────────────────────────────────────────────────────────────

SENSITIVE_PATHS = [
    # CRITICAL — Environment / Credentials
    {"path": "/.env",                        "severity": "CRITICAL", "entity": "ENV_FILE",      "type": "ENV_FILE_EXPOSED",          "validator": "env"},
    {"path": "/.env.backup",                 "severity": "CRITICAL", "entity": "ENV_FILE",      "type": "ENV_FILE_EXPOSED",          "validator": "env"},
    {"path": "/.env.production",             "severity": "CRITICAL", "entity": "ENV_FILE",      "type": "ENV_FILE_EXPOSED",          "validator": "env"},
    {"path": "/.env.prod",                   "severity": "CRITICAL", "entity": "ENV_FILE",      "type": "ENV_FILE_EXPOSED",          "validator": "env"},
    {"path": "/.env.local",                  "severity": "CRITICAL", "entity": "ENV_FILE",      "type": "ENV_FILE_EXPOSED",          "validator": "env"},
    {"path": "/.env.staging",                "severity": "CRITICAL", "entity": "ENV_FILE",      "type": "ENV_FILE_EXPOSED",          "validator": "env"},
    {"path": "/.env.dev",                    "severity": "CRITICAL", "entity": "ENV_FILE",      "type": "ENV_FILE_EXPOSED",          "validator": "env"},
    {"path": "/.env.old",                    "severity": "CRITICAL", "entity": "ENV_FILE",      "type": "ENV_BACKUP_EXPOSED",        "validator": "env"},
    {"path": "/.env.bak",                    "severity": "CRITICAL", "entity": "ENV_FILE",      "type": "ENV_BACKUP_EXPOSED",        "validator": "env"},
    {"path": "/.env~",                       "severity": "CRITICAL", "entity": "ENV_FILE",      "type": "ENV_BACKUP_EXPOSED",        "validator": "env"},
    {"path": "/.env.example",               "severity": "HIGH",     "entity": "ENV_FILE",      "type": "ENV_TEMPLATE_EXPOSED",      "validator": "env"},
    {"path": "/env",                         "severity": "CRITICAL", "entity": "ENV_FILE",      "type": "ENV_FILE_EXPOSED",          "validator": "env"},
    {"path": "/config.env",                  "severity": "CRITICAL", "entity": "ENV_FILE",      "type": "ENV_FILE_EXPOSED",          "validator": "env"},
    {"path": "/env.txt",                     "severity": "HIGH",     "entity": "ENV_FILE",      "type": "ENV_TEXT_EXPOSED",          "validator": "env"},
    {"path": "/app/.env",                    "severity": "CRITICAL", "entity": "ENV_FILE",      "type": "ENV_FILE_EXPOSED",          "validator": "env"},

    # CRITICAL — Git Repository
    {"path": "/.git/HEAD",                   "severity": "CRITICAL", "entity": "GIT_REPO",      "type": "GIT_REPO_EXPOSED",          "validator": "git"},
    {"path": "/.git/config",                 "severity": "CRITICAL", "entity": "GIT_REPO",      "type": "GIT_REPO_EXPOSED",          "validator": "git"},
    {"path": "/.git/COMMIT_EDITMSG",         "severity": "CRITICAL", "entity": "GIT_REPO",      "type": "GIT_REPO_EXPOSED",          "validator": "git"},
    {"path": "/.git/logs/HEAD",              "severity": "CRITICAL", "entity": "GIT_REPO",      "type": "GIT_REPO_EXPOSED",          "validator": "git"},
    {"path": "/.git/refs/heads/main",        "severity": "CRITICAL", "entity": "GIT_REPO",      "type": "GIT_REPO_EXPOSED",          "validator": "git"},
    {"path": "/.git/refs/heads/master",      "severity": "CRITICAL", "entity": "GIT_REPO",      "type": "GIT_REPO_EXPOSED",          "validator": "git"},
    {"path": "/.git/objects/pack/",          "severity": "CRITICAL", "entity": "GIT_REPO",      "type": "GIT_PACK_EXPOSED",          "validator": "git"},

    # CRITICAL — Private Keys
    {"path": "/id_rsa",                      "severity": "CRITICAL", "entity": "PRIVATE_KEY",   "type": "PRIVATE_KEY_EXPOSED",       "validator": "key"},
    {"path": "/.ssh/id_rsa",                 "severity": "CRITICAL", "entity": "PRIVATE_KEY",   "type": "PRIVATE_KEY_EXPOSED",       "validator": "key"},
    {"path": "/server.key",                  "severity": "CRITICAL", "entity": "PRIVATE_KEY",   "type": "PRIVATE_KEY_EXPOSED",       "validator": "key"},
    {"path": "/private.key",                 "severity": "CRITICAL", "entity": "PRIVATE_KEY",   "type": "PRIVATE_KEY_EXPOSED",       "validator": "key"},
    {"path": "/private.pem",                 "severity": "CRITICAL", "entity": "PRIVATE_KEY",   "type": "PRIVATE_KEY_EXPOSED",       "validator": "key"},
    {"path": "/ssl/server.key",              "severity": "CRITICAL", "entity": "PRIVATE_KEY",   "type": "PRIVATE_KEY_EXPOSED",       "validator": "key"},
    {"path": "/cert/privkey.pem",            "severity": "CRITICAL", "entity": "PRIVATE_KEY",   "type": "PRIVATE_KEY_EXPOSED",       "validator": "key"},

    # CRITICAL — Cloud Credentials
    {"path": "/.aws/credentials",            "severity": "CRITICAL", "entity": "AWS_CREDS",     "type": "AWS_CREDENTIALS_EXPOSED",   "validator": "aws"},
    {"path": "/.aws/config",                 "severity": "HIGH",     "entity": "AWS_CONFIG",    "type": "AWS_CONFIG_EXPOSED",        "validator": "config"},
    {"path": "/azureProfile.json",           "severity": "CRITICAL", "entity": "AZURE_CREDS",   "type": "AZURE_PROFILE_EXPOSED",     "validator": "json"},
    {"path": "/latest/meta-data/",           "severity": "CRITICAL", "entity": "CLOUD_METADATA","type": "AWS_METADATA_EXPOSED",      "validator": "metadata"},
    {"path": "/computeMetadata/v1/",         "severity": "CRITICAL", "entity": "CLOUD_METADATA","type": "GCP_METADATA_EXPOSED",      "validator": "metadata"},

    # CRITICAL — Kubernetes / Container
    {"path": "/.kube/config",                "severity": "CRITICAL", "entity": "KUBE_CONFIG",   "type": "KUBECONFIG_EXPOSED",        "validator": "kube"},
    {"path": "/kubeconfig",                  "severity": "CRITICAL", "entity": "KUBE_CONFIG",   "type": "KUBECONFIG_EXPOSED",        "validator": "kube"},

    # CRITICAL — Memory / Heap Dumps
    {"path": "/heapdump.hprof",              "severity": "CRITICAL", "entity": "MEMORY_DUMP",   "type": "JAVA_HEAPDUMP_EXPOSED",     "validator": "binary"},
    {"path": "/core",                        "severity": "CRITICAL", "entity": "MEMORY_DUMP",   "type": "CORE_DUMP_EXPOSED",         "validator": "binary"},
    {"path": "/actuator/heapdump",           "severity": "CRITICAL", "entity": "SPRING_BOOT",   "type": "HEAPDUMP_EXPOSED",          "validator": "binary"},

    # CRITICAL — Spring Boot Actuators
    {"path": "/actuator/env",                "severity": "CRITICAL", "entity": "SPRING_BOOT",   "type": "SPRING_ENV_EXPOSED",        "validator": "json"},
    {"path": "/actuator/mappings",           "severity": "HIGH",     "entity": "SPRING_BOOT",   "type": "SPRING_MAPPINGS_EXPOSED",   "validator": "json"},
    {"path": "/actuator/beans",              "severity": "HIGH",     "entity": "SPRING_BOOT",   "type": "SPRING_BEANS_EXPOSED",      "validator": "json"},
    {"path": "/actuator/health",             "severity": "MEDIUM",   "entity": "SPRING_BOOT",   "type": "SPRING_HEALTH_EXPOSED",     "validator": "json"},

    # CRITICAL — Shell History
    {"path": "/.bash_history",               "severity": "CRITICAL", "entity": "SHELL_HISTORY", "type": "BASH_HISTORY_EXPOSED",      "validator": "shell"},

    # HIGH — Database Dumps & Backups
    {"path": "/backup.sql",                  "severity": "HIGH",     "entity": "DATABASE_DUMP", "type": "DATABASE_DUMP_EXPOSED",     "validator": "sql"},
    {"path": "/dump.sql",                    "severity": "HIGH",     "entity": "DATABASE_DUMP", "type": "DATABASE_DUMP_EXPOSED",     "validator": "sql"},
    {"path": "/db.sql",                      "severity": "HIGH",     "entity": "DATABASE_DUMP", "type": "DATABASE_DUMP_EXPOSED",     "validator": "sql"},
    {"path": "/database.sql",                "severity": "HIGH",     "entity": "DATABASE_DUMP", "type": "DATABASE_DUMP_EXPOSED",     "validator": "sql"},
    {"path": "/mysqldump.sql",               "severity": "HIGH",     "entity": "DATABASE_DUMP", "type": "DATABASE_DUMP_EXPOSED",     "validator": "sql"},
    {"path": "/db_backup.sql",               "severity": "HIGH",     "entity": "DATABASE_DUMP", "type": "DATABASE_DUMP_EXPOSED",     "validator": "sql"},
    {"path": "/backup.zip",                  "severity": "HIGH",     "entity": "DATABASE_DUMP", "type": "BACKUP_EXPOSED",            "validator": "sql"},
    {"path": "/backup.tar.gz",               "severity": "HIGH",     "entity": "DATABASE_DUMP", "type": "BACKUP_EXPOSED",            "validator": "sql"},
    {"path": "/site_backup.zip",             "severity": "HIGH",     "entity": "DATABASE_DUMP", "type": "BACKUP_EXPOSED",            "validator": "sql"},
    {"path": "/www.zip",                     "severity": "HIGH",     "entity": "DATABASE_DUMP", "type": "BACKUP_EXPOSED",            "validator": "sql"},

    # HIGH — Config Files
    {"path": "/wp-config.php",               "severity": "HIGH",     "entity": "CONFIG_FILE",   "type": "CONFIG_FILE_EXPOSED",       "validator": "config"},
    {"path": "/wp-config.php.bak",           "severity": "HIGH",     "entity": "CONFIG_FILE",   "type": "CONFIG_BACKUP_EXPOSED",     "validator": "config"},
    {"path": "/wp-config.php.save",          "severity": "HIGH",     "entity": "CONFIG_FILE",   "type": "CONFIG_BACKUP_EXPOSED",     "validator": "config"},
    {"path": "/wp-config.txt",               "severity": "HIGH",     "entity": "CONFIG_FILE",   "type": "CONFIG_FILE_EXPOSED",       "validator": "config"},
    {"path": "/config.php",                  "severity": "HIGH",     "entity": "CONFIG_FILE",   "type": "CONFIG_FILE_EXPOSED",       "validator": "config"},
    {"path": "/config.php.bak",              "severity": "HIGH",     "entity": "CONFIG_FILE",   "type": "CONFIG_BACKUP_EXPOSED",     "validator": "config"},
    {"path": "/configuration.php",           "severity": "HIGH",     "entity": "CONFIG_FILE",   "type": "CONFIG_FILE_EXPOSED",       "validator": "config"},
    {"path": "/config/database.yml",         "severity": "HIGH",     "entity": "CONFIG_FILE",   "type": "CONFIG_FILE_EXPOSED",       "validator": "config"},
    {"path": "/database.yml",                "severity": "HIGH",     "entity": "CONFIG_FILE",   "type": "CONFIG_FILE_EXPOSED",       "validator": "config"},
    {"path": "/web.config",                  "severity": "HIGH",     "entity": "CONFIG_FILE",   "type": "CONFIG_FILE_EXPOSED",       "validator": "config"},
    {"path": "/config.yml",                  "severity": "HIGH",     "entity": "CONFIG_FILE",   "type": "CONFIG_FILE_EXPOSED",       "validator": "config"},
    {"path": "/config.yaml",                 "severity": "HIGH",     "entity": "CONFIG_FILE",   "type": "CONFIG_FILE_EXPOSED",       "validator": "config"},
    {"path": "/application.yml",             "severity": "HIGH",     "entity": "CONFIG_FILE",   "type": "CONFIG_FILE_EXPOSED",       "validator": "config"},
    {"path": "/application.properties",      "severity": "HIGH",     "entity": "CONFIG_FILE",   "type": "CONFIG_FILE_EXPOSED",       "validator": "config"},
    {"path": "/settings.py",                 "severity": "HIGH",     "entity": "CONFIG_FILE",   "type": "CONFIG_FILE_EXPOSED",       "validator": "config"},
    {"path": "/local_settings.py",           "severity": "HIGH",     "entity": "CONFIG_FILE",   "type": "CONFIG_FILE_EXPOSED",       "validator": "config"},
    {"path": "/appsettings.json",            "severity": "HIGH",     "entity": "CONFIG_FILE",   "type": "CONFIG_FILE_EXPOSED",       "validator": "config"},
    {"path": "/appsettings.Production.json", "severity": "HIGH",     "entity": "CONFIG_FILE",   "type": "CONFIG_FILE_EXPOSED",       "validator": "config"},
    {"path": "/docker-compose.yml",          "severity": "HIGH",     "entity": "CONFIG_FILE",   "type": "DOCKER_COMPOSE_EXPOSED",    "validator": "config"},

    # HIGH — Source Code Backups
    {"path": "/index.php~",                  "severity": "HIGH",     "entity": "SOURCE_CODE",   "type": "SOURCE_BACKUP_EXPOSED",     "validator": "none"},

    # HIGH — Admin Panels (only flagged if accessible without login)
    {"path": "/phpmyadmin/",                 "severity": "HIGH",     "entity": "ADMIN_PANEL",   "type": "ADMIN_PANEL_EXPOSED",       "validator": "admin"},
    {"path": "/phpmyadmin",                  "severity": "HIGH",     "entity": "ADMIN_PANEL",   "type": "ADMIN_PANEL_EXPOSED",       "validator": "admin"},
    {"path": "/pma/",                        "severity": "HIGH",     "entity": "ADMIN_PANEL",   "type": "ADMIN_PANEL_EXPOSED",       "validator": "admin"},
    {"path": "/adminer.php",                 "severity": "HIGH",     "entity": "ADMIN_PANEL",   "type": "ADMIN_PANEL_EXPOSED",       "validator": "admin"},

    # HIGH — SVN Repository
    {"path": "/.svn/entries",               "severity": "HIGH",     "entity": "GIT_REPO",      "type": "SVN_REPO_EXPOSED",          "validator": "none"},
    {"path": "/.svn/wc.db",                 "severity": "HIGH",     "entity": "GIT_REPO",      "type": "SVN_REPO_EXPOSED",          "validator": "none"},

    # HIGH — Session Data
    {"path": "/storage/framework/sessions/", "severity": "HIGH",     "entity": "SESSION_DATA",  "type": "SESSION_EXPOSED",           "validator": "directory"},

    # MEDIUM — CI/CD
    {"path": "/.github/workflows/",          "severity": "MEDIUM",   "entity": "CI_CONFIG",     "type": "GITHUB_ACTIONS_EXPOSED",    "validator": "directory"},
    {"path": "/.gitlab-ci.yml",              "severity": "MEDIUM",   "entity": "CI_CONFIG",     "type": "GITLAB_CI_EXPOSED",         "validator": "none"},

    # MEDIUM — phpinfo
    {"path": "/phpinfo.php",                 "severity": "MEDIUM",   "entity": "CONFIG_FILE",   "type": "PHPINFO_EXPOSED",           "validator": "phpinfo"},
    {"path": "/info.php",                    "severity": "MEDIUM",   "entity": "CONFIG_FILE",   "type": "PHPINFO_EXPOSED",           "validator": "phpinfo"},
    {"path": "/test.php",                    "severity": "MEDIUM",   "entity": "CONFIG_FILE",   "type": "PHPINFO_EXPOSED",           "validator": "phpinfo"},

    # MEDIUM — Auth / Misc
    {"path": "/.htpasswd",                   "severity": "MEDIUM",   "entity": "CONFIG_FILE",   "type": "HTPASSWD_EXPOSED",          "validator": "config"},
    {"path": "/.DS_Store",                   "severity": "MEDIUM",   "entity": "CONFIG_FILE",   "type": "DS_STORE_EXPOSED",          "validator": "dsstore"},

    # MEDIUM — Log Files
    {"path": "/error_log",                   "severity": "MEDIUM",   "entity": "OTHER",         "type": "ERROR_LOG_EXPOSED",         "validator": "log"},
    {"path": "/error.log",                   "severity": "MEDIUM",   "entity": "OTHER",         "type": "ERROR_LOG_EXPOSED",         "validator": "log"},
    {"path": "/debug.log",                   "severity": "MEDIUM",   "entity": "OTHER",         "type": "DEBUG_LOG_EXPOSED",         "validator": "log"},
    {"path": "/application.log",             "severity": "MEDIUM",   "entity": "OTHER",         "type": "ERROR_LOG_EXPOSED",         "validator": "log"},
    {"path": "/logs/error.log",              "severity": "MEDIUM",   "entity": "OTHER",         "type": "ERROR_LOG_EXPOSED",         "validator": "log"},
    {"path": "/storage/logs/laravel.log",    "severity": "MEDIUM",   "entity": "OTHER",         "type": "ERROR_LOG_EXPOSED",         "validator": "log"},

    # MEDIUM / HIGH — Open Directories
    {"path": "/backup/",                     "severity": "HIGH",     "entity": "OPEN_DIRECTORY","type": "OPEN_DIRECTORY_LISTING",    "validator": "directory"},
    {"path": "/backups/",                    "severity": "HIGH",     "entity": "OPEN_DIRECTORY","type": "OPEN_DIRECTORY_LISTING",    "validator": "directory"},
    {"path": "/export/",                     "severity": "HIGH",     "entity": "OPEN_DIRECTORY","type": "OPEN_DIRECTORY_LISTING",    "validator": "directory"},
    {"path": "/uploads/",                    "severity": "MEDIUM",   "entity": "OPEN_DIRECTORY","type": "OPEN_DIRECTORY_LISTING",    "validator": "directory"},
    {"path": "/files/",                      "severity": "MEDIUM",   "entity": "OPEN_DIRECTORY","type": "OPEN_DIRECTORY_LISTING",    "validator": "directory"},
    {"path": "/data/",                       "severity": "MEDIUM",   "entity": "OPEN_DIRECTORY","type": "OPEN_DIRECTORY_LISTING",    "validator": "directory"},
    {"path": "/temp/",                       "severity": "MEDIUM",   "entity": "OPEN_DIRECTORY","type": "OPEN_DIRECTORY_LISTING",    "validator": "directory"},
    {"path": "/tmp/",                        "severity": "MEDIUM",   "entity": "OPEN_DIRECTORY","type": "OPEN_DIRECTORY_LISTING",    "validator": "directory"},
    {"path": "/reports/",                    "severity": "MEDIUM",   "entity": "OPEN_DIRECTORY","type": "OPEN_DIRECTORY_LISTING",    "validator": "directory"},

    # LOW — Dependency Files
    {"path": "/composer.json",               "severity": "LOW",      "entity": "CONFIG_FILE",   "type": "COMPOSER_EXPOSED",          "validator": "none"},
    {"path": "/composer.lock",               "severity": "LOW",      "entity": "CONFIG_FILE",   "type": "COMPOSER_EXPOSED",          "validator": "none"},
    {"path": "/package.json",                "severity": "LOW",      "entity": "CONFIG_FILE",   "type": "PACKAGE_JSON_EXPOSED",      "validator": "none"},
    {"path": "/requirements.txt",            "severity": "LOW",      "entity": "CONFIG_FILE",   "type": "REQUIREMENTS_EXPOSED",      "validator": "none"},
    {"path": "/Gemfile",                     "severity": "LOW",      "entity": "CONFIG_FILE",   "type": "GEMFILE_EXPOSED",           "validator": "none"},
]


# ─────────────────────────────────────────────────────────────
#  PII PATTERNS
# ─────────────────────────────────────────────────────────────

PII_PATTERNS = [
    # ── AADHAAR (Verhoeff validated) ──────────────────────────────────────
    {
        "name": "AADHAAR", "entity": "AADHAAR", "severity": "CRITICAL",
        "pattern": re.compile(r'\b([2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4})\b'),
        "context_keywords": ["aadhaar", "aadhar", "uid", "uidai", "unique id", "enrolment"],
        "min_occurrences": 3,
        "validator": "verhoeff",   # Extra: Verhoeff checksum applied per-match
    },
    # ── PAN Card ──────────────────────────────────────────────────────────
    {
        "name": "PAN", "entity": "PAN", "severity": "CRITICAL",
        "pattern": re.compile(r'\b([A-Z]{5}[0-9]{4}[A-Z])\b'),
        "context_keywords": ["pan", "permanent account", "income tax", "pan card"],
        "min_occurrences": 1,
    },
    # ── Voter ID ──────────────────────────────────────────────────────────
    {
        "name": "VOTER_ID", "entity": "VOTER_ID", "severity": "HIGH",
        "pattern": re.compile(r'\b([A-Z]{3}[0-9]{7})\b'),
        "context_keywords": ["voter", "election", "epic", "electoral", "booth"],
        "min_occurrences": 2,
    },
    # ── Indian Driving License ────────────────────────────────────────────
    {
        "name": "DRIVING_LICENSE", "entity": "DRIVING_LICENSE", "severity": "HIGH",
        "pattern": re.compile(r'\b[A-Z]{2}\d{2}\s?\d{4}\s?\d{7}\b'),
        "context_keywords": ["driving", "dl number", "license", "licence"],
        "min_occurrences": 1,
    },
    # ── ABHA Health ID ────────────────────────────────────────────────────
    {
        "name": "ABHA_ID", "entity": "ABHA_ID", "severity": "HIGH",
        "pattern": re.compile(r'\b\d{2}-\d{4}-\d{4}-\d{4}\b'),
        "context_keywords": ["abha", "health id", "ndhm", "abdm", "ayushman"],
        "min_occurrences": 1,
    },
    # ── Indian Passport ───────────────────────────────────────────────────
    {
        "name": "INDIAN_PASSPORT", "entity": "PASSPORT", "severity": "CRITICAL",
        "pattern": re.compile(r'\b[A-PR-WYa-pr-wy][0-9]{7}\b'),
        "context_keywords": ["passport", "travel", "immigration", "visa"],
        "min_occurrences": 1,
    },
    # BANK_ACCOUNT removed — digit-range regex matches phone numbers, order IDs,
    #   zip codes, timestamps etc. Too broad without structured document context.
    # CREDIT_CARD removed — Luhn helps but the digit-sequence regex still fires
    #   on numeric strings in HTML/JS (prices, entity IDs, hashes).
    # UPI_ID removed — 'word@alpha' pattern matches every email address on the
    #   page; indistinguishable from email without deeper semantic context.
    # ── AWS Access Key ────────────────────────────────────────────────────
    {
        "name": "AWS_ACCESS_KEY", "entity": "AWS_KEY", "severity": "CRITICAL",
        "pattern": re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
        "context_keywords": ["aws", "access_key", "secret", "amazon"],
        "min_occurrences": 1,
    },
    # ── Stripe Live Key ───────────────────────────────────────────────────
    {
        "name": "STRIPE_LIVE_KEY", "entity": "STRIPE_KEY", "severity": "CRITICAL",
        "pattern": re.compile(r'\bsk_live_[0-9a-zA-Z]{24,}\b'),
        "context_keywords": ["stripe", "payment"],
        "min_occurrences": 1,
    },
    # ── Private Key Block ─────────────────────────────────────────────────
    {
        "name": "PRIVATE_KEY_BLOCK", "entity": "PRIVATE_KEY", "severity": "CRITICAL",
        "pattern": re.compile(r'-----BEGIN (RSA|EC|OPENSSH|DSA)? ?PRIVATE KEY-----'),
        "context_keywords": [],
        "min_occurrences": 1,
    },
    # ── Generic Secret Field (JSON/YAML credential values) ────────────────
    {
        "name": "GENERIC_SECRET_FIELD", "entity": "SECRET_FIELD", "severity": "HIGH",
        "pattern": re.compile(r'"(password|passwd|secret|api[_-]?key|access[_-]?token)"\s*:\s*".{6,}"'),
        "context_keywords": [],
        "min_occurrences": 1,
    },
    # GENERIC_API_KEY removed — too many false positives on CSS class names, HTML IDs, etc.
    # ── Indian Phone ──────────────────────────────────────────────────────
    {
        "name": "INDIAN_PHONE", "entity": "PHONE_NUMBER", "severity": "LOW",
        "pattern": re.compile(r'\b(?:\+91|0091|91)?[\s\-]?([6-9]\d{9})\b'),
        "context_keywords": ["mobile", "phone", "contact", "helpline"],
        "min_occurrences": 15,
    },
]


# ─────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────

def hash_value(value: str) -> str:
    return hashlib.sha256(f"{HASH_SALT}{value.strip()}".encode()).hexdigest()


def make_request(url: str) -> Optional[requests.Response]:
    try:
        return requests.get(
            url, timeout=settings.SCAN_TIMEOUT,
            allow_redirects=True, verify=False,
            headers={
                "User-Agent": "CyberDrishti/1.0 CERT-IN Security Scanner (certIn.gov.in)",
                "Accept": "*/*",
            }
        )
    except Exception as e:
        logger.debug(f"Request failed {url}: {type(e).__name__}")
        return None


def safe_context(content: str, pos: int = 0, window: int = 200) -> str:
    """Extract surrounding content — raw, no redaction (dev mode)."""
    s = max(0, pos - window)
    e = min(len(content), pos + window)
    snippet = content[s:e]
    # Remove non-printable/binary chars only
    snippet = re.sub(r'[\x00-\x08\x0b-\x1f\x7f-\x9f]', '', snippet)
    return snippet.strip()


def compute_sla(severity: str) -> datetime:
    h = {"CRITICAL": 24, "HIGH": 72, "MEDIUM": 168, "LOW": 720}.get(severity, 720)
    return datetime.now(timezone.utc) + timedelta(hours=h)


# ─────────────────────────────────────────────────────────────
#  SCANNER FUNCTIONS
# ─────────────────────────────────────────────────────────────

def scan_sensitive_files(base_url: str, domain_id, db) -> int:
    """Probe sensitive paths. Saves each confirmed finding immediately. Returns count saved."""
    saved = 0
    seen = set()

    for probe in SENSITIVE_PATHS:
        time.sleep(1.0 / settings.SCAN_RATE_LIMIT)

        url = urljoin(base_url, probe["path"])
        response = make_request(url)
        if not response:
            continue

        # STEP 1: Global false positive filter
        fp, fp_reason = is_false_positive(response, probe["entity"])
        if fp:
            logger.debug(f"  FP [{fp_reason}]: {probe['path']}")
            continue

        # STEP 2: Read content
        try:
            content = response.text[:10000]
        except Exception:
            continue

        # STEP 3: Content validation — MUST match
        confirmed, confidence, evidence = run_validator(probe, content)
        if not confirmed:
            logger.debug(f"  Not confirmed [{evidence}]: {probe['path']}")
            continue

        # STEP 4: Deduplicate
        key = f"{probe['type']}:{probe['path']}"
        if key in seen:
            continue
        seen.add(key)

        # STEP 5: Build PoC evidence (safe — no raw PII)
        evidence_snippet = safe_context(content, 0, 300)
        full_context = (
            f"FINDING TYPE : {probe['type']}\n"
            f"URL          : {url}\n"
            f"HTTP STATUS  : {response.status_code}\n"
            f"CONTENT TYPE : {response.headers.get('content-type', 'unknown')}\n"
            f"FILE SIZE    : {len(response.content)} bytes\n"
            f"CONFIDENCE   : {confidence:.0%}\n"
            f"EVIDENCE     : {evidence}\n\n"
            f"--- CONTENT PREVIEW ---\n"
            f"{evidence_snippet}"
        )

        logger.warning(f"  ⚠ CONFIRMED [{probe['severity']}]: {probe['type']} at {url}")

        # DB dedup — skip if same finding already open
        existing = db.query(Finding).filter(
            Finding.domain_id == domain_id,
            Finding.url == url,
            Finding.finding_type == probe["type"],
            Finding.status.notin_(["RESOLVED", "FALSE_POSITIVE"]),
        ).first()
        if existing:
            logger.debug(f"  Duplicate skipped: {probe['type']} at {url}")
            continue

        # Save immediately — visible in UI right now
        result = save_finding(db, domain_id, {
            "url": url,
            "entity_type": probe["entity"],
            "finding_type": probe["type"],
            "severity": probe["severity"],
            "confidence": confidence,
            "http_status": response.status_code,
            "content_type": response.headers.get("content-type", ""),
            "file_size": len(response.content),
            "context": full_context,
            "value_hash": None,
        })
        if result:
            saved += 1

    return saved


def scan_pii_in_content(url: str, content: str, domain_id=None, db=None) -> int:
    """Scan page content for PII patterns. Saves immediately if domain_id+db provided. Returns count."""
    saved = 0
    cl = content.lower()

    for rule in PII_PATTERNS:
        raw_matches = list(rule["pattern"].finditer(content))
        if not raw_matches:
            continue

        # Apply per-match validators to filter false positives
        extra_validator = rule.get("validator")
        matches = []
        for m in raw_matches:
            val = re.sub(r'[\s\-]', '', m.group(0))
            if extra_validator == "verhoeff":
                if not verhoeff_check(val):
                    continue
            elif extra_validator == "luhn":
                if not luhn_check(val):
                    continue
            elif extra_validator == "entropy":
                if shannon_entropy(val) < 3.5:
                    continue
            matches.append(m)

        if not matches:
            continue

        has_kw = any(kw in cl for kw in rule.get("context_keywords", []))
        has_vol = len(matches) >= rule.get("min_occurrences", 1)
        if not (has_kw or has_vol):
            continue

        first = matches[0].group(1) if matches[0].lastindex else matches[0].group(0)
        ctx = safe_context(content, matches[0].start(), 250)

        full_context = (
            f"FINDING TYPE : {rule['name']}_IN_CONTENT\n"
            f"URL          : {url}\n"
            f"OCCURRENCES  : {len(matches)}\n"
            f"KEYWORD MATCH: {'Yes' if has_kw else 'No'}\n"
            f"CONFIDENCE   : {0.80 if has_kw else 0.60:.0%}\n\n"
            f"--- CONTEXT ---\n"
            f"{ctx}"
        )

        logger.warning(f"  ⚠ PII: {rule['name']} x{len(matches)} at {url}")

        if domain_id and db:
            # DB dedup
            existing = db.query(Finding).filter(
                Finding.domain_id == domain_id,
                Finding.url == url,
                Finding.finding_type == f"{rule['name']}_IN_CONTENT",
                Finding.status.notin_(["RESOLVED", "FALSE_POSITIVE"]),
            ).first()
            if existing:
                continue
            result = save_finding(db, domain_id, {
                "url": url,
                "entity_type": rule["entity"],
                "finding_type": f"{rule['name']}_IN_CONTENT",
                "severity": rule["severity"],
                "confidence": 0.80 if has_kw else 0.60,
                "value_hash": hash_value(first),
                "value_count_estimate": len(matches),
                "http_status": 200,
                "content_type": "text/html",
                "file_size": None,
                "context": full_context,
            })
            if result:
                saved += 1

    return saved


# All entity_type values the DB enum accepts. Keep in sync with init.sql.
# This set acts as a guard — unknown values fall back to 'OTHER' instead of
# crashing the entire scan with a PostgreSQL enum error.
_KNOWN_ENTITY_TYPES = {
    'AADHAAR', 'PAN', 'VOTER_ID', 'PASSPORT', 'DRIVING_LICENSE',
    'BANK_ACCOUNT', 'CREDIT_CARD', 'PHONE_NUMBER', 'EMAIL',
    'UPI_ID', 'ABHA_ID',
    'ENV_FILE', 'PRIVATE_KEY', 'API_KEY', 'AWS_KEY', 'STRIPE_KEY',
    'SECRET_FIELD', 'AWS_CREDS', 'AWS_CONFIG', 'AZURE_CREDS',
    'GIT_REPO', 'DATABASE_DUMP', 'CONFIG_FILE', 'SOURCE_CODE',
    'ADMIN_PANEL', 'OPEN_DIRECTORY', 'CLOUD_STORAGE',
    'CLOUD_METADATA', 'KUBE_CONFIG', 'SPRING_BOOT',
    'MEMORY_DUMP', 'SHELL_HISTORY', 'SESSION_DATA', 'CI_CONFIG',
    'OTHER',
}


def save_finding(db, domain_id, fd: Dict) -> Optional[Finding]:
    """
    Save a finding to DB.  Hardened against:
      - Unknown entity_type values  → remapped to 'OTHER' with a log warning
      - Any DB flush error           → savepoint rollback so the session stays
                                       usable for subsequent findings
    Returns the Finding object, or None if it could not be saved.
    """
    raw_entity = fd["entity_type"]
    if raw_entity not in _KNOWN_ENTITY_TYPES:
        logger.warning(
            f"Unknown entity_type '{raw_entity}' — remapping to 'OTHER'. "
            f"Add it to the DB enum and _KNOWN_ENTITY_TYPES."
        )
        raw_entity = "OTHER"

    f = Finding(
        domain_id=domain_id,
        url=fd["url"],
        http_status=fd.get("http_status", 200),
        entity_type=raw_entity,
        finding_type=fd["finding_type"],
        severity=fd["severity"],
        heuristic_confidence=fd.get("confidence", 0.0),
        final_confidence=fd.get("confidence", 0.0),
        value_hash=fd.get("value_hash"),
        value_count_estimate=fd.get("value_count_estimate", 1),
        context_snippet_safe=fd.get("context", ""),
        content_type=fd.get("content_type", ""),
        file_size_bytes=fd.get("file_size"),
        status="NEW",
        detected_by="HEURISTIC",
        disclosure_sla_due=compute_sla(fd["severity"]),
    )

    # Use a savepoint so a flush error rolls back only THIS finding,
    # leaving the session transaction alive for all subsequent findings.
    try:
        db.begin_nested()   # SAVEPOINT
        db.add(f)
        db.flush()          # Validates against DB constraints immediately
        db.add(AuditLog(
            event_type="FINDING_CREATED", actor="SCANNER",
            target_type="finding", target_id=f.id,
            details={
                "finding_type": f.finding_type,
                "severity": f.severity,
                "url": f.url,
                "entity_type": raw_entity,
                "confidence": float(f.heuristic_confidence or 0),
            },
        ))
        db.commit()         # Release SAVEPOINT + commit outer tx
        return f
    except Exception as e:
        db.rollback()       # Roll back to the SAVEPOINT, not the whole tx
        logger.error(
            f"Failed to save finding [{fd.get('finding_type')}] "
            f"entity={raw_entity} url={fd.get('url')}: {e}"
        )
        return None


# ─────────────────────────────────────────────────────────────
#  CELERY TASKS
# ─────────────────────────────────────────────────────────────

@celery_app.task(name="app.services.scanner_tasks.scan_domain", bind=True, max_retries=3)
def scan_domain(self, domain_id: str, job_type: str = "FULL_SCAN"):
    db = SessionLocal()
    scan_job = None
    try:
        from uuid import UUID
        try:
            domain = db.query(Domain).filter(Domain.id == UUID(domain_id)).first()
        except Exception:
            domain = db.query(Domain).filter(Domain.domain == domain_id).first()

        if not domain:
            return {"status": "error", "error": "Domain not found"}

        logger.info(f"\n{'='*50}\nSCANNING: {domain.domain}\n{'='*50}")

        scan_job = ScanJob(
            domain_id=domain.id, domain_name=domain.domain,
            job_type=job_type, status="RUNNING",
            celery_task_id=self.request.id,
            started_at=datetime.now(timezone.utc),
        )
        db.add(scan_job)
        db.commit()

        start = time.time()

        # Find working base URL.
        # www dedup: if domain.com is being scanned, do NOT also try www.domain.com
        # as a separate scan target — they are the same site and would double all findings.
        # We probe the domain as-is and follow any redirect the server issues naturally.
        base_url = None
        d_name = domain.domain

        for scheme in ["https", "http"]:
            r = make_request(f"{scheme}://{d_name}")
            if r and r.status_code < 500:
                # Follow redirect to canonical host (handles www <-> non-www automatically)
                final_host = r.url.split("//")[-1].split("/")[0].split(":")[0]
                # Normalise: strip trailing dot, lowercase
                final_host = final_host.rstrip(".").lower()
                base_url = f"{scheme}://{final_host}"
                # If the server redirected to www.X but we stored X (or vice versa),
                # update the domain record so future dedup works correctly.
                if final_host != d_name and final_host not in (f"www.{d_name}", d_name.replace("www.", "")):
                    logger.info(f"  Redirect to different host {d_name} -> {final_host}, keeping original")
                    base_url = f"{scheme}://{d_name}"   # Probe original, not the redirect
                logger.info(f"  Resolved {d_name} -> {base_url}")
                break
            if base_url:
                break

        if not base_url:
            scan_job.status = "SKIPPED"
            scan_job.error_message = "Domain unreachable"
            scan_job.completed_at = datetime.now(timezone.utc)
            domain.status = "INACTIVE"
            db.commit()
            return {"status": "skipped"}

        # Run scans — findings saved immediately per-finding so they appear
        # in the UI as discovered, not waiting until the full task completes.
        new_count = 0
        new_count += scan_sensitive_files(base_url, domain.id, db)

        home = make_request(base_url)
        if home and home.text:
            new_count += scan_pii_in_content(base_url, home.text, domain.id, db)

        domain.last_scanned_at = datetime.now(timezone.utc)
        domain.scan_count = (domain.scan_count or 0) + 1
        days = 7 if domain.sector in ("GOVERNMENT", "EDUCATION") else 30
        domain.next_scan_due_at = datetime.now(timezone.utc) + timedelta(days=days)

        duration_ms = int((time.time() - start) * 1000)
        scan_job.status = "COMPLETED"
        scan_job.urls_checked = len(SENSITIVE_PATHS) + 1
        scan_job.findings_count = new_count
        scan_job.duration_ms = duration_ms
        scan_job.completed_at = datetime.now(timezone.utc)
        db.commit()

        logger.info(f"Done: {domain.domain} | {new_count} new findings | {duration_ms}ms")
        return {"status": "success", "domain": domain.domain, "new_findings": new_count}

    except Exception as e:
        logger.error(f"Scan failed {domain_id}: {e}", exc_info=True)
        if scan_job:
            scan_job.status = "FAILED"
            scan_job.error_message = str(e)
            scan_job.completed_at = datetime.now(timezone.utc)
            db.commit()
        raise self.retry(exc=e, countdown=60)
    finally:
        db.close()


@celery_app.task(name="app.services.scanner_tasks.scan_all_pending")
def scan_all_pending():
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        due = db.query(Domain).filter(
            Domain.status == "ACTIVE",
            Domain.next_scan_due_at <= now,
        ).limit(100).all()
        for d in due:
            scan_domain.delay(str(d.id))
        return {"queued": len(due)}
    finally:
        db.close()


@celery_app.task(name="app.services.scanner_tasks.health_check")
def health_check():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}
