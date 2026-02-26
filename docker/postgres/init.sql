-- ─────────────────────────────────────────────────────────────
--  CyberDrishti — Database Schema
--  PostgreSQL 15
--  IMPORTANT: No column in any table stores raw PII.
--             Only salted hashes + metadata are permitted.
-- ─────────────────────────────────────────────────────────────

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─────────────────────────────────────────────────────────────
--  ENUM TYPES
-- ─────────────────────────────────────────────────────────────

CREATE TYPE severity_level AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO');
CREATE TYPE finding_status AS ENUM ('NEW', 'CONFIRMED', 'DISCLOSED', 'RESOLVED', 'FALSE_POSITIVE', 'ESCALATED');
CREATE TYPE scan_status AS ENUM ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'SKIPPED');
CREATE TYPE entity_type AS ENUM (
    -- PII / Identity
    'AADHAAR', 'PAN', 'VOTER_ID', 'PASSPORT', 'DRIVING_LICENSE',
    'BANK_ACCOUNT', 'CREDIT_CARD', 'PHONE_NUMBER', 'EMAIL',
    'UPI_ID', 'ABHA_ID',
    -- Secrets / Credentials
    'ENV_FILE', 'PRIVATE_KEY', 'API_KEY', 'AWS_KEY', 'STRIPE_KEY',
    'SECRET_FIELD', 'AWS_CREDS', 'AWS_CONFIG', 'AZURE_CREDS',
    -- Infrastructure Exposure
    'GIT_REPO', 'DATABASE_DUMP', 'CONFIG_FILE', 'SOURCE_CODE',
    'ADMIN_PANEL', 'OPEN_DIRECTORY', 'CLOUD_STORAGE',
    'CLOUD_METADATA', 'KUBE_CONFIG', 'SPRING_BOOT',
    'MEMORY_DUMP', 'SHELL_HISTORY', 'SESSION_DATA', 'CI_CONFIG',
    -- Generic
    'OTHER'
);
CREATE TYPE domain_status AS ENUM ('PENDING', 'ACTIVE', 'INACTIVE', 'BLOCKED', 'WHITELISTED');

-- ─────────────────────────────────────────────────────────────
--  TABLE: domains
--  The central inventory of all discovered Indian web assets.
-- ─────────────────────────────────────────────────────────────

CREATE TABLE domains (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain              VARCHAR(255) NOT NULL UNIQUE,
    tld                 VARCHAR(50),
    iocs_score          SMALLINT DEFAULT 0 CHECK (iocs_score >= 0 AND iocs_score <= 100),
    status              domain_status DEFAULT 'PENDING',

    -- Infrastructure
    ip_address          INET,
    asn                 VARCHAR(20),
    hosting_provider    VARCHAR(100),
    cdn_detected        VARCHAR(50),
    country_code        VARCHAR(5) DEFAULT 'IN',

    -- Signals used for IOCS scoring
    signal_whois_in     BOOLEAN DEFAULT FALSE,   -- WHOIS registrant is Indian
    signal_ip_in        BOOLEAN DEFAULT FALSE,   -- IP geolocates to India
    signal_payment_gw   BOOLEAN DEFAULT FALSE,   -- Indian payment gateway found
    signal_gst_number   BOOLEAN DEFAULT FALSE,   -- GST number on site
    signal_lang_in      BOOLEAN DEFAULT FALSE,   -- Indian language detected
    signal_registry     BOOLEAN DEFAULT FALSE,   -- Found in MCA/DPIIT registry

    -- Scan tracking
    last_scanned_at     TIMESTAMPTZ,
    next_scan_due_at    TIMESTAMPTZ DEFAULT NOW(),
    scan_count          INTEGER DEFAULT 0,
    baseline_hash       VARCHAR(64),             -- SHA-256 of last scan fingerprint

    -- Metadata
    discovered_via      VARCHAR(50),             -- 'CT_LOG', 'SHODAN', 'REGISTRY', etc.
    sector              VARCHAR(50),             -- 'GOVERNMENT', 'EDUCATION', 'HEALTHCARE', etc.
    vendor_fingerprint  VARCHAR(200),            -- CMS/framework: 'WordPress 6.4.2', 'Joomla', etc.
    contact_email       VARCHAR(255),            -- Security contact email (security.txt or manual)
    notes               TEXT,

    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_domains_iocs ON domains(iocs_score DESC);
CREATE INDEX idx_domains_status ON domains(status);
CREATE INDEX idx_domains_next_scan ON domains(next_scan_due_at) WHERE status = 'ACTIVE';
CREATE INDEX idx_domains_tld ON domains(tld);
CREATE INDEX idx_domains_sector ON domains(sector);

-- ─────────────────────────────────────────────────────────────
--  TABLE: findings
--  Every exposure detected. NEVER stores raw PII.
-- ─────────────────────────────────────────────────────────────

CREATE TABLE findings (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain_id               UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,

    -- Location
    url                     TEXT NOT NULL,
    url_path                VARCHAR(500),
    http_status             SMALLINT,

    -- What was found (NO RAW VALUES — hashes only)
    entity_type             entity_type NOT NULL,
    finding_type            VARCHAR(100) NOT NULL,   -- e.g. 'ENV_FILE_EXPOSED', 'AADHAAR_IN_HTML'
    value_hash              VARCHAR(64),             -- SHA-256(salt + detected_value) — no raw PII
    value_count_estimate    INTEGER DEFAULT 1,       -- Estimated number of records exposed

    -- Severity & confidence
    severity                severity_level NOT NULL,
    heuristic_confidence    NUMERIC(4,3) DEFAULT 0,  -- 0.000 to 1.000
    ml_confidence           NUMERIC(4,3),
    final_confidence        NUMERIC(4,3),

    -- Status & workflow
    status                  finding_status DEFAULT 'NEW',
    dark_web_confirmed      BOOLEAN DEFAULT FALSE,
    vendor_fingerprint      VARCHAR(200),

    -- Context (safe metadata only, NO extracted content)
    context_snippet_safe    TEXT,    -- Surrounding text with PII fully masked, e.g. "name: [REDACTED], id: [REDACTED]"
    file_size_bytes         BIGINT,
    content_type            VARCHAR(100),

    -- Disclosure tracking
    disclosed_at            TIMESTAMPTZ,
    disclosure_sla_due      TIMESTAMPTZ,
    acknowledged_at         TIMESTAMPTZ,
    resolved_at             TIMESTAMPTZ,
    escalation_level        SMALLINT DEFAULT 0,      -- 0=none, 1=org, 2=regulator, 3=cert-in direct

    -- Audit
    detected_by             VARCHAR(50) DEFAULT 'HEURISTIC',  -- 'HEURISTIC', 'NER', 'OCR', 'ANALYST'
    reviewed_by             VARCHAR(100),            -- Analyst username if human-reviewed
    reviewed_at             TIMESTAMPTZ,
    false_positive_reason   TEXT,

    created_at              TIMESTAMPTZ DEFAULT NOW(),
    updated_at              TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_findings_domain ON findings(domain_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_entity ON findings(entity_type);
CREATE INDEX idx_findings_sla ON findings(disclosure_sla_due) WHERE status NOT IN ('RESOLVED', 'FALSE_POSITIVE');
CREATE INDEX idx_findings_created ON findings(created_at DESC);

-- ─────────────────────────────────────────────────────────────
--  TABLE: scan_jobs
--  Tracks every scan task executed by the Celery worker.
-- ─────────────────────────────────────────────────────────────

CREATE TABLE scan_jobs (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain_id       UUID REFERENCES domains(id) ON DELETE SET NULL,
    domain_name     VARCHAR(255) NOT NULL,
    job_type        VARCHAR(50) NOT NULL,    -- 'FULL_SCAN', 'RESCAN', 'PILOT'
    status          scan_status DEFAULT 'PENDING',
    celery_task_id  VARCHAR(255),

    -- Results
    urls_checked    INTEGER DEFAULT 0,
    findings_count  INTEGER DEFAULT 0,
    errors_count    INTEGER DEFAULT 0,
    duration_ms     INTEGER,

    -- Timing
    queued_at       TIMESTAMPTZ DEFAULT NOW(),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,

    error_message   TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_scanjobs_domain ON scan_jobs(domain_id);
CREATE INDEX idx_scanjobs_status ON scan_jobs(status);
CREATE INDEX idx_scanjobs_created ON scan_jobs(created_at DESC);

-- ─────────────────────────────────────────────────────────────
--  TABLE: audit_logs
--  Tamper-evident record of every platform action.
-- ─────────────────────────────────────────────────────────────

CREATE TABLE audit_logs (
    id              BIGSERIAL PRIMARY KEY,
    event_type      VARCHAR(100) NOT NULL,    -- 'SCAN_STARTED', 'FINDING_CREATED', 'DISCLOSURE_SENT', etc.
    actor           VARCHAR(100) DEFAULT 'SYSTEM',
    target_type     VARCHAR(50),              -- 'domain', 'finding', 'scan_job'
    target_id       UUID,
    details         JSONB,
    ip_address      INET,
    event_at        TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_audit_event ON audit_logs(event_type);
CREATE INDEX idx_audit_actor ON audit_logs(actor);
CREATE INDEX idx_audit_target ON audit_logs(target_type, target_id);
CREATE INDEX idx_audit_time ON audit_logs(event_at DESC);

-- ─────────────────────────────────────────────────────────────
--  TABLE: disclosure_events
--  Tracks every notification sent to affected organizations.
-- ─────────────────────────────────────────────────────────────

CREATE TABLE disclosure_events (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id      UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    recipient_email VARCHAR(255),
    recipient_type  VARCHAR(50),    -- 'PRIMARY', 'CC_NIC', 'CC_UGC', 'ESCALATION'
    subject         VARCHAR(500),
    sent_at         TIMESTAMPTZ,
    send_status     VARCHAR(20),    -- 'SENT', 'FAILED', 'PENDING'
    error_message   TEXT,
    ack_token       VARCHAR(64) UNIQUE,       -- random token for acknowledgement link
    acknowledged_at TIMESTAMPTZ,              -- set when org clicks the ack link
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_disclosure_finding ON disclosure_events(finding_id);
CREATE INDEX idx_disclosure_ack_token ON disclosure_events(ack_token);

-- ─────────────────────────────────────────────────────────────
--  VIEW: dashboard_summary
--  Quick stats for the dashboard (no PII).
-- ─────────────────────────────────────────────────────────────

CREATE VIEW dashboard_summary AS
SELECT
    COUNT(DISTINCT d.id)                                        AS total_domains,
    COUNT(DISTINCT CASE WHEN d.status = 'ACTIVE' THEN d.id END) AS active_domains,
    COUNT(DISTINCT f.id)                                        AS total_findings,
    COUNT(DISTINCT CASE WHEN f.severity = 'CRITICAL' AND f.status NOT IN ('RESOLVED','FALSE_POSITIVE') THEN f.id END) AS open_critical,
    COUNT(DISTINCT CASE WHEN f.severity = 'HIGH'     AND f.status NOT IN ('RESOLVED','FALSE_POSITIVE') THEN f.id END) AS open_high,
    COUNT(DISTINCT CASE WHEN f.severity = 'MEDIUM'   AND f.status NOT IN ('RESOLVED','FALSE_POSITIVE') THEN f.id END) AS open_medium,
    COUNT(DISTINCT CASE WHEN f.status = 'RESOLVED'   THEN f.id END) AS resolved_findings,
    COUNT(DISTINCT CASE WHEN f.status = 'DISCLOSED'  THEN f.id END) AS pending_remediation
FROM domains d
LEFT JOIN findings f ON f.domain_id = d.id;

-- ─────────────────────────────────────────────────────────────
--  Trigger: auto-update updated_at columns
-- ─────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_domains_updated
    BEFORE UPDATE ON domains
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_findings_updated
    BEFORE UPDATE ON findings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ─────────────────────────────────────────────────────────────
--  Seed: Insert known safe whitelist entries
-- ─────────────────────────────────────────────────────────────

INSERT INTO audit_logs (event_type, actor, details)
VALUES ('SYSTEM_INIT', 'SYSTEM', '{"message": "CyberDrishti database initialized successfully", "version": "1.0.0"}');
