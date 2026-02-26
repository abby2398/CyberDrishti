# backend/app/models/models.py
# ─────────────────────────────────────────
#  SQLAlchemy ORM models.
#  These map Python classes to DB tables.
# ─────────────────────────────────────────

import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Integer, SmallInteger, Boolean, Text,
    DateTime, Numeric, BigInteger, ForeignKey, Enum as SAEnum
)
from sqlalchemy.dialects.postgresql import UUID, INET, JSONB
from sqlalchemy.orm import relationship
from app.db.database import Base
import enum


# ── Python Enums (mirror the DB enums) ───────────────────────

class SeverityLevel(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class FindingStatus(str, enum.Enum):
    NEW = "NEW"
    CONFIRMED = "CONFIRMED"
    DISCLOSED = "DISCLOSED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ESCALATED = "ESCALATED"

class ScanStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"

class DomainStatus(str, enum.Enum):
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    BLOCKED = "BLOCKED"
    WHITELISTED = "WHITELISTED"

class EntityType(str, enum.Enum):
    AADHAAR = "AADHAAR"
    PAN = "PAN"
    VOTER_ID = "VOTER_ID"
    PASSPORT = "PASSPORT"
    DRIVING_LICENSE = "DRIVING_LICENSE"
    BANK_ACCOUNT = "BANK_ACCOUNT"
    CREDIT_CARD = "CREDIT_CARD"
    PHONE_NUMBER = "PHONE_NUMBER"
    EMAIL = "EMAIL"
    ENV_FILE = "ENV_FILE"
    GIT_REPO = "GIT_REPO"
    DATABASE_DUMP = "DATABASE_DUMP"
    CONFIG_FILE = "CONFIG_FILE"
    ADMIN_PANEL = "ADMIN_PANEL"
    OPEN_DIRECTORY = "OPEN_DIRECTORY"
    CLOUD_STORAGE = "CLOUD_STORAGE"
    PRIVATE_KEY = "PRIVATE_KEY"
    API_KEY = "API_KEY"
    OTHER = "OTHER"


# ── Models ────────────────────────────────────────────────────

class Domain(Base):
    __tablename__ = "domains"

    id                  = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain              = Column(String(255), unique=True, nullable=False, index=True)
    tld                 = Column(String(50))
    iocs_score          = Column(SmallInteger, default=0)
    status              = Column(String(20), default="PENDING")

    ip_address          = Column(INET)
    asn                 = Column(String(20))
    hosting_provider    = Column(String(100))
    cdn_detected        = Column(String(50))
    country_code        = Column(String(5), default="IN")

    signal_whois_in     = Column(Boolean, default=False)
    signal_ip_in        = Column(Boolean, default=False)
    signal_payment_gw   = Column(Boolean, default=False)
    signal_gst_number   = Column(Boolean, default=False)
    signal_lang_in      = Column(Boolean, default=False)
    signal_registry     = Column(Boolean, default=False)

    last_scanned_at     = Column(DateTime(timezone=True))
    next_scan_due_at    = Column(DateTime(timezone=True), default=datetime.now)
    scan_count          = Column(Integer, default=0)
    baseline_hash       = Column(String(64))

    discovered_via      = Column(String(50))
    sector              = Column(String(50))
    notes               = Column(Text)

    created_at          = Column(DateTime(timezone=True), default=datetime.now)
    updated_at          = Column(DateTime(timezone=True), default=datetime.now, onupdate=datetime.now)

    # Relationships
    findings            = relationship("Finding", back_populates="domain", cascade="all, delete-orphan")
    scan_jobs           = relationship("ScanJob", back_populates="domain")

    def __repr__(self):
        return f"<Domain {self.domain} IOCS={self.iocs_score}>"


class Finding(Base):
    __tablename__ = "findings"

    id                      = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain_id               = Column(UUID(as_uuid=True), ForeignKey("domains.id", ondelete="CASCADE"), nullable=False)

    url                     = Column(Text, nullable=False)
    url_path                = Column(String(500))
    http_status             = Column(SmallInteger)

    entity_type             = Column(String(50), nullable=False)
    finding_type            = Column(String(100), nullable=False)
    value_hash              = Column(String(64))          # SHA-256(salt+value) — NO RAW PII
    value_count_estimate    = Column(Integer, default=1)

    severity                = Column(String(20), nullable=False)
    heuristic_confidence    = Column(Numeric(4, 3), default=0)
    ml_confidence           = Column(Numeric(4, 3))
    final_confidence        = Column(Numeric(4, 3))

    status                  = Column(String(30), default="NEW")
    dark_web_confirmed      = Column(Boolean, default=False)
    vendor_fingerprint      = Column(String(200))

    context_snippet_safe    = Column(Text)   # PII-masked context only
    file_size_bytes         = Column(BigInteger)
    content_type            = Column(String(100))

    disclosed_at            = Column(DateTime(timezone=True))
    disclosure_sla_due      = Column(DateTime(timezone=True))
    acknowledged_at         = Column(DateTime(timezone=True))
    resolved_at             = Column(DateTime(timezone=True))
    escalation_level        = Column(SmallInteger, default=0)

    detected_by             = Column(String(50), default="HEURISTIC")
    reviewed_by             = Column(String(100))
    reviewed_at             = Column(DateTime(timezone=True))
    false_positive_reason   = Column(Text)

    created_at              = Column(DateTime(timezone=True), default=datetime.now)
    updated_at              = Column(DateTime(timezone=True), default=datetime.now, onupdate=datetime.now)

    # Relationships
    domain                  = relationship("Domain", back_populates="findings")
    disclosures             = relationship("DisclosureEvent", back_populates="finding", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Finding {self.finding_type} @ {self.url} [{self.severity}]>"


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain_id       = Column(UUID(as_uuid=True), ForeignKey("domains.id", ondelete="SET NULL"), nullable=True)
    domain_name     = Column(String(255), nullable=False)
    job_type        = Column(String(50), nullable=False)
    status          = Column(String(20), default="PENDING")
    celery_task_id  = Column(String(255))

    urls_checked    = Column(Integer, default=0)
    findings_count  = Column(Integer, default=0)
    errors_count    = Column(Integer, default=0)
    duration_ms     = Column(Integer)

    queued_at       = Column(DateTime(timezone=True), default=datetime.now)
    started_at      = Column(DateTime(timezone=True))
    completed_at    = Column(DateTime(timezone=True))

    error_message   = Column(Text)
    created_at      = Column(DateTime(timezone=True), default=datetime.now)

    domain          = relationship("Domain", back_populates="scan_jobs")

    def __repr__(self):
        return f"<ScanJob {self.domain_name} [{self.status}]>"


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id          = Column(BigInteger, primary_key=True, autoincrement=True)
    event_type  = Column(String(100), nullable=False, index=True)
    actor       = Column(String(100), default="SYSTEM")
    target_type = Column(String(50))
    target_id   = Column(UUID(as_uuid=True))
    details     = Column(JSONB)
    ip_address  = Column(INET)
    event_at    = Column(DateTime(timezone=True), default=datetime.now, index=True)

    def __repr__(self):
        return f"<AuditLog {self.event_type} by {self.actor}>"


class DisclosureEvent(Base):
    __tablename__ = "disclosure_events"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id      = Column(UUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    recipient_email = Column(String(255))
    recipient_type  = Column(String(50))
    subject         = Column(String(500))
    sent_at         = Column(DateTime(timezone=True))
    send_status     = Column(String(20))
    error_message   = Column(Text)
    created_at      = Column(DateTime(timezone=True), default=datetime.now)

    finding         = relationship("Finding", back_populates="disclosures")
