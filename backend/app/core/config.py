# backend/app/core/config.py
# ─────────────────────────────────────────
#  All settings loaded from .env file.
# ─────────────────────────────────────────

from pydantic_settings import BaseSettings
from functools import lru_cache
from typing import Optional


class Settings(BaseSettings):
    # Project
    PROJECT_NAME: str = "CyberDrishti"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"

    # Database
    DATABASE_URL: str

    # Redis
    REDIS_URL: str

    # Security
    SECRET_KEY: str = "changeme"
    API_KEY: str = "changeme"

    # Scanner
    SCAN_RATE_LIMIT: int = 5
    SCAN_TIMEOUT: int = 10
    SCAN_MAX_RETRIES: int = 3
    SCAN_CONCURRENCY: int = 4

    # External APIs
    SHODAN_API_KEY: Optional[str] = None
    CENSYS_API_ID: Optional[str] = None
    CENSYS_API_SECRET: Optional[str] = None
    WHOIS_XML_API_KEY: Optional[str] = None
    HIBP_API_KEY: Optional[str] = None
    INTELX_API_KEY: Optional[str] = None

    # Email
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    DISCLOSURE_FROM_EMAIL: str = "disclosures@cyberdrishti.local"

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "logs/cyberdrishti.log"

    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
