# backend/app/db/database.py
# ─────────────────────────────────────────
#  Database connection using SQLAlchemy.
# ─────────────────────────────────────────

from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("db.database")

# Create synchronous engine (simpler for beginners, works perfectly)
engine = create_engine(
    settings.DATABASE_URL,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,   # Verify connection before use
    echo=False,           # Set True to see all SQL queries (useful for debugging)
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db() -> Session:
    """
    FastAPI dependency — yields a database session.
    Automatically closes session when request is done.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_db_connection() -> bool:
    """Verify database is reachable."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        logger.info("Database connection: OK")
        return True
    except Exception as e:
        logger.error(f"Database connection FAILED: {e}")
        return False
