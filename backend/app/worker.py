# backend/app/worker.py
# ─────────────────────────────────────────
#  Celery worker — task queue engine.
#  Runs the scanner tasks in the background.
# ─────────────────────────────────────────

from celery import Celery
from celery.schedules import crontab
from app.core.config import settings
from app.core.logging import get_logger, setup_logging

setup_logging(settings.LOG_LEVEL, settings.LOG_FILE)
logger = get_logger("worker")

# Create Celery app
celery_app = Celery(
    "cyberdrishti",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "app.services.scanner_tasks",
        "app.services.corpus_tasks",
    ]
)

# Celery configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,           # Only ack after task completes (safe retry)
    worker_prefetch_multiplier=1,  # Process one task at a time per worker
    task_max_retries=3,
    task_default_retry_delay=60,   # Retry after 60 seconds

    # Periodic scan schedule
    beat_schedule={
        # Phase 1: daily pilot corpus refresh (gov/edu)
        "daily-pilot-corpus-refresh": {
            "task": "app.services.corpus_tasks.run_pilot_corpus_refresh",
            "schedule": crontab(hour=2, minute=0),
        },
        # Phase 2: weekly full Indian corpus refresh (all TLDs)
        "weekly-phase2-corpus-refresh": {
            "task": "app.services.corpus_tasks.run_corpus_refresh_phase2",
            "schedule": crontab(day_of_week=0, hour=3, minute=0),
        },
        # Phase 2: differential rescan queue (every 6h)
        # Enqueues domains whose per-sector TTL has elapsed
        "rescan-queue": {
            "task": "app.services.corpus_tasks.queue_domains_for_rescan",
            "schedule": crontab(hour="*/6", minute=30),
        },
        # Scan queue: process ACTIVE domains every 30 min
        "scan-all-pending": {
            "task": "app.services.scanner_tasks.scan_all_pending",
            "schedule": crontab(minute="*/30"),
        },
        # Health check every 5 minutes
        "health-check": {
            "task": "app.services.scanner_tasks.health_check",
            "schedule": crontab(minute="*/5"),
        },
    },
)

# Alias for import
worker = celery_app
