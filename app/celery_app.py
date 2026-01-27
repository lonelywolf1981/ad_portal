import os

from celery import Celery

from .env_settings import get_env

REDIS_URL = get_env().redis_url

# Use container TZ if provided (e.g. TZ=Asia/Almaty).
# Celery otherwise logs/schedules in UTC by default.
TZ_NAME = (os.getenv("TZ") or "UTC").strip() or "UTC"
ENABLE_UTC = TZ_NAME.upper() in {"UTC", "GMT", "ETC/UTC", "ETC/GMT"}

celery_app = Celery(
    "ad_portal",
    broker=REDIS_URL,
    backend=REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone=TZ_NAME,
    enable_utc=ENABLE_UTC,
)

# Periodic scheduler (Celery Beat)
# A frequent "tick" task decides when the real scan is due (e.g., every 120 minutes).
celery_app.conf.beat_schedule = {
    "maybe-run-network-scan": {
        "task": "app.tasks.maybe_run_network_scan",
        "schedule": 60.0,  # every minute
    }
}

# Ensure task modules are imported
from . import tasks  # noqa: E402,F401
