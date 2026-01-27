from celery import Celery
from .env_settings import get_env

REDIS_URL = get_env().redis_url

celery_app = Celery(
    "ad_portal",
    broker=REDIS_URL,
    backend=REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    enable_utc=False,
    timezone="Asia/Almaty",
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
