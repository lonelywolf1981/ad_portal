from celery import Celery
from .env_settings import get_env
from .schema import ensure_schema

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
    timezone="UTC",
    enable_utc=True,
)

# Ensure DB schema exists for the worker/beat processes.
ensure_schema()

# Discover tasks in the "app" package (app/tasks.py).
celery_app.autodiscover_tasks(["app"])

# Periodic scheduler: keep it frequent and decide in DB whether scan is due.
celery_app.conf.beat_schedule = {
    "maybe-run-network-scan": {
        "task": "app.tasks.maybe_run_network_scan",
        "schedule": 60.0,  # seconds
    }
}
