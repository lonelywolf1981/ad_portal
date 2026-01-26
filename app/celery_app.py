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
    timezone="UTC",
    enable_utc=True,
)
