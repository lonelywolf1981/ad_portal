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

from celery.signals import worker_ready  # noqa: E402


@worker_ready.connect
def _clear_stale_scan_lock(**_kwargs) -> None:
    """A single worker runs the scans: when it (re)starts, no scan can still be running.

    A lock left by a killed worker (container recreate, OOM) otherwise blocked scans until the
    stale-lock TTL expired.
    """
    import logging

    from sqlalchemy import update

    from .models import AppSettings
    from .repo import db_session

    try:
        with db_session() as db:
            res = db.execute(
                update(AppSettings)
                .where(AppSettings.id == 1, AppSettings.net_scan_lock_ts.is_not(None))
                .values(net_scan_lock_ts=None, net_scan_last_summary="Прервано перезапуском worker.")
            )
            db.commit()
            if res.rowcount:
                logging.getLogger(__name__).warning("Снята блокировка net-scan, оставшаяся от прерванного сканирования")
    except Exception:
        logging.getLogger(__name__).warning("Не удалось проверить блокировку net-scan при старте worker", exc_info=True)
