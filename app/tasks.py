from __future__ import annotations

from datetime import datetime, timedelta

from .celery_app import celery_app
from .repo import db_session, get_or_create_settings
from .crypto import decrypt_str
from .net_scan import scan_presence
from .presence import upsert_presence_bulk


# If a scan crashes mid-flight, allow new runs after this TTL.
_LOCK_STALE_HOURS = 6


def _utcnow() -> datetime:
    # NOTE: keep naive UTC datetimes for compatibility with existing SQLite DateTime usage.
    return datetime.utcnow()


@celery_app.task(name="app.tasks.maybe_run_network_scan")
def maybe_run_network_scan() -> dict:
    """
    Runs frequently (Celery Beat). Decides whether a full scan is due and schedules it.

    Returns a small status dict that ends up in worker logs.
    """
    with db_session() as db:
        st = get_or_create_settings(db)

        if not getattr(st, "net_scan_enabled", False):
            return {"status": "disabled"}

        now = _utcnow()

        # Clear stale lock (previous crash / killed worker)
        if st.net_scan_lock_ts and (now - st.net_scan_lock_ts) > timedelta(hours=_LOCK_STALE_HOURS):
            st.net_scan_lock_ts = None
            db.commit()

        # If locked -> a scan is already running
        if st.net_scan_lock_ts:
            return {"status": "running"}

        interval_min = int(getattr(st, "net_scan_interval_min", 120) or 120)
        if interval_min < 10:
            interval_min = 10

        last = getattr(st, "net_scan_last_run_ts", None)
        if last and (now - last) < timedelta(minutes=interval_min):
            next_run = last + timedelta(minutes=interval_min)
            try:
                nxt = next_run.isoformat(sep=" ", timespec="seconds")
            except Exception:
                nxt = str(next_run)
            return {"status": "not_due", "next_run": nxt}

        # Lock and schedule scan
        st.net_scan_lock_ts = now
        db.commit()

    run_network_scan.delay()
    return {"status": "scheduled"}


# Backward-compatible alias (older beat schedule may call this name)
@celery_app.task(name="app.tasks.net_scan_tick")
def net_scan_tick() -> dict:
    return maybe_run_network_scan()


@celery_app.task(name="app.tasks.run_network_scan")
def run_network_scan() -> dict:
    """Performs a full scan and updates user_presence + settings status.

    Always clears lock in DB.
    """
    started = _utcnow()

    # Load config under DB session
    with db_session() as db:
        st = get_or_create_settings(db)

        # Ensure lock exists
        if not st.net_scan_lock_ts:
            st.net_scan_lock_ts = started

        # Optional: show that scan is running
        st.net_scan_last_summary = "Выполняется..."
        db.commit()

        if not getattr(st, "net_scan_enabled", False):
            st.net_scan_last_run_ts = started
            st.net_scan_last_summary = "Сканирование отключено."
            st.net_scan_lock_ts = None
            db.commit()
            return {"status": "disabled"}

        cidrs = (getattr(st, "net_scan_cidrs", "") or "").strip()
        q_user = (getattr(st, "host_query_username", "") or "").strip()
        q_pass = decrypt_str(getattr(st, "host_query_password_enc", "") or "")
        domain = (getattr(st, "ad_domain", "") or "").strip()

        if not cidrs:
            st.net_scan_last_run_ts = started
            st.net_scan_last_summary = "CIDR не задан."
            st.net_scan_lock_ts = None
            db.commit()
            return {"status": "no_cidr"}

        if not (q_user and q_pass):
            st.net_scan_last_run_ts = started
            st.net_scan_last_summary = "Не заданы учётные данные для опроса хостов (Host query user/password)."
            st.net_scan_lock_ts = None
            db.commit()
            return {"status": "no_creds"}

        per_method_timeout_s = int(getattr(st, "host_query_timeout_s", 60) or 60)
        conc = int(getattr(st, "net_scan_concurrency", 64) or 64)
        probe_ms = int(getattr(st, "net_scan_probe_timeout_ms", 350) or 350)

    # Run scan outside DB transaction
    try:
        res = scan_presence(
            cidrs_text=cidrs,
            domain_suffix=domain,
            query_username=q_user,
            query_password=q_pass,
            per_method_timeout_s=per_method_timeout_s,
            concurrency=conc,
            probe_timeout_ms=probe_ms,
        )

        with db_session() as db:
            updated = upsert_presence_bulk(db, res.presence)

            st = get_or_create_settings(db)
            finished = _utcnow()
            dur_s = int((finished - started).total_seconds())
            skipped = max(0, int(res.total_ips) - int(res.alive))
            summary = (
                f"OK. Цели: {res.total_ips}. "
                f"Проверено (после probe): {res.alive}. "
                f"Пропущено: {skipped}. "
                f"Ошибок: {res.errors}. "
                f"Обновлено пользователей: {updated}. "
                f"Длительность: {dur_s} сек."
            )

            st.net_scan_last_run_ts = finished
            st.net_scan_last_summary = (summary or "")[:512]
            st.net_scan_lock_ts = None
            db.commit()

        return {"status": "ok", "summary": summary[:512]}

    except Exception as e:
        # Best-effort status update + unlock
        with db_session() as db:
            st = get_or_create_settings(db)
            st.net_scan_last_run_ts = _utcnow()
            st.net_scan_last_summary = (f"Ошибка: {str(e) or type(e).__name__}")[:512]
            st.net_scan_lock_ts = None
            db.commit()
        return {"status": "error"}
