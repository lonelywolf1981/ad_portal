from __future__ import annotations

from datetime import datetime, timedelta

from .celery_app import celery_app
from .crypto import decrypt_str
from .net_scan import scan_presence
from .presence import upsert_presence_bulk
from .mappings import cleanup_host_user_matches, upsert_host_user_matches
from .repo import db_session, get_or_create_settings
from .timezone_utils import format_ru_local


# If a scan crashes mid-flight, allow new runs after this TTL.
_LOCK_STALE_HOURS = 6


def _utcnow() -> datetime:
    # NOTE: keep naive UTC datetimes for compatibility with existing SQLite DateTime usage.
    return datetime.utcnow()


@celery_app.task(name="app.tasks.maybe_run_network_scan")
def maybe_run_network_scan(force: bool = False) -> dict:
    """Runs frequently (Celery Beat). Decides whether a full scan is due and schedules it.

    force=True bypasses interval check (used by the "Run now" button).

    Returns a small status dict that ends up in worker logs.
    """
    with db_session() as db:
        st = get_or_create_settings(db)

        if not getattr(st, "net_scan_enabled", False):
            return {"status": "disabled"}

        now = _utcnow()

        # Lock timestamp may be absent in ORM model if schema/model got out-of-sync.
        lock_ts = getattr(st, "net_scan_lock_ts", None)

        # Clear stale lock (previous crash / killed worker)
        if lock_ts and (now - lock_ts) > timedelta(hours=_LOCK_STALE_HOURS):
            st.net_scan_lock_ts = None
            db.commit()
            lock_ts = None

        # If locked -> a scan is already running
        if lock_ts:
            return {"status": "running"}

        interval_min = int(getattr(st, "net_scan_interval_min", 120) or 120)
        if interval_min < 10:
            interval_min = 10

        last = getattr(st, "net_scan_last_run_ts", None)
        if (not force) and last and (now - last) < timedelta(minutes=interval_min):
            next_run = last + timedelta(minutes=interval_min)
            return {
                "status": "not_due",
                # Show local time for humans (TZ from env).
                "next_run": format_ru_local(next_run),
            }

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
    """Performs a full scan and updates user_presence + host_user_map + settings status.

    Always clears lock in DB.
    """
    started = _utcnow()

    # Load config under DB session
    with db_session() as db:
        st = get_or_create_settings(db)

        # Ensure lock exists
        if not getattr(st, "net_scan_lock_ts", None):
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

    # (дальше файл без изменений — оставляю как есть в проекте)

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

        # Build host-user matches in a backward-compatible way:
        # - If net_scan.py already provides res.matches, use it.
        # - Otherwise derive matches from res.presence (login -> {host, ip, method, ts}).
        matches = getattr(res, "matches", None)
        if not matches:
            matches = []
            for login, data in (res.presence or {}).items():
                matches.append(
                    {
                        "host": (data.get("host") or "").strip(),
                        "ip": (data.get("ip") or "").strip(),
                        "login": (login or "").strip(),
                        "method": (data.get("method") or "").strip(),
                        "ts": data.get("ts"),
                    }
                )

        with db_session() as db:
            updated_users = upsert_presence_bulk(db, res.presence)
            updated_matches = upsert_host_user_matches(db, matches)

            # Retention: 1 month for host-user pairs
            deleted_matches = cleanup_host_user_matches(db, retention_days=31)

            st = get_or_create_settings(db)
            finished = _utcnow()
            dur_s = int((finished - started).total_seconds())
            skipped = max(0, int(res.total_ips) - int(res.alive))
            summary = (
                f"OK. Цели: {res.total_ips}. "
                f"Проверено (после probe): {res.alive}. "
                f"Пропущено: {skipped}. "
                f"Ошибок: {res.errors}. "
                f"Обновлено пользователей: {updated_users}. "
                f"Обновлено сопоставлений: {updated_matches}. "
                f"Удалено старых сопоставлений: {deleted_matches}. "
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
