from __future__ import annotations

from datetime import datetime, timedelta
import logging

from sqlalchemy import update, delete

from .celery_app import celery_app
from .ad import ADClient
from .services.ad import ad_cfg_from_settings
from .crypto import decrypt_str
from .net_scan import scan_presence
from .presence import upsert_presence_bulk
from .mappings import cleanup_host_user_matches, upsert_host_user_matches
from .shares import cleanup_shares, upsert_shares_bulk
from .repo import db_session, get_or_create_settings
from .models import AppSettings, ScanStatsHistory
from .timezone_utils import format_ru_local
from .utils.numbers import clamp_int


# If a scan crashes mid-flight, allow new runs after this TTL.
_LOCK_STALE_HOURS = 1
log = logging.getLogger(__name__)


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
            db.execute(
                update(AppSettings)
                .where(AppSettings.id == 1, AppSettings.net_scan_lock_ts == lock_ts)
                .values(net_scan_lock_ts=None)
            )
            db.commit()
            lock_ts = None

        # If locked -> a scan is already running
        if lock_ts:
            return {"status": "running"}

        interval_min = clamp_int(getattr(st, "net_scan_interval_min", 120), default=120, min_v=10, max_v=24 * 60)

        last = getattr(st, "net_scan_last_run_ts", None)
        if (not force) and last and (now - last) < timedelta(minutes=interval_min):
            next_run = last + timedelta(minutes=interval_min)
            return {
                "status": "not_due",
                # Show local time for humans (TZ from env).
                "next_run": format_ru_local(next_run),
            }

        # Atomically acquire lock to avoid double scheduling across workers.
        got_lock = db.execute(
            update(AppSettings)
            .where(AppSettings.id == 1, AppSettings.net_scan_lock_ts.is_(None))
            .values(net_scan_lock_ts=now)
        )
        db.commit()
        if int(got_lock.rowcount or 0) == 0:
            return {"status": "running"}

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

        # Background scan has its own per-method timeout setting.
        per_method_timeout_s = clamp_int(
            getattr(st, "net_scan_method_timeout_s", 20),
            default=20,
            min_v=5,
            max_v=180,
        )
        conc = clamp_int(getattr(st, "net_scan_concurrency", 64), default=64, min_v=1, max_v=256)
        probe_ms = clamp_int(getattr(st, "net_scan_probe_timeout_ms", 350), default=350, min_v=50, max_v=5000)
        do_enum_shares = bool(getattr(st, "net_scan_enum_shares", True))

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
            enum_shares=do_enum_shares,
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

            # SMB-шары
            shares_list = getattr(res, "shares", None) or []
            updated_shares = upsert_shares_bulk(db, shares_list) if shares_list else 0
            cleanup_shares(db, retention_days=31)

            # Retention: 1 month for host-user pairs
            deleted_matches = cleanup_host_user_matches(db, retention_days=31)

            st = get_or_create_settings(db)
            finished = _utcnow()
            dur_s = int((finished - started).total_seconds())
            skipped = max(0, int(res.total_ips) - int(res.alive))
            retention_days = clamp_int(
                getattr(st, "net_scan_stats_retention_days", 30),
                default=30,
                min_v=7,
                max_v=365,
            )

            users_total: int | None = None
            users_enabled: int | None = None
            try:
                cfg = ad_cfg_from_settings(st)
                if cfg:
                    c = ADClient(cfg)
                    ok, _ = c.service_bind()
                    if ok:
                        total, enabled = c.count_users_total_and_enabled()
                        users_total = int(total)
                        users_enabled = int(enabled)
            except Exception:
                log.warning("Не удалось получить AD-метрики для графика статистики", exc_info=True)

            shares_part = f"Обнаружено ресурсов: {updated_shares}. " if updated_shares else ""
            summary = (
                f"OK. Цели: {res.total_ips}. "
                f"Проверено (после probe): {res.alive}. "
                f"Пропущено: {skipped}. "
                f"Ошибок: {res.errors}. "
                f"Обновлено пользователей: {updated_users}. "
                f"Обновлено сопоставлений: {updated_matches}. "
                f"{shares_part}"
                f"Удалено старых сопоставлений: {deleted_matches}. "
                f"Длительность: {dur_s} сек."
            )

            st.net_scan_last_run_ts = finished
            st.net_scan_last_summary = (summary or "")[:512]
            st.net_scan_lock_ts = None

            db.add(
                ScanStatsHistory(
                    ts=finished,
                    users_total=users_total,
                    users_enabled=users_enabled,
                    users_online=int(updated_users),
                )
            )
            cutoff_hist = finished - timedelta(days=retention_days)
            db.execute(delete(ScanStatsHistory).where(ScanStatsHistory.ts < cutoff_hist))
            db.commit()

        return {"status": "ok", "summary": summary[:512]}

    except Exception as e:
        log.exception("Ошибка выполнения фонового net-scan")
        # Best-effort status update + unlock
        with db_session() as db:
            st = get_or_create_settings(db)
            st.net_scan_last_run_ts = _utcnow()
            st.net_scan_last_summary = (f"Ошибка: {str(e) or type(e).__name__}")[:512]
            st.net_scan_lock_ts = None
            db.commit()
        return {"status": "error"}
