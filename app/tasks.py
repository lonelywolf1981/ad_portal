from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from typing import Any

from celery.utils.log import get_task_logger
from sqlalchemy.dialects.sqlite import insert

from .celery_app import celery_app
from .crypto import decrypt_str
from .repo import db_session, get_or_create_settings
from .schema import ensure_schema
from .models import UserPresence
from .presence import normalize_login
from .net_scan import parse_cidrs, expand_hosts, is_windows_candidate, reverse_dns, HostScanResult
from .host_logon import find_logged_on_users


logger = get_task_logger(__name__)


_MAX_HOSTS = 10000  # safety cap


def _clamp_int(v: Any, default: int, lo: int, hi: int) -> int:
    try:
        n = int(v)
    except Exception:
        n = int(default)
    if n < lo:
        n = lo
    if n > hi:
        n = hi
    return n


@celery_app.task(name="app.tasks.maybe_run_network_scan")
def maybe_run_network_scan(force: bool = False) -> dict:
    """Lightweight gatekeeper task triggered by Celery Beat.

    We keep Beat schedule static (e.g., every 60s) and decide in this task if
    the real scan should be started based on DB settings.
    """
    ensure_schema()

    with db_session() as db:
        st = get_or_create_settings(db)

        if not getattr(st, "net_scan_enabled", False):
            return {"status": "disabled"}

        now = datetime.utcnow()

        # stale lock protection: if running > 6 hours, unlock
        if st.net_scan_is_running and st.net_scan_run_started_ts:
            if now - st.net_scan_run_started_ts > timedelta(hours=6):
                st.net_scan_is_running = False
                st.net_scan_run_started_ts = None
                db.commit()
            else:
                return {"status": "running"}

        if not force:
            interval_min = _clamp_int(st.net_scan_interval_min, 120, 30, 24 * 60)
            if st.net_scan_last_run_ts and (now - st.net_scan_last_run_ts).total_seconds() < interval_min * 60:
                return {"status": "not_due"}

        # Acquire lock
        st.net_scan_is_running = True
        st.net_scan_run_started_ts = now
        db.commit()

    # Schedule actual scan asynchronously
    run_network_scan.delay(force)
    return {"status": "scheduled"}


def _scan_one_host(ip: str, domain_suffix: str, q_user: str, q_pass: str, method_timeout_s: int, probe_timeout_s: float) -> HostScanResult:
    try:
        if not is_windows_candidate(ip, probe_timeout_s=probe_timeout_s):
            return HostScanResult(ip=ip, hostname="", method="", users=[], error="skipped")

        hostname = reverse_dns(ip)
        users, method, _elapsed_ms, _attempts = find_logged_on_users(
            raw_target=ip,
            domain_suffix=domain_suffix,
            query_username=q_user,
            query_password=q_pass,
            per_method_timeout_s=method_timeout_s,
        )
        norm_users = [normalize_login(u) for u in (users or [])]
        norm_users = [u for u in norm_users if u]
        return HostScanResult(ip=ip, hostname=hostname, method=method or "", users=norm_users)
    except Exception as e:
        return HostScanResult(ip=ip, hostname="", method="", users=[], error=str(e)[:200])


@celery_app.task(name="app.tasks.run_network_scan")
def run_network_scan(force: bool = False) -> dict:
    """Main network scan: map user -> last seen host.

    Reads settings from DB:
    - CIDR list
    - interval/concurrency
    - credentials for host query
    """
    ensure_schema()

    started = datetime.utcnow()

    # Load settings snapshot
    with db_session() as db:
        st = get_or_create_settings(db)
        enabled = bool(getattr(st, "net_scan_enabled", False))
        cidr_text = st.net_scan_cidrs or ""
        interval_min = _clamp_int(st.net_scan_interval_min, 120, 30, 24 * 60)
        concurrency = _clamp_int(st.net_scan_concurrency, 64, 4, 256)
        method_timeout_s = _clamp_int(st.net_scan_method_timeout_s, 20, 5, 60)
        probe_timeout_ms = _clamp_int(st.net_scan_probe_timeout_ms, 350, 100, 1500)

        domain_suffix = (st.ad_domain or "").strip()
        q_user = (st.host_query_username or "").strip()
        q_pass = decrypt_str(st.host_query_password_enc)

    if not enabled:
        # Release lock if disabled in the middle
        with db_session() as db:
            st = get_or_create_settings(db)
            st.net_scan_is_running = False
            st.net_scan_run_started_ts = None
            db.commit()
        return {"status": "disabled"}

    cidrs = parse_cidrs(cidr_text)
    hosts = expand_hosts(cidrs, limit=_MAX_HOSTS)
    total_targets = len(hosts)

    if total_targets == 0:
        summary = "Сканирование не выполнено: список CIDR пуст." 
        with db_session() as db:
            st = get_or_create_settings(db)
            st.net_scan_last_run_ts = datetime.utcnow()
            st.net_scan_last_summary = summary
            st.net_scan_is_running = False
            st.net_scan_run_started_ts = None
            db.commit()
        return {"status": "empty", "summary": summary}

    if not (q_user and q_pass):
        summary = "Сканирование не выполнено: не заданы Host query user/password в настройках." 
        with db_session() as db:
            st = get_or_create_settings(db)
            st.net_scan_last_run_ts = datetime.utcnow()
            st.net_scan_last_summary = summary
            st.net_scan_is_running = False
            st.net_scan_run_started_ts = None
            db.commit()
        return {"status": "no_creds", "summary": summary}

    # Extra protection: avoid too frequent runs (even if run-now is clicked often).
    if not force:
        with db_session() as db:
            st = get_or_create_settings(db)
            if st.net_scan_last_run_ts and (started - st.net_scan_last_run_ts).total_seconds() < min(15, interval_min) * 60:
                st.net_scan_is_running = False
                st.net_scan_run_started_ts = None
                db.commit()
                return {"status": "throttled"}

    probe_timeout_s = probe_timeout_ms / 1000.0
    scanned = 0
    skipped = 0
    errors = 0
    hits_users = 0

    # DB writes happen in the main thread.
    def upsert_presence(db, login_key: str, host: str, ip: str, method: str, ts: datetime) -> None:
        stmt = insert(UserPresence).values(
            user_login=login_key,
            host=host or "",
            ip=ip or "",
            method=method or "",
            last_seen_ts=ts,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[UserPresence.user_login],
            set_={
                "host": host or "",
                "ip": ip or "",
                "method": method or "",
                "last_seen_ts": ts,
            },
        )
        db.execute(stmt)

    now_ts = datetime.utcnow()

    with ThreadPoolExecutor(max_workers=concurrency) as ex, db_session() as db:
        futs = [
            ex.submit(_scan_one_host, ip, domain_suffix, q_user, q_pass, method_timeout_s, probe_timeout_s)
            for ip in hosts
        ]

        batch_ops = 0
        for fut in as_completed(futs):
            res = fut.result()
            if res.error == "skipped":
                skipped += 1
                continue
            if res.error:
                errors += 1
                continue

            scanned += 1
            if res.users:
                for u in res.users:
                    upsert_presence(db, u, res.hostname or "", res.ip, res.method, now_ts)
                    hits_users += 1
                    batch_ops += 1
                    if batch_ops >= 250:
                        db.commit()
                        batch_ops = 0

        if batch_ops:
            db.commit()

    finished = datetime.utcnow()
    dur_s = int((finished - started).total_seconds())
    summary = (
        f"OK. Цели: {total_targets}. Проверено (после probe): {scanned}. "
        f"Пропущено: {skipped}. Ошибок: {errors}. Обновлено пользователей: {hits_users}. "
        f"Длительность: {dur_s} сек."
    )

    with db_session() as db:
        st = get_or_create_settings(db)
        st.net_scan_last_run_ts = finished
        st.net_scan_last_summary = summary
        st.net_scan_is_running = False
        st.net_scan_run_started_ts = None
        db.commit()

    logger.info("Network scan done: %s", summary)
    return {"status": "ok", "summary": summary}
