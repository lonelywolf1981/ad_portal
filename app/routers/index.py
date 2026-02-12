from __future__ import annotations

import re
import threading
from datetime import datetime, timedelta, timezone
import logging

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select

from ..deps import require_initialized_or_redirect
from ..repo import db_session, get_or_create_settings
from ..services.ad import ad_cfg_from_settings
from ..ad import ADClient
from ..models import ScanStatsHistory, HostShare
from ..shares import hidden_share_expr
from ..timezone_utils import format_ru_local
from ..webui import templates


router = APIRouter()
log = logging.getLogger(__name__)
_AD_STATS_TTL = timedelta(seconds=60)
_AD_STATS_LOCK = threading.Lock()
_AD_STATS_CACHE: dict[str, object] = {
    "ts": None,
    "total": "—",
    "enabled": "—",
}


def _get_ad_stats_cached(cfg) -> tuple[int | str, int | str]:
    now = datetime.utcnow()
    with _AD_STATS_LOCK:
        ts = _AD_STATS_CACHE.get("ts")
        if isinstance(ts, datetime) and (now - ts) <= _AD_STATS_TTL:
            return _AD_STATS_CACHE.get("total", "—"), _AD_STATS_CACHE.get("enabled", "—")

    total: int | str = "—"
    enabled: int | str = "—"
    try:
        client = ADClient(cfg)
        ok, _ = client.service_bind()
        if ok:
            total, enabled = client.count_users_total_and_enabled()
    except Exception:
        pass

    with _AD_STATS_LOCK:
        _AD_STATS_CACHE["ts"] = now
        _AD_STATS_CACHE["total"] = total
        _AD_STATS_CACHE["enabled"] = enabled
    return total, enabled


@router.get("/", response_class=HTMLResponse)
def index(request: Request):
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth
    user = auth

    net_scan_last_run = ""
    net_scan_last_summary = ""
    net_scan_last_token = ""
    net_scan_is_running = False
    net_scan_enabled = False
    net_scan_ready = False
    ip_phones_ready = False

    # AD stats (placeholders by default; page must not fail if AD is unreachable)
    ad_users_total: int | str = "—"
    ad_users_enabled: int | str = "—"
    online_users: int | str = "—"
    matches_last_scan: int | str = "—"
    shares_visible: int | str = "—"
    shares_hidden: int | str = "—"
    stats_history_points: list[dict] = []
    stats_retention_days = 30
    stats_scans_total = 0
    stats_chart_line_color = "#0d6efd"
    stats_chart_fill_color = "rgba(13,110,253,0.16)"
    stats_chart_point_color = "#0d6efd"
    stats_chart_show_points = True

    try:
        with db_session() as db:
            st = get_or_create_settings(db)
            stats_retention_days = max(7, min(365, int(getattr(st, "net_scan_stats_retention_days", 30) or 30)))
            stats_chart_line_color = getattr(st, "net_scan_chart_line_color", "#0d6efd") or "#0d6efd"
            stats_chart_fill_color = getattr(st, "net_scan_chart_fill_color", "rgba(13,110,253,0.16)") or "rgba(13,110,253,0.16)"
            stats_chart_point_color = getattr(st, "net_scan_chart_point_color", "#0d6efd") or "#0d6efd"
            stats_chart_show_points = bool(getattr(st, "net_scan_chart_show_points", True))

            net_scan_enabled = bool(getattr(st, "net_scan_enabled", False))
            cidrs_txt = (getattr(st, "net_scan_cidrs", "") or "").strip()
            net_scan_ready = bool(net_scan_enabled and cidrs_txt)
            ip_phones_ready = bool(
                bool(getattr(st, "ip_phones_enabled", False))
                and bool((getattr(st, "ip_phones_ami_host", "") or "").strip())
                and bool((getattr(st, "ip_phones_ami_user", "") or "").strip())
                and bool((getattr(st, "ip_phones_ami_password_enc", "") or "").strip())
            )

            dt = getattr(st, "net_scan_last_run_ts", None)
            if dt:
                net_scan_last_run = format_ru_local(dt)
                try:
                    net_scan_last_token = dt.isoformat(timespec="seconds")
                except Exception:
                    net_scan_last_token = str(dt)

            net_scan_last_summary = (getattr(st, "net_scan_last_summary", "") or "").strip()

            # Authoritative "running" marker is net_scan_lock_ts (set/cleared by background task).
            net_scan_is_running = bool(getattr(st, "net_scan_lock_ts", None))

            # Online users count comes from net-scan summary ("Обновлено пользователей: N")
            m = re.search(r"Обновлено пользователей:\s*(\d+)", net_scan_last_summary)
            if m:
                online_users = int(m.group(1))

            # Количество сопоставлений из последнего скана
            m2 = re.search(r"Обновлено сопоставлений:\s*(\d+)", net_scan_last_summary)
            if m2:
                matches_last_scan = int(m2.group(1))

            # Количество SMB-шар: общие и скрытые (по биту SPECIAL и/или суффиксу '$').
            from sqlalchemy import func as sa_func
            try:
                shares_visible = int(
                    db.scalar(
                        select(sa_func.count()).select_from(HostShare)
                        .where(~hidden_share_expr())
                    ) or 0
                )
                shares_hidden = int(
                    db.scalar(
                        select(sa_func.count()).select_from(HostShare)
                        .where(hidden_share_expr())
                    ) or 0
                )
            except Exception:
                shares_visible = "—"
                shares_hidden = "—"

            hist_rows = db.scalars(
                select(ScanStatsHistory)
                .where(ScanStatsHistory.ts >= (datetime.utcnow() - timedelta(days=stats_retention_days)))
                .order_by(ScanStatsHistory.ts.asc())
            ).all()
            if hist_rows:
                stats_scans_total = len(hist_rows)
                last = hist_rows[-1]
                if last.users_total is not None:
                    ad_users_total = int(last.users_total)
                if last.users_enabled is not None:
                    ad_users_enabled = int(last.users_enabled)
                if last.users_online is not None:
                    online_users = int(last.users_online)

                stats_history_points = [
                    {
                        "ts": (
                            r.ts.replace(tzinfo=timezone.utc).isoformat(timespec="seconds")
                            if isinstance(r.ts, datetime)
                            else str(r.ts)
                        ),
                        "total": (int(r.users_total) if r.users_total is not None else None),
                        "enabled": (int(r.users_enabled) if r.users_enabled is not None else None),
                        "online": (int(r.users_online) if r.users_online is not None else None),
                    }
                    for r in hist_rows
                ]
            else:
                # Fallback for initial period with no history yet.
                cfg = ad_cfg_from_settings(st)
                if cfg:
                    ad_users_total, ad_users_enabled = _get_ad_stats_cached(cfg)
    except Exception:
        # Do not fail the main page if settings schema is missing or AD is down.
        log.warning("Ошибка при подготовке данных главной страницы", exc_info=True)

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "user": user,
            "net_scan_last_run": net_scan_last_run,
            "net_scan_last_summary": net_scan_last_summary,
            "net_scan_last_token": net_scan_last_token,
            "net_scan_is_running": net_scan_is_running,
            "net_scan_enabled": net_scan_enabled,
            "net_scan_ready": net_scan_ready,
            "ip_phones_ready": ip_phones_ready,
            "ad_users_total": ad_users_total,
            "ad_users_enabled": ad_users_enabled,
            "online_users": online_users,
            "stats_history_points": stats_history_points,
            "stats_retention_days": stats_retention_days,
            "stats_scans_total": stats_scans_total,
            "stats_chart_line_color": stats_chart_line_color,
            "stats_chart_fill_color": stats_chart_fill_color,
            "stats_chart_point_color": stats_chart_point_color,
            "stats_chart_show_points": stats_chart_show_points,
            "matches_last_scan": matches_last_scan,
            "shares_visible": shares_visible,
            "shares_hidden": shares_hidden,
        },
    )


@router.get("/net-scan/poll", response_class=HTMLResponse)
def net_scan_poll(request: Request, last: str = ""):
    """HTMX poll endpoint.

    Behaviour:
    - While scan is running: keep polling (no reload).
    - When a new scan *finishes* (last_run token changes and lock is cleared): ask HTMX to refresh the page.
    """
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    last = (last or "").strip()
    cur_token = ""
    is_running = False
    try:
        with db_session() as db:
            st = get_or_create_settings(db)
            net_scan_enabled = bool(getattr(st, "net_scan_enabled", False))
            dt = getattr(st, "net_scan_last_run_ts", None)
            if dt:
                try:
                    cur_token = dt.isoformat(timespec="seconds")
                except Exception:
                    cur_token = str(dt)
            # Authoritative "running" marker is net_scan_lock_ts (set/cleared by background task).
            is_running = bool(getattr(st, "net_scan_lock_ts", None))
    except Exception:
        log.warning("Ошибка poll-эндпоинта net-scan", exc_info=True)

    # Refresh only when scan finished and we see a NEW last_run token.
    should_refresh = (not is_running) and bool(cur_token) and (cur_token != last)

    headers = {}
    if should_refresh:
        # HTMX native full refresh (more reliable than injecting <script>).
        headers["HX-Refresh"] = "true"

    # Keep polling; always emit next token in the URL.
    html = (
        f"<div id='net-scan-poll' class='d-none' "
        f"hx-get='/net-scan/poll?last={cur_token}' "
        f"hx-trigger='load, every 5s' "
        f"hx-swap='outerHTML'></div>"
    )
    return HTMLResponse(content=html, status_code=200, headers=headers)
