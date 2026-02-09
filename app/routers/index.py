from __future__ import annotations

import re

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from ..deps import require_initialized_or_redirect
from ..repo import db_session, get_or_create_settings
from ..services.ad import ad_cfg_from_settings
from ..ad import ADClient
from ..timezone_utils import format_ru_local
from ..webui import templates


router = APIRouter()


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

    # AD stats (placeholders by default; page must not fail if AD is unreachable)
    ad_users_total: int | str = "—"
    ad_users_enabled: int | str = "—"
    online_users: int | str = "—"

    try:
        with db_session() as db:
            st = get_or_create_settings(db)

            net_scan_enabled = bool(getattr(st, "net_scan_enabled", False))
            cidrs_txt = (getattr(st, "net_scan_cidrs", "") or "").strip()
            net_scan_ready = bool(net_scan_enabled and cidrs_txt)

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

            # AD totals (total + enabled)
            cfg = ad_cfg_from_settings(st)
            if cfg:
                client = ADClient(cfg)
                ok, _ = client.service_bind()
                if ok:
                    total, enabled = client.count_users_total_and_enabled()
                    ad_users_total = total
                    ad_users_enabled = enabled
    except Exception:
        # do not fail the main page if settings schema is missing or AD is down
        pass

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
            "ad_users_total": ad_users_total,
            "ad_users_enabled": ad_users_enabled,
            "online_users": online_users,
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
        pass

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
