from __future__ import annotations

import re

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from ..deps import require_initialized_or_redirect
from ..repo import db_session, get_or_create_settings
from ..timezone_utils import format_ru_local
from ..webui import templates
from ..services.ad import ad_cfg_from_settings
from ..ad import ADClient


router = APIRouter()


_RE_UPDATED_USERS = re.compile(r"Обновлено\s+пользовател(?:ей|я):\s*(\d+)", re.IGNORECASE)


def _parse_updated_users(summary: str) -> int | None:
    if not summary:
        return None
    m = _RE_UPDATED_USERS.search(summary)
    if not m:
        return None
    try:
        return int(m.group(1))
    except Exception:
        return None


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

    # AD / scan stats for the "Сеанс" block.
    ad_users_total: int | None = None
    ad_users_enabled: int | None = None
    online_users_last_scan: int | None = None

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

            # --- Online users (authoritative source = net-scan summary) ---
            # We deliberately do NOT infer this from timestamps (TZ/type issues); the scanner already reports the count.
            online_users_last_scan = _parse_updated_users(net_scan_last_summary)

            # --- AD user counts (total / enabled) ---
            # Show only when AD is configured; failure should NOT break the page.
            try:
                cfg = ad_cfg_from_settings(st)
                if cfg:
                    client = ADClient(cfg)
                    ok_t, _, cnt_t = client.count_users(enabled_only=False)
                    ok_e, _, cnt_e = client.count_users(enabled_only=True)
                    if ok_t:
                        ad_users_total = int(cnt_t)
                    if ok_e:
                        ad_users_enabled = int(cnt_e)
            except Exception:
                pass
    except Exception:
        # do not fail the main page if settings schema is missing
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
            "online_users_last_scan": online_users_last_scan,
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
