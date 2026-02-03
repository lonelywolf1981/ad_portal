from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

from ..deps import get_current_user
from ..repo import db_session, get_or_create_settings
from ..timezone_utils import format_ru_local
from ..webui import templates


router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def index(request: Request):
    try:
        user = get_current_user(request)
    except HTTPException as e:
        if e.status_code == status.HTTP_401_UNAUTHORIZED:
            return RedirectResponse(url="/login", status_code=303)
        raise

    net_scan_last_run = ""
    net_scan_last_summary = ""
    net_scan_last_token = ""
    net_scan_is_running = False
    try:
        with db_session() as db:
            st = get_or_create_settings(db)
            dt = getattr(st, "net_scan_last_run_ts", None)
            if dt:
                net_scan_last_run = format_ru_local(dt)
                try:
                    net_scan_last_token = dt.isoformat(timespec="seconds")
                except Exception:
                    net_scan_last_token = str(dt)
            net_scan_last_summary = (getattr(st, "net_scan_last_summary", "") or "").strip()
            net_scan_is_running = bool(getattr(st, "net_scan_is_running", False))
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
        },
    )


@router.get("/net-scan/poll", response_class=HTMLResponse)
def net_scan_poll(request: Request, last: str = ""):
    """HTMX poll endpoint: triggers full page reload when a new scan finishes."""
    try:
        _ = get_current_user(request)
    except HTTPException as e:
        if e.status_code == status.HTTP_401_UNAUTHORIZED:
            return HTMLResponse(content="", status_code=401, headers={"HX-Redirect": "/login"})
        raise

    last = (last or "").strip()
    cur_token = ""
    is_running = False
    try:
        with db_session() as db:
            st = get_or_create_settings(db)
            dt = getattr(st, "net_scan_last_run_ts", None)
            if dt:
                try:
                    cur_token = dt.isoformat(timespec="seconds")
                except Exception:
                    cur_token = str(dt)
            is_running = bool(getattr(st, "net_scan_is_running", False))
    except Exception:
        pass

    should_reload = bool(cur_token and last and (cur_token != last) and (not is_running))
    html = (
        f"<div id='net-scan-poll' hx-get='/net-scan/poll?last={cur_token}' hx-trigger='every 10s' hx-swap='outerHTML'>"
        f"{'<script>window.location.reload();</script>' if should_reload else ''}"
        f"</div>"
    )
    return HTMLResponse(content=html, status_code=200)
