from __future__ import annotations

import io

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from openpyxl import Workbook

from ..deps import require_session_or_hx_redirect, require_initialized_or_redirect
from ..mappings import cleanup_host_user_matches, search_host_user_matches
from ..presence import fmt_dt_ru
from ..repo import db_session
from ..utils.net import ip_key, ip_subnet_key, natural_key, short_hostname, subnet_badge_class
from ..webui import templates

router = APIRouter()

def _require_presence_enabled() -> bool:
    """Presence/mapping features depend on periodic net-scan.

    If net-scan is disabled, show a friendly message instead of empty/cryptic errors.
    """
    from ..repo import db_session, get_or_create_settings

    try:
        with db_session() as db:
            st = get_or_create_settings(db)
            enabled = bool(getattr(st, "net_scan_enabled", False))
            cidrs_txt = (getattr(st, "net_scan_cidrs", "") or "").strip()
            return bool(enabled and cidrs_txt)
    except Exception:
        # If settings are not available, be conservative and disable presence.
        return False


def _presence_disabled_response(request: Request) -> HTMLResponse:
    return HTMLResponse(
        content="""<div class='alert alert-secondary mb-0'>
        Вкладка «Сопоставления» недоступна, потому что <strong>периодическое сетевое сканирование</strong> не настроено
        (выключено или не заданы диапазоны CIDR).
        Откройте <a href='/settings?mode=init'>чеклист</a> и выполните пункты для вкладки «Сопоставления».
        </div>""",
        status_code=200,
    )



@router.get("/presence/search", response_class=HTMLResponse)
def presence_search(request: Request, q: str = "", sort: str = "when", dir: str = "desc"):
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    if not _require_presence_enabled():
        return _presence_disabled_response(request)

    q = (q or "").strip()
    sort = (sort or "when").strip().lower()
    dir = (dir or "desc").strip().lower()
    if sort not in {"host", "ip", "login", "when"}:
        sort = "when"
    if dir not in {"asc", "desc"}:
        dir = "desc"
    lim = 200 if not q else 500

    with db_session() as db:
        cleanup_host_user_matches(db, retention_days=31)
        rows = search_host_user_matches(db, q=q, limit=lim)

    reverse = (dir == "desc")

    def _row_key(r):
        if sort == "host":
            return natural_key(short_hostname(getattr(r, "host", "")))
        if sort == "ip":
            return ip_key(getattr(r, "ip", ""))
        if sort == "login":
            return natural_key(getattr(r, "user_login", ""))
        dt = getattr(r, "last_seen_ts", None)
        return (dt is None, dt)

    try:
        rows = sorted(rows, key=_row_key, reverse=reverse)
    except Exception:
        pass

    items = []
    for r in rows:
        ip = (r.ip or "").strip()
        subnet = ip_subnet_key(ip)
        items.append(
            {
                "host": (r.host or "").strip(),
                "ip": ip,
                "subnet": subnet,
                "subnet_class": subnet_badge_class(subnet),
                "login": (r.user_login or "").strip(),
                "when": fmt_dt_ru(getattr(r, "last_seen_ts", None)),
            }
        )

    return templates.TemplateResponse(
        "presence_results.html",
        {"request": request, "items": items, "q": q, "sort": sort, "dir": dir},
    )


@router.get("/presence/export.xlsx")
def presence_export_xlsx(request: Request, q: str = "", sort: str = "when", dir: str = "desc"):
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        # If session is missing, always redirect for a download endpoint.
        return RedirectResponse(url="/login", status_code=303)

    q = (q or "").strip()
    sort = (sort or "when").strip().lower()
    dir = (dir or "desc").strip().lower()
    if sort not in {"host", "ip", "login", "when"}:
        sort = "when"
    if dir not in {"asc", "desc"}:
        dir = "desc"
    lim = 200 if not q else 500

    with db_session() as db:
        cleanup_host_user_matches(db, retention_days=31)
        rows = search_host_user_matches(db, q=q, limit=lim)

    reverse = (dir == "desc")

    def _row_key(r):
        if sort == "host":
            return natural_key(short_hostname(getattr(r, "host", "")))
        if sort == "ip":
            return ip_key(getattr(r, "ip", ""))
        if sort == "login":
            return natural_key(getattr(r, "user_login", ""))
        dt = getattr(r, "last_seen_ts", None)
        return (dt is None, dt)

    try:
        rows = sorted(rows, key=_row_key, reverse=reverse)
    except Exception:
        pass

    wb = Workbook()
    ws = wb.active
    ws.title = "Сопоставления"

    ws.append(["Имя хоста", "IP", "Логин", "Когда обнаружено"])
    for cell in ws[1]:
        cell.font = cell.font.copy(bold=True)

    for r in rows:
        ws.append(
            [
                (r.host or "").strip() or "—",
                (r.ip or "").strip() or "—",
                (r.user_login or "").strip() or "",
                fmt_dt_ru(getattr(r, "last_seen_ts", None)) or "—",
            ]
        )

    for i, w in enumerate([26, 18, 22, 22], start=1):
        ws.column_dimensions[chr(ord("A") + i - 1)].width = w

    bio = io.BytesIO()
    wb.save(bio)
    bio.seek(0)

    headers = {"Content-Disposition": "attachment; filename=\"presence.xlsx\""}
    return StreamingResponse(
        bio,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers=headers,
    )
