from __future__ import annotations

import io

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from openpyxl import Workbook

from ..deps import get_current_user
from ..mappings import cleanup_host_user_matches, search_host_user_matches
from ..presence import fmt_dt_ru
from ..repo import db_session
from ..utils.net import ip_key, ip_subnet_key, natural_key, short_hostname, subnet_badge_class
from ..webui import templates

router = APIRouter()


@router.get("/presence/search", response_class=HTMLResponse)
def presence_search(request: Request, q: str = "", sort: str = "when", dir: str = "desc"):
    try:
        _ = get_current_user(request)
    except HTTPException as e:
        if e.status_code == status.HTTP_401_UNAUTHORIZED:
            return HTMLResponse(content="", status_code=401, headers={"HX-Redirect": "/login"})
        raise

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
    try:
        _ = get_current_user(request)
    except HTTPException as e:
        if e.status_code == status.HTTP_401_UNAUTHORIZED:
            return RedirectResponse(url="/login", status_code=303)
        raise

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
