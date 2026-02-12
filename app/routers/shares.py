from __future__ import annotations

import io
import logging
import re

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from openpyxl import Workbook

from ..deps import require_session_or_hx_redirect, require_initialized_or_redirect
from ..presence import fmt_dt_ru
from ..repo import db_session
from ..shares import search_shares, STYPE_SPECIAL
from ..utils.net import ip_key, ip_subnet_key, natural_key, short_hostname, subnet_badge_class
from ..webui import templates

router = APIRouter()
log = logging.getLogger(__name__)


# ---------- Константы типов шар ----------
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs
STYPE_DISKTREE = 0x0
STYPE_PRINTQ = 0x1
STYPE_DEVICE = 0x2
STYPE_IPC = 0x3

# Стандартные описания Windows-шар (русская локаль).
# Используются для исправления повреждённой кодировки в существующих данных.
_KNOWN_REMARKS: dict[str, str] = {
    "IPC$": "Удаленный IPC",
    "ADMIN$": "Удаленный Admin",
}
# Паттерн: 3+ символов «?» подряд — признак повреждённой кодировки
_CORRUPTED_RE = re.compile(r"\?{3,}")


def _fix_remark(share_name: str, remark: str) -> str:
    """Исправление повреждённых описаний шар (проблемы кодировки).

    Если remark содержит 3+ символов «?» подряд — это утерянная кириллица.
    Для стандартных Windows-шар подставляем известное описание.
    Для дисковых шар вида X$ — «Стандартный общий ресурс».
    """
    if not remark or not _CORRUPTED_RE.search(remark):
        return remark
    name_upper = (share_name or "").strip().upper()
    # Известные шары
    if name_upper in _KNOWN_REMARKS:
        return _KNOWN_REMARKS[name_upper]
    # Буквенные диски: C$, D$, E$ и т.д.
    if re.match(r"^[A-Z]\$$", name_upper):
        return "Стандартный общий ресурс"
    # Остальные — убираем мусор из «?», оставляем ASCII-часть
    cleaned = _CORRUPTED_RE.sub("…", remark).strip()
    return cleaned if cleaned and cleaned != "…" else ""


def _share_type_label(share_name: str, t: int) -> str:
    """Человекочитаемый тип шары."""
    base = t & 0x0FFFFFFF
    labels = {STYPE_DISKTREE: "Диск", STYPE_PRINTQ: "Принтер", STYPE_DEVICE: "Устройство", STYPE_IPC: "IPC"}
    label = labels.get(base, f"0x{t:x}")
    if _is_hidden_share(share_name, t):
        label += " (скрытый)"
    return label


def _is_hidden_share(share_name: str, share_type: int) -> bool:
    return bool((share_type & STYPE_SPECIAL) != 0 or (share_name or "").strip().endswith("$"))


def _parse_hidden_flag(raw: str | int | None) -> bool:
    if raw is None:
        return False
    s = str(raw).strip().lower()
    return s in {"1", "true", "on", "yes"}


def _require_shares_enabled() -> bool:
    """Шары доступны только при включённом net-scan."""
    from ..repo import db_session, get_or_create_settings

    try:
        with db_session() as db:
            st = get_or_create_settings(db)
            enabled = bool(getattr(st, "net_scan_enabled", False))
            cidrs_txt = (getattr(st, "net_scan_cidrs", "") or "").strip()
            return bool(enabled and cidrs_txt)
    except Exception:
        log.warning("Не удалось проверить доступность вкладки Общие папки", exc_info=True)
        return False


def _shares_disabled_response(request: Request) -> HTMLResponse:
    return HTMLResponse(
        content="""<div class='alert alert-secondary mb-0'>
        Вкладка «Общие папки» недоступна, потому что <strong>периодическое сетевое сканирование</strong> не настроено
        (выключено или не заданы диапазоны CIDR).
        Откройте <a href='/settings?mode=init'>чеклист</a> и выполните пункты для вкладки «Сопоставления».
        </div>""",
        status_code=200,
    )


@router.get("/shares/search", response_class=HTMLResponse)
def shares_search(
    request: Request,
    q: str = "",
    sort: str = "when",
    dir: str = "desc",
    hidden: str = "0",
):
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    if not _require_shares_enabled():
        return _shares_disabled_response(request)

    q = (q or "").strip()
    sort = (sort or "host").strip().lower()
    dir = (dir or "asc").strip().lower()
    if sort not in {"host", "ip", "name", "type", "when"}:
        sort = "host"
    if dir not in {"asc", "desc"}:
        dir = "asc"

    show_hidden = _parse_hidden_flag(hidden)
    lim = 200 if not q else 500

    with db_session() as db:
        rows = search_shares(db, q=q, show_hidden=show_hidden, limit=lim)

    reverse = (dir == "desc")

    def _row_key(r):
        if sort == "host":
            return natural_key(short_hostname(getattr(r, "host", "")))
        if sort == "ip":
            return ip_key(getattr(r, "ip", ""))
        if sort == "name":
            return natural_key(getattr(r, "share_name", ""))
        if sort == "type":
            return (getattr(r, "share_type", 0) or 0,)
        dt = getattr(r, "last_seen_ts", None)
        return (dt is None, dt)

    try:
        rows = sorted(rows, key=_row_key, reverse=reverse)
    except Exception:
        log.warning("Не удалось отсортировать результаты общих папок", exc_info=True)

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
                "share_name": (r.share_name or "").strip(),
                "share_type": _share_type_label(r.share_name or "", r.share_type or 0),
                "is_hidden": _is_hidden_share(r.share_name or "", r.share_type or 0),
                "remark": _fix_remark(r.share_name or "", (r.remark or "").strip()),
                "when": fmt_dt_ru(getattr(r, "last_seen_ts", None)),
            }
        )

    grouped_items = []
    i = 0
    while i < len(items):
        key = (items[i]["host"], items[i]["ip"])
        j = i + 1
        while j < len(items) and (items[j]["host"], items[j]["ip"]) == key:
            j += 1
        span = j - i
        for k in range(i, j):
            row = dict(items[k])
            row["show_host"] = (k == i)
            row["host_rowspan"] = span
            grouped_items.append(row)
        i = j

    return templates.TemplateResponse(
        "shares_results.html",
        {
            "request": request,
            "items": grouped_items,
            "q": q,
            "sort": sort,
            "dir": dir,
            "hidden": 1 if show_hidden else 0,
        },
    )


@router.get("/shares/export.xlsx")
def shares_export_xlsx(
    request: Request,
    q: str = "",
    sort: str = "when",
    dir: str = "desc",
    hidden: str = "0",
):
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return RedirectResponse(url="/login", status_code=303)

    q = (q or "").strip()
    sort = (sort or "host").strip().lower()
    dir = (dir or "asc").strip().lower()
    if sort not in {"host", "ip", "name", "type", "when"}:
        sort = "host"
    if dir not in {"asc", "desc"}:
        dir = "asc"

    show_hidden = _parse_hidden_flag(hidden)
    lim = 200 if not q else 500

    with db_session() as db:
        rows = search_shares(db, q=q, show_hidden=show_hidden, limit=lim)

    reverse = (dir == "desc")

    def _row_key(r):
        if sort == "host":
            return natural_key(short_hostname(getattr(r, "host", "")))
        if sort == "ip":
            return ip_key(getattr(r, "ip", ""))
        if sort == "name":
            return natural_key(getattr(r, "share_name", ""))
        if sort == "type":
            return (getattr(r, "share_type", 0) or 0,)
        dt = getattr(r, "last_seen_ts", None)
        return (dt is None, dt)

    try:
        rows = sorted(rows, key=_row_key, reverse=reverse)
    except Exception:
        log.warning("Не удалось отсортировать результаты общих папок для экспорта", exc_info=True)

    wb = Workbook()
    ws = wb.active
    ws.title = "Общие папки"

    ws.append(["Имя хоста", "IP", "Имя ресурса", "Тип", "Описание", "Когда обнаружено"])
    for cell in ws[1]:
        cell.font = cell.font.copy(bold=True)

    for r in rows:
        ws.append(
            [
                (r.host or "").strip() or "—",
                (r.ip or "").strip() or "—",
                (r.share_name or "").strip() or "",
                _share_type_label(r.share_name or "", r.share_type or 0),
                _fix_remark(r.share_name or "", (r.remark or "").strip()) or "",
                fmt_dt_ru(getattr(r, "last_seen_ts", None)) or "—",
            ]
        )

    for i, w in enumerate([26, 18, 22, 14, 30, 22], start=1):
        ws.column_dimensions[chr(ord("A") + i - 1)].width = w

    bio = io.BytesIO()
    wb.save(bio)
    bio.seek(0)

    headers = {"Content-Disposition": "attachment; filename=\"shares.xlsx\""}
    return StreamingResponse(
        bio,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers=headers,
    )
