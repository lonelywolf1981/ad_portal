from __future__ import annotations

import io
import logging
import re

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from openpyxl import Workbook

from ..crypto import decrypt_str
from ..deps import require_initialized_or_redirect
from ..host_query.api import close_host_share
from ..presence import fmt_dt_ru
from ..repo import db_session, get_or_create_settings
from ..shares import delete_share, fix_remark_encoding, search_shares, STYPE_SPECIAL
from ..utils.numbers import clamp_int
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


def _clean_corrupted_text(text: str) -> str:
    s = (text or "").strip()
    if not s or not _CORRUPTED_RE.search(s):
        return s
    s = re.sub(r"\?+", " ", s)
    s = re.sub(r"\s+", " ", s).strip(" .,-")
    # Если после очистки не осталось букв/цифр — это чистый мусор кодировки.
    if not re.search(r"[A-Za-zА-Яа-я0-9]", s):
        return ""
    return s


def _fix_remark(share_name: str, remark: str) -> str:
    """Исправление повреждённых описаний шар (проблемы кодировки).

    Если remark содержит 3+ символов «?» подряд — это утерянная кириллица.
    Для стандартных Windows-шар подставляем известное описание.
    Для дисковых шар вида X$ — «Стандартный общий ресурс».
    """
    remark = fix_remark_encoding(remark)
    if not remark or not _CORRUPTED_RE.search(remark):
        return remark
    name_upper = (share_name or "").strip().upper()
    # Известные шары
    if name_upper in _KNOWN_REMARKS:
        return _KNOWN_REMARKS[name_upper]
    # Буквенные диски: C$, D$, E$ и т.д.
    if re.match(r"^[A-Z]\$$", name_upper):
        return "Стандартный общий ресурс"
    # Остальные — максимально безопасная очистка от мусора кодировки.
    return _clean_corrupted_text(remark)


def _share_type_label(share_name: str, t: int) -> str:
    """Человекочитаемый тип шары."""
    base = t & 0x0FFFFFFF
    labels = {STYPE_DISKTREE: "Диск", STYPE_PRINTQ: "Принтер", STYPE_DEVICE: "Устройство", STYPE_IPC: "IPC"}
    label = labels.get(base, f"0x{t:x}")
    if _is_hidden_share(share_name, t):
        label += " (скрытый)"
    return label


def _share_kind_and_icon(share_name: str, share_type: int) -> tuple[str, str]:
    """UI hint: kind + icon for share link.

    base types:
      0 Disk, 1 PrintQueue, 2 Device, 3 IPC
    hidden/system:
      STYPE_SPECIAL bit and/or '$' suffix
    """
    raw = int(share_type or 0)
    base = raw & 0x0FFFFFFF
    if _is_hidden_share(share_name, raw):
        return ("hidden", "🔒")
    if base == STYPE_PRINTQ:
        return ("print", "🖨️")
    if base == STYPE_IPC:
        return ("ipc", "🔌")
    if base == STYPE_DEVICE:
        return ("device", "💽")
    return ("disk", "📁")


def _is_hidden_share(share_name: str, share_type: int) -> bool:
    return bool((share_type & STYPE_SPECIAL) != 0 or (share_name or "").strip().endswith("$"))


def _parse_hidden_flag(raw: str | int | None) -> bool:
    if raw is None:
        return False
    s = str(raw).strip().lower()
    return s in {"1", "true", "on", "yes"}


def _is_protected_share_name(name: str) -> bool:
    n = (name or "").strip().upper()
    if n in {"ADMIN$", "IPC$", "PRINT$"}:
        return True
    return bool(re.match(r"^[A-Z]\$$", n))


def _render_shares_results(
    request: Request,
    *,
    q: str,
    sort: str,
    dir: str,
    show_hidden: bool,
    action_result: dict | None = None,
):
    lim = 200 if not q else 500
    with db_session() as db:
        rows = search_shares(db, q=q, show_hidden=show_hidden, limit=lim)

    reverse = (dir == "desc")

    # Group results by (host, ip) so the UI can collapse per-host blocks.
    groups_map: dict[tuple[str, str], dict] = {}
    for r in rows:
        host = (getattr(r, "host", "") or "").strip()
        ip = (getattr(r, "ip", "") or "").strip()
        key = (host, ip)

        g = groups_map.get(key)
        if g is None:
            subnet = ip_subnet_key(ip)
            g = {
                "host": host,
                "ip": ip,
                "subnet": subnet,
                "subnet_class": subnet_badge_class(subnet),
                "last_seen_ts": getattr(r, "last_seen_ts", None),
                "items": [],
            }
            groups_map[key] = g

        # Track latest seen ts per host-group for "when" sort on groups.
        ts = getattr(r, "last_seen_ts", None)
        if ts and (g.get("last_seen_ts") is None or ts > g["last_seen_ts"]):
            g["last_seen_ts"] = ts

        name = (getattr(r, "share_name", "") or "").strip()
        raw_type = int(getattr(r, "share_type", 0) or 0)
        kind, icon = _share_kind_and_icon(name, raw_type)
        g["items"].append(
            {
                "share_name": name,
                "share_name_display": _clean_corrupted_text(name),
                "share_type": _share_type_label(name, raw_type),
                "share_type_raw": raw_type,
                "share_kind": kind,
                "share_icon": icon,
                "is_hidden": _is_hidden_share(name, raw_type),
                "remark": _fix_remark(name, (getattr(r, "remark", "") or "").strip()),
                "when": fmt_dt_ru(ts),
                "last_seen_ts": ts,
                "can_close": not _is_protected_share_name(name),
            }
        )

    groups = list(groups_map.values())

    # Sorting behavior:
    # - host/ip: sort host blocks
    # - when: sort host blocks by latest detected share timestamp
    # - name/type: sort shares inside each host block
    try:
        if sort == "host":
            groups = sorted(groups, key=lambda g: natural_key(short_hostname(g.get("host", ""))), reverse=reverse)
        elif sort == "ip":
            groups = sorted(groups, key=lambda g: ip_key(g.get("ip", "")), reverse=reverse)
        elif sort == "when":
            groups = sorted(groups, key=lambda g: (g.get("last_seen_ts") is None, g.get("last_seen_ts")), reverse=reverse)
        elif sort == "name":
            for g in groups:
                g["items"] = sorted(g["items"], key=lambda it: natural_key(it.get("share_name", "")), reverse=reverse)
            groups = sorted(groups, key=lambda g: natural_key(short_hostname(g.get("host", ""))))
        elif sort == "type":
            for g in groups:
                g["items"] = sorted(g["items"], key=lambda it: (it.get("share_type_raw", 0),), reverse=reverse)
            groups = sorted(groups, key=lambda g: natural_key(short_hostname(g.get("host", ""))))
        else:
            groups = sorted(groups, key=lambda g: natural_key(short_hostname(g.get("host", ""))))
    except Exception:
        log.warning("Не удалось отсортировать результаты общих папок", exc_info=True)

    return templates.TemplateResponse(
        "shares_results.html",
        {
            "request": request,
            "groups": groups,
            "q": q,
            "sort": sort,
            "dir": dir,
            "hidden": 1 if show_hidden else 0,
            "action_result": action_result,
        },
    )


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
    return _render_shares_results(
        request,
        q=q,
        sort=sort,
        dir=dir,
        show_hidden=show_hidden,
    )


@router.post("/shares/close", response_class=HTMLResponse)
def shares_close(
    request: Request,
    host: str = Form(""),
    ip: str = Form(""),
    share_name: str = Form(""),
    q: str = Form(""),
    sort: str = Form("when"),
    dir: str = Form("desc"),
    hidden: str = Form("0"),
):
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    q = (q or "").strip()
    sort = (sort or "host").strip().lower()
    dir = (dir or "asc").strip().lower()
    if sort not in {"host", "ip", "name", "type", "when"}:
        sort = "host"
    if dir not in {"asc", "desc"}:
        dir = "asc"
    show_hidden = _parse_hidden_flag(hidden)

    user_name = (auth.get("username") or "").strip() or "unknown"
    if not bool(auth.get("settings", False)):
        return _render_shares_results(
            request,
            q=q,
            sort=sort,
            dir=dir,
            show_hidden=show_hidden,
            action_result={"ok": False, "message": "Недостаточно прав для закрытия ресурса."},
        )

    host = (host or "").strip()
    ip = (ip or "").strip()
    share_name = (share_name or "").strip()
    target = host or ip

    if not target or not share_name:
        return _render_shares_results(
            request,
            q=q,
            sort=sort,
            dir=dir,
            show_hidden=show_hidden,
            action_result={"ok": False, "message": "Не указан хост/IP или имя ресурса."},
        )

    if _is_protected_share_name(share_name):
        return _render_shares_results(
            request,
            q=q,
            sort=sort,
            dir=dir,
            show_hidden=show_hidden,
            action_result={"ok": False, "message": f"Системный ресурс {share_name} нельзя закрыть из интерфейса."},
        )

    with db_session() as db:
        st = get_or_create_settings(db)
        domain_suffix = (st.ad_domain or "").strip()
        query_user = (st.host_query_username or "").strip()
        query_pwd = decrypt_str(getattr(st, "host_query_password_enc", "") or "")
        timeout_s = clamp_int(getattr(st, "host_query_timeout_s", 60), default=60, min_v=5, max_v=180)

    ok, msg, method = close_host_share(
        raw_target=target,
        domain_suffix=domain_suffix,
        query_username=query_user,
        query_password=query_pwd,
        share_name=share_name,
        per_method_timeout_s=timeout_s,
    )
    if ok:
        try:
            with db_session() as db:
                delete_share(db, host=host, share_name=share_name)
        except Exception:
            log.warning("Не удалось удалить шару из локального кэша после закрытия", exc_info=True)
        log.info("Share closed by %s: target=%s share=%s method=%s", user_name, target, share_name, method)
        res = {"ok": True, "message": f"Доступ к ресурсу {share_name} закрыт ({method})."}
    else:
        log.warning("Share close failed by %s: target=%s share=%s method=%s msg=%s", user_name, target, share_name, method, msg)
        res = {"ok": False, "message": f"Не удалось закрыть ресурс {share_name}.", "details": msg}

    return _render_shares_results(
        request,
        q=q,
        sort=sort,
        dir=dir,
        show_hidden=show_hidden,
        action_result=res,
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
