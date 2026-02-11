from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse

from ..deps import require_initialized_or_redirect
from ..services.ip_phones import get_avail_with_ad
from ..utils.net import ip_key, natural_key
from ..webui import templates

router = APIRouter()
log = logging.getLogger(__name__)


@router.get("/ip-phones", response_class=HTMLResponse)
def ip_phones_tab(request: Request):
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth
    return templates.TemplateResponse("ip_phones_fragment.html", {"request": request, "user": auth})


@router.get("/ip-phones/avail-with-ad", response_class=HTMLResponse)
def ip_phones_avail_with_ad(
    request: Request,
    q: str = "",
    sort: str = "extension",
    dir: str = "asc",
    filter: str = "all",
):
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    sort = (sort or "extension").strip().lower()
    dir = (dir or "asc").strip().lower()
    filter = (filter or "all").strip().lower()
    if sort not in {"extension", "ip", "user"}:
        sort = "extension"
    if dir not in {"asc", "desc"}:
        dir = "asc"
    if filter not in {"all", "matched", "unmatched"}:
        filter = "all"

    try:
        data = get_avail_with_ad(q)

        # Счётчики для бейджей (после текстового поиска, до фильтра matched/unmatched)
        all_items = data.get("items") or []
        badge_total = len(all_items)
        badge_matched = sum(1 for row in all_items if row.get("users"))
        badge_unmatched = badge_total - badge_matched

        # Фильтрация по сопоставлению
        items = all_items
        if filter == "matched":
            items = [row for row in items if row.get("users")]
        elif filter == "unmatched":
            items = [row for row in items if not row.get("users")]

        # Сортировка
        reverse = (dir == "desc")

        def _row_key(row):
            if sort == "extension":
                return natural_key(row.get("extension", ""))
            if sort == "ip":
                return ip_key(row.get("ip", ""))
            # sort == "user": без сопоставления — в конец при asc
            users = row.get("users") or []
            if not users:
                return (1, [])
            fio = users[0].get("fio", "") if users else ""
            return (0, natural_key(fio))

        try:
            items = sorted(items, key=_row_key, reverse=reverse)
        except Exception:
            log.warning("Не удалось отсортировать результаты IP-телефонов", exc_info=True)

        data["items"] = items
        data["total"] = len(items)
        data["matched"] = sum(1 for row in items if row.get("users"))
        data["unmatched"] = max(0, len(items) - data["matched"])
        data["badge_total"] = badge_total
        data["badge_matched"] = badge_matched
        data["badge_unmatched"] = badge_unmatched

        return templates.TemplateResponse(
            "partials/ip_phones_results.html",
            {
                "request": request,
                "data": data,
                "user": auth,
                "sort": sort,
                "dir": dir,
                "filter": filter,
            },
        )
    except Exception:
        log.exception("Не удалось загрузить данные IP-телефонов")
        return HTMLResponse(
            "<div id='ip-phones-results' class='mt-3'>"
            "<div class='alert alert-danger mb-0'>Ошибка загрузки данных IP-телефонов. Попробуйте позже.</div>"
            "</div>",
            status_code=200,
        )


@router.get("/ip-phones/health")
def ip_phones_health(request: Request):
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth
    try:
        data = get_avail_with_ad("")
        return JSONResponse(
            {
                "status": "ok" if data.get("ok") else "degraded",
                "total": int(data.get("total", 0) or 0),
                "matched": int(data.get("matched", 0) or 0),
                "message": data.get("message", ""),
                "ad_warning": data.get("ad_warning", ""),
            }
        )
    except Exception as exc:
        return JSONResponse({"status": "error", "error": str(exc)}, status_code=500)
