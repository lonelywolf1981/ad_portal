from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse

from ..deps import require_initialized_or_redirect
from ..services.ip_phones import get_avail_with_ad
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
def ip_phones_avail_with_ad(request: Request, q: str = ""):
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth
    try:
        data = get_avail_with_ad(q)
        return templates.TemplateResponse("partials/ip_phones_results.html", {"request": request, "data": data, "user": auth})
    except Exception:
        log.exception("Не удалось загрузить данные IP-телефонов")
        return HTMLResponse(
            "<div class='alert alert-danger mb-0'>Ошибка загрузки данных IP-телефонов. Попробуйте позже.</div>",
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
