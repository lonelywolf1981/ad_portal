from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from ..crypto import decrypt_str
from ..deps import require_session_or_hx_redirect
from ..host_logon import find_logged_on_users
from ..repo import db_session, get_or_create_settings
from ..utils.numbers import clamp_int
from ..webui import htmx_alert, templates, ui_result


router = APIRouter()


@router.get("/hosts/logon", response_class=HTMLResponse)
def hosts_logon(request: Request, target: str = ""):
    """Определить, какой пользователь(и) залогинен на удалённом хосте."""
    auth = require_session_or_hx_redirect(request)
    if not isinstance(auth, dict):
        return auth

    is_htmx = request.headers.get("HX-Request") is not None

    target = (target or "").strip()
    if len(target) < 2:
        if is_htmx:
            # HTMX doesn't swap content for 4xx/5xx responses by default.
            # For inline feedback we return 200 and show an alert in the target.
            return htmx_alert(ui_result(False, "Введите имя хоста или IP."), status_code=200)
        return templates.TemplateResponse(
            "host_logon_results.html",
            {
                "request": request,
                "target": target,
                "users": [],
                "method": "",
                "elapsed_ms": 0,
                "attempts": [],
                "error": "Введите имя хоста или IP.",
            },
        )

    with db_session() as db:
        st = get_or_create_settings(db)

        domain_suffix = (st.ad_domain or "").strip()
        query_user = (st.host_query_username or "").strip()
        query_pwd = decrypt_str(getattr(st, "host_query_password_enc", "") or "")
        timeout_s = clamp_int(getattr(st, "host_query_timeout_s", 60), default=60, min_v=5, max_v=300)

    users, method, elapsed_ms, attempts = find_logged_on_users(
        raw_target=target,
        domain_suffix=domain_suffix,
        query_username=query_user,
        query_password=query_pwd,
        per_method_timeout_s=timeout_s,
    )

    return templates.TemplateResponse(
        "host_logon_results.html",
        {
            "request": request,
            "target": target,
            "users": users,
            "method": method,
            "elapsed_ms": elapsed_ms,
            "attempts": attempts,
            "error": "",
        },
    )
