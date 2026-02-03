from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import HTMLResponse

from ..crypto import decrypt_str
from ..deps import get_current_user
from ..host_logon import find_logged_on_users
from ..repo import db_session, get_or_create_settings
from ..webui import templates


router = APIRouter()


@router.get("/hosts/logon", response_class=HTMLResponse)
def hosts_logon(request: Request, target: str = ""):
    """Определить, какой пользователь(и) залогинен на удалённом хосте."""
    try:
        _ = get_current_user(request)
    except HTTPException as e:
        if e.status_code == status.HTTP_401_UNAUTHORIZED:
            return HTMLResponse(content="", status_code=401, headers={"HX-Redirect": "/login"})
        raise

    target = (target or "").strip()
    if len(target) < 2:
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
        timeout_s = int(getattr(st, "host_query_timeout_s", 60) or 60)

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
