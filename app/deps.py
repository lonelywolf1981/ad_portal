from __future__ import annotations

from fastapi import Request, HTTPException, status
from fastapi.responses import RedirectResponse, Response
from .session import read_session

SESSION_MAX_AGE = 8 * 60 * 60


def get_current_user(request: Request) -> dict:
    token = request.cookies.get("ad_portal_session", "")
    data = read_session(token, SESSION_MAX_AGE) if token else None
    if not data:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return data


def require_session_or_hx_redirect(request: Request, redirect_to: str = "/login") -> dict | Response:
    """Return user dict if session is valid, otherwise redirect to login.

    - For HTMX requests: respond with 401 + HX-Redirect header.
    - For normal browser navigation: 303 redirect.
    """

    token = request.cookies.get("ad_portal_session", "")
    data = read_session(token, SESSION_MAX_AGE) if token else None
    if data:
        return data

    is_hx = bool(request.headers.get("HX-Request"))
    if is_hx:
        return Response(status_code=status.HTTP_401_UNAUTHORIZED, headers={"HX-Redirect": redirect_to})
    return RedirectResponse(url=redirect_to, status_code=status.HTTP_303_SEE_OTHER)


def require_settings_access(request: Request) -> dict:
    user = get_current_user(request)
    if not user.get("settings", False):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    return user


def require_initialized_or_redirect(request: Request) -> dict | Response:
    """Требует активную сессию и (для боевых разделов) завершённую инициализацию.

    Важно:
    - Проверка сессии выполняется первой (иначе получаются «вечные» редиректы в init).
    - В неинициализированном состоянии разрешаем переход на /settings (форма) и /settings?mode=init (чеклист).
    - Для HTMX используем HX-Redirect.
    """

    auth = require_session_or_hx_redirect(request)
    if not isinstance(auth, dict):
        return auth

    # Разрешённые пути в init-режиме (нужны, чтобы админ мог заполнить настройки).
    path = request.url.path or ""
    if path.startswith("/settings"):
        return auth
    if path.startswith("/login"):
        return auth
    if path.startswith("/static"):
        return auth

    # Polling endpoints are safe to call during init (HTMX widgets on pages).
    if path.startswith("/net-scan/poll"):
        return auth

    from .repo import db_session
    from .services.settings.storage import get_settings

    with db_session() as db:
        st = get_settings(db)
        if not bool(st.is_initialized):
            is_hx = bool(request.headers.get("HX-Request"))
            if is_hx:
                return Response(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    headers={"HX-Redirect": "/settings?mode=init"},
                )
            return RedirectResponse(url="/settings?mode=init", status_code=status.HTTP_303_SEE_OTHER)

    return auth
