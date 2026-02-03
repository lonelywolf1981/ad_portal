from __future__ import annotations

from fastapi import Request, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.responses import Response
from .session import read_session

SESSION_MAX_AGE = 8 * 60 * 60


def get_current_user(request: Request) -> dict:
    token = request.cookies.get("ad_portal_session", "")
    data = read_session(token, SESSION_MAX_AGE) if token else None
    if not data:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return data


def require_settings_access(request: Request) -> dict:
    user = get_current_user(request)
    if not user.get("settings", False):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    return user


def require_session_or_hx_redirect(request: Request, *, redirect_to: str = "/login") -> dict | Response:
    """Return session user or an appropriate redirect response.

    - For HTMX requests (HX-Request header): return 401 + HX-Redirect.
    - For normal requests: return 303 redirect.

    This keeps router code DRY and consistent.
    """
    try:
        return get_current_user(request)
    except HTTPException as e:
        if e.status_code != status.HTTP_401_UNAUTHORIZED:
            raise

        # HTMX -> client-side redirect via header
        if request.headers.get("HX-Request") is not None:
            return HTMLResponse(content="", status_code=401, headers={"HX-Redirect": redirect_to})

        # Full page -> classic redirect
        return RedirectResponse(url=redirect_to, status_code=303)
