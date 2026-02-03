from __future__ import annotations

from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from .deps import SESSION_MAX_AGE
from .env_settings import get_env
from .session import create_session


templates = Jinja2Templates(directory="app/templates")


def set_session_cookie(resp: RedirectResponse, payload: dict) -> None:
    """Set signed session cookie (kept in one place for all auth flows)."""
    env = get_env()
    token = create_session(payload)
    resp.set_cookie(
        key="ad_portal_session",
        value=token,
        httponly=True,
        secure=env.cookie_secure,
        samesite="lax",
        max_age=SESSION_MAX_AGE,
    )
