from __future__ import annotations

from fastapi import Request, HTTPException, status
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
