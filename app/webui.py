from __future__ import annotations

from html import escape

from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from .deps import SESSION_MAX_AGE
from .env_settings import get_env
from .session import create_session


templates = Jinja2Templates(directory="app/templates")


def ui_result(ok: bool, message: str, details: str | None = None) -> dict:
    """Unified UI result shape for HTMX interactions.

    Format:
      {"ok": bool, "message": str, "details": str}
    """

    return {
        "ok": bool(ok),
        "message": str(message or ""),
        "details": str(details or ""),
    }


def htmx_alert(result: dict, *, status_code: int = 200) -> HTMLResponse:
    """Return a Bootstrap alert HTML snippet for HTMX swaps.

    We intentionally generate markup inline (no separate partial/template) to avoid
    package/template wiring issues and keep the surface minimal.
    """

    ok = bool(result.get("ok"))
    message = escape(str(result.get("message") or ""))
    details = escape(str(result.get("details") or ""))

    # Bootstrap: danger for errors, success for ok, secondary if empty message.
    if not message and not details:
        level = "secondary"
    else:
        level = "success" if ok else "danger"

    parts: list[str] = [f"<div class='alert alert-{level} py-2 mb-0'>"]
    if message:
        parts.append(f"<div>{message}</div>")
    if details:
        parts.append(f"<div class='small mt-1'><code>{details}</code></div>")
    parts.append("</div>")
    return HTMLResponse("".join(parts), status_code=status_code)


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
