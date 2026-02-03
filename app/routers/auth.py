from __future__ import annotations

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..repo import db_session, get_or_create_settings
from ..services import ad_authenticate, audit_login, local_authenticate
from ..webui import set_session_cookie, templates


router = APIRouter()


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    with db_session() as db:
        st = get_or_create_settings(db)
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "auth_mode": st.auth_mode, "error_local": "", "error_ad": ""},
        )


@router.post("/login/local")
def login_local(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = request.client.host if request.client else ""
    ua = request.headers.get("user-agent", "")

    with db_session() as db:
        st = get_or_create_settings(db)
        res = local_authenticate(db, username.strip(), password)
        if not res:
            audit_login(db, username, "local", False, ip, ua, "invalid", "invalid-local-credentials")
            return templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "auth_mode": st.auth_mode,
                    "error_local": "Неверный логин или пароль.",
                    "error_ad": "",
                },
            )

        payload = {
            "u": res["username"],
            "dn": res["display_name"],
            "auth": "local",
            "settings": res["settings"],
            "groups": [],
        }
        resp = RedirectResponse(url="/", status_code=303)
        set_session_cookie(resp, payload)
        audit_login(db, res["username"], "local", True, ip, ua, "ok", "")
        return resp


@router.post("/login/ad")
def login_ad(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = request.client.host if request.client else ""
    ua = request.headers.get("user-agent", "")

    with db_session() as db:
        st = get_or_create_settings(db)
        if st.auth_mode != "ad":
            audit_login(db, username, "ad", False, ip, ua, "forbidden", "ad-auth-disabled")
            return templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "auth_mode": st.auth_mode,
                    "error_local": "",
                    "error_ad": "AD-вход отключён в настройках.",
                },
            )

        res, msg = ad_authenticate(db, st, username.strip(), password)
        if not res:
            audit_login(db, username, "ad", False, ip, ua, "invalid", msg)
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "auth_mode": st.auth_mode, "error_local": "", "error_ad": msg},
            )

        payload = {
            "u": res["username"],
            "dn": res.get("display_name", ""),
            "auth": "ad",
            "settings": bool(res.get("settings", False)),
            "groups": res.get("groups", []),
        }
        resp = RedirectResponse(url="/", status_code=303)
        set_session_cookie(resp, payload)
        audit_login(db, res["username"], "ad", True, ip, ua, "ok", "")
        return resp


@router.get("/logout")
def logout():
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie("ad_portal_session")
    return resp
