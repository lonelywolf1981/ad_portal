from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from ..repo import db_session, get_or_create_settings
from ..services import ad_authenticate, audit_login, local_authenticate
from ..webui import htmx_alert, set_session_cookie, templates, ui_result


router = APIRouter()


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    with db_session() as db:
        st = get_or_create_settings(db)
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "auth_mode": st.auth_mode, "error_local": "", "error_ad": ""},
        )


def _is_hx(request: Request) -> bool:
    return bool(request.headers.get("HX-Request"))


@router.post("/login/local")
async def login_local(request: Request):
    form = await request.form()
    username = str(form.get("username") or "").strip()
    password = str(form.get("password") or "")
    ip = request.client.host if request.client else ""
    ua = request.headers.get("user-agent", "")

    with db_session() as db:
        st = get_or_create_settings(db)
        if not username:
            if _is_hx(request):
                return htmx_alert(ui_result(False, "Введите логин."), status_code=200)
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "auth_mode": st.auth_mode, "error_local": "Введите логин.", "error_ad": ""},
            )
        if not password:
            if _is_hx(request):
                return htmx_alert(ui_result(False, "Введите пароль."), status_code=200)
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "auth_mode": st.auth_mode, "error_local": "Введите пароль.", "error_ad": ""},
            )

        res = local_authenticate(db, username, password)
        if not res:
            audit_login(db, username, "local", False, ip, ua, "invalid", "invalid-local-credentials")
            if _is_hx(request):
                return htmx_alert(ui_result(False, "Неверный логин или пароль."), status_code=200)
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "auth_mode": st.auth_mode, "error_local": "Неверный логин или пароль.", "error_ad": ""},
            )

        payload = {
            "u": res["username"],
            "dn": res["display_name"],
            "auth": "local",
            "settings": res["settings"],
            "groups": [],
        }
        if _is_hx(request):
            resp: Response = Response(status_code=200, headers={"HX-Redirect": "/"})
        else:
            resp = RedirectResponse(url="/", status_code=303)
        set_session_cookie(resp, payload)
        audit_login(db, res["username"], "local", True, ip, ua, "ok", "")
        return resp


@router.post("/login/ad")
async def login_ad(request: Request):
    form = await request.form()
    username = str(form.get("username") or "").strip()
    password = str(form.get("password") or "")
    ip = request.client.host if request.client else ""
    ua = request.headers.get("user-agent", "")

    with db_session() as db:
        st = get_or_create_settings(db)
        if st.auth_mode != "ad":
            audit_login(db, username, "ad", False, ip, ua, "forbidden", "ad-auth-disabled")
            if _is_hx(request):
                return htmx_alert(ui_result(False, "AD-вход отключён в настройках."), status_code=200)
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "auth_mode": st.auth_mode, "error_local": "", "error_ad": "AD-вход отключён в настройках."},
            )

        if not username:
            if _is_hx(request):
                return htmx_alert(ui_result(False, "Введите логин."), status_code=200)
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "auth_mode": st.auth_mode, "error_local": "", "error_ad": "Введите логин."},
            )
        if not password:
            if _is_hx(request):
                return htmx_alert(ui_result(False, "Введите пароль."), status_code=200)
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "auth_mode": st.auth_mode, "error_local": "", "error_ad": "Введите пароль."},
            )

        res, msg = ad_authenticate(db, st, username, password)
        if not res:
            audit_login(db, username, "ad", False, ip, ua, "invalid", msg)
            if _is_hx(request):
                return htmx_alert(ui_result(False, msg), status_code=200)
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
        if _is_hx(request):
            resp: Response = Response(status_code=200, headers={"HX-Redirect": "/"})
        else:
            resp = RedirectResponse(url="/", status_code=303)
        set_session_cookie(resp, payload)
        audit_login(db, res["username"], "ad", True, ip, ua, "ok", "")
        return resp


@router.get("/logout")
def logout():
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie("ad_portal_session")
    return resp
