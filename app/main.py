from __future__ import annotations


from fastapi import FastAPI, Request, Form, HTTPException, status
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .env_settings import get_env
from .db import engine
from .models import Base
from .repo import db_session, get_or_create_settings, ensure_bootstrap_admin
from .security import hash_password
from .session import create_session
from .deps import get_current_user, require_settings_access, SESSION_MAX_AGE
from .services import (
    audit_login, local_authenticate, ad_authenticate, save_settings,
    ad_test_and_load_groups, get_groups_cache, groups_dn_to_name_map
)
from .ad_utils import split_group_dns

Base.metadata.create_all(bind=engine)

app = FastAPI(title="AD Portal")
templates = Jinja2Templates(directory="app/templates")
app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.on_event("startup")
def _startup():
    env = get_env()
    with db_session() as db:
        get_or_create_settings(db)
        ensure_bootstrap_admin(db, env.bootstrap_admin_user, hash_password(env.bootstrap_admin_password))


def _set_session_cookie(resp: RedirectResponse, payload: dict) -> None:
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


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    with db_session() as db:
        st = get_or_create_settings(db)
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "auth_mode": st.auth_mode, "error_local": "", "error_ad": ""},
        )


@app.post("/login/local")
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
                {"request": request, "auth_mode": st.auth_mode, "error_local": "Неверный логин или пароль.", "error_ad": ""},
            )

        payload = {"u": res["username"], "dn": res["display_name"], "auth": "local", "settings": res["settings"], "groups": []}
        resp = RedirectResponse(url="/", status_code=303)
        _set_session_cookie(resp, payload)
        audit_login(db, res["username"], "local", True, ip, ua, "ok", "")
        return resp


@app.post("/login/ad")
def login_ad(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = request.client.host if request.client else ""
    ua = request.headers.get("user-agent", "")

    with db_session() as db:
        st = get_or_create_settings(db)
        if st.auth_mode != "ad":
            audit_login(db, username, "ad", False, ip, ua, "forbidden", "ad-auth-disabled")
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "auth_mode": st.auth_mode, "error_local": "", "error_ad": "AD-вход отключён в настройках."},
            )

        res, msg = ad_authenticate(db, st, username.strip(), password)
        if not res:
            audit_login(db, username, "ad", False, ip, ua, "invalid", msg)
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "auth_mode": st.auth_mode, "error_local": "", "error_ad": msg},
            )

        payload = {"u": res["username"], "dn": res["display_name"], "auth": "ad", "settings": res["settings"], "groups": res["groups"]}
        resp = RedirectResponse(url="/", status_code=303)
        _set_session_cookie(resp, payload)
        audit_login(db, res["username"], "ad", True, ip, ua, "ok", "")
        return resp


@app.get("/logout")
def logout():
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie("ad_portal_session")
    return resp


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    try:
        user = get_current_user(request)
    except HTTPException as e:
        if e.status_code == status.HTTP_401_UNAUTHORIZED:
            return RedirectResponse(url="/login", status_code=303)
        raise
    return templates.TemplateResponse("index.html", {"request": request, "user": user})


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    user = require_settings_access(request)
    saved = request.query_params.get("saved") == "1"

    with db_session() as db:
        st = get_or_create_settings(db)
        groups_cache = get_groups_cache(st)

        class G:
            def __init__(self, dn, name):
                self.dn = dn
                self.name = name

        groups_cache_objs = [G(x.get("dn", ""), x.get("name", "")) for x in groups_cache if x.get("dn") and x.get("name")]
        dn_name_map = groups_dn_to_name_map(st)

        selected_app = set(split_group_dns(st.allowed_app_group_dns))
        selected_settings = set(split_group_dns(st.allowed_settings_group_dns))

        return templates.TemplateResponse(
            "settings.html",
            {
                "request": request,
                "user": user,
                "st": st,
                "saved": saved,
                "groups_cache": groups_cache_objs,
                "dn_name_map": dn_name_map,
                "selected_app_dns": selected_app,
                "selected_settings_dns": selected_settings,
            },
        )


@app.post("/settings/save")
def settings_save(
    request: Request,
    auth_mode: str = Form("local"),
    ad_dc_short: str = Form(""),
    ad_domain: str = Form(""),
    ad_conn_mode: str = Form("ldaps"),
    ad_bind_username: str = Form(""),
    ad_bind_password: str = Form(""),
    allowed_app_group_dns: list[str] = Form([]),
    allowed_settings_group_dns: list[str] = Form([]),
):
    _ = require_settings_access(request)

    with db_session() as db:
        st = get_or_create_settings(db)
        save_settings(
            db,
            st,
            {
                "auth_mode": auth_mode,
                "ad_dc_short": ad_dc_short,
                "ad_domain": ad_domain,
                "ad_conn_mode": ad_conn_mode,
                "ad_bind_username": ad_bind_username,
                "ad_bind_password": ad_bind_password,
                "allowed_app_group_dns": allowed_app_group_dns,
                "allowed_settings_group_dns": allowed_settings_group_dns,
            },
        )
    return RedirectResponse(url="/settings?saved=1", status_code=303)


@app.post("/settings/ad/test", response_class=HTMLResponse)
def settings_ad_test(
    request: Request,
    ad_dc_short: str = Form(""),
    ad_domain: str = Form(""),
    ad_conn_mode: str = Form("ldaps"),
    ad_bind_username: str = Form(""),
    ad_bind_password: str = Form(""),
):
    _ = require_settings_access(request)

    with db_session() as db:
        st = get_or_create_settings(db)

        ok, msg, _groups = ad_test_and_load_groups(
            db,
            st,
            override={
                "ad_dc_short": ad_dc_short.strip(),
                "ad_domain": ad_domain.strip(),
                "ad_conn_mode": ad_conn_mode.strip(),
                "ad_bind_username": ad_bind_username.strip(),
                "ad_bind_password": ad_bind_password,
            },
        )

        alert_cls = "alert-success" if ok else "alert-danger"

        groups_cache = get_groups_cache(st)

        class G:
            def __init__(self, dn, name):
                self.dn = dn
                self.name = name

        groups_cache_objs = [G(x.get("dn", ""), x.get("name", "")) for x in groups_cache if x.get("dn") and x.get("name")]
        dn_name_map = groups_dn_to_name_map(st)

        selected_app = set(split_group_dns(st.allowed_app_group_dns))
        selected_settings = set(split_group_dns(st.allowed_settings_group_dns))

        groups_html = templates.get_template("settings_groups.html").render(
            {
                "groups_cache": groups_cache_objs,
                "dn_name_map": dn_name_map,
                "selected_app_dns": selected_app,
                "selected_settings_dns": selected_settings,
                "request": request,
            }
        )

        return HTMLResponse(
            content=f'''
            <div class="alert {alert_cls} py-2 mb-3">{msg}</div>
            <div id="group-selectors" hx-swap-oob="true">
              {groups_html}
            </div>
            ''',
            status_code=200,
        )
