from __future__ import annotations


from fastapi import FastAPI, Request, Form, HTTPException, status
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import base64
from datetime import datetime, timezone
import re

from sqlalchemy import text

from .env_settings import get_env
from .db import engine
from .models import Base
from .repo import db_session, get_or_create_settings, ensure_bootstrap_admin
from .security import hash_password
from .crypto import decrypt_str
from .session import create_session
from .deps import get_current_user, require_settings_access, SESSION_MAX_AGE
from .services import (
    audit_login, local_authenticate, ad_authenticate, save_settings,
    ad_test_and_load_groups, get_groups_cache, groups_dn_to_name_map
)
from .services import ad_cfg_from_settings
from .ad_utils import split_group_dns
from .ldap_client import ADClient
from .host_logon import find_logged_on_users

Base.metadata.create_all(bind=engine)


def _migrate_app_settings() -> None:
    """Minimal SQLite schema migration for newly added columns (no Alembic)."""
    with engine.begin() as conn:
        cols = [r[1] for r in conn.exec_driver_sql("PRAGMA table_info(app_settings)").fetchall()]

        if "host_query_username" not in cols:
            conn.exec_driver_sql(
                "ALTER TABLE app_settings ADD COLUMN host_query_username VARCHAR(128) NOT NULL DEFAULT ''"
            )
        if "host_query_password_enc" not in cols:
            conn.exec_driver_sql(
                "ALTER TABLE app_settings ADD COLUMN host_query_password_enc VARCHAR(2048) NOT NULL DEFAULT ''"
            )
        if "host_query_timeout_s" not in cols:
            conn.exec_driver_sql(
                "ALTER TABLE app_settings ADD COLUMN host_query_timeout_s INTEGER NOT NULL DEFAULT 60"
            )


app = FastAPI(title="AD Portal")
templates = Jinja2Templates(directory="app/templates")
app.mount("/static", StaticFiles(directory="app/static"), name="static")


def _dn_to_id(dn: str) -> str:
    """URL-safe identifier for a DN (used for HTML ids and query params)."""
    b = base64.urlsafe_b64encode((dn or "").encode("utf-8")).decode("ascii")
    return b.rstrip("=")


def _id_to_dn(s: str) -> str:
    s = (s or "").strip()
    if not s:
        raise ValueError("empty")
    pad = "=" * (-len(s) % 4)
    raw = base64.urlsafe_b64decode((s + pad).encode("ascii"))
    return raw.decode("utf-8", errors="replace")


def _dn_first_component_value(dn: str) -> str:
    """Return first RDN value from a DN (e.g. CN=USB-Deny,OU=... -> USB-Deny)."""
    s = (dn or "").strip()
    if not s:
        return ""

    # Extract first RDN (handle escaped commas)
    first = []
    esc = False
    for ch in s:
        if esc:
            first.append(ch)
            esc = False
            continue
        if ch == "\\":
            esc = True
            continue
        if ch == ",":
            break
        first.append(ch)
    rdn = "".join(first).strip()

    if "=" in rdn:
        _, val = rdn.split("=", 1)
        val = val.strip()
    else:
        val = rdn

    # Unescape common DN escapes
    val = val.replace("\\,", ",").replace("\\+", "+").replace("\\=", "=").replace('\\"', '"')
    return val.strip()


def _fmt_dt_human(v: str) -> str:
    """Human-friendly datetime: DD.MM.YYYY HH:MM:SS (best-effort).

    Supports ISO-8601 and AD GeneralizedTime (YYYYmmddHHMMSS(.fff)Z).
    """
    s = (v or "").strip()
    if not s:
        return ""

    # AD GeneralizedTime: 20260126042000.0Z or 20260126042000Z
    m = re.match(r"^(\d{14})(?:\.(\d+))?Z$", s)
    if m:
        try:
            dt = datetime.strptime(m.group(1), "%Y%m%d%H%M%S")
            return dt.strftime("%d.%m.%Y %H:%M:%S")
        except Exception:
            pass

    try:
        s2 = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s2)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt.strftime("%d.%m.%Y %H:%M:%S")
    except Exception:
        return s


# Оставляем только поля, которые нужны в «Подробнее»
_DETAIL_LABELS: dict[str, str] = {
    "department": "Отдел",
    "memberOf": "Группы",
    "whenCreated": "Создан",
    "whenChanged": "Изменён",
    "lastLogonTimestamp": "Последний вход (timestamp)",
    "pwdLastSet": "Пароль обновлён",
    "distinguishedName": "Путь",
    "otherPager": "ПИН код",
}


def _build_detail_items(details: dict) -> list[dict]:
    order = [
        "department",
        "memberOf",
        "whenCreated",
        "whenChanged",
        "lastLogonTimestamp",
        "pwdLastSet",
        "distinguishedName",
        "otherPager",
    ]

    items: list[dict] = []

    # Special rule: show PIN code even if empty
    has_other_pager = "otherPager" in details

    for k in order:
        label = _DETAIL_LABELS.get(k, k)

        if k not in details:
            if k == "otherPager" and not has_other_pager:
                items.append({"key": k, "label": label, "value": "—", "is_list": False})
            continue

        v = details.get(k)

        # Groups: show short names only (CN/first RDN value) as badges
        if k == "memberOf":
            vals = v if isinstance(v, list) else [v]
            names = []
            for gdn in vals:
                n = _dn_first_component_value(str(gdn))
                if n:
                    names.append(n)
            names = sorted(set(names), key=lambda x: x.lower())
            if not names:
                continue
            items.append({"key": k, "label": label, "value": names, "is_list": True, "is_badges": True})
            continue

        # Human-friendly date/time
        if k in {"whenCreated", "whenChanged", "lastLogonTimestamp", "pwdLastSet"}:
            s = str(v).strip()
            if not s:
                continue
            items.append({"key": k, "label": label, "value": _fmt_dt_human(s), "is_list": False})
            continue

        if isinstance(v, list):
            vv = [str(x).strip() for x in v if str(x).strip()]
            if not vv:
                if k == "otherPager":
                    items.append({"key": k, "label": label, "value": "—", "is_list": False})
                continue
            items.append({"key": k, "label": label, "value": vv, "is_list": True})
        else:
            s = str(v).strip()
            if not s:
                if k == "otherPager":
                    items.append({"key": k, "label": label, "value": "—", "is_list": False})
                continue
            items.append({"key": k, "label": label, "value": s, "is_list": False})

    return items


@app.on_event("startup")
def _startup():
    _migrate_app_settings()
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

        payload = {
            "u": res["username"],
            "dn": res.get("display_name", ""),
            "auth": "ad",
            "settings": bool(res.get("settings", False)),
            "groups": res.get("groups", []),
        }
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
def settings_page(request: Request, saved: int = 0):
    user = require_settings_access(request)
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
    host_query_username: str = Form(""),
    host_query_password: str = Form(""),
    host_query_timeout_s: int = Form(60),
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
                "host_query_username": host_query_username,
                "host_query_password": host_query_password,
                "host_query_timeout_s": host_query_timeout_s,
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
    host_query_username: str = Form(""),
    host_query_password: str = Form(""),
    host_query_timeout_s: int = Form(60),
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
                "host_query_username": host_query_username,
                "host_query_password": host_query_password,
                "host_query_timeout_s": host_query_timeout_s,
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


@app.get("/users/search", response_class=HTMLResponse)
def users_search(request: Request, q: str = ""):
    # Require an active session; for htmx requests redirect via HX-Redirect.
    try:
        _ = get_current_user(request)
    except HTTPException as e:
        if e.status_code == status.HTTP_401_UNAUTHORIZED:
            return HTMLResponse(content="", status_code=401, headers={"HX-Redirect": "/login"})
        raise

    q = (q or "").strip()
    if len(q) < 2:
        return templates.TemplateResponse(
            "users_results.html",
            {"request": request, "users": [], "error": "Введите минимум 2 символа для поиска."},
        )

    with db_session() as db:
        st = get_or_create_settings(db)
        cfg = ad_cfg_from_settings(st)
        if not cfg:
            return templates.TemplateResponse(
                "users_results.html",
                {"request": request, "users": [], "error": "AD не настроен. Откройте «Настройки» и заполните параметры подключения."},
            )

    client = ADClient(cfg)
    ok, msg, items = client.search_users(q, limit=40)
    if not ok:
        return templates.TemplateResponse(
            "users_results.html",
            {"request": request, "users": [], "error": msg or "Ошибка поиска в AD."},
        )

    users = []
    for it in items:
        dn = it.get("dn", "")
        users.append({
            "id": _dn_to_id(dn),
            "fio": it.get("fio", "") or "",
            "login": it.get("login", "") or "",
            "email": it.get("mail", "") or "",
        })

    return templates.TemplateResponse(
        "users_results.html",
        {"request": request, "users": users, "error": ""},
    )


@app.get("/users/details", response_class=HTMLResponse)
def user_details(request: Request, id: str = ""):
    try:
        _ = get_current_user(request)
    except HTTPException as e:
        if e.status_code == status.HTTP_401_UNAUTHORIZED:
            return HTMLResponse(content="", status_code=401, headers={"HX-Redirect": "/login"})
        raise

    try:
        dn = _id_to_dn(id)
    except Exception:
        return templates.TemplateResponse(
            "user_details.html",
            {"request": request, "items": [], "error": "Некорректный идентификатор пользователя."},
        )

    with db_session() as db:
        st = get_or_create_settings(db)
        cfg = ad_cfg_from_settings(st)
        if not cfg:
            return templates.TemplateResponse(
                "user_details.html",
                {"request": request, "items": [], "error": "AD не настроен."},
            )

    client = ADClient(cfg)
    ok, msg, details = client.get_user_details(dn)
    if not ok:
        return templates.TemplateResponse(
            "user_details.html",
            {"request": request, "items": [], "error": msg or "Не удалось получить данные из AD."},
        )

    items = _build_detail_items(details)
    return templates.TemplateResponse(
        "user_details.html",
        {"request": request, "items": items, "error": ""},
    )


@app.get("/hosts/logon", response_class=HTMLResponse)
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
            {"request": request, "target": target, "users": [], "method": "", "elapsed_ms": 0, "attempts": [], "error": "Введите имя хоста или IP."},
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
