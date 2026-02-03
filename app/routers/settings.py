from __future__ import annotations

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..ad_utils import split_group_dns
from ..deps import require_session_or_hx_redirect
from ..repo import db_session, get_or_create_settings
from ..services import (
    ad_test_and_load_groups,
    get_groups_cache,
    groups_dn_to_name_map,
    save_settings,
)
from ..timezone_utils import format_ru_local
from ..webui import templates


router = APIRouter()


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, saved: int = 0):
    auth = require_session_or_hx_redirect(request)
    if not isinstance(auth, dict):
        return auth

    user = auth
    if not user.get("settings", False):
        return HTMLResponse(
            content="<div class='container py-4'><div class='alert alert-danger'>Доступ запрещён.</div></div>",
            status_code=403,
        )
    with db_session() as db:
        st = get_or_create_settings(db)

        net_scan_last_run_ui = "—"
        try:
            dt = getattr(st, "net_scan_last_run_ts", None)
            if dt:
                net_scan_last_run_ui = format_ru_local(dt) or "—"
        except Exception:
            pass

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
                "net_scan_last_run_ui": net_scan_last_run_ui,
            },
        )

# остальной файл без изменений


@router.post("/settings/save")
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
    net_scan_enabled: str = Form(""),
    net_scan_cidrs: str = Form(""),
    net_scan_interval_min: int = Form(120),
    net_scan_concurrency: int = Form(64),
    net_scan_method_timeout_s: int = Form(20),
    net_scan_probe_timeout_ms: int = Form(350),
    allowed_app_group_dns: list[str] = Form([]),
    allowed_settings_group_dns: list[str] = Form([]),
):
    auth = require_session_or_hx_redirect(request)
    if not isinstance(auth, dict):
        return auth
    if not auth.get("settings", False):
        return HTMLResponse(
            content="<div class='container py-4'><div class='alert alert-danger'>Доступ запрещён.</div></div>",
            status_code=403,
        )

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
                "net_scan_enabled": net_scan_enabled,
                "net_scan_cidrs": net_scan_cidrs,
                "net_scan_interval_min": net_scan_interval_min,
                "net_scan_concurrency": net_scan_concurrency,
                "net_scan_method_timeout_s": net_scan_method_timeout_s,
                "net_scan_probe_timeout_ms": net_scan_probe_timeout_ms,
                "allowed_app_group_dns": allowed_app_group_dns,
                "allowed_settings_group_dns": allowed_settings_group_dns,
            },
        )
    return RedirectResponse(url="/settings?saved=1", status_code=303)


@router.post("/settings/ad/test", response_class=HTMLResponse)
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
    auth = require_session_or_hx_redirect(request)
    if not isinstance(auth, dict):
        return auth
    if not auth.get("settings", False):
        return HTMLResponse(
            content="<div class='alert alert-danger py-2 mb-3'>Доступ запрещён.</div>",
            status_code=403,
        )

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
            content=f"""
            <div class="alert {alert_cls} py-2 mb-3">{msg}</div>
            <div id="group-selectors" hx-swap-oob="true">
              {groups_html}
            </div>
            """,
            status_code=200,
        )


@router.post("/settings/net_scan/run", response_class=HTMLResponse)
def settings_net_scan_run(request: Request):
    auth = require_session_or_hx_redirect(request)
    if not isinstance(auth, dict):
        return auth
    if not auth.get("settings", False):
        return HTMLResponse(
            content="<div class='alert alert-danger py-2 mb-0'>Доступ запрещён.</div>",
            status_code=403,
        )

    with db_session() as db:
        st = get_or_create_settings(db)
        if not getattr(st, "net_scan_enabled", False):
            return HTMLResponse(
                content="<div class='alert alert-warning py-2 mb-0'>Фоновое сканирование выключено. Включите его в настройках и сохраните.</div>",
                status_code=200,
            )
        if getattr(st, "net_scan_is_running", False):
            return HTMLResponse(
                content="<div class='alert alert-info py-2 mb-0'>Сканирование уже выполняется.</div>",
                status_code=200,
            )

    # Force run: bypass interval check, keep safety throttle in task.
    from ..tasks import maybe_run_network_scan

    maybe_run_network_scan.delay(True)
    return HTMLResponse(
        content="<div class='alert alert-success py-2 mb-0'>Сканирование поставлено в очередь (Celery). Обновите страницу через пару минут, чтобы увидеть результат.</div>",
        status_code=200,
    )
