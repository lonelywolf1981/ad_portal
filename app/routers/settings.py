from __future__ import annotations

from fastapi import APIRouter, Form, Request, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse

from ..ad_utils import split_group_dns
from ..deps import require_session_or_hx_redirect
from ..repo import db_session, get_or_create_settings
from ..services import (
    ad_test_and_load_groups,
    get_groups_cache,
    groups_dn_to_name_map,
    save_settings,
)

from ..services.settings import (
    AppSettingsSchema,
    export_settings,
    import_settings,
    get_settings as get_settings_typed,
    save_settings as save_settings_typed,
    validate_ad,
    validate_host_query,
    validate_net_scan,
)
from ..timezone_utils import format_ru_local
from ..webui import templates


router = APIRouter()


def _alert_html(ok: bool, message: str, details: str = "", hints: list[str] | None = None) -> str:
    cls = "alert-success" if ok else "alert-danger"
    extra = ""
    if details:
        extra += f"<div class='small text-secondary mt-1'>{details}</div>"
    if hints:
        li = "".join([f"<li>{h}</li>" for h in hints])
        extra += f"<ul class='small mt-2 mb-0'>{li}</ul>"
    return f"<div class='alert {cls} py-2 mb-0'>{message}{extra}</div>"


def _build_settings_for_validation(db, form: dict) -> AppSettingsSchema:
    """Merge current DB settings with form overrides.

    - Empty password fields keep existing decrypted values.
    """

    cur = get_settings_typed(db)

    # AD overrides
    cur.auth_mode = (form.get("auth_mode") or cur.auth_mode or "local").strip() or "local"
    cur.ad.dc_short = (form.get("ad_dc_short") or cur.ad.dc_short or "").strip()
    cur.ad.domain = (form.get("ad_domain") or cur.ad.domain or "").strip()
    cur.ad.conn_mode = (form.get("ad_conn_mode") or cur.ad.conn_mode or "ldaps").strip()  # type: ignore[assignment]
    cur.ad.bind_username = (form.get("ad_bind_username") or cur.ad.bind_username or "").strip()
    if form.get("ad_bind_password"):
        cur.ad.bind_password = form.get("ad_bind_password") or ""

    # Host query overrides
    cur.host_query.username = (form.get("host_query_username") or cur.host_query.username or "").strip()
    if form.get("host_query_password"):
        cur.host_query.password = form.get("host_query_password") or ""
    try:
        cur.host_query.timeout_s = int(form.get("host_query_timeout_s") or cur.host_query.timeout_s or 60)
    except Exception:
        pass
    cur.host_query.test_host = (form.get("host_query_test_host") or cur.host_query.test_host or "").strip()

    # Net scan overrides
    cur.net_scan.enabled = bool(form.get("net_scan_enabled"))
    cur.net_scan.cidrs = [x.strip() for x in (form.get("net_scan_cidrs") or "").splitlines() if x.strip()]
    for k in ("net_scan_interval_min", "net_scan_concurrency", "net_scan_method_timeout_s", "net_scan_probe_timeout_ms"):
        if k in form and form.get(k) not in (None, ""):
            try:
                v = int(form.get(k))
            except Exception:
                continue
            if k == "net_scan_interval_min":
                cur.net_scan.interval_min = v
            elif k == "net_scan_concurrency":
                cur.net_scan.concurrency = v
            elif k == "net_scan_method_timeout_s":
                cur.net_scan.method_timeout_s = v
            elif k == "net_scan_probe_timeout_ms":
                cur.net_scan.probe_timeout_ms = v

    # group selection overrides (UI sends lists)
    cur.ad.allowed_app_group_dns = list(form.get("allowed_app_group_dns") or cur.ad.allowed_app_group_dns or [])
    cur.ad.allowed_settings_group_dns = list(form.get("allowed_settings_group_dns") or cur.ad.allowed_settings_group_dns or [])

    # Re-validate to apply constraints/normalization.
    return AppSettingsSchema.model_validate(cur.model_dump())


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
    host_query_test_host: str = Form(""),
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


@router.post("/settings/validate/ad", response_class=HTMLResponse)
async def settings_validate_ad(request: Request):
    auth = require_session_or_hx_redirect(request)
    if not isinstance(auth, dict):
        return auth
    if not auth.get("settings", False):
        return HTMLResponse(content=_alert_html(False, "Доступ запрещён."), status_code=403)

    form = dict(await request.form())
    with db_session() as db:
        st = _build_settings_for_validation(db, form)
    res = validate_ad(st)
    return HTMLResponse(content=_alert_html(res.ok, res.message, res.details, res.hints), status_code=200)


@router.post("/settings/validate/host", response_class=HTMLResponse)
async def settings_validate_host(request: Request):
    auth = require_session_or_hx_redirect(request)
    if not isinstance(auth, dict):
        return auth
    if not auth.get("settings", False):
        return HTMLResponse(content=_alert_html(False, "Доступ запрещён."), status_code=403)

    form = dict(await request.form())
    with db_session() as db:
        st = _build_settings_for_validation(db, form)
    res = validate_host_query(st)
    return HTMLResponse(content=_alert_html(res.ok, res.message, res.details, res.hints), status_code=200)


@router.post("/settings/validate/net", response_class=HTMLResponse)
async def settings_validate_net(request: Request):
    auth = require_session_or_hx_redirect(request)
    if not isinstance(auth, dict):
        return auth
    if not auth.get("settings", False):
        return HTMLResponse(content=_alert_html(False, "Доступ запрещён."), status_code=403)

    form = dict(await request.form())
    with db_session() as db:
        st = _build_settings_for_validation(db, form)
    res = validate_net_scan(st)
    return HTMLResponse(content=_alert_html(res.ok, res.message, res.details, res.hints), status_code=200)


@router.get("/settings/export.json")
def settings_export_json(request: Request, include_secrets: int = 0):
    auth = require_session_or_hx_redirect(request)
    if not isinstance(auth, dict):
        return auth
    if not auth.get("settings", False):
        return JSONResponse({"ok": False, "message": "forbidden"}, status_code=403)

    with db_session() as db:
        st = get_settings_typed(db)
        payload = export_settings(st, include_secrets=bool(include_secrets))

    resp = JSONResponse(payload)
    resp.headers["Content-Disposition"] = "attachment; filename=ad_portal_settings.json"
    return resp


@router.post("/settings/import")
async def settings_import_json(request: Request, file: UploadFile = File(...)):
    auth = require_session_or_hx_redirect(request)
    if not isinstance(auth, dict):
        return auth
    if not auth.get("settings", False):
        return HTMLResponse(
            content="<div class='container py-4'><div class='alert alert-danger'>Доступ запрещён.</div></div>",
            status_code=403,
        )

    raw = await file.read()
    try:
        imported = import_settings(raw)
    except Exception as e:
        return RedirectResponse(url=f"/settings?saved=0&import_err=1", status_code=303)

    with db_session() as db:
        # Keep existing secrets if import file has them blank (default export behavior).
        save_settings_typed(db, imported, keep_secrets_if_blank=True)

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
