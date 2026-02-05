from __future__ import annotations

import ipaddress
import json
import inspect
from types import SimpleNamespace

from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

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

from ..ad.client import ADClient
from ..ad.models import ADConfig
from ..crypto import decrypt_str
from ..host_query.api import find_logged_on_users


router = APIRouter()



def _dict_to_obj(x):
    """Convert nested dict/list into objects with attribute access.

    Это нужно для совместимости: новая реализация `save_settings` может ожидать объект
    (pydantic/dataclass), а старая передавала обычный dict.
    """
    if isinstance(x, dict):
        return SimpleNamespace(**{k: _dict_to_obj(v) for k, v in x.items()})
    if isinstance(x, list):
        return [_dict_to_obj(v) for v in x]
    return x


def _truthy_flag(v) -> bool:
    """Normalize HTML form flags (checkboxes) into bool."""
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    s = str(v).strip().lower()
    return s in {"1", "true", "on", "yes", "y"}


def _coerce_settings_payload(payload: dict) -> object:
    """Coerce legacy flat payload into the new typed settings schema.

    `app.services.settings.storage.save_settings()` expects `AppSettingsSchema`.
    The settings form historically posted a flat dict.
    """

    # Lazy import to avoid heavy imports / cycles at module import time.
    from ..services.settings import AppSettingsSchema, CURRENT_SCHEMA_VERSION

    if not isinstance(payload, dict):
        return payload

    # If payload already looks like the typed schema, validate as-is.
    if isinstance(payload.get("ad"), dict) and isinstance(payload.get("host_query"), dict) and isinstance(
        payload.get("net_scan"), dict
    ):
        return AppSettingsSchema.model_validate(payload)

    data = {
        "schema_version": int(payload.get("schema_version") or CURRENT_SCHEMA_VERSION),
        "auth_mode": (payload.get("auth_mode") or "local").strip() or "local",
        "ad": {
            "dc_short": payload.get("ad_dc_short", ""),
            "domain": payload.get("ad_domain", ""),
            "conn_mode": (payload.get("ad_conn_mode") or "ldaps").strip() or "ldaps",
            "bind_username": payload.get("ad_bind_username", ""),
            "bind_password": payload.get("ad_bind_password", ""),
            "allowed_app_group_dns": payload.get("allowed_app_group_dns") or [],
            "allowed_settings_group_dns": payload.get("allowed_settings_group_dns") or [],
        },
        "host_query": {
            "username": payload.get("host_query_username", ""),
            "password": payload.get("host_query_password", ""),
            "timeout_s": int(payload.get("host_query_timeout_s") or 60),
        },
        "net_scan": {
            "enabled": _truthy_flag(payload.get("net_scan_enabled")),
            "cidrs": _parse_cidrs(payload.get("net_scan_cidrs", "")),
            "interval_min": int(payload.get("net_scan_interval_min") or 120),
            "concurrency": int(payload.get("net_scan_concurrency") or 64),
            "method_timeout_s": int(payload.get("net_scan_method_timeout_s") or 20),
            "probe_timeout_ms": int(payload.get("net_scan_probe_timeout_ms") or 350),
        },
    }

    return AppSettingsSchema.model_validate(data)


def _call_save_settings_compat(db, st, payload: dict) -> None:
    """Compatibility shim for settings persistence.

    В кодовой базе встречаются два варианта сигнатуры `save_settings`:

    1) legacy:
       save_settings(db, st, payload)

    2) new (рефакторинг в app/services/settings/*):
       save_settings(db, payload)

    Чтобы не ловить 500 из-за несовпадения сигнатуры, выбираем режим по introspection.
    """

    try:
        sig = inspect.signature(save_settings)
        pos_params = [
            p
            for p in sig.parameters.values()
            if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
        ]
        if len(pos_params) <= 2:
            # New implementation expects a typed `AppSettingsSchema` tree.
            save_settings(db, _coerce_settings_payload(payload))
        else:
            save_settings(db, st, payload)
    except (TypeError, ValueError):
        # Fallback: try legacy first, then the new one.
        try:
            save_settings(db, st, payload)
        except TypeError:
            save_settings(db, _coerce_settings_payload(payload))


def _alert(ok: bool, message: str, details: str = "") -> str:
    cls = "alert-success" if ok else "alert-danger"
    det = f"<div class='small text-secondary mt-1'>{details}</div>" if details else ""
    return f"<div class='alert {cls} py-2 mb-0'>{message}{det}</div>"


def _parse_cidrs(text: str) -> list[str]:
    out: list[str] = []
    for raw in (text or "").splitlines():
        s = raw.strip()
        if not s or s.startswith("#") or s.startswith(";"):
            continue
        out.append(s)
    return out


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
        _call_save_settings_compat(
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
def settings_validate_ad(
    request: Request,
    ad_dc_short: str = Form(""),
    ad_domain: str = Form(""),
    ad_conn_mode: str = Form("ldaps"),
    ad_bind_username: str = Form(""),
    ad_bind_password: str = Form(""),
):
    """Validate AD connection/bind without touching group cache."""

    auth = require_session_or_hx_redirect(request)
    if not isinstance(auth, dict):
        return auth
    if not auth.get("settings", False):
        return HTMLResponse(content=_alert(False, "Доступ запрещён."), status_code=403)

    with db_session() as db:
        st = get_or_create_settings(db)

        dc = (ad_dc_short or st.ad_dc_short or "").strip()
        domain = (ad_domain or st.ad_domain or "").strip()
        mode = (ad_conn_mode or ("ldaps" if st.ad_use_ssl else "starttls") or "ldaps").strip()

        bind_user = (ad_bind_username or st.ad_bind_username or "").strip()
        bind_pw = (ad_bind_password or "").strip() or decrypt_str(st.ad_bind_password_enc)

    if not (dc and domain and bind_user and bind_pw):
        return HTMLResponse(content=_alert(False, "AD: заполните DC/домен/bind user и пароль."), status_code=200)

    if mode == "ldaps":
        port, use_ssl, starttls = 636, True, False
    else:
        port, use_ssl, starttls = 389, False, True

    try:
        cfg = ADConfig(
            dc_short=dc,
            domain=domain,
            port=port,
            use_ssl=use_ssl,
            starttls=starttls,
            bind_username=bind_user,
            bind_password=bind_pw,
            tls_validate=bool(getattr(st, "ad_tls_validate", False)),
            ca_pem=getattr(st, "ad_ca_pem", "") or "",
        )
        client = ADClient(cfg)
        ok, res = client.service_bind()
        if ok:
            return HTMLResponse(content=_alert(True, "AD: подключение и bind успешны."), status_code=200)
        return HTMLResponse(
            content=_alert(False, "AD: не удалось подключиться или выполнить bind", details=f"Ошибка bind: {res}"),
            status_code=200,
        )
    except Exception as e:
        return HTMLResponse(content=_alert(False, "AD: ошибка проверки", details=str(e)), status_code=200)


@router.post("/settings/validate/host", response_class=HTMLResponse)
def settings_validate_host(
    request: Request,
    host_query_test_host: str = Form(""),
    host_query_username: str = Form(""),
    host_query_password: str = Form(""),
    host_query_timeout_s: int = Form(60),
):
    auth = require_session_or_hx_redirect(request)
    if not isinstance(auth, dict):
        return auth
    if not auth.get("settings", False):
        return HTMLResponse(content=_alert(False, "Доступ запрещён."), status_code=403)

    test_host = (host_query_test_host or "").strip()
    if not test_host:
        return HTMLResponse(
            content=_alert(False, "Host query: укажите тестовый хост (hostname или IP)."),
            status_code=200,
        )

    with db_session() as db:
        st = get_or_create_settings(db)
        domain_suffix = (st.ad_domain or "").strip()

        user = (host_query_username or st.host_query_username or "").strip()
        pw = (host_query_password or "").strip() or decrypt_str(st.host_query_password_enc)
        timeout = int(host_query_timeout_s or st.host_query_timeout_s or 60)

    if not (user and pw):
        return HTMLResponse(
            content=_alert(False, "Host query: заполните user/password (пароль должен быть задан)."),
            status_code=200,
        )

    try:
        users, method, total_ms, attempts = find_logged_on_users(
            test_host,
            domain_suffix,
            user,
            pw,
            per_method_timeout_s=timeout,
        )
        if users:
            u = ", ".join(users[:5])
            more = "…" if len(users) > 5 else ""
            return HTMLResponse(
                content=_alert(True, f"Host query: OK ({method}, {total_ms} ms)", details=f"Пользователи: {u}{more}"),
                status_code=200,
            )

        # No users found is still a successful connectivity check.
        last = attempts[-1].message if attempts else "Нет данных"
        return HTMLResponse(
            content=_alert(True, f"Host query: ответ получен ({total_ms} ms)", details=last),
            status_code=200,
        )
    except Exception as e:
        return HTMLResponse(content=_alert(False, "Host query: ошибка проверки", details=str(e)), status_code=200)


@router.post("/settings/validate/net", response_class=HTMLResponse)
def settings_validate_net(
    request: Request,
    net_scan_enabled: str = Form(""),
    net_scan_cidrs: str = Form(""),
):
    auth = require_session_or_hx_redirect(request)
    if not isinstance(auth, dict):
        return auth
    if not auth.get("settings", False):
        return HTMLResponse(content=_alert(False, "Доступ запрещён."), status_code=403)

    if not bool(net_scan_enabled):
        return HTMLResponse(content=_alert(True, "Net scan: выключено (это нормально)."), status_code=200)

    cidrs = _parse_cidrs(net_scan_cidrs)
    if not cidrs:
        return HTMLResponse(content=_alert(False, "Net scan: включено, но CIDR не задан."), status_code=200)

    bad: list[str] = []
    too_big: list[str] = []
    for raw in cidrs:
        try:
            net = ipaddress.ip_network(raw, strict=False)
            if net.num_addresses > 65536:
                too_big.append(str(net))
        except Exception:
            bad.append(raw)

    if bad:
        return HTMLResponse(content=_alert(False, "Net scan: ошибка CIDR", details="; ".join(bad)), status_code=200)
    if too_big:
        return HTMLResponse(
            content=_alert(False, "Net scan: слишком большой диапазон", details="; ".join(too_big)),
            status_code=200,
        )

    return HTMLResponse(content=_alert(True, "Net scan: проверка пройдена."), status_code=200)


@router.get("/settings/export.json")
def settings_export_json(request: Request, include_secrets: int = 0):
    auth = require_session_or_hx_redirect(request)
    if not isinstance(auth, dict):
        return auth
    if not auth.get("settings", False):
        return JSONResponse({"ok": False, "message": "forbidden"}, status_code=403)

    with db_session() as db:
        st = get_or_create_settings(db)
        payload = {
            "auth_mode": st.auth_mode,
            "ad": {
                "dc": st.ad_dc_short,
                "domain": st.ad_domain,
                "conn_mode": "ldaps" if st.ad_use_ssl else "starttls",
                "bind_username": st.ad_bind_username,
                "bind_password": decrypt_str(st.ad_bind_password_enc) if include_secrets else "",
            },
            "host_query": {
                "username": st.host_query_username,
                "password": decrypt_str(st.host_query_password_enc) if include_secrets else "",
                "timeout_s": st.host_query_timeout_s,
            },
            "net_scan": {
                "enabled": bool(st.net_scan_enabled),
                "cidrs": st.net_scan_cidrs,
                "interval_min": st.net_scan_interval_min,
                "concurrency": st.net_scan_concurrency,
                "method_timeout_s": int(getattr(st, "net_scan_method_timeout_s", 20) or 20),
                "probe_timeout_ms": st.net_scan_probe_timeout_ms,
            },
            "allowed_app_group_dns": split_group_dns(st.allowed_app_group_dns),
            "allowed_settings_group_dns": split_group_dns(st.allowed_settings_group_dns),
        }

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
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return RedirectResponse(url="/settings?saved=0&import_err=1", status_code=303)

    # Map JSON -> form dict compatible with existing save_settings().
    try:
        form = {
            "auth_mode": data.get("auth_mode") or "local",
            "ad_dc_short": (data.get("ad") or {}).get("dc") or "",
            "ad_domain": (data.get("ad") or {}).get("domain") or "",
            "ad_conn_mode": (data.get("ad") or {}).get("conn_mode") or "ldaps",
            "ad_bind_username": (data.get("ad") or {}).get("bind_username") or "",
            "ad_bind_password": (data.get("ad") or {}).get("bind_password") or "",
            "host_query_username": (data.get("host_query") or {}).get("username") or "",
            "host_query_password": (data.get("host_query") or {}).get("password") or "",
            "host_query_timeout_s": (data.get("host_query") or {}).get("timeout_s") or 60,
            "net_scan_enabled": bool((data.get("net_scan") or {}).get("enabled")),
            "net_scan_cidrs": (data.get("net_scan") or {}).get("cidrs") or "",
            "net_scan_interval_min": (data.get("net_scan") or {}).get("interval_min") or 120,
            "net_scan_concurrency": (data.get("net_scan") or {}).get("concurrency") or 64,
            "net_scan_method_timeout_s": (data.get("net_scan") or {}).get("method_timeout_s") or 20,
            "net_scan_probe_timeout_ms": (data.get("net_scan") or {}).get("probe_timeout_ms") or 350,
            "allowed_app_group_dns": data.get("allowed_app_group_dns") or [],
            "allowed_settings_group_dns": data.get("allowed_settings_group_dns") or [],
        }
    except Exception:
        return RedirectResponse(url="/settings?saved=0&import_err=1", status_code=303)

    with db_session() as db:
        st = get_or_create_settings(db)
        save_settings(db, st, form)

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