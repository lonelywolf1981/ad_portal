from __future__ import annotations

import ipaddress
import json
import inspect
import re
import logging
from html import escape as html_escape
from datetime import datetime, timedelta
from pydantic import ValidationError

from types import SimpleNamespace

from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from sqlalchemy import distinct, func, select

from ..ad_utils import split_group_dns
from ..deps import require_session_or_hx_redirect
from ..repo import db_session, get_or_create_settings
from ..services import ad_test_and_load_groups, get_groups_cache, groups_dn_to_name_map, save_settings
from ..services.settings import (
    AppSettingsSchema,
    export_settings,
    get_settings as get_typed_settings,
    import_settings,
    save_settings as save_typed_settings,
    validate_ad,
    validate_host_query,
    validate_net_scan,
)
from ..timezone_utils import format_ru_local
from ..webui import htmx_alert, templates, ui_result

from ..models import HostUserMap, UserPresence

from ..ad.client import ADClient
from ..ad.models import ADConfig
from ..crypto import decrypt_str
from ..host_query.api import find_logged_on_users


router = APIRouter()
log = logging.getLogger(__name__)
MAX_SETTINGS_IMPORT_BYTES = 1 * 1024 * 1024



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


def _normalize_pem(v: str | None) -> str:
    """Normalize PEM text for stable storage and predictable TLS behavior."""
    s = (v or "").strip()
    if not s:
        return ""
    # Normalize line endings to avoid hash mismatches and confusing diffs.
    return s.replace("\r\n", "\n").replace("\r", "\n")


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
        "core": {
            "ui": {
                "initialized": False  # будет вычислено в свойстве is_initialized
            }
        },
        "auth": {"mode": (payload.get("auth_mode") or "local").strip() or "local"},
        "auth_mode": (payload.get("auth_mode") or "local").strip() or "local",
        "ad": {
            "dc_short": payload.get("ad_dc_short", ""),
            "domain": payload.get("ad_domain", ""),
            "conn_mode": (payload.get("ad_conn_mode") or "ldaps").strip() or "ldaps",
            "bind_username": payload.get("ad_bind_username", ""),
            "bind_password": payload.get("ad_bind_password", ""),
            "tls_validate": _truthy_flag(payload.get("ad_tls_validate")),
            "ca_pem": _normalize_pem(payload.get("ad_ca_pem")),
            "allowed_app_group_dns": payload.get("allowed_app_group_dns") or [],
            "allowed_settings_group_dns": payload.get("allowed_settings_group_dns") or [],
        },
        "host_query": {
            "username": payload.get("host_query_username", ""),
            "password": payload.get("host_query_password", ""),
            "timeout_s": int(payload.get("host_query_timeout_s") or 60),
        },
        "ip_phones": {
            "enabled": _truthy_flag(payload.get("ip_phones_enabled")),
            "ami_host": payload.get("ip_phones_ami_host", ""),
            "ami_port": int(payload.get("ip_phones_ami_port") or 5038),
            "ami_user": payload.get("ip_phones_ami_user", ""),
            "ami_password": payload.get("ip_phones_ami_password", ""),
            "ami_timeout_s": int(payload.get("ip_phones_ami_timeout_s") or 5),
        },
        "net_scan": {
            "enabled": _truthy_flag(payload.get("net_scan_enabled")),
            "cidrs": _parse_cidrs(payload.get("net_scan_cidrs", "")),
            "dns_server": (payload.get("net_scan_dns_server") or "").strip(),
            "interval_min": int(payload.get("net_scan_interval_min") or 120),
            "concurrency": int(payload.get("net_scan_concurrency") or 64),
            "method_timeout_s": int(payload.get("net_scan_method_timeout_s") or 20),
            "probe_timeout_ms": int(payload.get("net_scan_probe_timeout_ms") or 350),
            "stats_retention_days": int(payload.get("net_scan_stats_retention_days") or 30),
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




def _humanize_pydantic_error_lines(e: ValidationError) -> list[str]:
    """Convert Pydantic errors into short human-readable RU messages.

    Важно для UI: никаких префиксов вида `ad.domain:` / `net_scan.cidrs:`.
    Возвращаем список строк, чтобы можно было красиво показать их списком.
    """

    items: list[str] = []
    for err in e.errors()[:3]:
        loc = ".".join([str(x) for x in (err.get("loc") or []) if x not in ("__root__",)])
        msg = (err.get("msg") or "").strip()

        # Pydantic may prefix our ValueError with 'Value error, ...' — strip it for UI.
        if msg.startswith("Value error, "):
            msg = msg[len("Value error, ") :].strip()
        elif msg.startswith("Value error: "):
            msg = msg[len("Value error: ") :].strip()

        # Normalize some common patterns
        if loc == "net_scan.cidrs":
            if not msg:
                msg = "Ошибка в списке диапазонов (CIDR)."

        if loc == "ad.domain":
            if not msg:
                msg = "Ошибка в имени домена."
        if loc == "ad.dc_short":
            if not msg:
                msg = "Ошибка в имени контроллера домена (DC short)."

        if msg:
            items.append(msg)

    if len(e.errors()) > 3:
        items.append(f"+ ещё {len(e.errors()) - 3} ошибок")
    return items


def _alert_response(ok: bool, message: str, details: str = "", *, status_code: int = 200) -> HTMLResponse:
    """Compatibility wrapper for settings validation endpoints.

    Settings validate tools are HTMX-driven and expect HTML fragments.
    We still standardize the underlying data shape via ui_result().
    """

    return htmx_alert(ui_result(ok, message, details), status_code=status_code)


def _effective_settings_from_form(db, form: dict) -> AppSettingsSchema:
    """Build effective settings (typed schema) for validate endpoints.

    - Uses DB as the source of truth (including decrypted secrets).
    - Overlays values from the current form (if provided).
    - If a password field is empty in the form, keeps existing secret.
    """

    cur = get_typed_settings(db)
    patch: dict = {
        "schema_version": cur.schema_version,
        "core": cur.core.model_dump(),
        "auth": {"mode": (form.get("auth_mode") or cur.auth.mode)},
        "auth_mode": (form.get("auth_mode") or cur.auth.mode),
        "ad": cur.ad.model_dump(),
        "host_query": cur.host_query.model_dump(),
        "ip_phones": cur.ip_phones.model_dump(),
        "net_scan": cur.net_scan.model_dump(),
    }

    # AD
    if form.get("ad_dc_short") is not None:
        patch["ad"]["dc_short"] = form.get("ad_dc_short") or patch["ad"]["dc_short"]
    if form.get("ad_domain") is not None:
        patch["ad"]["domain"] = form.get("ad_domain") or patch["ad"]["domain"]
    if form.get("ad_conn_mode"):
        patch["ad"]["conn_mode"] = (form.get("ad_conn_mode") or "").strip() or patch["ad"]["conn_mode"]
    if form.get("ad_tls_validate") is not None:
        patch["ad"]["tls_validate"] = _truthy_flag(form.get("ad_tls_validate"))
    if form.get("ad_ca_pem") is not None:
        patch["ad"]["ca_pem"] = _normalize_pem(form.get("ad_ca_pem"))
    if form.get("ad_bind_username") is not None:
        patch["ad"]["bind_username"] = form.get("ad_bind_username") or patch["ad"]["bind_username"]
    if (form.get("ad_bind_password") or "").strip():
        patch["ad"]["bind_password"] = form.get("ad_bind_password")

    # Host query
    if form.get("host_query_username") is not None:
        patch["host_query"]["username"] = form.get("host_query_username") or patch["host_query"]["username"]
    if (form.get("host_query_password") or "").strip():
        patch["host_query"]["password"] = form.get("host_query_password")
    if form.get("host_query_timeout_s") is not None:
        try:
            patch["host_query"]["timeout_s"] = int(form.get("host_query_timeout_s") or patch["host_query"]["timeout_s"])
        except Exception:
            log.warning("Некорректное значение host_query_timeout_s", exc_info=True)
    if form.get("host_query_test_host") is not None:
        patch["host_query"]["test_host"] = (form.get("host_query_test_host") or "").strip()

    # IP phones
    if "ip_phones_enabled" in form:
        patch["ip_phones"]["enabled"] = bool(form.get("ip_phones_enabled"))
    if form.get("ip_phones_ami_host") is not None:
        patch["ip_phones"]["ami_host"] = (form.get("ip_phones_ami_host") or "").strip()
    if form.get("ip_phones_ami_user") is not None:
        patch["ip_phones"]["ami_user"] = (form.get("ip_phones_ami_user") or "").strip()
    if (form.get("ip_phones_ami_password") or "").strip():
        patch["ip_phones"]["ami_password"] = form.get("ip_phones_ami_password")
    if form.get("ip_phones_ami_port") is not None:
        try:
            patch["ip_phones"]["ami_port"] = int(form.get("ip_phones_ami_port") or patch["ip_phones"]["ami_port"])
        except Exception:
            log.warning("Некорректное значение ip_phones_ami_port", exc_info=True)
    if form.get("ip_phones_ami_timeout_s") is not None:
        try:
            patch["ip_phones"]["ami_timeout_s"] = int(
                form.get("ip_phones_ami_timeout_s") or patch["ip_phones"]["ami_timeout_s"]
            )
        except Exception:
            log.warning("Некорректное значение ip_phones_ami_timeout_s", exc_info=True)

    # Net scan
    if "net_scan_enabled" in form:
        patch["net_scan"]["enabled"] = bool(form.get("net_scan_enabled"))
    if form.get("net_scan_cidrs") is not None:
        patch["net_scan"]["cidrs"] = _parse_cidrs(form.get("net_scan_cidrs") or "")
    if form.get("net_scan_dns_server") is not None:
        patch["net_scan"]["dns_server"] = (form.get("net_scan_dns_server") or "").strip()
    if form.get("net_scan_stats_retention_days") is not None:
        try:
            patch["net_scan"]["stats_retention_days"] = int(
                form.get("net_scan_stats_retention_days") or patch["net_scan"]["stats_retention_days"]
            )
        except Exception:
            log.warning("Некорректное значение net_scan_stats_retention_days", exc_info=True)

    return AppSettingsSchema.model_validate(patch)


def _parse_cidrs(text: str) -> list[str]:
    out: list[str] = []
    for raw in (text or "").splitlines():
        s = raw.strip()
        if not s or s.startswith("#") or s.startswith(";"):
            continue
        out.append(s)
    return out


def _render_validate_result(res) -> HTMLResponse:
    details = res.details or ""
    if getattr(res, "hints", None):
        hints = [h for h in (res.hints or []) if (h or "").strip()]
        if hints:
            if details:
                details += "\n\n"
            details += "Рекомендации:\n" + "\n".join(f"• {h}" for h in hints)
    
    # Если результат неудачный, добавляем возможность просмотра подробностей
    if not res.ok and details:
        # Формируем HTML с кнопкой "Подробнее"
        details_id = f"validate-details-{hash(details) % 10000}"  # уникальный ID для каждого сообщения
        content = f"""
        <div class="alert alert-danger py-2 mb-0">
          <div class="d-flex justify-content-between align-items-start">
            <div>{html_escape(res.message)}</div>
            <button class="btn btn-link btn-sm p-0 ms-2" type="button" data-bs-toggle="collapse" data-bs-target="#{details_id}" aria-expanded="false" aria-controls="{details_id}">
              Подробнее
            </button>
          </div>
          <div class="collapse mt-2" id="{details_id}">
            <div class="card card-body p-2 small bg-light">
              <pre class="mb-0">{html_escape(details)}</pre>
            </div>
          </div>
        </div>
        """
        return HTMLResponse(content=content, status_code=200)
    else:
        return _alert_response(bool(res.ok), res.message, details)


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, saved: int = 0, mode: str = ""):
    auth = require_session_or_hx_redirect(request)
    if not isinstance(auth, dict):
        return auth

    with db_session() as db:
        st = get_or_create_settings(db)
        typed = get_typed_settings(db)
        is_initialized = bool(typed.is_initialized)

        # Для вкладки «Сопоставления»: требуется включённый периодический net-scan и заданные диапазоны.
        net_scan_ready = bool(
            bool(getattr(st, "net_scan_enabled", False))
            and bool((getattr(st, "net_scan_cidrs", "") or "").strip())
        )

        # Bootstrap rule: пока приложение не инициализировано, разрешаем зайти в настройки
        # любому аутентифицированному пользователю (иначе получается «курица/яйцо» для AD-режима).
        # После инициализации — только тем, у кого есть флаг `settings`.
        user = auth
        if is_initialized and (not user.get("settings", False)):
            return HTMLResponse(
                content="<div class='container py-4'><div class='alert alert-danger'>Доступ запрещён.</div></div>",
                status_code=403,
            )

        # Режим чеклиста включаем только по явному запросу (?mode=init).
        # Иначе /settings всегда должен показывать форму настроек (иначе получается «вечный init»).
        if mode == "init":
            # Чеклист:
            # - «обязательное» для базовой работы
            # - «для вкладки Сопоставления» (не блокирует остальное, но управляет вкладкой)
            mandatory = {
                "has_local_or_ad_admin": st.auth_mode in ["local", "ad"],
                "ad_configured": st.auth_mode != "ad" or (st.ad_domain and st.ad_dc_short and st.ad_bind_username),
                "host_query_creds": bool(st.host_query_username),
            }
            mapping = {
                "net_scan_enabled": bool(st.net_scan_enabled),
                "net_scan_ranges": bool((st.net_scan_cidrs or "").strip()),
            }
            
            return templates.TemplateResponse(
                "settings_init.html",
                {
                    "request": request,
                    "user": user,
                    "st": st,
                    "mandatory": mandatory,
                    "mapping": mapping,
                    "all_mandatory_passed": all(mandatory.values()),
                    "net_scan_ready": net_scan_ready,
                    "is_initialized": is_initialized,
                },
            )

        net_scan_last_run_ui = "—"
        net_scan_last_token = ""
        net_scan_is_running = False
        online_users_last_scan: int | None = None
        logged_users_found_last_scan: int | None = None
        try:
            dt = getattr(st, "net_scan_last_run_ts", None)
            # Defensive: depending on SQLite driver / legacy schema, DateTime columns may come back as strings.
            # We need a real datetime for window computations.
            if dt and not isinstance(dt, datetime):
                try:
                    dt = datetime.fromisoformat(str(dt))
                except Exception:
                    # Try a common SQLite format: "YYYY-MM-DD HH:MM:SS[.ffffff]"
                    try:
                        dt = datetime.strptime(str(dt), "%Y-%m-%d %H:%M:%S")
                    except Exception:
                        try:
                            dt = datetime.strptime(str(dt), "%Y-%m-%d %H:%M:%S.%f")
                        except Exception:
                            dt = None
            if dt:
                net_scan_last_run_ui = format_ru_local(dt) or "—"
                try:
                    net_scan_last_token = dt.isoformat(timespec="seconds")
                except Exception:
                    net_scan_last_token = str(dt)
            # Authoritative "running" marker is net_scan_lock_ts (set/cleared by background task).
            net_scan_is_running = bool(getattr(st, "net_scan_lock_ts", None))

            # --- Stats based on the *last scan window* ---
            # Important: st.net_scan_last_run_ts is the scan *end* time.
            # host_user_map/user_presence rows may have last_seen_ts a bit earlier (inside the scan),
            # so filtering by >= end_time would incorrectly yield 0.
            if dt:
                summary = (getattr(st, "net_scan_last_summary", "") or "").strip()
                dur_s: int | None = None
                m = re.search(r"Длительность:\s*(\d+)\s*сек", summary)
                if m:
                    try:
                        dur_s = int(m.group(1))
                    except Exception:
                        dur_s = None

                # Fallback window: take 10 minutes if duration is unknown.
                window_start = dt - timedelta(seconds=dur_s) if dur_s else (dt - timedelta(minutes=10))

                online_users_last_scan = int(
                    db.scalar(
                        select(func.count())
                        .select_from(UserPresence)
                        .where(UserPresence.last_seen_ts >= window_start)
                    )
                    or 0
                )

                logged_users_found_last_scan = int(
                    db.scalar(
                        select(func.count(distinct(HostUserMap.user_login)))
                        .where(HostUserMap.last_seen_ts >= window_start)
                    )
                    or 0
                )
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
                "is_initialized": is_initialized,
                "net_scan_ready": net_scan_ready,
                "saved": saved,
                "groups_cache": groups_cache_objs,
                "dn_name_map": dn_name_map,
                "selected_app_dns": selected_app,
                "selected_settings_dns": selected_settings,
                "net_scan_last_run_ui": net_scan_last_run_ui,
                "net_scan_last_token": net_scan_last_token,
                "net_scan_is_running": net_scan_is_running,
                "online_users_last_scan": online_users_last_scan,
                "logged_users_found_last_scan": logged_users_found_last_scan,
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
    ad_tls_validate: str = Form(""),
    ad_ca_pem: str = Form(""),
    host_query_username: str = Form(""),
    host_query_password: str = Form(""),
    host_query_timeout_s: int = Form(60),
    ip_phones_enabled: str = Form(""),
    ip_phones_ami_host: str = Form(""),
    ip_phones_ami_port: int = Form(5038),
    ip_phones_ami_user: str = Form(""),
    ip_phones_ami_password: str = Form(""),
    ip_phones_ami_timeout_s: int = Form(5),
    net_scan_enabled: str = Form(""),
    net_scan_cidrs: str = Form(""),
    net_scan_dns_server: str = Form(""),
    net_scan_interval_min: int = Form(120),
    net_scan_concurrency: int = Form(64),
    net_scan_method_timeout_s: int = Form(20),
    net_scan_probe_timeout_ms: int = Form(350),
    net_scan_stats_retention_days: int = Form(30),
    allowed_app_group_dns: list[str] = Form([]),
    allowed_settings_group_dns: list[str] = Form([]),
):
    auth = require_session_or_hx_redirect(request)
    if not isinstance(auth, dict):
        return auth

    with db_session() as db:
        typed = get_typed_settings(db)
        is_initialized = bool(typed.is_initialized)

        # В init-режиме разрешаем сохранять настройки любому аутентифицированному пользователю.
        # После инициализации — только с правом settings.
        if is_initialized and (not auth.get("settings", False)):
            return HTMLResponse(
                content="<div class='container py-4'><div class='alert alert-danger'>Доступ запрещён.</div></div>",
                status_code=403,
            )

        st = get_or_create_settings(db)
        try:
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
                    "ad_tls_validate": ad_tls_validate,
                    "ad_ca_pem": ad_ca_pem,
                    "host_query_username": host_query_username,
                    "host_query_password": host_query_password,
                    "host_query_timeout_s": host_query_timeout_s,
                    "ip_phones_enabled": ip_phones_enabled,
                    "ip_phones_ami_host": ip_phones_ami_host,
                    "ip_phones_ami_port": ip_phones_ami_port,
                    "ip_phones_ami_user": ip_phones_ami_user,
                    "ip_phones_ami_password": ip_phones_ami_password,
                    "ip_phones_ami_timeout_s": ip_phones_ami_timeout_s,
                    "net_scan_enabled": net_scan_enabled,
                    "net_scan_cidrs": net_scan_cidrs,
                    "net_scan_dns_server": net_scan_dns_server,
                    "net_scan_interval_min": net_scan_interval_min,
                    "net_scan_concurrency": net_scan_concurrency,
                    "net_scan_method_timeout_s": net_scan_method_timeout_s,
                    "net_scan_probe_timeout_ms": net_scan_probe_timeout_ms,
                    "net_scan_stats_retention_days": net_scan_stats_retention_days,
                    "allowed_app_group_dns": allowed_app_group_dns,
                    "allowed_settings_group_dns": allowed_settings_group_dns,
                },
            )
        except ValidationError as e:
            lines = _humanize_pydantic_error_lines(e)
            details = "\n".join(lines)
            if request.headers.get("HX-Request") == "true":
                # Для HTMX показываем ошибки списком (иначе переносы строк схлопываются в один текст).
                return htmx_alert(
                    {
                        "ok": False,
                        "message": "Настройки не сохранены",
                        "details": "",
                        "hints": lines,
                    },
                    status_code=200,
                )
            from urllib.parse import quote
            return RedirectResponse(url=f"/settings?err={quote(details)}#settings-save", status_code=303)

    if request.headers.get("HX-Request") == "true":
        # For HTMX: do a full redirect (HX-Redirect) to avoid swapping the whole page into the target div.
        resp = HTMLResponse(content="", status_code=204)
        resp.headers["HX-Redirect"] = "/settings?saved=1"
        return resp

    return RedirectResponse(url="/settings?saved=1", status_code=303)

@router.post("/settings/validate/ad", response_class=HTMLResponse)
def settings_validate_ad(
    request: Request,
    ad_dc_short: str = Form(""),
    ad_domain: str = Form(""),
    ad_conn_mode: str = Form("ldaps"),
    ad_bind_username: str = Form(""),
    ad_bind_password: str = Form(""),
    ad_tls_validate: str = Form(""),
    ad_ca_pem: str = Form(""),
):
    """Validate AD connection/bind (Stage 1 validator; without saving)."""

    auth = require_session_or_hx_redirect(request)
    if not isinstance(auth, dict):
        return auth
    with db_session() as db:
        typed = get_typed_settings(db)
        is_initialized = bool(typed.is_initialized)
        if is_initialized and (not auth.get("settings", False)):
            return _alert_response(False, "Доступ запрещён.", status_code=403)

        eff = _effective_settings_from_form(
            db,
            {
                "ad_dc_short": ad_dc_short,
                "ad_domain": ad_domain,
                "ad_conn_mode": ad_conn_mode,
                "ad_bind_username": ad_bind_username,
                "ad_bind_password": ad_bind_password,
                "ad_tls_validate": ad_tls_validate,
                "ad_ca_pem": ad_ca_pem,
                # keep existing secrets if blank
            },
        )

    res = validate_ad(eff)
    return _render_validate_result(res)


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
    with db_session() as db:
        typed = get_typed_settings(db)
        is_initialized = bool(typed.is_initialized)
        if is_initialized and (not auth.get("settings", False)):
            return _alert_response(False, "Доступ запрещён.", status_code=403)

        eff = _effective_settings_from_form(
            db,
            {
                "host_query_test_host": host_query_test_host,
                "host_query_username": host_query_username,
                "host_query_password": host_query_password,
                "host_query_timeout_s": host_query_timeout_s,
            },
        )

    res = validate_host_query(eff)
    return _render_validate_result(res)


@router.post("/settings/validate/net", response_class=HTMLResponse)
def settings_validate_net(
    request: Request,
    net_scan_enabled: str = Form(""),
    net_scan_cidrs: str = Form(""),
    net_scan_dns_server: str = Form(""),
):
    auth = require_session_or_hx_redirect(request)
    if not isinstance(auth, dict):
        return auth
    with db_session() as db:
        typed = get_typed_settings(db)
        is_initialized = bool(typed.is_initialized)
        if is_initialized and (not auth.get("settings", False)):
            return _alert_response(False, "Доступ запрещён.", status_code=403)

        eff = _effective_settings_from_form(
            db,
            {
                "net_scan_enabled": net_scan_enabled,
                "net_scan_cidrs": net_scan_cidrs,
                "net_scan_dns_server": net_scan_dns_server,
            },
        )

    res = validate_net_scan(eff)
    return _render_validate_result(res)


@router.get("/settings/export.json")
def settings_export_json(request: Request, include_secrets: int = 0):
    auth = require_session_or_hx_redirect(request)
    if not isinstance(auth, dict):
        return auth
    with db_session() as db:
        typed = get_typed_settings(db)
        is_initialized = bool(typed.is_initialized)
        if is_initialized and (not auth.get("settings", False)):
            return JSONResponse({"ok": False, "message": "forbidden"}, status_code=403)

        data = typed
        payload = export_settings(data, include_secrets=bool(include_secrets))

    schema_v = int(payload.get("schema_version") or 0)
    resp = JSONResponse(payload)
    resp.headers["Content-Disposition"] = f"attachment; filename=ad_portal_settings_v{schema_v}.json"
    return resp


@router.post("/settings/import")
async def settings_import_json(request: Request, file: UploadFile = File(...)):
    auth = require_session_or_hx_redirect(request)
    if not isinstance(auth, dict):
        return auth
    with db_session() as db:
        typed = get_typed_settings(db)
        is_initialized = bool(typed.is_initialized)
        if is_initialized and (not auth.get("settings", False)):
            return HTMLResponse(
                content="<div class='container py-4'><div class='alert alert-danger'>Доступ запрещён.</div></div>",
                status_code=403,
            )

    hx = (request.headers.get('HX-Request', '') or '').lower() == 'true'

    content_type = (getattr(file, "content_type", "") or "").lower()
    if content_type and ("json" not in content_type) and (content_type != "text/plain"):
        msg = "Импорт: ожидается JSON-файл."
        if hx:
            return htmx_alert(ui_result(False, msg), status_code=200)
        return RedirectResponse(url="/settings?saved=0&import_err=1", status_code=303)

    raw = await file.read(MAX_SETTINGS_IMPORT_BYTES + 1)
    if len(raw) > MAX_SETTINGS_IMPORT_BYTES:
        msg = f"Импорт: файл слишком большой (максимум {MAX_SETTINGS_IMPORT_BYTES // 1024} KB)."
        if hx:
            return htmx_alert(ui_result(False, msg), status_code=200)
        return RedirectResponse(url="/settings?saved=0&import_err=1", status_code=303)
    try:
        imported = import_settings(raw)
    except Exception as e:
        log.warning("Ошибка импорта настроек из JSON", exc_info=True)
        if hx:
            return htmx_alert(ui_result(False, "Импорт: ошибка", str(e)), status_code=200)
        return RedirectResponse(url="/settings?saved=0&import_err=1", status_code=303)

    with db_session() as db:
        # Keep secrets if the imported file redacted them.
        save_typed_settings(db, imported, keep_secrets_if_blank=True)

        # Re-read to see what is effectively present after merge.
        eff = get_typed_settings(db)
        missing: list[str] = []
        if not (eff.ad.bind_password or "").strip():
            missing.append("AD bind password")
        if not (eff.host_query.password or "").strip():
            missing.append("Host query password")

    if hx:
        details = "Настройки применены"
        if missing:
            details += "\n\nВнимание: в импортируемом файле отсутствуют пароли (или они пустые): " + ", ".join(missing) + "."
            details += "\nЭкспортируйте настройки с паролями (кнопка 'Экспорт (с паролями)'), либо введите пароль(и) вручную и нажмите 'Сохранить'."
        return htmx_alert(ui_result(True, "Импорт: успешно", details), status_code=200)
    return RedirectResponse(url="/settings?saved=1", status_code=303)


@router.post("/settings/ad/test", response_class=HTMLResponse)
def settings_ad_test(
    request: Request,
    ad_dc_short: str = Form(""),
    ad_domain: str = Form(""),
    ad_conn_mode: str = Form("ldaps"),
    ad_bind_username: str = Form(""),
    ad_bind_password: str = Form(""),
    ad_tls_validate: str = Form(""),
    ad_ca_pem: str = Form(""),
    host_query_username: str = Form(""),
    host_query_password: str = Form(""),
    host_query_timeout_s: int = Form(60),
    net_scan_dns_server: str = Form(""),
):
    auth = require_session_or_hx_redirect(request)
    if not isinstance(auth, dict):
        return auth
    with db_session() as db:
        typed = get_typed_settings(db)
        is_initialized = bool(typed.is_initialized)
        if is_initialized and (not auth.get("settings", False)):
            return HTMLResponse(
                content="<div class='alert alert-danger py-2 mb-3'>Доступ запрещён.</div>",
                status_code=403,
            )

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
                "ad_tls_validate": ad_tls_validate,
                "ad_ca_pem": ad_ca_pem,
                "host_query_username": host_query_username,
                "host_query_password": host_query_password,
                "host_query_timeout_s": host_query_timeout_s,
                "net_scan_dns_server": net_scan_dns_server,
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

        # Добавляем кнопку "Подробнее" для ошибок
        details_btn = ""
        details_div = ""
        if not ok:
            details_btn = """
            <button class="btn btn-link btn-sm p-0 ms-2" type="button" data-bs-toggle="collapse" data-bs-target="#ad-error-details" aria-expanded="false" aria-controls="ad-error-details">
              Подробнее
            </button>
            """
            details_div = f"""
            <div class="collapse mt-2" id="ad-error-details">
              <div class="card card-body p-2 small bg-light">
                {html_escape(msg)}
              </div>
            </div>
            """

        safe_msg = html_escape(msg)
        return HTMLResponse(
            content=f"""
            <div class="alert {alert_cls} py-2 mb-3">
              <div class="d-flex justify-content-between align-items-start">
                <div>{safe_msg}</div>
                {details_btn}
              </div>
              {details_div}
            </div>
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
    with db_session() as db:
        typed = get_typed_settings(db)
        is_initialized = bool(typed.is_initialized)
        if is_initialized and (not auth.get("settings", False)):
            return HTMLResponse(
                content="<div class='alert alert-danger py-2 mb-0'>Доступ запрещён.</div>",
                status_code=403,
            )

        st = get_or_create_settings(db)
        if not getattr(st, "net_scan_enabled", False):
            return HTMLResponse(
                content="<div class='alert alert-warning py-2 mb-0'>Фоновое сканирование выключено. Включите его в настройках и сохраните.</div>",
                status_code=200,
            )
        # Authoritative "running" marker is net_scan_lock_ts (set/cleared by background task).
        if getattr(st, "net_scan_lock_ts", None):
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
