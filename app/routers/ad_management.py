from __future__ import annotations

import logging

from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse

from ..deps import require_session_or_hx_redirect, require_initialized_or_redirect
from ..ad import ADClient
from ..repo import db_session, get_or_create_settings
from ..services import ad_mgmt_cfg_from_settings
from ..services.audit import audit_login
from ..utils.dn import dn_to_id, id_to_dn, dn_first_component_value
from ..webui import htmx_alert, templates, ui_result

log = logging.getLogger(__name__)

import re

_DN_PATTERN = re.compile(
    r"^(?:(?:CN|OU|DC|O|L|ST|C)=[^,]+,)*(?:CN|OU|DC|O|L|ST|C)=[^,]+$",
    re.IGNORECASE,
)


def _is_valid_dn(dn: str) -> bool:
    """Базовая проверка формата Distinguished Name."""
    return bool(dn and _DN_PATTERN.match(dn.strip()))


# Системные контейнеры AD, которые не подходят для создания пользователей/групп.
_SYSTEM_CONTAINERS = {
    "builtin", "computers", "foreignsecurityprincipals", "keys",
    "lostandfound", "managed service accounts", "ntds quotas",
    "program data", "system", "tpm devices",
    "infrastructure", "domainupdates",
}


def _build_ou_tree(containers: list[dict], *, allow_users_container: bool = False) -> list[dict]:
    """Отфильтровать системные контейнеры и отсортировать для отображения деревом.

    Возвращает список с полем 'depth' (уровень вложенности) и 'label' (отступ + имя).
    allow_users_container — включить контейнер CN=Users (для создания групп).
    """
    filtered = []
    for c in containers:
        name_lower = (c.get("name") or "").strip().lower()
        # Пропускаем системные контейнеры
        if name_lower in _SYSTEM_CONTAINERS:
            continue
        # Пропускаем контейнеры типа container (оставляем только OU),
        # но CN=Users можно разрешить отдельно
        if c.get("type") == "container":
            if allow_users_container and name_lower == "users":
                pass  # разрешаем
            else:
                continue
        filtered.append(c)

    # Считаем глубину по количеству компонентов DN
    for c in filtered:
        dn = c.get("dn", "")
        parts = [p.strip() for p in dn.split(",") if p.strip()]
        # Глубина = кол-во OU-компонентов минус 1 (базовый уровень)
        ou_parts = [p for p in parts if p.upper().startswith("OU=")]
        c["depth"] = max(0, len(ou_parts) - 1)
        c["label"] = c.get("name", dn)

    # Сортировка по DN для корректного отображения дерева
    filtered.sort(key=lambda x: (x.get("dn") or "").lower())
    return filtered


def _audit_ad_op(request: Request, auth: dict, action: str, target: str, success: bool, details: str = "") -> None:
    """Записать операцию управления AD в аудит."""
    username = auth.get("username", "?")
    ip = request.client.host if request.client else "?"
    ua = request.headers.get("user-agent", "")
    try:
        with db_session() as db:
            audit_login(
                db,
                username=username,
                auth_type="ad_mgmt",
                success=success,
                ip=ip,
                ua=ua,
                result_code=action,
                details=f"{target}: {details}"[:512],
            )
    except Exception:
        log.warning("Не удалось записать аудит операции AD: %s %s", action, target)

def _get_user_groups(client: ADClient, user_dn: str) -> list[dict]:
    """Получить актуальный список групп пользователя для рендера фрагмента."""
    ok, _msg, details = client.get_user_details(user_dn)
    if not ok or not details:
        return []
    member_of = details.get("memberOf", [])
    if isinstance(member_of, str):
        member_of = [member_of]
    groups = []
    for g in member_of:
        if not g:
            continue
        groups.append({
            "dn": str(g),
            "name": dn_first_component_value(str(g)),
        })
    return groups


router = APIRouter()


def _admin_guard(request: Request, auth: dict) -> HTMLResponse | None:
    """Block non-admin users from AD management routes."""
    if auth.get("settings", False):
        return None
    is_htmx = request.headers.get("HX-Request") is not None
    if is_htmx:
        return htmx_alert(ui_result(False, "Доступ запрещён."), status_code=200)
    return HTMLResponse(
        content="<div class='container py-4'><div class='alert alert-danger'>Доступ запрещён.</div></div>",
        status_code=403,
    )


def _mgmt_cfg_or_alert(
    request: Request,
    *,
    template_name: str,
    empty_ctx: dict,
) -> tuple[object | None, HTMLResponse | None]:
    """Build management ADConfig from settings or return a ready-to-send error response."""
    is_htmx = request.headers.get("HX-Request") is not None
    with db_session() as db:
        st = get_or_create_settings(db)
        cfg = ad_mgmt_cfg_from_settings(st)

    if cfg:
        return cfg, None

    msg = (
        "Для управления AD требуется настроенное подключение к AD. "
        "Откройте «Настройки» и заполните параметры подключения (DC, домен, bind user/password)."
    )
    if is_htmx:
        return None, htmx_alert(ui_result(False, msg), status_code=200)

    ctx = dict(empty_ctx)
    ctx.update({"request": request, "error": msg})
    return None, templates.TemplateResponse(template_name, ctx)


@router.get("/ad-management", response_class=HTMLResponse)
def ad_management_page(request: Request):
    """Main AD management page with warning and tabs for users/groups."""
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    guard = _admin_guard(request, auth)
    if guard:
        return guard

    # We do a soft-check here to show a warning in the UI.
    mgmt_error = ""
    try:
        with db_session() as db:
            st = get_or_create_settings(db)
            cfg = ad_mgmt_cfg_from_settings(st)
        if not cfg:
            mgmt_error = (
                "Управление AD недоступно: не настроено подключение к AD. "
                "Заполните в «Настройки» параметры подключения (DC, домен, bind user/password)."
            )
    except Exception:
        mgmt_error = ""

    # When loaded inside the main UI via HTMX (tab pane), return a fragment to avoid nesting full layout.
    tmpl = "ad_management_fragment.html" if request.headers.get("HX-Request") else "ad_management.html"

    return templates.TemplateResponse(
        tmpl,
        {
            "request": request,
            "user": auth,
            "mgmt_error": mgmt_error,
        },
    )


@router.get("/ad-management/users", response_class=HTMLResponse)
def ad_management_users(request: Request, q: str = ""):
    """Search and display AD users for management."""
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    guard = _admin_guard(request, auth)
    if guard:
        return guard

    cfg, resp = _mgmt_cfg_or_alert(request, template_name="ad_management_users.html", empty_ctx={"users": []})
    if resp is not None:
        return resp

    client = ADClient(cfg)  # type: ignore[arg-type]
    
    users = []
    error = ""
    
    # If search query is provided, search for users
    if q and len(q.strip()) >= 2:
        ok, msg, items = client.search_users(q.strip(), limit=50)
        if not ok:
            error = msg or "Ошибка поиска в AD."
        else:
            for it in items:
                dn = it.get("dn", "")
                users.append(
                    {
                        "id": dn_to_id(dn),
                        "fio": it.get("fio", "") or "",
                        "login": it.get("login", "") or "",
                        "email": it.get("mail", "") or "",
                        "dn": dn,
                    }
                )
    else:
        # If no search query, show a message
        if q and len(q.strip()) > 0:
            error = "Введите минимум 2 символа для поиска."

    return templates.TemplateResponse(
        "ad_management_users.html",
        {"request": request, "users": users, "error": error},
    )


@router.get("/ad-management/groups", response_class=HTMLResponse)
def ad_management_groups(request: Request, q: str = ""):
    """Search and display AD groups for management."""
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    guard = _admin_guard(request, auth)
    if guard:
        return guard

    cfg, resp = _mgmt_cfg_or_alert(request, template_name="ad_management_groups.html", empty_ctx={"groups": []})
    if resp is not None:
        return resp

    client = ADClient(cfg)  # type: ignore[arg-type]

    groups: list[dict] = []
    error = ""

    if q and len(q.strip()) >= 2:
        ok, msg, items = client.search_groups(q.strip(), limit=50)
        if not ok:
            error = msg or "Ошибка поиска групп в AD."
        else:
            for it in items:
                dn = it.get("dn", "")
                groups.append(
                    {
                        "id": dn_to_id(dn),
                        "name": it.get("name", "") or "",
                        "description": it.get("description", "") or "",
                        "dn": dn,
                    }
                )
    elif q and len(q.strip()) > 0:
        error = "Введите минимум 2 символа для поиска."

    return templates.TemplateResponse(
        "ad_management_groups.html",
        {"request": request, "groups": groups, "error": error},
    )


@router.get("/ad-management/user-details", response_class=HTMLResponse)
def ad_management_user_details(request: Request, id: str = ""):
    """Display detailed information about an AD user and provide editing capabilities."""
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    guard = _admin_guard(request, auth)
    if guard:
        return guard

    try:
        dn = id_to_dn(id)
    except Exception:
        return templates.TemplateResponse(
            "ad_management_user_edit.html",
            {"request": request, "user_data": {}, "error": "Некорректный идентификатор пользователя."},
        )

    cfg, resp = _mgmt_cfg_or_alert(request, template_name="ad_management_user_edit.html", empty_ctx={"user_data": {}})
    if resp is not None:
        return resp

    client = ADClient(cfg)  # type: ignore[arg-type]
    ok, msg, details = client.get_user_details(dn)
    if not ok:
        return templates.TemplateResponse(
            "ad_management_user_edit.html",
            {"request": request, "user_data": {}, "error": msg or "Не удалось получить данные из AD."},
        )

    # userAccountControl — определяем disabled/locked
    uac = 0
    uac_raw = details.get("userAccountControl")
    if uac_raw is not None:
        try:
            uac = int(uac_raw)
        except (ValueError, TypeError):
            uac = 0
    is_disabled = bool(uac & 0x2)

    lockout_raw = details.get("lockoutTime")
    is_locked = False
    if lockout_raw is not None:
        # lockoutTime=0 → ldap3 возвращает datetime(1601,1,1) → нормализация в ISO-строку "1601-..."
        # Реальная блокировка → актуальная дата (202x-...).
        s = str(lockout_raw)
        try:
            is_locked = int(s) > 0
        except (ValueError, TypeError):
            # ISO-строка: "1601-01-01..." = не заблокирован, иначе заблокирован
            is_locked = bool(s) and not s.startswith("1601")

    # otherPager — multi-valued
    pager_raw = details.get("otherPager", [])
    if isinstance(pager_raw, str):
        pager_raw = [pager_raw]
    pager_list = [str(p) for p in pager_raw if p]

    # Prepare user data for editing form
    user_data = {
        "dn": dn,
        "id": id,
        "username": details.get("sAMAccountName", ""),
        "first_name": details.get("givenName", ""),
        "last_name": details.get("sn", ""),
        "display_name": details.get("displayName", ""),
        "mobile": details.get("mobile", ""),
        "ipPhone": details.get("ipPhone", ""),
        "title": details.get("title", ""),
        "department": details.get("department", ""),
        "otherPager_1": pager_list[0] if len(pager_list) > 0 else "",
        "otherPager_2": pager_list[1] if len(pager_list) > 1 else "",
        "is_disabled": is_disabled,
        "is_locked": is_locked,
        "groups": details.get("memberOf", []),
    }

    # Подготовить группы для фрагмента ad_management_user_edit_groups.html
    groups = _get_user_groups(client, dn)

    return templates.TemplateResponse(
        "ad_management_user_edit.html",
        {
            "request": request,
            "user_data": user_data,
            "user_dn": dn,
            "groups": groups,
            "error": "",
            "success": "",
        },
    )


@router.post("/ad-management/update-user")
def ad_management_update_user(
    request: Request,
    user_dn: str = Form(...),
    first_name: str = Form(""),
    last_name: str = Form(""),
    display_name: str = Form(""),
    mobile: str = Form(""),
    ipPhone: str = Form(""),
    title: str = Form(""),
    department: str = Form(""),
    otherPager_1: str = Form(""),
    otherPager_2: str = Form(""),
    password: str = Form(""),
    password_confirm: str = Form(""),
):
    """Update user attributes in AD."""
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    guard = _admin_guard(request, auth)
    if guard:
        return guard

    # Валидация пароля
    if password:
        if password != password_confirm:
            return htmx_alert(ui_result(False, "Пароли не совпадают."), status_code=200)
        if not all(0x20 <= ord(c) <= 0x7E for c in password):
            return htmx_alert(ui_result(False, "Пароль содержит недопустимые символы (только английские буквы, цифры, спецсимволы)."), status_code=200)

    cfg, resp = _mgmt_cfg_or_alert(request, template_name="ad_management_user_edit.html", empty_ctx={"user_data": {}})
    if resp is not None:
        return resp

    client = ADClient(cfg)  # type: ignore[arg-type]

    pager_list = [p.strip() for p in [otherPager_1, otherPager_2] if p and p.strip()]

    user_data = {
        'first_name': first_name if first_name else None,
        'last_name': last_name if last_name else None,
        'display_name': display_name if display_name else None,
        'mobile': mobile if mobile else None,
        'ipPhone': ipPhone if ipPhone else None,
        'title': title if title else None,
        'department': department if department else None,
        'otherPager': pager_list,
    }

    if password:
        user_data['password'] = password

    ok, msg = client.update_user(user_dn, user_data)
    _audit_ad_op(request, auth, "update_user", user_dn, ok, msg)
    return htmx_alert(ui_result(ok, msg), status_code=200)


@router.post("/ad-management/unlock-user")
def ad_management_unlock_user(
    request: Request,
    user_dn: str = Form(...),
):
    """Разблокировать учётную запись пользователя."""
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    guard = _admin_guard(request, auth)
    if guard:
        return guard

    cfg, resp = _mgmt_cfg_or_alert(request, template_name="ad_management_user_edit.html", empty_ctx={"user_data": {}})
    if resp is not None:
        return resp

    client = ADClient(cfg)  # type: ignore[arg-type]
    ok, msg = client.unlock_user(user_dn)
    _audit_ad_op(request, auth, "unlock_user", user_dn, ok, msg)
    return htmx_alert(ui_result(ok, msg), status_code=200)


@router.post("/ad-management/toggle-user-enabled")
def ad_management_toggle_user_enabled(
    request: Request,
    user_dn: str = Form(...),
    enable: str = Form("true"),
):
    """Включить или отключить учётную запись пользователя."""
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    guard = _admin_guard(request, auth)
    if guard:
        return guard

    cfg, resp = _mgmt_cfg_or_alert(request, template_name="ad_management_user_edit.html", empty_ctx={"user_data": {}})
    if resp is not None:
        return resp

    client = ADClient(cfg)  # type: ignore[arg-type]
    do_enable = enable.lower() in ("true", "1", "yes")
    ok, msg = client.set_user_enabled(user_dn, do_enable)
    _audit_ad_op(request, auth, "enable_user" if do_enable else "disable_user", user_dn, ok, msg)
    return htmx_alert(ui_result(ok, msg), status_code=200)


@router.post("/ad-management/delete-user")
def ad_management_delete_user(
    request: Request,
    user_dn: str = Form(...),
):
    """Delete a user from AD."""
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    guard = _admin_guard(request, auth)
    if guard:
        return guard

    cfg, resp = _mgmt_cfg_or_alert(request, template_name="ad_management_users.html", empty_ctx={"users": []})
    if resp is not None:
        return resp

    client = ADClient(cfg)  # type: ignore[arg-type]
    ok, msg = client.delete_user(user_dn)
    _audit_ad_op(request, auth, "delete_user", user_dn, ok, msg)
    return htmx_alert(ui_result(ok, msg), status_code=200)


@router.post("/ad-management/add-user-to-group")
def ad_management_add_user_to_group(
    request: Request,
    user_dn: str = Form(...),
    group_dn: str = Form(...),
):
    """Add a user to an AD group."""
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    guard = _admin_guard(request, auth)
    if guard:
        return guard

    cfg, resp = _mgmt_cfg_or_alert(request, template_name="ad_management_groups.html", empty_ctx={"groups": []})
    if resp is not None:
        return resp

    client = ADClient(cfg)  # type: ignore[arg-type]
    ok, msg = client.add_user_to_group(user_dn, group_dn)
    _audit_ad_op(request, auth, "add_to_group", f"{user_dn} -> {group_dn}", ok, msg)
    return htmx_alert(ui_result(ok, msg), status_code=200)


@router.post("/ad-management/add-users-to-group")
def ad_management_add_users_to_group(
    request: Request,
    group_dn: str = Form(...),
    user_dns: list[str] = Form([]),
):
    """Add multiple users to an AD group.

    HTMX helper: used by the "checkbox list" in group editor.
    """
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    guard = _admin_guard(request, auth)
    if guard:
        return guard

    if not user_dns:
        return htmx_alert(ui_result(False, "Не выбраны пользователи."), status_code=200)

    cfg, resp = _mgmt_cfg_or_alert(request, template_name="ad_management_groups.html", empty_ctx={"groups": []})
    if resp is not None:
        return resp

    client = ADClient(cfg)  # type: ignore[arg-type]

    ok_count = 0
    errors: list[str] = []
    for dn in user_dns:
        ok, msg = client.add_user_to_group(dn, group_dn)
        if ok:
            ok_count += 1
        else:
            errors.append(msg or "Ошибка")

    if errors:
        # Keep response compact.
        msg = f"Добавлено: {ok_count}. Ошибок: {len(errors)}. Первая ошибка: {errors[0]}"
        return htmx_alert(ui_result(False, msg), status_code=200)

    return htmx_alert(ui_result(True, f"Добавлено пользователей: {ok_count}"), status_code=200)


@router.post("/ad-management/remove-user-from-group")
def ad_management_remove_user_from_group(
    request: Request,
    user_dn: str = Form(...),
    group_dn: str = Form(...),
):
    """Remove a user from an AD group."""
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    guard = _admin_guard(request, auth)
    if guard:
        return guard

    cfg, resp = _mgmt_cfg_or_alert(request, template_name="ad_management_groups.html", empty_ctx={"groups": []})
    if resp is not None:
        return resp

    client = ADClient(cfg)  # type: ignore[arg-type]
    ok, msg = client.remove_user_from_group(user_dn, group_dn)
    _audit_ad_op(request, auth, "remove_from_group", f"{user_dn} <- {group_dn}", ok, msg)
    return htmx_alert(ui_result(ok, msg), status_code=200)


def _get_group_members(client: ADClient, group_dn: str) -> tuple[list[dict], list[dict]]:
    """Получить участников группы: (users, groups)."""
    ok, _msg, members = client.get_group_members(group_dn)
    if not ok:
        return [], []
    return members.get("users", []), members.get("groups", [])


@router.get("/ad-management/group-details", response_class=HTMLResponse)
def ad_management_group_details(request: Request, id: str = ""):
    """Display detailed information about an AD group and provide editing capabilities."""
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    guard = _admin_guard(request, auth)
    if guard:
        return guard

    try:
        dn = id_to_dn(id)
    except Exception:
        return templates.TemplateResponse(
            "ad_management_group_edit.html",
            {"request": request, "group_data": {}, "error": "Некорректный идентификатор группы."},
        )

    cfg, resp = _mgmt_cfg_or_alert(
        request,
        template_name="ad_management_group_edit.html",
        empty_ctx={"group_data": {}},
    )
    if resp is not None:
        return resp

    client = ADClient(cfg)  # type: ignore[arg-type]

    group_info = {
        "dn": dn,
        "id": id,
        "name": dn_first_component_value(dn),
    }

    members_users, members_groups = _get_group_members(client, dn)

    return templates.TemplateResponse(
        "ad_management_group_edit.html",
        {
            "request": request,
            "group_data": group_info,
            "group_dn": dn,
            "members_users": members_users,
            "members_groups": members_groups,
            "error": "",
            "success": "",
        },
    )


@router.post("/ad-management/group-remove-member", response_class=HTMLResponse)
def group_remove_member(
    request: Request,
    group_dn: str = Form(...),
    member_dn: str = Form(...),
):
    """Удалить участника (пользователя или группу) из группы и вернуть обновлённый фрагмент."""
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    guard = _admin_guard(request, auth)
    if guard:
        return guard

    cfg, resp = _mgmt_cfg_or_alert(
        request, template_name="ad_management_group_members.html", empty_ctx={}
    )
    if resp is not None:
        return resp

    client = ADClient(cfg)  # type: ignore[arg-type]
    ok, msg = client.remove_user_from_group(member_dn, group_dn)
    _audit_ad_op(request, auth, "remove_from_group", f"{member_dn} <- {group_dn}", ok, msg)

    error = "" if ok else (msg or "Ошибка удаления из группы.")
    success = "Участник удалён из группы." if ok else ""
    members_users, members_groups = _get_group_members(client, group_dn)

    return templates.TemplateResponse(
        "ad_management_group_members.html",
        {
            "request": request,
            "group_dn": group_dn,
            "members_users": members_users,
            "members_groups": members_groups,
            "error": error,
            "success": success,
        },
    )


@router.post("/ad-management/group-add-member", response_class=HTMLResponse)
def group_add_member(
    request: Request,
    group_dn: str = Form(...),
    member_dn: str = Form(...),
):
    """Добавить участника (пользователя или группу) в группу и вернуть обновлённый фрагмент."""
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    guard = _admin_guard(request, auth)
    if guard:
        return guard

    cfg, resp = _mgmt_cfg_or_alert(
        request, template_name="ad_management_group_members.html", empty_ctx={}
    )
    if resp is not None:
        return resp

    client = ADClient(cfg)  # type: ignore[arg-type]
    ok, msg = client.add_user_to_group(member_dn, group_dn)
    _audit_ad_op(request, auth, "add_to_group", f"{member_dn} -> {group_dn}", ok, msg)

    error = "" if ok else (msg or "Ошибка добавления в группу.")
    success = "Участник добавлен в группу." if ok else ""
    members_users, members_groups = _get_group_members(client, group_dn)

    return templates.TemplateResponse(
        "ad_management_group_members.html",
        {
            "request": request,
            "group_dn": group_dn,
            "members_users": members_users,
            "members_groups": members_groups,
            "error": error,
            "success": success,
        },
    )


@router.get("/ad-management/search-for-group-members", response_class=HTMLResponse)
def search_for_group_members(request: Request, term: str = ""):
    """Поиск пользователей и групп для добавления в группу (HTMX-фрагмент)."""
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    guard = _admin_guard(request, auth)
    if guard:
        return guard

    tmpl = "ad_management_group_search_members.html"

    if not term or len(term.strip()) < 2:
        return templates.TemplateResponse(
            tmpl,
            {"request": request, "found_users": [], "found_groups": [], "error": "", "no_results": False},
        )

    cfg, resp = _mgmt_cfg_or_alert(request, template_name=tmpl, empty_ctx={})
    if resp is not None:
        return resp

    client = ADClient(cfg)  # type: ignore[arg-type]

    # Поиск пользователей
    found_users: list[dict] = []
    ok_u, _msg_u, items_u = client.search_users(term.strip(), limit=10)
    if ok_u:
        for it in items_u:
            found_users.append({
                "dn": it.get("dn", ""),
                "fio": it.get("fio", ""),
                "login": it.get("login", ""),
            })

    # Поиск групп
    found_groups: list[dict] = []
    ok_g, _msg_g, items_g = client.search_groups(term.strip(), limit=10)
    if ok_g:
        for it in items_g:
            found_groups.append({
                "dn": it.get("dn", ""),
                "name": it.get("name", ""),
                "description": it.get("description", ""),
            })

    no_results = not found_users and not found_groups
    error = ""
    if not ok_u and not ok_g:
        error = "Ошибка поиска в AD."

    return templates.TemplateResponse(
        tmpl,
        {
            "request": request,
            "found_users": found_users,
            "found_groups": found_groups,
            "error": error,
            "no_results": no_results,
        },
    )


@router.post("/ad-management/create-user")
async def ad_management_create_user(request: Request):
    """Создать нового пользователя в AD (финальный шаг wizard)."""
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    guard = _admin_guard(request, auth)
    if guard:
        return guard

    cfg, resp = _mgmt_cfg_or_alert(request, template_name="ad_management_users.html", empty_ctx={"users": []})
    if resp is not None:
        return resp

    form = await request.form()
    username = (form.get("username") or "").strip()
    ou = (form.get("ou") or "").strip()
    password = form.get("password") or ""
    password_confirm = form.get("password_confirm") or ""

    # Валидация
    if not username:
        return htmx_alert(ui_result(False, "Не указан логин."), status_code=200)
    if not ou or not _is_valid_dn(ou):
        return htmx_alert(ui_result(False, "Некорректный формат DN организационной единицы."), status_code=200)
    if not password:
        return htmx_alert(ui_result(False, "Не указан пароль."), status_code=200)
    if password != password_confirm:
        return htmx_alert(ui_result(False, "Пароли не совпадают."), status_code=200)
    if not all(0x20 <= ord(c) <= 0x7E for c in password):
        return htmx_alert(ui_result(False, "Пароль содержит недопустимые символы."), status_code=200)

    first_name = (form.get("first_name") or "").strip()
    last_name = (form.get("last_name") or "").strip()
    display_name = (form.get("display_name") or "").strip()

    # ПИН-коды
    pager1 = (form.get("otherPager_1") or "").strip()
    pager2 = (form.get("otherPager_2") or "").strip()
    other_pager = [p for p in [pager1, pager2] if p]

    # Группы
    groups = [g.strip() for g in form.getlist("groups") if g and g.strip()]

    client = ADClient(cfg)  # type: ignore[arg-type]

    user_data = {
        "username": username,
        "first_name": first_name,
        "last_name": last_name,
        "display_name": display_name if display_name else f"{first_name} {last_name}".strip(),
        "email": (form.get("email") or "").strip(),
        "ou": ou,
        "password": password,
        "company": (form.get("company") or "").strip(),
        "department": (form.get("department") or "").strip(),
        "title": (form.get("title") or "").strip(),
        "description": (form.get("description") or "").strip(),
        "ipPhone": (form.get("ipPhone") or "").strip(),
        "otherPager": other_pager,
        "groups": groups,
        "must_change_password": bool(form.get("must_change_password")),
        "password_never_expires": bool(form.get("password_never_expires")),
    }

    ok, msg, new_dn = client.create_user(user_data)
    _audit_ad_op(request, auth, "create_user", new_dn or username, ok, msg)
    if ok and new_dn:
        msg = f"{msg} DN: {new_dn}"
    return htmx_alert(ui_result(ok, msg), status_code=200)


@router.post("/ad-management/create-group")
def ad_management_create_group(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    ou: str = Form(None),  # Organizational Unit where to create the group
    custom_ou: str = Form(None),  # Custom OU if user specifies their own
    scope: str = Form("global"),  # global, domainlocal, universal
    category: str = Form("security"),  # security, distribution
):
    """Create a new group in AD."""
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    guard = _admin_guard(request, auth)
    if guard:
        return guard

    cfg, resp = _mgmt_cfg_or_alert(request, template_name="ad_management_groups.html", empty_ctx={"groups": []})
    if resp is not None:
        return resp

    client = ADClient(cfg)  # type: ignore[arg-type]

    # Determine which OU to use - custom takes precedence
    final_ou = (custom_ou or ou or "").strip()

    if not final_ou:
        return htmx_alert(ui_result(False, "Не указана организационная единица (OU)."), status_code=200)
    if not _is_valid_dn(final_ou):
        return htmx_alert(ui_result(False, "Некорректный формат DN организационной единицы."), status_code=200)

    # Prepare group data
    group_data = {
        'name': name,
        'description': description,
        'ou': final_ou,
        'scope': scope,
        'category': category,
    }

    ok, msg, new_dn = client.create_group(group_data)
    _audit_ad_op(request, auth, "create_group", new_dn or name, ok, msg)
    if ok and new_dn:
        msg = f"{msg} DN: {new_dn}"
    return htmx_alert(ui_result(ok, msg), status_code=200)


@router.post("/ad-management/delete-group")
def ad_management_delete_group(
    request: Request,
    group_dn: str = Form(...),
):
    """Delete a group from AD."""
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    guard = _admin_guard(request, auth)
    if guard:
        return guard

    cfg, resp = _mgmt_cfg_or_alert(request, template_name="ad_management_groups.html", empty_ctx={"groups": []})
    if resp is not None:
        return resp

    client = ADClient(cfg)  # type: ignore[arg-type]
    ok, msg = client.delete_group(group_dn)
    _audit_ad_op(request, auth, "delete_group", group_dn, ok, msg)
    return htmx_alert(ui_result(ok, msg), status_code=200)


@router.get("/ad-management/create-user-wizard", response_class=HTMLResponse)
def create_user_wizard_step1(request: Request):
    """Шаг 1: Выбор OU для создания пользователя."""
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    guard = _admin_guard(request, auth)
    if guard:
        return guard

    cfg, resp = _mgmt_cfg_or_alert(request, template_name="ad_management_create_user_step1.html", empty_ctx={})
    if resp is not None:
        return resp

    client = ADClient(cfg)  # type: ignore[arg-type]
    ok, msg, containers = client.list_containers(limit=2000)
    if not ok:
        containers = []
    else:
        containers = _build_ou_tree(containers)

    return templates.TemplateResponse(
        "ad_management_create_user_step1.html",
        {"request": request, "containers": containers, "error": ("" if ok else (msg or ""))},
    )


@router.post("/ad-management/create-user-step2", response_class=HTMLResponse)
def create_user_wizard_step2(
    request: Request,
    ou: str = Form(...),
):
    """Шаг 2: Выбор шаблонного пользователя из OU."""
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    guard = _admin_guard(request, auth)
    if guard:
        return guard

    if not _is_valid_dn(ou):
        return htmx_alert(ui_result(False, "Некорректный формат DN организационной единицы."), status_code=200)

    cfg, resp = _mgmt_cfg_or_alert(request, template_name="ad_management_create_user_step2.html", empty_ctx={})
    if resp is not None:
        return resp

    client = ADClient(cfg)  # type: ignore[arg-type]
    ok, msg, users = client.list_users_in_ou(ou, limit=200)
    error = "" if ok else (msg or "Ошибка получения пользователей.")

    # Читаемое имя OU
    ou_label = dn_first_component_value(ou)

    return templates.TemplateResponse(
        "ad_management_create_user_step2.html",
        {"request": request, "ou": ou, "ou_label": ou_label, "users": users, "error": error},
    )


@router.post("/ad-management/create-user-step3", response_class=HTMLResponse)
async def create_user_wizard_step3(request: Request):
    """Шаг 3: Форма заполнения данных пользователя."""
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    guard = _admin_guard(request, auth)
    if guard:
        return guard

    form = await request.form()
    ou = (form.get("ou") or "").strip()
    template_user_dn = (form.get("template_user_dn") or "").strip()

    if not ou or not _is_valid_dn(ou):
        return htmx_alert(ui_result(False, "Некорректный формат DN организационной единицы."), status_code=200)

    ou_label = dn_first_component_value(ou)

    # Данные формы (могут быть предзаполнены при «Назад» из шага 4)
    d = {
        "ou": ou,
        "ou_label": ou_label,
        "template_user_dn": template_user_dn,
        "template_display": "",
        "username": (form.get("username") or "").strip(),
        "first_name": (form.get("first_name") or "").strip(),
        "last_name": (form.get("last_name") or "").strip(),
        "display_name": (form.get("display_name") or "").strip(),
        "email": (form.get("email") or "").strip(),
        # Do not prefill password fields when returning to step 3.
        "password": "",
        "password_confirm": "",
        "must_change_password": bool(form.get("must_change_password")),
        "cannot_change_password": bool(form.get("cannot_change_password")),
        "password_never_expires": bool(form.get("password_never_expires")),
        "otherPager_1": (form.get("otherPager_1") or "").strip(),
        "otherPager_2": (form.get("otherPager_2") or "").strip(),
        "ipPhone": (form.get("ipPhone") or "").strip(),
        "company": (form.get("company") or "").strip(),
        "department": (form.get("department") or "").strip(),
        "title": (form.get("title") or "").strip(),
        "description": (form.get("description") or "").strip(),
        "groups": form.getlist("groups"),
        "group_names": [],
    }

    # Если пришли с шага 2 (template_user_dn задан) и поля ещё пустые — загрузить шаблон
    has_prefilled = bool(d["username"] or d["first_name"] or d["company"] or d["department"])
    if template_user_dn and not has_prefilled:
        cfg, resp = _mgmt_cfg_or_alert(
            request, template_name="ad_management_create_user_step3.html", empty_ctx={}
        )
        if resp is not None:
            return resp
        client = ADClient(cfg)  # type: ignore[arg-type]
        ok, msg, details = client.get_user_details(template_user_dn)
        if ok and details:
            d["template_display"] = details.get("displayName", "") or details.get("sAMAccountName", "")
            d["company"] = details.get("company", "") or ""
            d["department"] = details.get("department", "") or ""
            d["title"] = details.get("title", "") or ""
            d["description"] = details.get("description", "") or ""
            d["ipPhone"] = details.get("ipPhone", "") or ""
            # memberOf
            member_of = details.get("memberOf", [])
            if isinstance(member_of, str):
                member_of = [member_of]
            d["groups"] = [str(g) for g in member_of if g]
            # otherPager
            pager = details.get("otherPager", [])
            if isinstance(pager, str):
                pager = [pager]
            pager = [str(p) for p in pager if p]
            d["otherPager_1"] = pager[0] if len(pager) > 0 else ""
            d["otherPager_2"] = pager[1] if len(pager) > 1 else ""
            # По умолчанию: сменить при входе
            d["must_change_password"] = True

    # Первый визит из шага 2 без шаблона — установить чекбокс «Сменить при входе» по умолчанию
    if not has_prefilled and not template_user_dn:
        d["must_change_password"] = True

    # Имена групп для отображения
    d["group_names"] = [dn_first_component_value(g) for g in d["groups"]]

    return templates.TemplateResponse(
        "ad_management_create_user_step3.html",
        {"request": request, "d": d, "error": ""},
    )


@router.post("/ad-management/create-user-step4", response_class=HTMLResponse)
async def create_user_wizard_step4(request: Request):
    """Шаг 4: Финальная карточка (ревью) перед созданием."""
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    guard = _admin_guard(request, auth)
    if guard:
        return guard

    form = await request.form()
    ou = (form.get("ou") or "").strip()
    ou_label = dn_first_component_value(ou)
    password = form.get("password") or ""
    password_confirm = form.get("password_confirm") or ""

    d = {
        "ou": ou,
        "ou_label": ou_label,
        "template_user_dn": (form.get("template_user_dn") or "").strip(),
        "username": (form.get("username") or "").strip(),
        "first_name": (form.get("first_name") or "").strip(),
        "last_name": (form.get("last_name") or "").strip(),
        "display_name": (form.get("display_name") or "").strip(),
        "email": (form.get("email") or "").strip(),
        # Never render plaintext password in HTML.
        "password": "",
        "password_confirm": "",
        "must_change_password": bool(form.get("must_change_password")),
        "cannot_change_password": bool(form.get("cannot_change_password")),
        "password_never_expires": bool(form.get("password_never_expires")),
        "otherPager_1": (form.get("otherPager_1") or "").strip(),
        "otherPager_2": (form.get("otherPager_2") or "").strip(),
        "ipPhone": (form.get("ipPhone") or "").strip(),
        "company": (form.get("company") or "").strip(),
        "department": (form.get("department") or "").strip(),
        "title": (form.get("title") or "").strip(),
        "description": (form.get("description") or "").strip(),
        "groups": form.getlist("groups"),
        "group_names": [],
    }

    # Серверная валидация
    errors: list[str] = []
    if not d["username"]:
        errors.append("Не указан логин.")
    if not password:
        errors.append("Не указан пароль.")
    if password != password_confirm:
        errors.append("Пароли не совпадают.")
    if password and not all(0x20 <= ord(c) <= 0x7E for c in password):
        errors.append("Пароль содержит недопустимые символы (только английские буквы, цифры, спецсимволы).")
    if not ou or not _is_valid_dn(ou):
        errors.append("Некорректный формат OU.")

    d["group_names"] = [dn_first_component_value(g) for g in d["groups"]]
    error = " ".join(errors) if errors else ""

    return templates.TemplateResponse(
        "ad_management_create_user_step4.html",
        {"request": request, "d": d, "error": error},
    )


@router.get("/ad-management/create-group-modal", response_class=HTMLResponse)
def ad_management_create_group_modal(request: Request):
    """Display modal for creating a new group."""
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    guard = _admin_guard(request, auth)
    if guard:
        return guard

    cfg, resp = _mgmt_cfg_or_alert(request, template_name="ad_management_create_group_modal.html", empty_ctx={})
    if resp is not None:
        return resp

    client = ADClient(cfg)  # type: ignore[arg-type]
    ok, msg, containers = client.list_containers(limit=2000)
    if not ok:
        containers = []
    else:
        containers = _build_ou_tree(containers, allow_users_container=True)

    return templates.TemplateResponse(
        "ad_management_create_group_modal.html",
        {"request": request, "containers": containers, "error": ("" if ok else (msg or ""))},
    )


@router.get("/ad-management/delete-user-modal", response_class=HTMLResponse)
def ad_management_delete_user_modal(request: Request, id: str = "", name: str = ""):
    """Display modal for deleting a user."""
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    guard = _admin_guard(request, auth)
    if guard:
        return guard

    try:
        dn = id_to_dn(id)
    except Exception:
        return templates.TemplateResponse(
            "ad_management_delete_user_modal.html",
            {"request": request, "error": "Некорректный идентификатор пользователя."}
        )

    return templates.TemplateResponse(
        "ad_management_delete_user_modal.html",
        {"request": request, "user_id": id, "user_name": name, "user_dn": dn}
    )


@router.get("/ad-management/delete-group-modal", response_class=HTMLResponse)
def ad_management_delete_group_modal(request: Request, id: str = "", name: str = ""):
    """Display modal for deleting a group."""
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    guard = _admin_guard(request, auth)
    if guard:
        return guard

    try:
        dn = id_to_dn(id)
    except Exception:
        return templates.TemplateResponse(
            "ad_management_delete_group_modal.html",
            {"request": request, "error": "Некорректный идентификатор группы."}
        )

    return templates.TemplateResponse(
        "ad_management_delete_group_modal.html",
        {"request": request, "group_id": id, "group_name": name, "group_dn": dn}
    )


@router.get("/ad-management/wizard-search-groups", response_class=HTMLResponse)
def wizard_search_groups(request: Request, term: str = "", mode: str = "wizard"):
    """Поиск групп AD для wizard создания пользователя (HTMX-фрагмент).

    mode=wizard → шаблон для wizard (addWizardGroup),
    mode=edit   → шаблон для редактирования (editUserAddGroup).
    """
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    guard = _admin_guard(request, auth)
    if guard:
        return guard

    tmpl = "ad_management_user_edit_groups_search.html" if mode == "edit" else "ad_management_wizard_groups_search.html"

    if not term or len(term.strip()) < 2:
        return templates.TemplateResponse(
            tmpl,
            {"request": request, "groups": [], "error": "", "no_results": False},
        )

    cfg, resp = _mgmt_cfg_or_alert(
        request, template_name=tmpl, empty_ctx={"groups": []}
    )
    if resp is not None:
        return resp

    client = ADClient(cfg)  # type: ignore[arg-type]
    ok, msg, items = client.search_groups(term.strip(), limit=15)
    if not ok:
        return templates.TemplateResponse(
            tmpl,
            {"request": request, "groups": [], "error": msg or "Ошибка поиска групп.", "no_results": False},
        )

    groups = []
    for it in items:
        groups.append({
            "dn": it.get("dn", ""),
            "name": it.get("name", ""),
            "description": it.get("description", ""),
        })

    return templates.TemplateResponse(
        tmpl,
        {"request": request, "groups": groups, "error": "", "no_results": (not groups)},
    )


@router.post("/ad-management/edit-user-remove-group", response_class=HTMLResponse)
def edit_user_remove_group(
    request: Request,
    user_dn: str = Form(...),
    group_dn: str = Form(...),
):
    """Удалить пользователя из группы AD (при редактировании) и вернуть обновлённый фрагмент."""
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    guard = _admin_guard(request, auth)
    if guard:
        return guard

    cfg, resp = _mgmt_cfg_or_alert(
        request, template_name="ad_management_user_edit_groups.html", empty_ctx={"groups": []}
    )
    if resp is not None:
        return resp

    client = ADClient(cfg)  # type: ignore[arg-type]
    ok, msg = client.remove_user_from_group(user_dn, group_dn)
    _audit_ad_op(request, auth, "remove_from_group", f"{user_dn} <- {group_dn}", ok, msg)

    # Перечитать актуальные группы пользователя
    error = "" if ok else (msg or "Ошибка удаления из группы.")
    success = "Пользователь удалён из группы." if ok else ""
    groups = _get_user_groups(client, user_dn)

    return templates.TemplateResponse(
        "ad_management_user_edit_groups.html",
        {"request": request, "user_dn": user_dn, "groups": groups, "error": error, "success": success},
    )


@router.post("/ad-management/edit-user-add-group", response_class=HTMLResponse)
def edit_user_add_group(
    request: Request,
    user_dn: str = Form(...),
    group_dn: str = Form(...),
):
    """Добавить пользователя в группу AD (при редактировании) и вернуть обновлённый фрагмент."""
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    guard = _admin_guard(request, auth)
    if guard:
        return guard

    cfg, resp = _mgmt_cfg_or_alert(
        request, template_name="ad_management_user_edit_groups.html", empty_ctx={"groups": []}
    )
    if resp is not None:
        return resp

    client = ADClient(cfg)  # type: ignore[arg-type]
    ok, msg = client.add_user_to_group(user_dn, group_dn)
    _audit_ad_op(request, auth, "add_to_group", f"{user_dn} -> {group_dn}", ok, msg)

    # Перечитать актуальные группы пользователя
    error = "" if ok else (msg or "Ошибка добавления в группу.")
    success = "Пользователь добавлен в группу." if ok else ""
    groups = _get_user_groups(client, user_dn)

    return templates.TemplateResponse(
        "ad_management_user_edit_groups.html",
        {"request": request, "user_dn": user_dn, "groups": groups, "error": error, "success": success},
    )


@router.get("/ad-management/search-users-for-group", response_class=HTMLResponse)
def ad_management_search_users_for_group(request: Request, term: str = "", group_dn: str = ""):
    """Search users to add to a group."""
    auth = require_initialized_or_redirect(request)
    if not isinstance(auth, dict):
        return auth

    guard = _admin_guard(request, auth)
    if guard:
        return guard

    cfg, resp = _mgmt_cfg_or_alert(request, template_name="ad_management_search_users.html", empty_ctx={"users": []})
    if resp is not None:
        return resp

    client = ADClient(cfg)  # type: ignore[arg-type]

    users = []
    error = ""

    if term and len(term.strip()) >= 2:
        ok, msg, items = client.search_users(term.strip(), limit=20)
        if not ok:
            error = msg or "Ошибка поиска в AD."
        else:
            for it in items:
                dn = it.get("dn", "")
                users.append(
                    {
                        "id": dn_to_id(dn),
                        "fio": it.get("fio", "") or "",
                        "login": it.get("login", "") or "",
                        "dn": dn,
                    }
                )
    else:
        if term and len(term.strip()) > 0:
            error = "Введите минимум 2 символа для поиска."

    return templates.TemplateResponse(
        "ad_management_search_users.html",
        {"request": request, "users": users, "error": error, "group_dn": group_dn}
    )
