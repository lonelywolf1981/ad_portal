from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

from ..deps import get_current_user
from ..ldap_client import ADClient
from ..net_scan import parse_cidrs, reverse_dns
from ..presence import fmt_dt_ru, get_presence_map, normalize_login
from ..repo import db_session, get_or_create_settings
from ..services import ad_cfg_from_settings
from ..utils.dn import dn_to_id, id_to_dn
from ..utils.net import looks_like_ipv4, short_hostname
from ..viewmodels.user_details import build_detail_items
from ..webui import templates


router = APIRouter()


@router.get("/users/search", response_class=HTMLResponse)
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
                {
                    "request": request,
                    "users": [],
                    "error": "AD не настроен. Откройте «Настройки» и заполните параметры подключения.",
                },
            )

    client = ADClient(cfg)
    ok, msg, items = client.search_users(q, limit=40)
    if not ok:
        return templates.TemplateResponse(
            "users_results.html",
            {"request": request, "users": [], "error": msg or "Ошибка поиска в AD."},
        )

    users: list[dict] = []
    for it in items:
        dn = it.get("dn", "")
        users.append(
            {
                "id": dn_to_id(dn),
                "fio": it.get("fio", "") or "",
                "login": it.get("login", "") or "",
                "email": it.get("mail", "") or "",
            }
        )

    # Enrich cards with last-known location (from background network scan)
    # Show BOTH: short hostname and IP. If hostname was not saved, try PTR via per-subnet DNS (network+1).
    try:
        with db_session() as db:
            st2 = get_or_create_settings(db)
            pres = get_presence_map(db, [u.get("login", "") for u in users])
            net_cidrs_text = (getattr(st2, "net_scan_cidrs", "") or "").strip()

        # Prime CIDR cache once for reverse_dns()
        if net_cidrs_text:
            try:
                parse_cidrs(net_cidrs_text)
            except Exception:
                net_cidrs_text = ""

        rdns_cache: dict[str, str] = {}

        for u in users:
            key = normalize_login(u.get("login", ""))
            p = pres.get(key) if key else None
            if not p:
                continue

            host_raw = (p.host or "").strip()
            ip_raw = (p.ip or "").strip()

            # Some earlier data may have stored IP in host field
            if not ip_raw and host_raw and looks_like_ipv4(host_raw):
                ip_raw = host_raw
                host_raw = ""

            host_short = short_hostname(host_raw)

            # Backfill hostname via PTR (per-subnet DNS) if only IP is known
            if not host_short and ip_raw and net_cidrs_text:
                if ip_raw not in rdns_cache:
                    try:
                        rdns_cache[ip_raw] = short_hostname(reverse_dns(ip_raw, timeout_s=0.8))
                    except Exception:
                        rdns_cache[ip_raw] = ""
                host_short = rdns_cache.get(ip_raw, "")

            u["found_host"] = host_short
            u["found_ip"] = ip_raw
            u["found_ts"] = fmt_dt_ru(p.last_seen_ts)
    except Exception:
        # Presence is optional; never break user search on errors.
        pass

    return templates.TemplateResponse(
        "users_results.html",
        {"request": request, "users": users, "error": ""},
    )


@router.get("/users/details", response_class=HTMLResponse)
def user_details(request: Request, id: str = ""):
    try:
        _ = get_current_user(request)
    except HTTPException as e:
        if e.status_code == status.HTTP_401_UNAUTHORIZED:
            return HTMLResponse(content="", status_code=401, headers={"HX-Redirect": "/login"})
        raise

    try:
        dn = id_to_dn(id)
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

    items = build_detail_items(details)
    return templates.TemplateResponse(
        "user_details.html",
        {"request": request, "items": items, "error": ""},
    )


@router.get("/users/view", response_class=HTMLResponse)
def user_view(request: Request, id: str = "", login: str = "", modal: int = 0):
    """Страница/модалка с деталями пользователя из AD.

    - По умолчанию возвращает полноценную страницу.
    - Если передан modal=1 или запрос сделан через HTMX (HX-Request),
      возвращает контент для Bootstrap-модалки.

    Принимает либо id (закодированный DN), либо login.
    """
    try:
        _ = get_current_user(request)
    except HTTPException as e:
        if e.status_code == status.HTTP_401_UNAUTHORIZED:
            return RedirectResponse(url="/login", status_code=303)
        raise

    id = (id or "").strip()
    login = (login or "").strip()

    dn = ""
    if id:
        try:
            dn = id_to_dn(id)
        except Exception:
            dn = ""

    is_modal = bool(modal) or (request.headers.get("HX-Request") is not None)
    tpl_name = "user_view_modal.html" if is_modal else "user_view.html"

    with db_session() as db:
        st = get_or_create_settings(db)
        cfg = ad_cfg_from_settings(st)
        if not cfg:
            return templates.TemplateResponse(
                tpl_name,
                {"request": request, "items": [], "error": "AD не настроен.", "caption": ""},
            )

    client = ADClient(cfg)

    if not dn and login:
        ok, msg, items = client.search_users(login, limit=8)
        if ok:
            lo = login.lower()
            for it in items:
                lg = (it.get("login") or "").strip().lower()
                if lg == lo:
                    dn = (it.get("dn") or "").strip()
                    break
            if not dn and items:
                dn = (items[0].get("dn") or "").strip()
        if not dn:
            return templates.TemplateResponse(
                tpl_name,
                {"request": request, "items": [], "error": msg or "Пользователь не найден.", "caption": login},
            )

    if not dn:
        return templates.TemplateResponse(
            tpl_name,
            {"request": request, "items": [], "error": "Не задан пользователь.", "caption": ""},
        )

    ok, msg, details = client.get_user_details(dn)
    if not ok:
        return templates.TemplateResponse(
            tpl_name,
            {
                "request": request,
                "items": [],
                "error": msg or "Не удалось получить данные из AD.",
                "caption": login or dn,
            },
        )

    caption = (
        (details.get("displayName") or "").strip()
        or (details.get("cn") or "").strip()
        or (login or "").strip()
        or dn
    )
    items2 = build_detail_items(details)
    return templates.TemplateResponse(
        tpl_name,
        {"request": request, "items": items2, "error": "", "caption": caption},
    )
