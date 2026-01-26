from __future__ import annotations

from datetime import datetime
import json
from sqlalchemy.orm import Session

from .models import LocalUser, AppSettings, LoginAudit
from .security import verify_password
from .crypto import encrypt_str, decrypt_str
from .ad_utils import split_group_dns
from .ldap_client import ADConfig, ADClient


def audit_login(db: Session, username: str, auth_type: str, success: bool, ip: str, ua: str, result_code: str, details: str = "") -> None:
    db.add(LoginAudit(
        username=username,
        auth_type=auth_type,
        success=success,
        ip=ip,
        user_agent=ua,
        result_code=result_code,
        details=details[:512],
    ))
    db.commit()


def local_authenticate(db: Session, username: str, password: str) -> dict | None:
    u = db.query(LocalUser).filter(LocalUser.username == username).one_or_none()
    if not u or not u.is_enabled:
        return None
    if not verify_password(password, u.password_hash):
        return None
    return {
        "username": u.username,
        "display_name": u.username,
        "auth": "local",
        "settings": bool(u.is_admin),
        "groups": [],
    }


def _ad_cfg_from_settings(st: AppSettings) -> ADConfig | None:
    if not st.ad_dc_short or not st.ad_domain or not st.ad_bind_username:
        return None
    pwd = decrypt_str(st.ad_bind_password_enc)
    return ADConfig(
        dc_short=st.ad_dc_short,
        domain=st.ad_domain,
        port=st.ad_port,
        use_ssl=st.ad_use_ssl,
        starttls=st.ad_starttls,
        bind_username=st.ad_bind_username,
        bind_password=pwd,
        tls_validate=st.ad_tls_validate,
        ca_pem=st.ad_ca_pem or "",
    )


def ad_cfg_from_settings(st: AppSettings) -> ADConfig | None:
    """Public wrapper to build ADConfig from current settings."""
    return _ad_cfg_from_settings(st)


def ad_test_and_load_groups(db: Session, st: AppSettings, override: dict | None = None) -> tuple[bool, str, list[dict]]:
    def pick(name, default):
        return override.get(name, default) if override else default

    mode = pick("ad_conn_mode", "ldaps")
    dc_short = pick("ad_dc_short", st.ad_dc_short)
    domain = pick("ad_domain", st.ad_domain)
    bind_user = pick("ad_bind_username", st.ad_bind_username)
    bind_pw = pick("ad_bind_password", "") or decrypt_str(st.ad_bind_password_enc)

    if mode == "ldaps":
        port, use_ssl, starttls = 636, True, False
    else:
        port, use_ssl, starttls = 389, False, True

    if not (dc_short and domain and bind_user and bind_pw):
        return False, "Заполните DC, домен, bind user и bind password.", []

    cfg = ADConfig(
        dc_short=dc_short,
        domain=domain,
        port=port,
        use_ssl=use_ssl,
        starttls=starttls,
        bind_username=bind_user,
        bind_password=bind_pw,
        tls_validate=False,
        ca_pem="",
    )

    client = ADClient(cfg)
    ok, res = client.service_bind()
    if not ok:
        msg = f"Ошибка bind: {res}"
        st.last_ad_test_ok = False
        st.last_ad_test_message = msg[:512]
        st.last_ad_test_ts = datetime.utcnow()
        db.commit()
        return False, msg, []

    groups = client.list_groups()
    st.groups_cache_json = json.dumps(groups, ensure_ascii=False)
    st.groups_cache_ts = datetime.utcnow()
    st.last_ad_test_ok = True
    st.last_ad_test_message = "OK"
    st.last_ad_test_ts = datetime.utcnow()

    # Also write the tested connection settings back when override is provided
    if override:
        st.ad_dc_short = dc_short
        st.ad_domain = domain
        st.ad_port = port
        st.ad_use_ssl = use_ssl
        st.ad_starttls = starttls
        st.ad_bind_username = bind_user
        st.ad_bind_password_enc = encrypt_str(bind_pw)

    db.commit()
    return True, "OK", groups


def ad_authenticate(db: Session, st: AppSettings, username: str, password: str) -> tuple[dict | None, str]:
    cfg = _ad_cfg_from_settings(st)
    if not cfg:
        return None, "AD не настроен (проверьте настройки)."

    client = ADClient(cfg)
    u = client.find_user_by_login(username)
    if not u:
        return None, "Неверный логин или пароль."

    if not client.verify_password(u.dn, password):
        return None, "Неверный логин или пароль."

    allowed_app = set(split_group_dns(st.allowed_app_group_dns))
    allowed_settings = set(split_group_dns(st.allowed_settings_group_dns))

    user_groups = set(u.member_of)

    # If allowed groups are configured, require intersection
    if allowed_app and not (user_groups & allowed_app):
        return None, "Доступ запрещён: пользователь не входит в разрешённые группы."

    can_settings = bool(user_groups & allowed_settings) if allowed_settings else False

    return {
        "username": u.sam or username,
        "display_name": u.display_name or u.sam or username,
        "auth": "ad",
        "settings": can_settings,
        "groups": list(u.member_of),
    }, "OK"


def save_settings(db: Session, st: AppSettings, form: dict) -> None:
    st.auth_mode = (form.get("auth_mode") or "local").strip()

    # AD connection
    st.ad_dc_short = (form.get("ad_dc_short") or "").strip()
    st.ad_domain = (form.get("ad_domain") or "").strip()

    mode = (form.get("ad_conn_mode") or "ldaps").strip()
    if mode == "ldaps":
        st.ad_port = 636
        st.ad_use_ssl = True
        st.ad_starttls = False
    else:
        st.ad_port = 389
        st.ad_use_ssl = False
        st.ad_starttls = True

    st.ad_bind_username = (form.get("ad_bind_username") or "").strip()
    pw = form.get("ad_bind_password") or ""
    if pw:
        st.ad_bind_password_enc = encrypt_str(pw)

    # Host logon query settings
    st.host_query_username = (form.get("host_query_username") or "").strip()
    qpw = form.get("host_query_password") or ""
    if qpw:
        st.host_query_password_enc = encrypt_str(qpw)

    try:
        t = int(form.get("host_query_timeout_s") or 60)
    except Exception:
        t = 60
    if t < 5:
        t = 5
    if t > 300:
        t = 300
    st.host_query_timeout_s = t

    # Access groups
    st.allowed_app_group_dns = ";".join(form.get("allowed_app_group_dns", []))
    st.allowed_settings_group_dns = ";".join(form.get("allowed_settings_group_dns", []))

    st.updated_at = datetime.utcnow()
    db.commit()


def get_groups_cache(st: AppSettings) -> list[dict]:
    try:
        return json.loads(st.groups_cache_json or "[]")
    except Exception:
        return []


def groups_dn_to_name_map(st: AppSettings) -> dict:
    m = {}
    for g in get_groups_cache(st):
        dn = g.get("dn")
        name = g.get("name")
        if dn and name:
            m[dn] = name
    return m
