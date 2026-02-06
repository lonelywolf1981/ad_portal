from __future__ import annotations

from datetime import datetime
import json

from sqlalchemy.orm import Session

from ..crypto import encrypt_str, decrypt_str
from ..ad_utils import split_group_dns
from ..models import AppSettings
from ..ad import ADConfig, ADClient


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
    tls_validate = bool(pick("ad_tls_validate", st.ad_tls_validate))
    ca_pem = (pick("ad_ca_pem", st.ad_ca_pem) or "")

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
        tls_validate=tls_validate,
        ca_pem=ca_pem,
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

    if override:
        st.ad_dc_short = dc_short
        st.ad_domain = domain
        st.ad_port = port
        st.ad_use_ssl = use_ssl
        st.ad_starttls = starttls
        st.ad_bind_username = bind_user
        st.ad_bind_password_enc = encrypt_str(bind_pw)
        st.ad_tls_validate = bool(tls_validate)
        st.ad_ca_pem = ca_pem or ""

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
