from __future__ import annotations

from typing import Dict, Any, List
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from .settings import get_settings
from .ldap_client import ADClient


def _serializer() -> URLSafeTimedSerializer:
    s = get_settings()
    return URLSafeTimedSerializer(s.secret_key, salt="ad-portal-session")


def create_session_payload(username: str, display_name: str, groups: List[str]) -> str:
    data = {"u": username, "dn": display_name, "g": groups}
    return _serializer().dumps(data)


def read_session_payload(token: str) -> Dict[str, Any] | None:
    s = get_settings()
    try:
        data = _serializer().loads(token, max_age=s.session_max_age_seconds)
        if not isinstance(data, dict) or "u" not in data:
            return None
        return data
    except (BadSignature, SignatureExpired):
        return None


def is_allowed(groups: List[str]) -> bool:
    """Проверка членства в разрешённых группах (по DN)."""
    s = get_settings()
    allowed = [x.strip() for x in s.ad_allowed_group_dns.split(";") if x.strip()]
    if not allowed:
        return False
    user_groups = set(groups)
    return any(g in user_groups for g in allowed)


def authenticate(login: str, password: str) -> dict | None:
    """Полная процедура:
    1) найти DN по логину (сервисным bind)
    2) проверить пароль (user bind)
    3) получить группы и проверить доступ
    """
    ad = ADClient()
    u = ad.find_user_by_login(login)
    if not u:
        return None

    if not ad.verify_password(u.dn, password):
        return None

    groups = u.member_of
    if not is_allowed(groups):
        return {"error": "forbidden", "user": u}

    return {
        "username": u.sam or login,
        "display_name": u.display_name or (u.sam or login),
        "mail": u.mail,
        "groups": groups,
    }
