from __future__ import annotations

from ...ad import ADClient
from .backend import AuthResult


def authenticate(username: str, password: str, settings) -> AuthResult:
    """Аутентификация пользователя через Active Directory.
    
    Args:
        username: Имя пользователя
        password: Пароль
        settings: Настройки приложения
        
    Returns:
        AuthResult: Результат аутентификации
    """
    # NOTE: ad_cfg_from_settings lives in app/services/ad.py (Stage 2 refactor).
    # The previous import from app/ad was wrong and breaks AD login at runtime.
    from ..ad import ad_cfg_from_settings
    
    cfg = ad_cfg_from_settings(settings)
    if not cfg:
        return AuthResult(success=False, error_message="AD не настроен (проверьте настройки).")

    client = ADClient(cfg)
    
    # Сначала находим пользователя по логину
    u = client.find_user_by_login(username)
    if not u:
        return AuthResult(success=False, error_message="Неверный логин или пароль.")

    # Проверяем пароль
    if not client.verify_password(u.dn, password):
        return AuthResult(success=False, error_message="Неверный логин или пароль.")

    # Проверяем, входит ли пользователь в разрешенные группы
    from ...ad_utils import split_group_dns
    allowed_app = set(split_group_dns(settings.allowed_app_group_dns))
    user_groups = set(u.member_of)

    if allowed_app and not (user_groups & allowed_app):
        return AuthResult(success=False, error_message="Доступ запрещён: пользователь не входит в разрешённые группы.")

    # Проверяем права на доступ к настройкам
    allowed_settings = set(split_group_dns(settings.allowed_settings_group_dns))
    can_settings = bool(user_groups & allowed_settings) if allowed_settings else False

    user_data = {
        "username": u.sam or username,
        "display_name": u.display_name or u.sam or username,
        "auth": "ad",
        "settings": can_settings,
        "groups": list(u.member_of),
    }
    
    return AuthResult(success=True, user_data=user_data)