from __future__ import annotations

from ...crypto import decrypt_str
from ...models import LocalUser
from ...security import verify_password
from .backend import AuthResult


def authenticate(username: str, password: str, settings) -> AuthResult:
    """Аутентификация локального пользователя.
    
    Args:
        username: Имя пользователя
        password: Пароль
        settings: Настройки приложения (не используется в локальной аутентификации)
        
    Returns:
        AuthResult: Результат аутентификации
    """
    from ...repo import db_session, get_local_user
    
    # Используем контекст сессии для получения пользователя
    with db_session() as db:
        user = get_local_user(db, username)
        if not user:
            return AuthResult(success=False, error_message="Неверное имя пользователя или пароль")
        
        if not user.is_enabled:
            return AuthResult(success=False, error_message="Пользователь заблокирован")
        
        if not verify_password(password, user.password_hash):
            return AuthResult(success=False, error_message="Неверное имя пользователя или пароль")
        
        # Получаем сессионные данные пользователя
        user_data = {
            "username": user.username,
            "display_name": user.username,  # для локальных пользователей отображаемое имя совпадает с логином
            "auth": "local",
            "settings": user.is_admin,  # локальные администраторы имеют доступ к настройкам
            "groups": []  # локальные пользователи не имеют групп AD
        }
        
        return AuthResult(success=True, user_data=user_data)