from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ...models import AppSettings


@dataclass
class AuthResult:
    """Результат аутентификации пользователя."""
    success: bool
    user_data: dict | None = None
    error_message: str = ""


def authenticate(mode: str, username: str, password: str, settings) -> AuthResult:
    """Единый метод аутентификации пользователя.
    
    Args:
        mode: Режим аутентификации ('local' или 'ad')
        username: Имя пользователя
        password: Пароль
        settings: Настройки приложения
        
    Returns:
        AuthResult: Результат аутентификации
    """
    if mode == "local":
        from .local import authenticate as local_auth
        return local_auth(username, password, settings)
    elif mode == "ad":
        from .ad import authenticate as ad_auth
        return ad_auth(username, password, settings)
    else:
        return AuthResult(success=False, error_message=f"Неизвестный режим аутентификации: {mode}")