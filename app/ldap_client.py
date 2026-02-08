"""
DEPRECATED: Этот файл является тонкой оберткой для обратной совместимости.
Модуль ldap_client был реорганизован в пакет app/ad/ в целях улучшения архитектуры.
Пожалуйста, обновите свои импорты с '..ldap_client import ...' на '..ad import ...'.
Этот файл будет удален в следующем релизе.
"""

import warnings

# Импортируем из нового местоположения
from .ad import ADClient, ADConfig, ADUser

# Выдаем предупреждение о депрекации
warnings.warn(
    "Модуль ldap_client.py устарел. Пожалуйста, используйте импорты из .ad вместо .ldap_client. "
    "Файл ldap_client.py будет удален в будущем релизе.",
    DeprecationWarning,
    stacklevel=2
)

__all__ = ["ADClient", "ADConfig", "ADUser"]