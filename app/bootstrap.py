"""Application bootstrap module.

Contains initialization logic that was previously in main.py.
"""

from .env_settings import get_env
from .repo import db_session, ensure_bootstrap_admin
from .schema import ensure_schema
from .security import hash_password


def initialize_application():
    """Initialize the application with required setup steps."""
    # Ensure database schema is up to date
    ensure_schema()

    # Initialize bootstrap admin user if needed
    env = get_env()
    with db_session() as db:
        ensure_bootstrap_admin(db, env.bootstrap_admin_user, hash_password(env.bootstrap_admin_password))

    # Настраиваем логирование из сохранённых настроек
    try:
        from .log_config import setup_logging
        from .services.settings import get_settings as get_typed_settings
        with db_session() as db:
            cfg = get_typed_settings(db)
            setup_logging(
                level=cfg.logging.level,
                retention_days=cfg.logging.retention_days,
                max_size_mb=cfg.logging.max_size_mb,
            )
    except Exception:
        # Fallback: базовое логирование, если настройки ещё не инициализированы
        from .log_config import setup_logging
        setup_logging()