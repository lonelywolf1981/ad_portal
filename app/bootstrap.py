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