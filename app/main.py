from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from .env_settings import get_env
from .repo import db_session, ensure_bootstrap_admin, get_or_create_settings
from .schema import ensure_schema
from .security import hash_password
from .webui import templates

# Настройка логирования - только ошибки
logging.getLogger("uvicorn.access").setLevel(logging.ERROR)


# Keep schema bootstrapping at import time (previous behavior).
ensure_schema()


app = FastAPI(title="AD Portal")
app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.on_event("startup")
def _startup():
    # Keep schema + bootstrap admin logic as-is.
    ensure_schema()
    env = get_env()
    with db_session() as db:
        get_or_create_settings(db)
        ensure_bootstrap_admin(db, env.bootstrap_admin_user, hash_password(env.bootstrap_admin_password))


# Routers
from .routers.health import router as health_router  # noqa: E402
from .routers.auth import router as auth_router  # noqa: E402
from .routers.index import router as index_router  # noqa: E402
from .routers.settings import router as settings_router  # noqa: E402
from .routers.users import router as users_router  # noqa: E402
from .routers.hosts import router as hosts_router  # noqa: E402
from .routers.presence import router as presence_router  # noqa: E402

app.include_router(health_router)
app.include_router(auth_router)
app.include_router(index_router)
app.include_router(settings_router)
app.include_router(users_router)
app.include_router(hosts_router)
app.include_router(presence_router)
