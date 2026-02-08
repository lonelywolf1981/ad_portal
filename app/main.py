from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from .bootstrap import initialize_application

# Настройка логирования - только ошибки
logging.getLogger("uvicorn.access").setLevel(logging.ERROR)


app = FastAPI(title="AD Portal")
app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.on_event("startup")
def _startup() -> None:
    # IMPORTANT: do not run bootstrap at import time (tests, reload, workers)
    initialize_application()


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
