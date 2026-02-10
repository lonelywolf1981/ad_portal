from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from .bootstrap import initialize_application


class CSRFMiddleware(BaseHTTPMiddleware):
    """Защита от CSRF для POST/PUT/DELETE/PATCH запросов.

    Для state-changing запросов проверяется источник:
    - Origin (предпочтительно),
    - либо Referer.
    Если оба заголовка отсутствуют, используем безопасный fallback:
    - Sec-Fetch-Site: same-origin/same-site/none,
    - либо разрешаем только login endpoints (совместимость со старыми прокси).
    """

    async def dispatch(self, request: Request, call_next):
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            # HTMX requests send a custom header which cannot be attached by a
            # cross-site form post without CORS preflight.
            if request.headers.get("HX-Request"):
                return await call_next(request)

            origin = request.headers.get("origin", "").strip()
            referer = request.headers.get("referer", "").strip()
            host = request.headers.get("host", "").strip().lower()

            if not host:
                return JSONResponse({"detail": "CSRF: отсутствует заголовок Host."}, status_code=403)

            # Проверяем Origin (наиболее надёжный)
            if origin:
                parsed = urlparse(origin)
                origin_host = (parsed.netloc or parsed.path).strip().lower()
                if origin_host != host:
                    return JSONResponse({"detail": "CSRF: несовпадение Origin."}, status_code=403)
            elif referer:
                parsed = urlparse(referer)
                referer_host = parsed.netloc.strip().lower()
                if referer_host and referer_host != host:
                    return JSONResponse({"detail": "CSRF: несовпадение Referer."}, status_code=403)
            else:
                sec_fetch_site = request.headers.get("sec-fetch-site", "").strip().lower()
                if sec_fetch_site in {"same-origin", "same-site", "none"}:
                    return await call_next(request)

                # Compatibility: some reverse-proxy/browser combinations can strip Origin/Referer
                # on login form submissions. Allow only auth endpoints in this fallback mode.
                path = request.url.path or ""
                if path in {"/login/local", "/login/ad"}:
                    return await call_next(request)

                return JSONResponse({"detail": "CSRF: отсутствуют Origin и Referer."}, status_code=403)

        return await call_next(request)

# Настройка логирования - только ошибки
logging.getLogger("uvicorn.access").setLevel(logging.ERROR)


@asynccontextmanager
async def lifespan(application: FastAPI):
    # Startup: инициализация БД, создание admin-пользователя и т.д.
    initialize_application()
    yield
    # Shutdown (если понадобится)


app = FastAPI(title="AD Portal", lifespan=lifespan)
app.add_middleware(CSRFMiddleware)
app.mount("/static", StaticFiles(directory="app/static"), name="static")


# Routers
from .routers.health import router as health_router  # noqa: E402
from .routers.auth import router as auth_router  # noqa: E402
from .routers.index import router as index_router  # noqa: E402
from .routers.settings import router as settings_router  # noqa: E402
from .routers.users import router as users_router  # noqa: E402
from .routers.hosts import router as hosts_router  # noqa: E402
from .routers.presence import router as presence_router  # noqa: E402
from .routers.ad_management import router as ad_management_router  # noqa: E402

app.include_router(health_router)
app.include_router(auth_router)
app.include_router(index_router)
app.include_router(settings_router)
app.include_router(users_router)
app.include_router(hosts_router)
app.include_router(presence_router)
app.include_router(ad_management_router)
