# Repository Guidelines

## Project Structure & Module Organization
Core application code lives in `app/`:
- `app/main.py`: FastAPI entrypoint and middleware.
- `app/routers/`: HTTP routes (`auth`, `users`, `settings`, `presence`, `ad_management`).
- `app/services/`: business logic (auth, settings, AD integration helpers).
- `app/ad/`, `app/host_query/`, `app/net_scan.py`, `app/tasks.py`: AD operations, host logon detection, background scan.
- `app/templates/` and `app/static/`: Jinja2 UI templates and assets.

Infra and runtime:
- `docker-compose.yml`: web, redis, celery worker/beat, nginx.
- `nginx/`: reverse proxy config.
- `data/`: SQLite DB volume.
- `documentations/`: module docs and internal notes.

## Build, Test, and Development Commands
- `docker compose up -d --build`: build and run full stack.
- `docker compose logs -f web`: stream web logs.
- `docker compose logs -f worker beat`: monitor background jobs.
- `docker compose down`: stop stack.
- Local app only: `uvicorn app.main:app --reload --host 0.0.0.0 --port 8000`.
- Quick syntax check: `python -m py_compile app/main.py` (or any changed module).

## Coding Style & Naming Conventions
- Python 3.11, PEP 8, 4-space indentation.
- Use `snake_case` for functions/variables, `PascalCase` for classes, uppercase for constants.
- Keep route handlers thin; move reusable logic into `services/`.
- Prefer explicit error handling and logging over silent `except: pass`.
- Templates: keep HTMX targets/ids stable; use clear partial names in `app/templates/partials/`.

## Testing Guidelines
- No dedicated automated test suite is currently committed.
- Before PR, perform manual smoke checks:
  - login (`/login/local`, `/login/ad`);
  - settings save/import;
  - user/group search;
  - net scan trigger/status.
- If adding tests, place them under `tests/` with names like `test_<feature>.py`.

## Commit & Pull Request Guidelines
- Follow existing commit style: concise imperative subject, e.g.  
  `Fix auth regressions, harden security, and improve scan stability`.
- Keep commits focused by concern (security, UI, scan logic).
- PR should include:
  - what changed and why;
  - risk/rollback notes for auth, CSRF, net-scan, or AD behavior;
  - screenshots for UI/template changes;
  - exact verification steps run.

## Security & Configuration Tips
- Never commit real secrets; use `.env` and `.env.example`.
- Key env vars: `APP_SECRET_KEY`, `APP_COOKIE_SECURE`, `REDIS_URL`, `HOST_QUERY_WINRM_INSECURE`.
- For production, keep `HOST_QUERY_WINRM_INSECURE=false` and use HTTPS with valid certs.
