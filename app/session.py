from __future__ import annotations

import json
import logging
import secrets
import time
from typing import Dict, Any

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from .env_settings import get_env

# Server-side sessions: the signed cookie carries only a random session id, the session itself lives in
# Redis. Logout deletes it for real, and the account is re-checked every few minutes, so a disabled user
# or one removed from the allowed group loses access without waiting up to 8 h for the cookie to expire.
# (Before 21.10.2026 the whole user payload incl. all memberOf DNs was stored in the cookie.)

SESSION_TTL_S = 8 * 60 * 60
REVALIDATE_EVERY_S = 5 * 60
_KEY = "adp:sess:{}"

log = logging.getLogger(__name__)
_redis_client = None


def _serializer() -> URLSafeTimedSerializer:
    s = get_env()
    return URLSafeTimedSerializer(s.secret_key, salt="ad-portal-session")


def _redis():
    global _redis_client
    if _redis_client is None:
        import redis

        _redis_client = redis.Redis.from_url(get_env().redis_url, decode_responses=True, socket_timeout=3)
    return _redis_client


def _sid_from_token(token: str, max_age_seconds: int) -> str | None:
    try:
        data = _serializer().loads(token, max_age=max_age_seconds)
    except (BadSignature, SignatureExpired):
        return None
    if isinstance(data, dict) and isinstance(data.get("sid"), str):
        return data["sid"]
    return None  # old cookie format (full payload) -> log in again


def create_session(data: Dict[str, Any]) -> str:
    sid = secrets.token_urlsafe(32)
    now = time.time()
    rec = dict(data)
    rec["_created"] = now
    rec["_checked"] = now
    _redis().setex(_KEY.format(sid), SESSION_TTL_S, json.dumps(rec, ensure_ascii=False))
    return _serializer().dumps({"sid": sid})


def destroy_session(token: str) -> None:
    sid = _sid_from_token(token, SESSION_TTL_S) if token else None
    if not sid:
        return
    try:
        _redis().delete(_KEY.format(sid))
    except Exception:
        log.warning("Не удалось удалить сессию из Redis", exc_info=True)


def _still_allowed(rec: dict) -> dict | None:
    """Re-check the account behind a session. Returns updated fields, {} = keep as is, None = revoke."""
    from .repo import db_session, get_local_user, get_or_create_settings

    username = str(rec.get("username") or "")
    if rec.get("auth") == "local":
        with db_session() as db:
            u = get_local_user(db, username)
            if not u or not u.is_enabled:
                return None
            return {"settings": bool(u.is_admin)}

    from .ad import ADClient
    from .ad_utils import split_group_dns
    from .services.ad import ad_cfg_from_settings

    with db_session() as db:
        st = get_or_create_settings(db)
        cfg = ad_cfg_from_settings(st)
        allowed_app = set(split_group_dns(st.allowed_app_group_dns))
        allowed_settings = set(split_group_dns(st.allowed_settings_group_dns))
    if not cfg:
        return {}
    state = ADClient(cfg).get_login_state(username)
    if state is None:
        return {}  # AD not reachable: keep the session, try again on the next request
    exists, enabled, member_of = state
    groups = set(member_of)
    if not exists or not enabled or (allowed_app and not (groups & allowed_app)):
        return None
    return {"settings": bool(groups & allowed_settings) if allowed_settings else False, "groups": member_of}


def read_session(token: str, max_age_seconds: int) -> Dict[str, Any] | None:
    sid = _sid_from_token(token, max_age_seconds)
    if not sid:
        return None
    key = _KEY.format(sid)
    try:
        raw = _redis().get(key)
    except Exception:
        log.warning("Redis недоступен: сессия не проверена", exc_info=True)
        return None
    if not raw:
        return None
    rec = json.loads(raw)

    now = time.time()
    if now - float(rec.get("_checked") or 0) > REVALIDATE_EVERY_S:
        try:
            upd = _still_allowed(rec)
        except Exception:
            log.warning("Ошибка перепроверки сессии %s", rec.get("username"), exc_info=True)
            upd = {}
        if upd is None:
            log.info("Сессия %s закрыта: учётка отключена или не в разрешённой группе", rec.get("username"))
            _redis().delete(key)
            return None
        rec.update(upd)
        rec["_checked"] = now
        _redis().set(key, json.dumps(rec, ensure_ascii=False), keepttl=True)

    return {k: v for k, v in rec.items() if not k.startswith("_")}
