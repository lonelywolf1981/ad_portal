from __future__ import annotations

from typing import Dict, Any
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from .env_settings import get_env


def _serializer() -> URLSafeTimedSerializer:
    s = get_env()
    return URLSafeTimedSerializer(s.secret_key, salt="ad-portal-session")


def create_session(data: Dict[str, Any]) -> str:
    return _serializer().dumps(data)


def read_session(token: str, max_age_seconds: int) -> Dict[str, Any] | None:
    try:
        data = _serializer().loads(token, max_age=max_age_seconds)
        # Compatibility: different builds used different payload shapes.
        # 1) "wrapped" format: {"u": {user_fields...}}
        # 2) "flat" format: {user_fields...}
        if not isinstance(data, dict):
            return None
        if "u" in data and isinstance(data.get("u"), dict):
            return data["u"]
        return data
    except (BadSignature, SignatureExpired):
        return None
