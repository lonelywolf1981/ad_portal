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
        if not isinstance(data, dict) or "u" not in data:
            return None
        return data
    except (BadSignature, SignatureExpired):
        return None
