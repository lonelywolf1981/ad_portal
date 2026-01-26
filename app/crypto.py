from __future__ import annotations

import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken
from .env_settings import get_env


def _fernet() -> Fernet:
    secret = get_env().secret_key.encode("utf-8")
    key = base64.urlsafe_b64encode(hashlib.sha256(secret).digest())
    return Fernet(key)


def encrypt_str(value: str) -> str:
    if not value:
        return ""
    f = _fernet()
    return f.encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_str(token: str) -> str:
    if not token:
        return ""
    f = _fernet()
    try:
        return f.decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return ""
