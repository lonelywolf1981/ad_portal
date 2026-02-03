from __future__ import annotations

from sqlalchemy.orm import Session

from ..models import LocalUser
from ..security import verify_password


def local_authenticate(db: Session, username: str, password: str) -> dict | None:
    u = db.query(LocalUser).filter(LocalUser.username == username).one_or_none()
    if not u or not u.is_enabled:
        return None
    if not verify_password(password, u.password_hash):
        return None
    return {
        "username": u.username,
        "display_name": u.username,
        "auth": "local",
        "settings": bool(u.is_admin),
        "groups": [],
    }
