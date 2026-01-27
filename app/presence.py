from __future__ import annotations

from datetime import datetime
from typing import Iterable

from sqlalchemy.orm import Session

from .models import UserPresence


def normalize_login(login: str) -> str:
    """Normalize login to a stable key.

    Examples:
    - "DOMAIN\\user" -> "user"
    - "user@domain"  -> "user"
    - "user"         -> "user"
    """
    s = (login or "").strip()
    if not s:
        return ""
    if "\\" in s:
        s = s.split("\\", 1)[1]
    if "@" in s:
        s = s.split("@", 1)[0]
    return (s or "").strip().lower()


def get_presence_map(db: Session, logins: Iterable[str]) -> dict[str, UserPresence]:
    keys = [normalize_login(x) for x in logins]
    keys = [k for k in keys if k]
    if not keys:
        return {}

    rows = db.query(UserPresence).filter(UserPresence.user_login.in_(list(set(keys)))).all()
    return {r.user_login: r for r in rows}


def fmt_dt_ru(dt: datetime | None) -> str:
    if not dt:
        return ""
    try:
        return dt.strftime("%d.%m.%Y %H:%M")
    except Exception:
        return str(dt)
