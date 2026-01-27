from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import UserPresence


def normalize_login(raw: str) -> str:
    """Normalize login to sAMAccountName-like token (lower).

    Supported:
      - DOMAIN\\user -> user
      - user@domain -> user
      - user -> user
    """
    s = (raw or "").strip()
    if not s:
        return ""
    if "\\" in s:
        s = s.split("\\", 1)[1]
    if "@" in s:
        s = s.split("@", 1)[0]
    return (s or "").strip().lower()


def fmt_dt_ru(dt: Any) -> str:
    """Human-friendly RU datetime string in UTC.

    - If dt is naive, it is treated as UTC.
    - Output: DD.MM.YYYY HH:MM:SS
    """
    if not dt:
        return ""
    try:
        # SQLAlchemy normally returns datetime, but be tolerant to strings.
        if isinstance(dt, str):
            # Try ISO-like first
            try:
                dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
            except Exception:
                return dt
        if isinstance(dt, datetime):
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            dt = dt.astimezone(timezone.utc)
            return dt.strftime("%d.%m.%Y %H:%M:%S")
    except Exception:
        pass
    return str(dt)


def get_presence_map(db: Session, logins: list[str]) -> dict[str, UserPresence]:
    keys = [normalize_login(x) for x in (logins or [])]
    keys = [k for k in keys if k]
    if not keys:
        return {}
    rows = db.scalars(select(UserPresence).where(UserPresence.user_login.in_(keys))).all()
    return {r.user_login: r for r in rows}


def upsert_presence_bulk(db: Session, items: dict[str, dict]) -> int:
    """Upsert presence records in bulk.

    items: { login_lower: {host, ip, method, ts(datetime)} }
    """
    if not items:
        return 0

    cnt = 0
    for login, data in items.items():
        login_key = normalize_login(login)
        if not login_key:
            continue
        host = (data.get("host") or "").strip()
        ip = (data.get("ip") or "").strip()
        method = (data.get("method") or "").strip()
        ts = data.get("ts") or datetime.now(timezone.utc)
        if isinstance(ts, datetime) and ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        row = db.get(UserPresence, login_key)
        if row is None:
            row = UserPresence(
                user_login=login_key,
                host=host,
                ip=ip,
                method=method,
                last_seen_ts=ts,
            )
            db.add(row)
            cnt += 1
        else:
            # update only if newer
            old = row.last_seen_ts or datetime.min.replace(tzinfo=timezone.utc)
            if isinstance(old, datetime) and old.tzinfo is None:
                old = old.replace(tzinfo=timezone.utc)
            if ts >= old:
                row.host = host
                row.ip = ip
                row.method = method
                row.last_seen_ts = ts
                cnt += 1

    db.commit()
    return cnt


# Backward-compatible aliases (older code may import different names)
def upsert_presence(db: Session, items: dict[str, dict]) -> int:
    return upsert_presence_bulk(db, items)
