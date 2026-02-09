from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from .models import HostUserMap
from .presence import normalize_login


def normalize_host(raw: str) -> str:
    """Normalize hostname for stable dedupe.

    We store short hostname (without domain) in lower-case.
    If hostname is empty, caller may pass IP or any label.
    """
    s = (raw or "").strip().rstrip(".")
    if not s:
        return ""
    # Short host (without domain)
    s = s.split(".", 1)[0]
    return s.lower()


def _utcnow_naive() -> datetime:
    # Keep naive UTC datetimes for compatibility with current SQLite DateTime usage.
    return datetime.utcnow()


def upsert_host_user_matches(db: Session, matches: list[dict[str, Any]]) -> int:
    """Upsert list of matches.

    match item schema (best-effort):
      {
        "host": "PC-01",  # hostname (any case)
        "ip": "192.168.1.10",
        "login": "user" | "DOMAIN\\user" | "user@domain",
        "method": "winrm"|"wmi"|"smb"|"",
        "ts": datetime
      }

    Dedup key: (host_norm, login_norm)
    """
    if not matches:
        return 0

    updated = 0
    for m in matches:
        host_raw = (m.get("host") or "").strip()
        ip = (m.get("ip") or "").strip()
        login_raw = (m.get("login") or "").strip()
        method = (m.get("method") or "").strip()
        ts = m.get("ts") or _utcnow_naive()
        if isinstance(ts, datetime) and ts.tzinfo is not None:
            # Store as naive UTC
            ts = ts.astimezone(timezone.utc).replace(tzinfo=None)

        host = normalize_host(host_raw)
        login = normalize_login(login_raw)
        if not login:
            continue
        # If hostname is unknown, still store mapping by IP to avoid losing the match.
        if not host:
            host = (ip or "").strip()
        if not host:
            continue

        row = db.get(HostUserMap, (host, login))
        if row is None:
            db.add(
                HostUserMap(
                    host=host,
                    user_login=login,
                    ip=ip,
                    method=method,
                    last_seen_ts=ts,
                )
            )
            updated += 1
            continue

        old = row.last_seen_ts or datetime.min
        if ts >= old:
            row.ip = ip
            row.method = method
            row.last_seen_ts = ts
            updated += 1

    db.commit()
    return updated


def cleanup_host_user_matches(db: Session, retention_days: int = 31) -> int:
    """Delete rows older than retention_days."""
    days = int(retention_days or 31)
    if days < 1:
        days = 1

    cutoff = _utcnow_naive() - timedelta(days=days)
    res = db.execute(delete(HostUserMap).where(HostUserMap.last_seen_ts < cutoff))
    db.commit()
    # SQLAlchemy may return None for rowcount in some configurations.
    return int(res.rowcount or 0)


def search_host_user_matches(db: Session, q: str = "", limit: int = 500) -> list[HostUserMap]:
    """Search by host/ip/login. Returns newest first."""
    q = (q or "").strip()
    lim = int(limit or 500)
    if lim < 1:
        lim = 1
    if lim > 2000:
        lim = 2000

    stmt = select(HostUserMap).order_by(HostUserMap.last_seen_ts.desc())

    if q:
        ql = q.lower().replace("%", r"\%").replace("_", r"\_")
        pat = f"%{ql}%"
        stmt = stmt.where(
            or_(
                func.lower(HostUserMap.host).like(pat, escape="\\"),
                func.lower(HostUserMap.ip).like(pat, escape="\\"),
                func.lower(HostUserMap.user_login).like(pat, escape="\\"),
            )
        )

    return db.scalars(stmt.limit(lim)).all()
