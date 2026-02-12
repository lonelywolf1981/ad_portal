from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from .models import HostShare
from .mappings import normalize_host

# Бит STYPE_SPECIAL — скрытые/системные шары (ADMIN$, C$, IPC$ и т.д.)
STYPE_SPECIAL = 0x80000000


def _utcnow_naive() -> datetime:
    return datetime.utcnow()


def hidden_share_expr():
    """SQL expression: share is hidden/system if SPECIAL bit set or name ends with '$'."""
    return or_(
        (HostShare.share_type.op("&")(STYPE_SPECIAL)) != 0,
        HostShare.share_name.like("%$"),
    )


def upsert_shares_bulk(db: Session, items: list[dict[str, Any]]) -> int:
    """Upsert список обнаруженных шар.

    Элемент:
      {
        "host": "PC-01",
        "ip": "192.168.1.10",
        "share_name": "Users",
        "share_type": 0,
        "remark": "Общая папка"
      }

    Ключ дедупликации: (host_norm, share_name).
    """
    if not items:
        return 0

    updated = 0
    for m in items:
        host_raw = (m.get("host") or "").strip()
        ip = (m.get("ip") or "").strip()
        share_name = (m.get("share_name") or "").strip()
        share_type = int(m.get("share_type", 0) or 0)
        remark = (m.get("remark") or "").strip()
        if share_name.endswith("$"):
            share_type |= STYPE_SPECIAL

        host = normalize_host(host_raw)
        if not host:
            host = ip
        if not host or not share_name:
            continue

        now = _utcnow_naive()
        row = db.get(HostShare, (host, share_name))
        if row is None:
            db.add(
                HostShare(
                    host=host,
                    share_name=share_name,
                    ip=ip,
                    share_type=share_type,
                    remark=remark,
                    last_seen_ts=now,
                )
            )
            updated += 1
        else:
            row.ip = ip
            row.share_type = share_type
            row.remark = remark
            row.last_seen_ts = now
            updated += 1

    db.commit()
    return updated


def replace_shares_snapshot(db: Session, items: list[dict[str, Any]], *, seen_ts: datetime | None = None) -> int:
    """Полностью заменить локальный снимок обнаруженных шар текущим результатом сканирования."""
    now = seen_ts or _utcnow_naive()
    dedup: dict[tuple[str, str], dict[str, Any]] = {}

    for m in (items or []):
        host_raw = (m.get("host") or "").strip()
        ip = (m.get("ip") or "").strip()
        share_name = (m.get("share_name") or "").strip()
        share_type = int(m.get("share_type", 0) or 0)
        remark = (m.get("remark") or "").strip()
        if share_name.endswith("$"):
            share_type |= STYPE_SPECIAL

        host = normalize_host(host_raw)
        if not host:
            host = ip
        if not host or not share_name:
            continue

        dedup[(host, share_name)] = {
            "host": host,
            "share_name": share_name,
            "ip": ip,
            "share_type": share_type,
            "remark": remark,
        }

    db.execute(delete(HostShare))
    for item in dedup.values():
        db.add(
            HostShare(
                host=item["host"],
                share_name=item["share_name"],
                ip=item["ip"],
                share_type=item["share_type"],
                remark=item["remark"],
                last_seen_ts=now,
            )
        )
    db.commit()
    return len(dedup)


def cleanup_shares(db: Session, retention_days: int = 31) -> int:
    """Удаление шар, не обнаруженных дольше retention_days."""
    days = max(1, int(retention_days or 31))
    cutoff = _utcnow_naive() - timedelta(days=days)
    res = db.execute(delete(HostShare).where(HostShare.last_seen_ts < cutoff))
    db.commit()
    return int(res.rowcount or 0)


def delete_share(db: Session, host: str, share_name: str) -> int:
    """Удалить запись шары из локального кэша после успешного удаления на хосте."""
    host_norm = normalize_host((host or "").strip())
    name = (share_name or "").strip()
    if not host_norm or not name:
        return 0
    res = db.execute(
        delete(HostShare).where(
            HostShare.host == host_norm,
            HostShare.share_name == name,
        )
    )
    db.commit()
    return int(res.rowcount or 0)


def search_shares(
    db: Session,
    q: str = "",
    show_hidden: bool = False,
    limit: int = 500,
) -> list[HostShare]:
    """Поиск шар по хосту, IP, имени ресурса или описанию.

    show_hidden=False исключает скрытые/системные шары:
    - с битом STYPE_SPECIAL
    - или по имени, оканчивающемуся на '$' (ADMIN$, C$, IPC$ ...)
    """
    q = (q or "").strip()
    lim = max(1, min(2000, int(limit or 500)))

    stmt = select(HostShare).order_by(HostShare.last_seen_ts.desc())

    if not show_hidden:
        stmt = stmt.where(~hidden_share_expr())

    if q:
        ql = q.lower().replace("%", r"\%").replace("_", r"\_")
        pat = f"%{ql}%"
        stmt = stmt.where(
            or_(
                func.lower(HostShare.host).like(pat, escape="\\"),
                func.lower(HostShare.ip).like(pat, escape="\\"),
                func.lower(HostShare.share_name).like(pat, escape="\\"),
                func.lower(HostShare.remark).like(pat, escape="\\"),
            )
        )

    return db.scalars(stmt.limit(lim)).all()
