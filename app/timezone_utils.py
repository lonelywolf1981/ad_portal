from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

try:
    # Python 3.9+
    from zoneinfo import ZoneInfo  # type: ignore
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore


def _tz_name() -> str:
    """Preferred TZ name from environment (Docker/Unix TZ)."""
    return (os.getenv("TZ") or "UTC").strip() or "UTC"


def get_local_tzinfo():
    """Return tzinfo for local display.

    - Tries system zoneinfo (ZoneInfo).
    - Falls back to fixed +05:00 for Asia/Almaty if zoneinfo is unavailable.
    - Defaults to UTC on any error.
    """
    name = _tz_name()

    # Best case: ZoneInfo database is available in the image.
    if ZoneInfo is not None:
        try:
            return ZoneInfo(name)
        except Exception:
            pass

    # Fallbacks (no tzdata inside the image)
    if name == "Asia/Almaty":
        return timezone(timedelta(hours=5))

    if name.upper() in {"UTC", "GMT", "ETC/UTC", "ETC/GMT"}:
        return timezone.utc

    return timezone.utc


LOCAL_TZ = get_local_tzinfo()


def _parse_dt_any(v: Any) -> Optional[datetime]:
    if v is None:
        return None

    if isinstance(v, datetime):
        dt = v
    elif isinstance(v, str):
        s = v.strip()
        if not s:
            return None
        try:
            # Support ISO timestamps with trailing Z.
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            return None
    else:
        return None

    # Treat naive datetimes as UTC (this is what we store in SQLite today).
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def to_local_dt(v: Any) -> Optional[datetime]:
    """Convert stored timestamp to local tz (aware datetime)."""
    dt = _parse_dt_any(v)
    if dt is None:
        return None
    try:
        return dt.astimezone(LOCAL_TZ)
    except Exception:
        return dt.astimezone(timezone.utc)


def format_iso_local(v: Any, *, timespec: str = "seconds") -> str:
    """Format timestamp for UI/logs as *local* time without TZ suffix.

    Returns ISO-like string: YYYY-MM-DD HH:MM:SS(.ffffff)
    """
    dt = to_local_dt(v)
    if dt is None:
        return ""

    # UI expects no "+05:00" suffix -> make it naive after conversion.
    naive = dt.replace(tzinfo=None)
    try:
        return naive.isoformat(sep=" ", timespec=timespec)
    except TypeError:
        s = naive.isoformat(sep=" ")
        if timespec == "seconds" and "." in s:
            s = s.split(".", 1)[0]
        return s


def format_ru_local(v: Any) -> str:
    """Format timestamp for UI as DD.MM.YYYY HH:MM:SS in local time."""
    dt = to_local_dt(v)
    if dt is None:
        return ""
    return dt.strftime("%d.%m.%Y %H:%M:%S")
