from __future__ import annotations

import re
from datetime import datetime, timezone

from ..timezone_utils import format_ru_local


_AD_GT_RE = re.compile(r"^(\d{14})(?:\.(\d+))?Z$")


def fmt_dt_human(v: str) -> str:
    """Human-friendly datetime for UI: DD.MM.YYYY HH:MM:SS (local TZ, best-effort).

    Supports:
    - ISO-8601 (with or without timezone)
    - AD GeneralizedTime (YYYYmmddHHMMSS(.fff)Z)

    Notes:
    - Naive timestamps are treated as UTC (how we store them in SQLite today).
    - Aware timestamps are converted to local TZ from TZ env (via timezone_utils).
    """
    s = (v or "").strip()
    if not s:
        return ""

    # AD GeneralizedTime: 20260126042000.0Z or 20260126042000Z
    m = _AD_GT_RE.match(s)
    if m:
        try:
            # GeneralizedTime with Z -> UTC
            dt = datetime.strptime(m.group(1), "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
            return format_ru_local(dt)
        except Exception:
            pass

    try:
        s2 = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s2)
        return format_ru_local(dt)
    except Exception:
        return s
