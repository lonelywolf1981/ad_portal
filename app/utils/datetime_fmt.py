from __future__ import annotations

import re
from datetime import datetime, timezone


_AD_GT_RE = re.compile(r"^(\d{14})(?:\.(\d+))?Z$")


def fmt_dt_human(v: str) -> str:
    """Human-friendly datetime: DD.MM.YYYY HH:MM:SS (best-effort).

    Supports ISO-8601 and AD GeneralizedTime (YYYYmmddHHMMSS(.fff)Z).
    """
    s = (v or "").strip()
    if not s:
        return ""

    # AD GeneralizedTime: 20260126042000.0Z or 20260126042000Z
    m = _AD_GT_RE.match(s)
    if m:
        try:
            dt = datetime.strptime(m.group(1), "%Y%m%d%H%M%S")
            return dt.strftime("%d.%m.%Y %H:%M:%S")
        except Exception:
            pass

    try:
        s2 = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s2)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt.strftime("%d.%m.%Y %H:%M:%S")
    except Exception:
        return s
