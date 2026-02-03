from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def escape_ldap_filter_value(value: str) -> str:
    """RFC 4515 escaping for LDAP filter values."""
    out: list[str] = []
    for ch in value:
        if ch == "\\":
            out.append("\\5c")
        elif ch == "*":
            out.append("\\2a")
        elif ch == "(":
            out.append("\\28")
        elif ch == ")":
            out.append("\\29")
        elif ch == "\x00":
            out.append("\\00")
        else:
            out.append(ch)
    return "".join(out)


def filetime_to_dt_str(v: Any) -> str | None:
    """Convert Windows FILETIME (100ns since 1601-01-01) to ISO datetime string (UTC)."""
    try:
        n = int(v)
    except Exception:
        return None
    if n <= 0:
        return None
    seconds = (n / 10_000_000) - 11_644_473_600
    if seconds <= 0:
        return None
    dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
    return dt.isoformat(timespec="seconds")
