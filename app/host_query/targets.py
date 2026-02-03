from __future__ import annotations

import re


_RE_IPv4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def is_ipv4(s: str) -> bool:
    s = (s or "").strip()
    if not _RE_IPv4.match(s):
        return False
    try:
        parts = [int(x) for x in s.split(".")]
        return len(parts) == 4 and all(0 <= p <= 255 for p in parts)
    except Exception:
        return False


def normalize_targets(raw: str, domain_suffix: str) -> list[str]:
    raw = (raw or "").strip()
    if not raw:
        return []

    if is_ipv4(raw):
        return [raw]

    # Already FQDN
    if "." in raw:
        return [raw]

    domain_suffix = (domain_suffix or "").strip().lstrip(".")
    if domain_suffix:
        # Try FQDN first, then short
        return [f"{raw}.{domain_suffix}", raw]
    return [raw]
