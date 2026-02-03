from __future__ import annotations

import ipaddress
import re


def short_hostname(name: str) -> str:
    s = (name or "").strip().rstrip(".")
    if not s:
        return ""
    return s.split(".", 1)[0]


def looks_like_ipv4(s: str) -> bool:
    try:
        ipaddress.ip_address((s or "").strip())
        return True
    except Exception:
        return False


def ip_subnet_key(ip: str) -> str:
    """Return a coarse subnet key for badge grouping (default: /24)."""
    s = (ip or "").strip()
    if not looks_like_ipv4(s):
        return ""
    parts = s.split(".")
    if len(parts) != 4:
        return ""
    return ".".join(parts[:3]) + ".0/24"


def subnet_badge_class(subnet_key: str) -> str:
    """Stable mapping subnet -> Bootstrap badge class."""
    if not subnet_key:
        return "text-bg-light border text-dark"
    variants = [
        "text-bg-primary",
        "text-bg-success",
        "text-bg-warning text-dark",
        "text-bg-danger",
        "text-bg-info text-dark",
        "text-bg-secondary",
        "text-bg-dark",
    ]
    idx = (sum(subnet_key.encode("utf-8")) % len(variants))
    return variants[idx]


_NAT_SPLIT_RE = re.compile(r"(\d+)")


def natural_key(s: str) -> list:
    """Human-friendly sort key: A2 < A10, case-insensitive."""
    s = (s or "").strip()
    if not s:
        return [""]
    parts = _NAT_SPLIT_RE.split(s)
    out: list = []
    for p in parts:
        if p == "":
            continue
        if p.isdigit():
            out.append(int(p))
        else:
            out.append(p.casefold())
    return out


def ip_key(ip: str) -> tuple:
    s = (ip or "").strip()
    try:
        return (0, int(ipaddress.IPv4Address(s)))
    except Exception:
        return (1, s.casefold())
