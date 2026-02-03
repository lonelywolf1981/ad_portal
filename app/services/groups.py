from __future__ import annotations

import json

from ..models import AppSettings


def get_groups_cache(st: AppSettings) -> list[dict]:
    try:
        return json.loads(st.groups_cache_json or "[]")
    except Exception:
        return []


def groups_dn_to_name_map(st: AppSettings) -> dict:
    m: dict = {}
    for g in get_groups_cache(st):
        dn = g.get("dn")
        name = g.get("name")
        if dn and name:
            m[dn] = name
    return m
