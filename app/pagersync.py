"""PIN codes PaperCut -> AD otherPager (the two "pager" numbers = PaperCut primary/secondary card numbers).

TS1 (where PaperCut runs) reads the card numbers locally with server-command every hour and POSTs them here
(/api/v1/pager-sync/papercut, own token). The portal compares them with AD and writes otherPager with its
service account svc-adportal (it already has write rights on users). Rules (decided 21.10.2026):
- enabled user objects (not computers) in the user OUs under OU=Domain Controllers only;
- service / test accounts are excluded (PAGERSYNC_EXCLUDE + svc*, test*, *.adm);
- AD is set to the PaperCut values when they differ (filled = was empty, updated = changed);
- users without card numbers in PaperCut are reported, AD is left as is.
Reports never contain PIN values. Every change goes to the audit log.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time

from ldap3 import MODIFY_REPLACE, SUBTREE

log = logging.getLogger(__name__)

REPORTS_KEY = "adp:pagersync:reports"
_SEARCH_BASE = "OU=Domain Controllers,DC=ubc,DC=local,DC=net"
_DEFAULT_EXCLUDE = "exchange,test1,stanok,conference,test_ad,operator,user,user_14,a.baidenko.adm"
_PIN_RE = re.compile(r"^\d{3,12}$")


def _excluded(sam: str) -> bool:
    s = (sam or "").lower()
    names = {x.strip().lower() for x in (os.getenv("PAGERSYNC_EXCLUDE") or _DEFAULT_EXCLUDE).split(",") if x.strip()}
    return s in names or s.startswith(("svc", "test")) or s.endswith(".adm")


def run_sync(entries: list[dict], *, apply: bool = True) -> dict:
    """entries: [{"user": login, "primary": "1234", "secondary": "5678"}] from PaperCut."""
    from .ad import ADClient
    from .repo import db_session, get_or_create_settings
    from .services.ad import ad_cfg_from_settings

    pc = {}
    for e in entries or []:
        u = str(e.get("user") or "").strip().lower()
        pins = [str(e.get(k) or "").strip() for k in ("primary", "secondary")]
        pins = [p for i, p in enumerate(pins) if _PIN_RE.match(p) and p not in pins[:i]]
        if u:
            pc[u] = pins

    with db_session() as db:
        cfg = ad_cfg_from_settings(get_or_create_settings(db))
    if not cfg:
        raise RuntimeError("AD не настроен")
    cl = ADClient(cfg)
    conn = cl._conn(cl.cfg.bind_principal, cl.cfg.bind_password)
    if not conn.bind():
        raise RuntimeError(f"bind: {conn.result.get('description')}")

    flt = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    entries_ad = conn.extend.standard.paged_search(_SEARCH_BASE, flt, SUBTREE, attributes=["sAMAccountName", "otherPager"], paged_size=500, generator=False)
    rep = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "apply": apply, "papercut_users": len(pc),
           "checked": 0, "excluded": 0, "unchanged": 0, "filled": [], "updated": [], "not_in_papercut": [], "no_pin_in_papercut": [], "errors": []}
    for item in entries_ad:
        if item.get("type") != "searchResEntry":
            continue
        a = item["attributes"]
        sam = str(a.get("sAMAccountName") or "")
        if not sam:
            continue
        if _excluded(sam):
            rep["excluded"] += 1
            continue
        rep["checked"] += 1
        cur = [str(x) for x in (a.get("otherPager") or [])]
        want = pc.get(sam.lower())
        if want is None:
            if not cur:
                rep["not_in_papercut"].append(sam)
            continue
        if not want:
            rep["no_pin_in_papercut"].append(sam)
            continue
        if sorted(cur) == sorted(want):
            rep["unchanged"] += 1
            continue
        kind = "filled" if not cur else "updated"
        if apply:
            ok = conn.modify(item["dn"], {"otherPager": [(MODIFY_REPLACE, want)]})
            if not ok:
                rep["errors"].append(f"{sam}: {conn.result.get('description')}")
                continue
        rep[kind].append(sam)
    conn.unbind()
    return rep


def store_report(rep: dict) -> None:
    from .session import _redis

    try:
        r = _redis()
        r.lpush(REPORTS_KEY, json.dumps(rep, ensure_ascii=False))
        r.ltrim(REPORTS_KEY, 0, 199)
    except Exception:
        log.warning("Не удалось сохранить отчёт pager-sync", exc_info=True)


def last_reports(n: int = 10) -> list[dict]:
    from .session import _redis

    try:
        return [json.loads(x) for x in _redis().lrange(REPORTS_KEY, 0, max(0, n - 1))]
    except Exception:
        return []
