"""Read-only JSON API for the infra agent / Telegram bot (OpenClaw on 192.168.66.30).

Auth: "Authorization: Bearer <token>"; the portal keeps only SHA-256 of the token (env API_READ_TOKEN_SHA256).
nginx additionally lets /api/ through only from the agent's address. Every call goes to the audit log
(auth_type "api"). Nothing here changes AD, hosts or the portal database.

  GET /api/v1/user/{login}          AD summary (enabled, locked, last logon, password set, title, groups) + where seen
  GET /api/v1/users?q=...           search users by name / login
  GET /api/v1/host/{host}           who was seen on the host (scan history); ?live=1 asks the host right now
  GET /api/v1/host/{host}/shares    SMB shares from the last scan
  GET /api/v1/scan                  last network scan: time and summary
  GET /api/v1/pins/{login}          the user's PIN codes (AD otherPager = PaperCut card numbers)
  GET /api/v1/pins-missing          enabled users with empty otherPager
  GET /api/v1/pager-sync            last PaperCut -> AD PIN sync reports (no PIN values)

  POST /api/v1/pager-sync/papercut  TS1 hourly sends PaperCut card numbers; the portal fills/updates otherPager
                                    (own token, env PAGERSYNC_TOKEN_SHA256; nginx lets it through only from TS1).
                                    The only call here that changes AD — see app/pagersync.py.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select

from ..models import HostShare, HostUserMap
from ..repo import db_session, get_or_create_settings
from ..services.audit import audit_action

router = APIRouter(prefix="/api/v1")

_LOCAL_TZ = timezone(timedelta(hours=5))  # Asia/Almaty (UTC+5), the scan stores naive UTC


def _local(dt: datetime | None) -> str | None:
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(_LOCAL_TZ).strftime("%Y-%m-%d %H:%M")


def _filetime(v) -> str | None:
    """AD time attribute -> local 'YYYY-MM-DD HH:MM'. get_user_details returns ISO strings, raw LDAP gives FILETIME."""
    if isinstance(v, str) and "-" in v:
        try:
            dt = datetime.fromisoformat(v)
        except ValueError:
            return None
        return None if dt.year < 1700 else _local(dt)
    try:
        n = int(v)
    except (TypeError, ValueError):
        if isinstance(v, datetime):
            return None if v.year < 1700 else _local(v)  # ldap3 turns 0 ("never") into 1601-01-01
        return None
    if n <= 0 or n >= 0x7FFFFFFFFFFFFFFF:
        return None
    return _local(datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=n // 10))


def _auth(request: Request, env: str = "API_READ_TOKEN_SHA256", who: str = "api-agent") -> dict | None:
    expected = (os.getenv(env) or "").strip().lower()
    hdr = request.headers.get("authorization", "")
    if not expected or not hdr.lower().startswith("bearer "):
        return None
    got = hashlib.sha256(hdr[7:].strip().encode("utf-8")).hexdigest()
    return {"username": who} if hmac.compare_digest(got, expected) else None


def _deny(request: Request) -> JSONResponse:
    audit_action(request, {"username": "api-unknown"}, "api", request.url.path, False, "bad or missing token")
    return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)


def _client():
    from ..ad import ADClient
    from ..services.ad import ad_cfg_from_settings

    with db_session() as db:
        cfg = ad_cfg_from_settings(get_or_create_settings(db))
    return ADClient(cfg) if cfg else None


def _first(v):
    if isinstance(v, list):
        return v[0] if v else None
    return v


@router.get("/user/{login}")
def api_user(request: Request, login: str, days: int = 30):
    who = _auth(request)
    if not who:
        return _deny(request)
    login = (login or "").strip()
    cl = _client()
    if not cl:
        return JSONResponse({"ok": False, "error": "AD not configured"}, status_code=503)
    u = cl.find_user_by_login(login)
    if not u:
        audit_action(request, who, "api", "user", False, login)
        return JSONResponse({"ok": False, "error": "user not found", "login": login}, status_code=404)
    ok, _msg, d = cl.get_user_details(u.dn)
    d = d or {}
    uac = int(_first(d.get("userAccountControl")) or 0)
    lockout = _first(d.get("lockoutTime"))
    locked = _filetime(lockout) is not None
    since = datetime.utcnow() - timedelta(days=max(1, min(days, 365)))
    with db_session() as db:
        seen = db.scalars(
            select(HostUserMap)
            .where(HostUserMap.user_login == (u.sam or login).lower(), HostUserMap.last_seen_ts >= since)
            .order_by(HostUserMap.last_seen_ts.desc())
            .limit(20)
        ).all()
        hosts = [{"host": r.host, "ip": r.ip, "last_seen": _local(r.last_seen_ts), "method": r.method} for r in seen]
    groups = [g.split(",", 1)[0].removeprefix("CN=") for g in (u.member_of or [])]
    out = {
        "ok": True,
        "login": u.sam,
        "name": u.display_name,
        "mail": u.mail or None,
        "title": _first(d.get("title")),
        "department": _first(d.get("department")),
        "phone": _first(d.get("telephoneNumber")) or _first(d.get("mobile")),
        "ip_phone": _first(d.get("ipPhone")),
        "enabled": not bool(uac & 0x2),
        "locked": locked,
        "lockout_time": _filetime(lockout) if locked else None,
        "password_never_expires": bool(uac & 0x10000),
        "password_set": _filetime(_first(d.get("pwdLastSet"))),
        "last_logon": _filetime(_first(d.get("lastLogonTimestamp"))),
        "bad_password_count": _first(d.get("badPwdCount")),
        "ou": u.dn.split(",", 1)[1] if "," in u.dn else "",
        "groups": sorted(groups),
        "seen_on_hosts": hosts,
    }
    audit_action(request, who, "api", "user", True, login)
    return out


@router.get("/users")
def api_users(request: Request, q: str = "", limit: int = 20):
    who = _auth(request)
    if not who:
        return _deny(request)
    q = (q or "").strip()
    if len(q) < 2:
        return JSONResponse({"ok": False, "error": "q must be at least 2 characters"}, status_code=400)
    cl = _client()
    if not cl:
        return JSONResponse({"ok": False, "error": "AD not configured"}, status_code=503)
    ok, msg, items = cl.search_users(q, limit=max(1, min(limit, 50)))
    audit_action(request, who, "api", "users", ok, q)
    if not ok:
        return JSONResponse({"ok": False, "error": msg}, status_code=502)
    return {"ok": True, "query": q, "users": [
        {"login": i.get("login") or i.get("sam"), "name": i.get("fio") or i.get("display"), "mail": i.get("mail")} for i in items
    ]}


def _norm_host(h: str) -> str:
    return (h or "").strip().split(".")[0].lower()


@router.get("/host/{host}")
def api_host(request: Request, host: str, live: int = 0, days: int = 30):
    who = _auth(request)
    if not who:
        return _deny(request)
    h = _norm_host(host)
    since = datetime.utcnow() - timedelta(days=max(1, min(days, 365)))
    with db_session() as db:
        rows = db.scalars(
            select(HostUserMap).where(HostUserMap.host == h, HostUserMap.last_seen_ts >= since)
            .order_by(HostUserMap.last_seen_ts.desc()).limit(20)
        ).all()
        hist = [{"login": r.user_login, "ip": r.ip, "last_seen": _local(r.last_seen_ts)} for r in rows]
        st = get_or_create_settings(db)
        domain, q_user = (st.ad_domain or "").strip(), (st.host_query_username or "").strip()
        from ..crypto import decrypt_str

        q_pass = decrypt_str(getattr(st, "host_query_password_enc", "") or "")
    out = {"ok": True, "host": h, "seen_users": hist}
    if live:
        from ..host_query.api import find_logged_on_users

        users, method, ms, attempts = find_logged_on_users(h, domain, q_user, q_pass, per_method_timeout_s=20)
        out["live"] = {"users": users, "method": method or None, "ms": ms,
                       "errors": [f"{a.method}: {a.message}" for a in attempts if a.status not in ("ok", "empty", "skipped")][:3]}
    audit_action(request, who, "api", "host", True, f"{h} live={bool(live)}")
    return out


@router.get("/host/{host}/shares")
def api_host_shares(request: Request, host: str):
    who = _auth(request)
    if not who:
        return _deny(request)
    h = _norm_host(host)
    with db_session() as db:
        rows = db.scalars(select(HostShare).where(HostShare.host == h).order_by(HostShare.share_name)).all()
        shares = [{"name": r.share_name, "type": r.share_type, "remark": r.remark, "ip": r.ip,
                   "last_seen": _local(r.last_seen_ts)} for r in rows]
    audit_action(request, who, "api", "shares", True, h)
    return {"ok": True, "host": h, "shares": shares}


@router.get("/scan")
def api_scan(request: Request):
    who = _auth(request)
    if not who:
        return _deny(request)
    with db_session() as db:
        st = get_or_create_settings(db)
        out = {"ok": True, "enabled": bool(st.net_scan_enabled), "running": bool(st.net_scan_lock_ts),
               "last_run": _local(st.net_scan_last_run_ts), "summary": st.net_scan_last_summary,
               "interval_min": st.net_scan_interval_min, "subnets": [c for c in (st.net_scan_cidrs or "").split() if c]}
    audit_action(request, who, "api", "scan", True, "")
    return out


@router.get("/pins/{login}")
def api_pins(request: Request, login: str):
    who = _auth(request)
    if not who:
        return _deny(request)
    login = (login or "").strip()
    cl = _client()
    if not cl:
        return JSONResponse({"ok": False, "error": "AD not configured"}, status_code=503)
    u = cl.find_user_by_login(login)
    if not u:
        audit_action(request, who, "api", "pins", False, login)
        return JSONResponse({"ok": False, "error": "user not found", "login": login}, status_code=404)
    _ok, _msg, d = cl.get_user_details(u.dn)
    pins = (d or {}).get("otherPager") or []
    pins = [str(p) for p in ([pins] if isinstance(pins, str) else pins) if p]
    audit_action(request, who, "api", "pins", True, u.sam or login)
    return {"ok": True, "login": u.sam, "name": u.display_name, "pins": pins}


@router.get("/pins-missing")
def api_pins_missing(request: Request):
    who = _auth(request)
    if not who:
        return _deny(request)
    from ..pagersync import _SEARCH_BASE, _excluded

    cl = _client()
    if not cl:
        return JSONResponse({"ok": False, "error": "AD not configured"}, status_code=503)
    ok, msg, items = cl.list_users_without_pin()
    audit_action(request, who, "api", "pins-missing", ok, "")
    if not ok:
        return JSONResponse({"ok": False, "error": msg}, status_code=502)
    base = _SEARCH_BASE.lower()
    users = [{"login": i["sam"], "name": i["display"]} for i in items
             if i["dn"].lower().endswith(base) and not _excluded(i["sam"])]
    return {"ok": True, "count": len(users), "users": users}


@router.get("/pager-sync")
def api_pager_sync(request: Request, n: int = 5):
    who = _auth(request)
    if not who:
        return _deny(request)
    from ..pagersync import last_reports

    audit_action(request, who, "api", "pager-sync", True, "")
    return {"ok": True, "reports": last_reports(max(1, min(n, 50)))}


@router.post("/pager-sync/papercut")
async def api_pager_sync_papercut(request: Request):
    who = _auth(request, "PAGERSYNC_TOKEN_SHA256", "pagersync-ts1")
    if not who:
        return _deny(request)
    from starlette.concurrency import run_in_threadpool

    from ..pagersync import run_sync, store_report

    try:
        body = await request.json()
        entries = list(body.get("entries") or [])
        apply = bool(body.get("apply", False))
    except Exception:
        return JSONResponse({"ok": False, "error": "bad json"}, status_code=400)
    try:
        rep = await run_in_threadpool(run_sync, entries, apply=apply)
    except Exception as e:
        audit_action(request, who, "api", "pager-sync", False, f"{type(e).__name__}: {e}")
        rep = {"ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "apply": apply, "fatal": f"{type(e).__name__}: {e}"}
        store_report(rep)
        return JSONResponse({"ok": False, **rep}, status_code=502)
    store_report(rep)
    for kind in ("filled", "updated"):
        for sam in rep[kind]:
            audit_action(request, who, "api", f"otherPager {kind}", apply, sam)
    audit_action(request, who, "api", "pager-sync", not rep["errors"],
                 f"apply={apply} filled={len(rep['filled'])} updated={len(rep['updated'])} errors={len(rep['errors'])}")
    return {"ok": True, **rep}
