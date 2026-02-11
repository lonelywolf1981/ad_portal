from __future__ import annotations

import logging
import re
from typing import Any

from asterisk.ami import AMIClient, SimpleAction

from ..ad import ADClient
from ..repo import db_session, get_or_create_settings
from .ad import ad_cfg_from_settings

log = logging.getLogger(__name__)

EXT4_RE = re.compile(r"^\d{4}$")
LINE_RE = re.compile(
    r"^Contact:\s+"
    r"(?P<aor>\S+?)/sip:(?P<extension>[^@]+)@(?P<ip>\d+\.\d+\.\d+\.\d+):(?P<port>\d+)\s+"
    r"(?P<hash>\S+)\s+"
    r"(?P<status>Avail|NonQual|Unavail|Unknown)\s+"
    r"(?P<rtt>[\d.]+)",
    re.IGNORECASE,
)


def _ami_command(*, host: str, port: int, user: str, password: str, command: str, timeout_s: int = 5) -> str:
    try:
        client = AMIClient(address=host, port=port, timeout=timeout_s)
    except TypeError:
        # Backward compatibility for older asterisk-ami versions.
        client = AMIClient(address=host, port=port)
    try:
        login_response = client.login(username=user, secret=password).response
        if login_response.is_error():
            raise RuntimeError(f"AMI login failed: {login_response}")

        response = client.send_action(SimpleAction("Command", Command=command)).response
        if response.is_error():
            raise RuntimeError(f"AMI command failed: {response}")

        output: Any = response.keys.get("Output", "")
        if isinstance(output, list):
            return "\n".join(str(x) for x in output)
        return str(output)
    finally:
        try:
            client.logoff()
        except Exception:
            pass


def _parse_contacts(raw: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if "Contact:" not in line:
            continue
        line = line.split("Contact:", 1)[1].strip()
        line = f"Contact: {line}"

        match = LINE_RE.search(line)
        if not match:
            continue

        extension = match.group("extension")
        ip = match.group("ip")
        status = match.group("status")
        if str(status).lower() != "avail":
            continue
        if not EXT4_RE.match(extension):
            continue

        items.append(
            {
                "extension": extension,
                "ip": ip,
                "status": status,
                "port": int(match.group("port")),
                "rtt_ms": float(match.group("rtt")),
            }
        )
    return items


def _row_matches_query(row: dict[str, Any], query: str) -> bool:
    q = (query or "").strip().lower()
    if not q:
        return True

    ext = str(row.get("extension") or "").lower()
    if q in ext:
        return True
    ip = str(row.get("ip") or "").lower()
    if q in ip:
        return True

    for user in (row.get("users") or []):
        fio = str(user.get("fio") or "").lower()
        login = str(user.get("login") or "").lower()
        if q in fio or q in login:
            return True
    return False


def get_avail_with_ad(query: str = "") -> dict[str, Any]:
    """Return available 4-digit PJSIP contacts enriched with AD users by ipPhone."""
    with db_session() as db:
        st = get_or_create_settings(db)
        enabled = bool(getattr(st, "ip_phones_enabled", False))
        host = (getattr(st, "ip_phones_ami_host", "") or "").strip()
        port = int(getattr(st, "ip_phones_ami_port", 5038) or 5038)
        user = (getattr(st, "ip_phones_ami_user", "") or "").strip()
        password = (getattr(st, "ip_phones_ami_password_enc", "") or "").strip()
        timeout_s = int(getattr(st, "ip_phones_ami_timeout_s", 5) or 5)

        if not enabled:
            return {"ok": False, "message": "Раздел IP-телефонов выключен в настройках.", "items": []}
        if not host or not user or not password:
            return {
                "ok": False,
                "message": "Не заполнены параметры AMI (host/user/password) в настройках.",
                "items": [],
            }

        from ..crypto import decrypt_str

        ami_password = decrypt_str(password)
        if not ami_password:
            return {
                "ok": False,
                "message": "AMI пароль отсутствует. Укажите его в настройках и сохраните.",
                "items": [],
            }

        raw = _ami_command(
            host=host,
            port=port,
            user=user,
            password=ami_password,
            command="pjsip show contacts",
            timeout_s=max(1, min(30, timeout_s)),
        )
        avail = _parse_contacts(raw)

        ad_by_ext: dict[str, list[dict[str, str]]] = {}
        ad_warning = ""
        cfg = ad_cfg_from_settings(st)
        if cfg:
            client = ADClient(cfg)
            ok, msg, mapped = client.users_by_ipphone_extension(limit=5000)
            if ok:
                ad_by_ext = mapped
            else:
                ad_warning = msg or "Не удалось получить данные пользователей из AD."
                log.warning("IP phones: AD enrichment failed: %s", ad_warning)
        else:
            ad_warning = "AD не настроен, сопоставление с пользователями недоступно."

        rows: list[dict[str, Any]] = []
        matched = 0
        for item in avail:
            users = ad_by_ext.get(item["extension"], [])
            if users:
                matched += 1
            rows.append(
                {
                    "extension": item["extension"],
                    "ip": item["ip"],
                    "status": item["status"],
                    "users": users,
                }
            )

        filtered_rows = [row for row in rows if _row_matches_query(row, query)]
        filtered_matched = sum(1 for row in filtered_rows if row.get("users"))

        return {
            "ok": True,
            "message": "",
            "ad_warning": ad_warning,
            "query": (query or "").strip(),
            "items": filtered_rows,
            "total": len(filtered_rows),
            "matched": filtered_matched,
            "unmatched": max(0, len(filtered_rows) - filtered_matched),
            "total_all": len(rows),
            "matched_all": matched,
        }
