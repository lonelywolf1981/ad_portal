from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional
import ssl

from ldap3 import (
    Server,
    Connection,
    ALL,
    SUBTREE,
    BASE,
    Tls,
    ALL_ATTRIBUTES,
    ALL_OPERATIONAL_ATTRIBUTES,
)
from ldap3.core.exceptions import LDAPException

from .models import ADConfig, ADUser
from .utils import escape_ldap_filter_value, filetime_to_dt_str


class ADClient:
    def __init__(self, cfg: ADConfig) -> None:
        self.cfg = cfg
        if cfg.tls_validate:
            tls = Tls(validate=ssl.CERT_REQUIRED)
        else:
            tls = Tls(validate=ssl.CERT_NONE)

        self.server = Server(
            host=cfg.host,
            port=cfg.port,
            use_ssl=cfg.use_ssl,
            get_info=ALL,
            tls=tls,
        )

    def _conn(self, user: str, password: str) -> Connection:
        conn = Connection(self.server, user=user, password=password, auto_bind=False)
        conn.open()
        if self.cfg.starttls:
            conn.start_tls()
        return conn

    def service_bind(self) -> tuple[bool, dict]:
        try:
            conn = self._conn(self.cfg.bind_principal, self.cfg.bind_password)
            ok = bool(conn.bind())
            res = dict(conn.result or {})
            conn.unbind()
            return ok, res
        except LDAPException as e:
            return False, {"error": str(e)}

    def find_user_by_login(self, login: str) -> Optional[ADUser]:
        login = (login or "").strip()
        if not login:
            return None
        base = self.cfg.base_dn
        if not base:
            return None

        conn: Connection | None = None
        try:
            conn = self._conn(self.cfg.bind_principal, self.cfg.bind_password)
            if not conn.bind():
                conn.unbind()
                return None

            if "@" in login:
                flt = f"(userPrincipalName={login})"
            else:
                flt = f"(sAMAccountName={login})"

            attrs = ["distinguishedName", "sAMAccountName", "displayName", "mail", "memberOf"]
            ok = conn.search(
                search_base=base,
                search_filter=f"(&(objectClass=user){flt})",
                search_scope=SUBTREE,
                attributes=attrs,
                size_limit=2,
            )
            if not ok or len(conn.entries) != 1:
                conn.unbind()
                return None

            e = conn.entries[0]
            dn = str(e.distinguishedName)
            sam = str(getattr(e, "sAMAccountName", "") or "")
            display = str(getattr(e, "displayName", "") or "")
            mail = str(getattr(e, "mail", "") or "")
            member_of = [str(x) for x in (getattr(e, "memberOf", []) or [])]
            conn.unbind()
            return ADUser(dn=dn, sam=sam, display_name=display, mail=mail, member_of=member_of)
        except LDAPException:
            try:
                if conn:
                    conn.unbind()
            except Exception:
                pass
            return None

    def verify_password(self, user_dn: str, password: str) -> bool:
        conn: Connection | None = None
        try:
            conn = self._conn(user_dn, password)
            return bool(conn.bind())
        except LDAPException:
            return False
        finally:
            try:
                if conn:
                    conn.unbind()
            except Exception:
                pass

    def list_groups(self, limit: int = 5000) -> list[dict]:
        base = self.cfg.base_dn
        if not base:
            return []

        conn = self._conn(self.cfg.bind_principal, self.cfg.bind_password)
        if not conn.bind():
            conn.unbind()
            return []

        attrs = ["distinguishedName", "cn", "name", "displayName"]
        ok = conn.search(
            search_base=base,
            search_filter="(&(objectClass=group))",
            search_scope=SUBTREE,
            attributes=attrs,
            size_limit=limit,
        )
        groups = []
        if ok:
            for e in conn.entries:
                dn = str(getattr(e, "distinguishedName", "") or "")
                cn = str(getattr(e, "cn", "") or "")
                disp = str(getattr(e, "displayName", "") or "")
                name = disp or cn or str(getattr(e, "name", "") or "")
                if dn and name:
                    groups.append({"dn": dn, "name": name})
        conn.unbind()
        groups.sort(key=lambda x: x["name"].lower())
        return groups

    def search_users(self, query: str, limit: int = 50) -> tuple[bool, str, list[dict]]:
        """Search users by partial name/surname/login.

        Returns: (ok, message, items)
        items: [{"dn": str, "sam": str, "display": str, "mail": str}]
        """
        q = (query or "").strip()
        if not q:
            return True, "", []

        base = self.cfg.base_dn
        if not base:
            return False, "BaseDN пустой (проверьте домен в настройках).", []

        tokens = [t for t in q.split() if t][:5]

        def token_or(t: str) -> str:
            t = escape_ldap_filter_value(t)
            return (
                f"(|"
                f"(displayName=*{t}*)"
                f"(givenName=*{t}*)"
                f"(sn=*{t}*)"
                f"(sAMAccountName=*{t}*)"
                f"(userPrincipalName=*{t}*)"
                f")"
            )

        and_block = "".join([token_or(t) for t in tokens])
        flt = f"(&(objectCategory=person)(objectClass=user){and_block})"

        attrs = [
            "distinguishedName",
            "sAMAccountName",
            "userPrincipalName",
            "displayName",
            "givenName",
            "sn",
            "mail",
        ]

        conn: Connection | None = None
        try:
            conn = self._conn(self.cfg.bind_principal, self.cfg.bind_password)
            if not conn.bind():
                res = dict(conn.result or {})
                conn.unbind()
                return False, f"Ошибка bind: {res}", []

            ok = conn.search(
                search_base=base,
                search_filter=flt,
                search_scope=SUBTREE,
                attributes=attrs,
                size_limit=limit,
            )

            if not ok:
                res = dict(conn.result or {})
                conn.unbind()
                return False, f"Поиск не выполнен: {res}", []

            items: list[dict] = []
            for e in conn.entries:
                dn = str(getattr(e, "distinguishedName", "") or "")
                if not dn:
                    continue

                sam = str(getattr(e, "sAMAccountName", "") or "")
                upn = str(getattr(e, "userPrincipalName", "") or "")
                display = str(getattr(e, "displayName", "") or "")
                given = str(getattr(e, "givenName", "") or "")
                sn = str(getattr(e, "sn", "") or "")
                mail = str(getattr(e, "mail", "") or "")

                fio = display.strip() or (f"{given} {sn}".strip()) or sam or upn
                login = sam or upn

                items.append({
                    "dn": dn,
                    "fio": fio,
                    "login": login,
                    "mail": mail,
                })

            conn.unbind()
            items.sort(key=lambda x: (x.get("fio") or "").lower())
            return True, "OK", items

        except LDAPException as e:
            try:
                if conn:
                    conn.unbind()
            except Exception:
                pass
            return False, f"LDAP ошибка: {e}", []

    def get_user_details(self, user_dn: str) -> tuple[bool, str, dict]:
        """Return a dict of all non-empty LDAP attributes for a user DN."""
        dn = (user_dn or "").strip()
        if not dn:
            return False, "Пустой DN пользователя.", {}

        conn: Connection | None = None
        try:
            conn = self._conn(self.cfg.bind_principal, self.cfg.bind_password)
            if not conn.bind():
                res = dict(conn.result or {})
                conn.unbind()
                return False, f"Ошибка bind: {res}", {}

            ok = conn.search(
                search_base=dn,
                search_filter="(objectClass=*)",
                search_scope=BASE,
                attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES],
                size_limit=1,
            )
            if not ok or len(conn.entries) != 1:
                res = dict(conn.result or {})
                conn.unbind()
                return False, f"Пользователь не найден. {res}", {}

            e = conn.entries[0]
            raw = e.entry_attributes_as_dict or {}
            raw.setdefault("distinguishedName", [dn])

            filetime_fields = {
                "lastLogonTimestamp",
                "lastLogon",
                "lastLogoff",
                "pwdLastSet",
                "accountExpires",
                "badPasswordTime",
            }

            out: dict[str, Any] = {}
            for k, v in raw.items():
                if v is None:
                    continue

                vals = v if isinstance(v, list) else [v]
                norm_vals: list[Any] = []
                for it in vals:
                    if it is None:
                        continue

                    if isinstance(it, (bytes, bytearray)):
                        try:
                            it = bytes(it).decode("utf-8", errors="replace")
                        except Exception:
                            it = repr(it)

                    if isinstance(it, datetime):
                        if it.tzinfo is None:
                            it = it.replace(tzinfo=timezone.utc)
                        it = it.astimezone(timezone.utc).isoformat(timespec="seconds")

                    if k in filetime_fields and isinstance(it, (int, str)):
                        s = filetime_to_dt_str(it)
                        if s:
                            it = s

                    if isinstance(it, str):
                        it = it.strip()
                        if not it:
                            continue

                    norm_vals.append(it)

                if not norm_vals:
                    continue
                if len(norm_vals) == 1:
                    out[k] = norm_vals[0]
                else:
                    out[k] = norm_vals

            conn.unbind()
            return True, "OK", out

        except LDAPException as e:
            try:
                if conn:
                    conn.unbind()
            except Exception:
                pass
            return False, f"LDAP ошибка: {e}", {}
