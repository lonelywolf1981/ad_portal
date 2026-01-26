from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, List
import ssl

from ldap3 import Server, Connection, ALL, SUBTREE, Tls
from ldap3.core.exceptions import LDAPException

from .ad_utils import domain_to_base_dn, build_dc_fqdn


@dataclass
class ADConfig:
    dc_short: str
    domain: str
    port: int
    use_ssl: bool
    starttls: bool
    bind_username: str
    bind_password: str
    tls_validate: bool = False
    ca_pem: str = ""

    @property
    def host(self) -> str:
        return build_dc_fqdn(self.dc_short, self.domain)

    @property
    def base_dn(self) -> str:
        return domain_to_base_dn(self.domain)

    @property
    def bind_principal(self) -> str:
        u = (self.bind_username or "").strip()
        d = (self.domain or "").strip().strip(".")
        if not u:
            return ""
        if "@" in u:
            return u
        return f"{u}@{d}" if d else u


@dataclass
class ADUser:
    dn: str
    sam: str
    display_name: str
    mail: str
    member_of: List[str]


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

        conn = None
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
        conn = None
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
