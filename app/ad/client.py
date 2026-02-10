from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional
import ssl
import hashlib
import os

from ldap3 import (
    Server,
    Connection,
    ALL,
    SUBTREE,
    LEVEL,
    BASE,
    Tls,
    ALL_ATTRIBUTES,
    ALL_OPERATIONAL_ATTRIBUTES,
    MODIFY_ADD,
    MODIFY_DELETE,
    MODIFY_REPLACE,
)
from ldap3.core.exceptions import LDAPException

from .models import ADConfig, ADUser
from .utils import escape_ldap_filter_value, filetime_to_dt_str


class ADClient:
    @staticmethod
    def _normalize_pem(pem: str) -> str:
        """Normalize PEM text (strip outer whitespace and normalize line endings)."""
        data = (pem or "").strip()
        # Normalize Windows newlines to \n to avoid hash mismatches.
        data = data.replace("\r\n", "\n").replace("\r", "\n")
        return data

    @staticmethod
    def _ensure_ca_file(pem: str) -> str:
        """Materialize CA PEM into a stable file path.

        ldap3.Tls historically supports ca_certs_file (works across versions).
        We store PEM under /tmp with a content hash, so multiple workers can reuse it.
        """

        data = ADClient._normalize_pem(pem)
        if not data:
            return ""

        # Minimal sanity check: avoid writing arbitrary text to /tmp and later confusing TLS errors.
        if "-----BEGIN CERTIFICATE-----" not in data or "-----END CERTIFICATE-----" not in data:
            raise ValueError("CA PEM не похож на сертификат (ожидается блок BEGIN/END CERTIFICATE)")

        h = hashlib.sha256(data.encode("utf-8")).hexdigest()[:16]
        path = f"/tmp/ad_portal_ca_{h}.pem"

        try:
            # Write only if missing or different.
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        if f.read().strip() == data:
                            return path
                except Exception:
                    pass

            with open(path, "w", encoding="utf-8") as f:
                f.write(data)
                if not data.endswith("\n"):
                    f.write("\n")
            try:
                os.chmod(path, 0o600)
            except Exception:
                pass
        except Exception:
            # If filesystem is read-only for some reason, fall back to system trust store.
            return ""

        return path

    def __init__(self, cfg: ADConfig) -> None:
        self.cfg = cfg

        tls_kwargs: dict[str, Any] = {
            "validate": ssl.CERT_REQUIRED if cfg.tls_validate else ssl.CERT_NONE,
        }
        # Apply custom CA only when verification is enabled.
        ca_pem = self._normalize_pem(cfg.ca_pem or "")
        if cfg.tls_validate and ca_pem:
            ca_file = self._ensure_ca_file(ca_pem)
            if ca_file:
                tls_kwargs["ca_certs_file"] = ca_file

        tls = Tls(**tls_kwargs)

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
        conn: Connection | None = None
        try:
            conn = self._conn(self.cfg.bind_principal, self.cfg.bind_password)
            ok = bool(conn.bind())
            res = dict(conn.result or {})
            return ok, res
        except LDAPException as e:
            return False, {"error": str(e), "description": str(e), "message": str(e)}
        finally:
            try:
                if conn:
                    conn.unbind()
            except Exception:
                pass

    def test_connection(self, timeout_s: float = 3.0) -> bool:
        """Lightweight connectivity check.

        Used by settings validation/UI. Performs:
        - TCP connect (ldap3 open)
        - optional StartTLS
        - bind with service credentials
        """

        # Use a dedicated Server instance with connect_timeout to avoid hanging.
        try:
            tls = self.server.tls
            srv = Server(
                host=self.cfg.host,
                port=self.cfg.port,
                use_ssl=self.cfg.use_ssl,
                get_info=ALL,
                tls=tls,
                connect_timeout=float(timeout_s),
            )
            conn = Connection(srv, user=self.cfg.bind_principal, password=self.cfg.bind_password, auto_bind=False)
            conn.open()
            if self.cfg.starttls:
                conn.start_tls()
            ok = bool(conn.bind())
            try:
                conn.unbind()
            except Exception:
                pass
            return ok
        except LDAPException:
            return False

    def test_connection_detailed(self, timeout_s: float = 3.0) -> tuple[bool, str]:
        """Detailed connectivity check with specific error information.

        Returns: (success, details_message)
        """
        try:
            # Проверяем резолвинг хоста
            import socket
            try:
                resolved_ip = socket.gethostbyname(self.cfg.host)
            except socket.gaierror as e:
                # Если не удалось разрешить имя, проверим, используется ли DNS сервер
                if self.cfg.dns_server:
                    from ..utils.net import resolve_hostname_with_dns
                    resolved_ip = resolve_hostname_with_dns(self.cfg.host, self.cfg.dns_server)
                    if not resolved_ip:
                        return False, f"Не удалось разрешить имя хоста '{self.cfg.host}' ни через системный резолвер, ни через указанный DNS-сервер ({self.cfg.dns_server}). Проверьте настройки DNS."
                    # Если резолвинг через указанный DNS-сервер успешен, используем полученный IP
                    target_host = resolved_ip
                else:
                    return False, f"Не удалось разрешить имя хоста '{self.cfg.host}'. Проверьте имя хоста или настройте DNS-сервер в настройках."
            else:
                # Если системный резолвинг прошел успешно, используем полученный IP
                target_host = resolved_ip

            # Проверяем доступность хоста
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(float(timeout_s))
            result = s.connect_ex((target_host, self.cfg.port))
            s.close()
            
            if result != 0:
                return False, f"Не удается подключиться к {target_host}:{self.cfg.port}. Проверьте доступность хоста и порта."

            tls = self.server.tls
            srv = Server(
                host=target_host,  # Используем резолвнутый IP
                port=self.cfg.port,
                use_ssl=self.cfg.use_ssl,
                get_info=ALL,
                tls=tls,
                connect_timeout=float(timeout_s),
            )
            conn = Connection(srv, user=self.cfg.bind_principal, password=self.cfg.bind_password, auto_bind=False)
            conn.open()
            
            if self.cfg.starttls:
                try:
                    conn.start_tls()
                except Exception as e:
                    return False, f"Ошибка при установке StartTLS: {str(e)}"
                    
            bind_result = conn.bind()
            result_dict = dict(conn.result or {})
            
            if not bind_result:
                error_msg = result_dict.get('message', 'Неизвестная ошибка')
                desc = result_dict.get('description', '')
                
                # Попробуем расшифровать наиболее распространенные ошибки
                if 'invalidCredentials' in error_msg or 'invalidCredentials' in desc:
                    error_msg = 'Неверные учетные данные (пользователь или пароль)'
                elif 'strongerAuthRequired' in error_msg or 'strongerAuthRequired' in desc:
                    error_msg = 'Требуется более безопасный метод аутентификации'
                elif 'connect_error' in error_msg:
                    error_msg = 'Ошибка подключения к серверу'
                elif 'SSL handshake failed' in error_msg:
                    error_msg = 'Ошибка SSL-соединения. Проверьте настройки TLS/SSL и сертификаты.'
                
                details = f"Ошибка при попытке bind: {error_msg}"
                if desc and desc != result_dict.get('message', ''):
                    details += f" ({desc})"
                    
                try:
                    conn.unbind()
                except Exception:
                    pass
                return False, details
            
            try:
                conn.unbind()
            except Exception:
                pass
                
            return True, "Подключение к AD успешно установлено"
        except LDAPException as e:
            return False, f"LDAP ошибка: {str(e)}"
        except Exception as e:
            return False, f"Общая ошибка: {str(e)}"

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

            safe_login = escape_ldap_filter_value(login)
            if "@" in login:
                flt = f"(userPrincipalName={safe_login})"
            else:
                flt = f"(sAMAccountName={safe_login})"

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

        conn: Connection | None = None
        try:
            conn = self._conn(self.cfg.bind_principal, self.cfg.bind_password)
            if not conn.bind():
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
            groups.sort(key=lambda x: x["name"].lower())
            return groups
        except LDAPException:
            return []
        finally:
            try:
                if conn:
                    conn.unbind()
            except Exception:
                pass

    def get_group_members(self, group_dn: str) -> tuple[bool, str, dict]:
        """Return direct members of an AD group.

        Returns: (ok, message, {"users": [...], "groups": [...]})
        users: [{"dn": str, "sam": str, "display": str, "mail": str}]
        groups: [{"dn": str, "name": str}]
        """
        group_dn = (group_dn or "").strip()
        if not group_dn:
            return False, "Пустой DN группы.", {}

        base = self.cfg.base_dn
        if not base:
            return False, "BaseDN пустой (проверьте домен в настройках).", {}

        conn: Connection | None = None
        try:
            conn = self._conn(self.cfg.bind_principal, self.cfg.bind_password)
            if not conn.bind():
                res = dict(conn.result or {})
                conn.unbind()
                return False, f"Ошибка bind: {res.get('description', 'неизвестная ошибка')}", {}

            escaped_dn = escape_ldap_filter_value(group_dn)
            flt = f"(memberOf={escaped_dn})"

            attrs = [
                "distinguishedName",
                "objectClass",
                "sAMAccountName",
                "displayName",
                "mail",
                "cn",
                "name",
            ]
            ok = conn.search(
                search_base=base,
                search_filter=flt,
                search_scope=SUBTREE,
                attributes=attrs,
                size_limit=1000,
            )
            if not ok:
                res = dict(conn.result or {})
                conn.unbind()
                return False, f"Поиск не выполнен: {res.get('description', 'неизвестная ошибка')}", {}

            users: list[dict] = []
            groups: list[dict] = []
            for e in conn.entries:
                dn = str(getattr(e, "distinguishedName", "") or "")
                if not dn:
                    continue

                obj_classes = [str(c).lower() for c in (getattr(e, "objectClass", []) or [])]

                if "group" in obj_classes:
                    cn = str(getattr(e, "cn", "") or "")
                    disp = str(getattr(e, "displayName", "") or "")
                    name = disp or cn or str(getattr(e, "name", "") or "")
                    groups.append({"dn": dn, "name": name})
                else:
                    sam = str(getattr(e, "sAMAccountName", "") or "")
                    display = str(getattr(e, "displayName", "") or "")
                    mail = str(getattr(e, "mail", "") or "")
                    users.append({
                        "dn": dn,
                        "sam": sam,
                        "display": display or sam,
                        "mail": mail,
                    })

            conn.unbind()
            users.sort(key=lambda x: (x.get("display") or "").lower())
            groups.sort(key=lambda x: (x.get("name") or "").lower())
            return True, "OK", {"users": users, "groups": groups}

        except LDAPException as e:
            try:
                if conn:
                    conn.unbind()
            except Exception:
                pass
            return False, f"LDAP ошибка: {e}", {}

    def list_disabled_users(self, limit: int = 5000) -> tuple[bool, str, list[dict]]:
        """Return all disabled AD users.

        Returns: (ok, message, [{"dn", "sam", "display", "mail", "when_changed"}])
        """
        base = self.cfg.base_dn
        if not base:
            return False, "BaseDN пустой (проверьте домен в настройках).", []

        conn: Connection | None = None
        try:
            conn = self._conn(self.cfg.bind_principal, self.cfg.bind_password)
            if not conn.bind():
                res = dict(conn.result or {})
                conn.unbind()
                return False, f"Ошибка bind: {res.get('description', 'неизвестная ошибка')}", []

            flt = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))"
            attrs = ["distinguishedName", "sAMAccountName", "displayName", "mail", "whenChanged"]

            items: list[dict] = []
            try:
                for entry in conn.extend.standard.paged_search(
                    search_base=base,
                    search_filter=flt,
                    search_scope=SUBTREE,
                    attributes=attrs,
                    paged_size=1000,
                    generator=True,
                ):
                    if entry.get("type") != "searchResEntry":
                        continue
                    a = entry.get("attributes", {})
                    dn = str(a.get("distinguishedName", "") or entry.get("dn", ""))
                    if not dn:
                        continue
                    sam = str(a.get("sAMAccountName", "") or "")
                    display = str(a.get("displayName", "") or "")
                    mail = str(a.get("mail", "") or "")
                    wc = a.get("whenChanged")
                    when_changed = ""
                    if wc:
                        if isinstance(wc, datetime):
                            when_changed = wc.strftime("%d.%m.%Y %H:%M")
                        else:
                            when_changed = str(wc)
                    items.append({
                        "dn": dn,
                        "sam": sam,
                        "display": display or sam,
                        "mail": mail,
                        "when_changed": when_changed,
                    })
                    if len(items) >= limit:
                        break
            except Exception:
                conn.search(
                    search_base=base, search_filter=flt, search_scope=SUBTREE,
                    attributes=attrs, size_limit=limit,
                )
                for e in conn.entries:
                    dn = str(getattr(e, "distinguishedName", "") or "")
                    if not dn:
                        continue
                    sam = str(getattr(e, "sAMAccountName", "") or "")
                    display = str(getattr(e, "displayName", "") or "")
                    mail = str(getattr(e, "mail", "") or "")
                    wc = getattr(e, "whenChanged", None)
                    when_changed = ""
                    if wc:
                        if isinstance(wc.value, datetime):
                            when_changed = wc.value.strftime("%d.%m.%Y %H:%M")
                        else:
                            when_changed = str(wc)
                    items.append({
                        "dn": dn,
                        "sam": sam,
                        "display": display or sam,
                        "mail": mail,
                        "when_changed": when_changed,
                    })

            conn.unbind()
            items.sort(key=lambda x: (x.get("display") or "").lower())
            return True, "OK", items

        except LDAPException as e:
            try:
                if conn:
                    conn.unbind()
            except Exception:
                pass
            return False, f"LDAP ошибка: {e}", []

    def list_users_without_pin(self, limit: int = 5000) -> tuple[bool, str, list[dict]]:
        """Return all enabled AD users with empty otherPager field.

        Returns: (ok, message, [{"dn", "sam", "display", "mail"}])
        """
        base = self.cfg.base_dn
        if not base:
            return False, "BaseDN пустой (проверьте домен в настройках).", []

        conn: Connection | None = None
        try:
            conn = self._conn(self.cfg.bind_principal, self.cfg.bind_password)
            if not conn.bind():
                res = dict(conn.result or {})
                conn.unbind()
                return False, f"Ошибка bind: {res.get('description', 'неизвестная ошибка')}", []

            flt = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(otherPager=*)))"
            attrs = ["distinguishedName", "sAMAccountName", "displayName", "mail"]

            items: list[dict] = []
            try:
                for entry in conn.extend.standard.paged_search(
                    search_base=base,
                    search_filter=flt,
                    search_scope=SUBTREE,
                    attributes=attrs,
                    paged_size=1000,
                    generator=True,
                ):
                    if entry.get("type") != "searchResEntry":
                        continue
                    a = entry.get("attributes", {})
                    dn = str(a.get("distinguishedName", "") or entry.get("dn", ""))
                    if not dn:
                        continue
                    sam = str(a.get("sAMAccountName", "") or "")
                    display = str(a.get("displayName", "") or "")
                    mail = str(a.get("mail", "") or "")
                    items.append({
                        "dn": dn,
                        "sam": sam,
                        "display": display or sam,
                        "mail": mail,
                    })
                    if len(items) >= limit:
                        break
            except Exception:
                conn.search(
                    search_base=base, search_filter=flt, search_scope=SUBTREE,
                    attributes=attrs, size_limit=limit,
                )
                for e in conn.entries:
                    dn = str(getattr(e, "distinguishedName", "") or "")
                    if not dn:
                        continue
                    sam = str(getattr(e, "sAMAccountName", "") or "")
                    display = str(getattr(e, "displayName", "") or "")
                    mail = str(getattr(e, "mail", "") or "")
                    items.append({
                        "dn": dn,
                        "sam": sam,
                        "display": display or sam,
                        "mail": mail,
                    })

            conn.unbind()
            items.sort(key=lambda x: (x.get("display") or "").lower())
            return True, "OK", items

        except LDAPException as e:
            try:
                if conn:
                    conn.unbind()
            except Exception:
                pass
            return False, f"LDAP ошибка: {e}", []

    def count_users_total_and_enabled(self) -> tuple[int, int]:
        """Return (total_users, enabled_users).

        Uses server-side LDAP filters; counts are based on direct user objects.
        """
        conn = self._conn(self.cfg.bind_principal, self.cfg.bind_password)
        if not conn.bind():
            conn.unbind()
            return 0, 0

        base = self.cfg.base_dn
        total_filter = "(&(objectCategory=person)(objectClass=user))"
        enabled_filter = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

        def _count(flt: str) -> int:
            n = 0
            try:
                for _ in conn.extend.standard.paged_search(
                    search_base=base,
                    search_filter=flt,
                    search_scope=SUBTREE,
                    attributes=[],
                    paged_size=1000,
                    generator=True,
                ):
                    n += 1
            except Exception:
                conn.search(search_base=base, search_filter=flt, search_scope=SUBTREE, attributes=[])
                n = len(conn.entries)
            return n

        try:
            total = _count(total_filter)
            enabled = _count(enabled_filter)
        finally:
            conn.unbind()
        return total, enabled

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
                return False, f"Ошибка bind: {res.get('description', 'неизвестная ошибка')}", []

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
                return False, f"Поиск не выполнен: {res.get('description', 'неизвестная ошибка')}", []

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
                return False, f"Ошибка bind: {res.get('description', 'неизвестная ошибка')}", {}

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
                return False, f"Пользователь не найден. {res.get('description', '')}", {}

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

    # ---------------------------
    # AD management operations
    # ---------------------------

    def search_groups(self, query: str, limit: int = 50) -> tuple[bool, str, list[dict]]:
        """Search groups by partial name/description.

        Returns: (ok, message, items)
        items: [{"dn": str, "name": str, "description": str}]
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
                f"(cn=*{t}*)"
                f"(name=*{t}*)"
                f"(displayName=*{t}*)"
                f"(description=*{t}*)"
                f")"
            )

        and_block = "".join([token_or(t) for t in tokens])
        flt = f"(&(objectClass=group){and_block})"

        attrs = ["distinguishedName", "cn", "name", "displayName", "description"]

        conn: Connection | None = None
        try:
            conn = self._conn(self.cfg.bind_principal, self.cfg.bind_password)
            if not conn.bind():
                res = dict(conn.result or {})
                conn.unbind()
                return False, f"Ошибка bind: {res.get('description', 'неизвестная ошибка')}", []

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
                return False, f"Поиск не выполнен: {res.get('description', 'неизвестная ошибка')}", []

            items: list[dict] = []
            for e in conn.entries:
                dn = str(getattr(e, "distinguishedName", "") or "")
                if not dn:
                    continue

                cn = str(getattr(e, "cn", "") or "")
                disp = str(getattr(e, "displayName", "") or "")
                name = disp or cn or str(getattr(e, "name", "") or "")
                desc = str(getattr(e, "description", "") or "")

                items.append({"dn": dn, "name": name, "description": desc})

            conn.unbind()
            items.sort(key=lambda x: (x.get("name") or "").lower())
            return True, "OK", items

        except LDAPException as e:
            try:
                if conn:
                    conn.unbind()
            except Exception:
                pass
            return False, f"LDAP ошибка: {e}", []

    def update_user(self, user_dn: str, data: dict) -> tuple[bool, str]:
        """Update common user attributes.

        Supports: givenName, sn, displayName, mail, telephoneNumber, mobile, department, company, manager
        and password (via microsoft extension) when provided.
        """

        dn = (user_dn or "").strip()
        if not dn:
            return False, "Пустой DN пользователя."

        data = data or {}

        # Map UI fields to LDAP attributes.
        field_map = {
            "first_name": "givenName",
            "last_name": "sn",
            "display_name": "displayName",
            "email": "mail",
            "telephone": "telephoneNumber",
            "mobile": "mobile",
            "department": "department",
            "company": "company",
            "title": "title",
            "ipPhone": "ipPhone",
        }

        changes: dict[str, list[tuple[int, list[str]]]] = {}
        for k, ldap_attr in field_map.items():
            if k not in data:
                continue
            v = data.get(k)
            if v is None:
                continue
            v = str(v).strip()
            if v == "":
                changes[ldap_attr] = [(MODIFY_DELETE, [])]
            else:
                changes[ldap_attr] = [(MODIFY_REPLACE, [v])]

        # otherPager — multi-valued
        if "otherPager" in data:
            pager_list = data.get("otherPager") or []
            if isinstance(pager_list, str):
                pager_list = [pager_list]
            pager_list = [p.strip() for p in pager_list if p and p.strip()]
            if pager_list:
                changes["otherPager"] = [(MODIFY_REPLACE, pager_list)]
            else:
                changes["otherPager"] = [(MODIFY_DELETE, [])]

        new_password = (data.get("password") or "").strip()

        conn: Connection | None = None
        try:
            conn = self._conn(self.cfg.bind_principal, self.cfg.bind_password)
            if not conn.bind():
                res = dict(conn.result or {})
                conn.unbind()
                return False, f"Ошибка bind: {res.get('description', 'неизвестная ошибка')}"

            if changes:
                ok = conn.modify(dn, changes)
                if not ok:
                    res = dict(conn.result or {})
                    conn.unbind()
                    return False, f"Не удалось обновить атрибуты: {res.get('description', 'неизвестная ошибка')}"

            if new_password:
                # Password changes in AD require a protected connection (LDAPS or StartTLS).
                if not (self.cfg.use_ssl or self.cfg.starttls):
                    conn.unbind()
                    return False, "Смена пароля требует защищенного соединения (LDAPS или StartTLS)."
                try:
                    ok = bool(conn.extend.microsoft.modify_password(dn, new_password))
                except Exception as e:
                    ok = False
                    err_desc = str(e)
                else:
                    r = dict(conn.result or {})
                    err_desc = r.get("description", "") or r.get("message", "неизвестная ошибка")

                if not ok:
                    conn.unbind()
                    return False, f"Не удалось сменить пароль: {err_desc}"

            conn.unbind()
            return True, "Изменения сохранены."

        except LDAPException as e:
            try:
                if conn:
                    conn.unbind()
            except Exception:
                pass
            return False, f"LDAP ошибка: {e}"

    def unlock_user(self, user_dn: str) -> tuple[bool, str]:
        """Разблокировать учётную запись (сбросить lockoutTime в 0)."""
        dn = (user_dn or "").strip()
        if not dn:
            return False, "Пустой DN пользователя."

        conn: Connection | None = None
        try:
            conn = self._conn(self.cfg.bind_principal, self.cfg.bind_password)
            if not conn.bind():
                res = dict(conn.result or {})
                conn.unbind()
                return False, f"Ошибка bind: {res.get('description', 'неизвестная ошибка')}"

            ok = conn.modify(dn, {"lockoutTime": [(MODIFY_REPLACE, ["0"])]})
            res = dict(conn.result or {})
            conn.unbind()
            if not ok:
                return False, f"Не удалось разблокировать: {res.get('description', 'неизвестная ошибка')}"
            return True, "Учётная запись разблокирована."

        except LDAPException as e:
            try:
                if conn:
                    conn.unbind()
            except Exception:
                pass
            return False, f"LDAP ошибка: {e}"

    def set_user_enabled(self, user_dn: str, enable: bool) -> tuple[bool, str]:
        """Включить или отключить учётную запись (toggle бита ACCOUNTDISABLE в userAccountControl)."""
        dn = (user_dn or "").strip()
        if not dn:
            return False, "Пустой DN пользователя."

        conn: Connection | None = None
        try:
            conn = self._conn(self.cfg.bind_principal, self.cfg.bind_password)
            if not conn.bind():
                res = dict(conn.result or {})
                conn.unbind()
                return False, f"Ошибка bind: {res.get('description', 'неизвестная ошибка')}"

            # Прочитать текущий userAccountControl
            ok = conn.search(
                search_base=dn,
                search_filter="(objectClass=*)",
                search_scope=BASE,
                attributes=["userAccountControl"],
                size_limit=1,
            )
            if not ok or not conn.entries:
                conn.unbind()
                return False, "Пользователь не найден."

            uac_raw = getattr(conn.entries[0], "userAccountControl", None)
            uac = int(uac_raw.value if uac_raw else 512)

            if enable:
                new_uac = uac & ~0x2  # Снять бит ACCOUNTDISABLE
            else:
                new_uac = uac | 0x2  # Установить бит ACCOUNTDISABLE

            ok = conn.modify(dn, {"userAccountControl": [(MODIFY_REPLACE, [str(new_uac)])]})
            res = dict(conn.result or {})
            conn.unbind()
            if not ok:
                return False, f"Не удалось изменить состояние: {res.get('description', 'неизвестная ошибка')}"
            return True, "Учётная запись включена." if enable else "Учётная запись отключена."

        except LDAPException as e:
            try:
                if conn:
                    conn.unbind()
            except Exception:
                pass
            return False, f"LDAP ошибка: {e}"

    def delete_user(self, user_dn: str) -> tuple[bool, str]:
        dn = (user_dn or "").strip()
        if not dn:
            return False, "Пустой DN пользователя."

        conn: Connection | None = None
        try:
            conn = self._conn(self.cfg.bind_principal, self.cfg.bind_password)
            if not conn.bind():
                res = dict(conn.result or {})
                conn.unbind()
                return False, f"Ошибка bind: {res.get('description', 'неизвестная ошибка')}"

            ok = bool(conn.delete(dn))
            res = dict(conn.result or {})
            conn.unbind()
            if not ok:
                return False, f"Не удалось удалить пользователя: {res.get('description', 'неизвестная ошибка')}"
            return True, "Пользователь удален."

        except LDAPException as e:
            try:
                if conn:
                    conn.unbind()
            except Exception:
                pass
            return False, f"LDAP ошибка: {e}"

    def add_user_to_group(self, user_dn: str, group_dn: str) -> tuple[bool, str]:
        u_dn = (user_dn or "").strip()
        g_dn = (group_dn or "").strip()
        if not u_dn or not g_dn:
            return False, "Не указан DN пользователя или группы."

        conn: Connection | None = None
        try:
            conn = self._conn(self.cfg.bind_principal, self.cfg.bind_password)
            if not conn.bind():
                res = dict(conn.result or {})
                conn.unbind()
                return False, f"Ошибка bind: {res.get('description', 'неизвестная ошибка')}"

            ok = conn.modify(g_dn, {"member": [(MODIFY_ADD, [u_dn])]})
            res = dict(conn.result or {})
            conn.unbind()
            if not ok:
                # AD returns "attributeOrValueExists" when already in group.
                desc = (res.get("description") or "").lower()
                if "attributeorvalueexists" in desc:
                    return True, "Пользователь уже состоит в группе."
                return False, f"Не удалось добавить пользователя в группу: {res.get('description', 'неизвестная ошибка')}"
            return True, "Пользователь добавлен в группу."

        except LDAPException as e:
            try:
                if conn:
                    conn.unbind()
            except Exception:
                pass
            return False, f"LDAP ошибка: {e}"

    def remove_user_from_group(self, user_dn: str, group_dn: str) -> tuple[bool, str]:
        u_dn = (user_dn or "").strip()
        g_dn = (group_dn or "").strip()
        if not u_dn or not g_dn:
            return False, "Не указан DN пользователя или группы."

        conn: Connection | None = None
        try:
            conn = self._conn(self.cfg.bind_principal, self.cfg.bind_password)
            if not conn.bind():
                res = dict(conn.result or {})
                conn.unbind()
                return False, f"Ошибка bind: {res.get('description', 'неизвестная ошибка')}"

            ok = conn.modify(g_dn, {"member": [(MODIFY_DELETE, [u_dn])]})
            res = dict(conn.result or {})
            conn.unbind()
            if not ok:
                # If not a member, AD may return "noSuchAttribute".
                desc = (res.get("description") or "").lower()
                if "nosuchattribute" in desc:
                    return True, "Пользователь не состоит в группе."
                return False, f"Не удалось удалить пользователя из группы: {res.get('description', 'неизвестная ошибка')}"
            return True, "Пользователь удален из группы."

        except LDAPException as e:
            try:
                if conn:
                    conn.unbind()
            except Exception:
                pass
            return False, f"LDAP ошибка: {e}"

    def list_containers(self, limit: int = 5000) -> tuple[bool, str, list[dict]]:
        """List OUs and generic containers under base DN.

        Returns items: [{"dn": str, "name": str, "type": "ou"|"container"}]
        """

        base = self.cfg.base_dn
        if not base:
            return False, "BaseDN пустой (проверьте домен в настройках).", []

        conn: Connection | None = None
        try:
            conn = self._conn(self.cfg.bind_principal, self.cfg.bind_password)
            if not conn.bind():
                res = dict(conn.result or {})
                conn.unbind()
                return False, f"Ошибка bind: {res.get('description', 'неизвестная ошибка')}", []

            flt = "(|(objectClass=organizationalUnit)(objectClass=container))"
            attrs = ["distinguishedName", "name", "ou", "cn", "objectClass"]

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
                return False, f"Поиск не выполнен: {res.get('description', 'неизвестная ошибка')}", []

            items: list[dict] = []
            for e in conn.entries:
                dn = str(getattr(e, "distinguishedName", "") or "")
                if not dn:
                    continue
                name = str(getattr(e, "ou", "") or "") or str(getattr(e, "cn", "") or "") or str(getattr(e, "name", "") or "")
                obj_classes = [str(c).lower() for c in (getattr(e, "objectClass", []) or [])]
                typ = "ou" if "organizationalunit" in obj_classes else "container"
                items.append({"dn": dn, "name": name or dn, "type": typ})

            conn.unbind()
            items.sort(key=lambda x: (x.get("dn") or "").lower())
            return True, "OK", items

        except LDAPException as e:
            try:
                if conn:
                    conn.unbind()
            except Exception:
                pass
            return False, f"LDAP ошибка: {e}", []

    def list_users_in_ou(self, ou_dn: str, limit: int = 200) -> tuple[bool, str, list[dict]]:
        """Получить список пользователей в конкретной OU (только прямые дочерние).

        Returns: (ok, message, users_list)
        """
        conn: Connection | None = None
        try:
            conn = self._conn(self.cfg.bind_principal, self.cfg.bind_password)
            if not conn.bind():
                res = dict(conn.result or {})
                conn.unbind()
                return False, f"Ошибка bind: {res.get('description', 'неизвестная ошибка')}", []

            attrs = [
                "distinguishedName", "sAMAccountName", "displayName", "mail",
                "department", "company", "title", "description",
                "memberOf", "otherPager", "ipPhone",
            ]
            flt = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            conn.search(
                search_base=ou_dn,
                search_filter=flt,
                search_scope=LEVEL,
                attributes=attrs,
                size_limit=limit,
            )
            items: list[dict] = []
            for entry in conn.entries:
                ea = entry.entry_attributes_as_dict
                # memberOf — список DN групп
                groups_raw = ea.get("memberOf", [])
                groups = [str(g) for g in groups_raw if g]
                # otherPager — multi-valued
                pager_raw = ea.get("otherPager", [])
                pager = [str(p) for p in pager_raw if p]

                def _first(lst: list, default: str = "") -> str:
                    """Безопасное извлечение первого элемента списка атрибутов."""
                    return str(lst[0]) if lst else default

                items.append({
                    "dn": str(entry.entry_dn),
                    "sam": _first(ea.get("sAMAccountName", [])),
                    "display": _first(ea.get("displayName", [])),
                    "mail": _first(ea.get("mail", [])),
                    "department": _first(ea.get("department", [])),
                    "company": _first(ea.get("company", [])),
                    "title": _first(ea.get("title", [])),
                    "description": _first(ea.get("description", [])),
                    "groups": groups,
                    "otherPager": pager,
                    "ipPhone": _first(ea.get("ipPhone", [])),
                })
            conn.unbind()
            items.sort(key=lambda x: (x.get("display") or x.get("sam") or "").lower())
            return True, "OK", items

        except LDAPException as e:
            try:
                if conn:
                    conn.unbind()
            except Exception:
                pass
            return False, f"LDAP ошибка: {e}", []

    def create_user(self, data: dict) -> tuple[bool, str, str]:
        """Создать пользователя в указанной OU.

        data keys:
            username, ou, first_name, last_name, display_name, email, password,
            company, department, title, description,
            otherPager (list[str]), ipPhone (str),
            groups (list[str] — DN групп),
            must_change_password (bool), password_never_expires (bool)

        Returns: (ok, message, new_dn)
        """

        data = data or {}
        username = (data.get("username") or "").strip()
        ou_dn = (data.get("ou") or "").strip()
        if not username:
            return False, "Не указан логин (sAMAccountName).", ""
        if not ou_dn:
            return False, "Не указана OU/контейнер для создания пользователя.", ""

        first_name = (data.get("first_name") or "").strip()
        last_name = (data.get("last_name") or "").strip()
        display_name = (data.get("display_name") or "").strip()
        email = (data.get("email") or "").strip()
        password = (data.get("password") or "").strip()

        # Новые поля
        company = (data.get("company") or "").strip()
        department = (data.get("department") or "").strip()
        title = (data.get("title") or "").strip()
        description = (data.get("description") or "").strip()
        ip_phone = (data.get("ipPhone") or "").strip()
        other_pager: list[str] = [
            p.strip() for p in (data.get("otherPager") or []) if p and p.strip()
        ]
        groups: list[str] = [
            g.strip() for g in (data.get("groups") or []) if g and g.strip()
        ]
        must_change_pw = bool(data.get("must_change_password"))
        pw_never_expires = bool(data.get("password_never_expires"))

        cn_value = display_name or f"{first_name} {last_name}".strip() or username

        # Escape RDN safely.
        try:
            from ldap3.utils.dn import escape_rdn
            cn_rdn = escape_rdn(cn_value)
        except Exception:
            cn_rdn = cn_value.replace("\\", "\\\\").replace(",", "\\,")

        new_dn = f"CN={cn_rdn},{ou_dn}"

        attrs: dict[str, Any] = {
            "objectClass": ["top", "person", "organizationalPerson", "user"],
            "sAMAccountName": username,
        }
        # UPN если домен известен
        dom = (self.cfg.domain or "").strip().strip(".")
        if dom:
            attrs["userPrincipalName"] = f"{username}@{dom}"

        if first_name:
            attrs["givenName"] = first_name
        if last_name:
            attrs["sn"] = last_name
        if display_name:
            attrs["displayName"] = display_name
        else:
            attrs["displayName"] = cn_value
        if email:
            attrs["mail"] = email
        if company:
            attrs["company"] = company
        if department:
            attrs["department"] = department
        if title:
            attrs["title"] = title
        if description:
            attrs["description"] = description
        if ip_phone:
            attrs["ipPhone"] = ip_phone
        if other_pager:
            attrs["otherPager"] = other_pager

        conn: Connection | None = None
        try:
            conn = self._conn(self.cfg.bind_principal, self.cfg.bind_password)
            if not conn.bind():
                res = dict(conn.result or {})
                conn.unbind()
                return False, f"Ошибка bind: {res.get('description', 'неизвестная ошибка')}", ""

            ok = bool(conn.add(new_dn, attributes=attrs))
            res = dict(conn.result or {})
            if not ok:
                conn.unbind()
                desc = res.get("description", "") or "неизвестная ошибка"
                # Расшифровка типичных ошибок
                if "insufficientAccessRights" in desc:
                    desc = "Недостаточно прав. Учётная запись bind не имеет разрешений на создание объектов в выбранной OU."
                elif "entryAlreadyExists" in desc:
                    desc = "Объект с таким именем уже существует в данной OU."
                elif "constraintViolation" in desc:
                    desc = f"Логин «{username}» уже используется другим объектом в домене (sAMAccountName должен быть уникальным)."
                elif "noSuchObject" in desc:
                    desc = "Указанная OU не найдена в AD."
                elif "unwillingToPerform" in desc:
                    desc = "Сервер отклонил запрос. Проверьте формат данных."
                return False, f"Не удалось создать пользователя: {desc}", ""

            # ── Установка пароля и включение учётной записи ──
            warnings: list[str] = []

            if password:
                if not (self.cfg.use_ssl or self.cfg.starttls):
                    conn.unbind()
                    return True, "Пользователь создан, но пароль не задан: требуется LDAPS/StartTLS.", new_dn

                try:
                    pw_ok = bool(conn.extend.microsoft.modify_password(new_dn, password))
                except Exception as e:
                    pw_ok = False
                    pw_desc = str(e)
                else:
                    r = dict(conn.result or {})
                    pw_desc = r.get("description", "") or r.get("message", "неизвестная ошибка")

                if not pw_ok:
                    conn.unbind()
                    return True, f"Пользователь создан, но пароль не задан: {pw_desc}", new_dn

                # Включение учётной записи + флаги UAC
                uac = 512  # NORMAL_ACCOUNT
                if pw_never_expires:
                    uac |= 0x10000  # DONT_EXPIRE_PASSWORD → 66048
                conn.modify(new_dn, {"userAccountControl": [(MODIFY_REPLACE, [str(uac)])]})

                # Принудительная смена пароля при первом входе
                if must_change_pw:
                    conn.modify(new_dn, {"pwdLastSet": [(MODIFY_REPLACE, ["0"])]})

            # ── Добавление в группы ──
            for g_dn in groups:
                try:
                    conn.modify(g_dn, {"member": [(MODIFY_ADD, [new_dn])]})
                    g_res = dict(conn.result or {})
                    g_desc = (g_res.get("description") or "").lower()
                    if not conn.result.get("result") == 0 and "attributeorvalueexists" not in g_desc:
                        g_name = g_dn.split(",")[0] if "," in g_dn else g_dn
                        warnings.append(f"Не добавлен в группу {g_name}")
                except Exception:
                    g_name = g_dn.split(",")[0] if "," in g_dn else g_dn
                    warnings.append(f"Ошибка при добавлении в группу {g_name}")

            conn.unbind()

            msg = "Пользователь создан."
            if warnings:
                msg += " Предупреждения: " + "; ".join(warnings) + "."
            return True, msg, new_dn

        except LDAPException as e:
            try:
                if conn:
                    conn.unbind()
            except Exception:
                pass
            return False, f"LDAP ошибка: {e}", ""

    def create_group(self, data: dict) -> tuple[bool, str, str]:
        """Create a group in given OU/container.

        data keys: name, description, ou, scope (global|domainlocal|universal), category (security|distribution)
        Returns: (ok, message, new_dn)
        """

        data = data or {}
        name = (data.get("name") or "").strip()
        ou_dn = (data.get("ou") or "").strip()
        if not name:
            return False, "Не указано имя группы.", ""
        if not ou_dn:
            return False, "Не указана OU/контейнер для создания группы.", ""

        description = (data.get("description") or "").strip()
        scope = (data.get("scope") or "global").strip().lower()
        category = (data.get("category") or "security").strip().lower()

        scope_bits = {
            "global": 0x00000002,
            "domainlocal": 0x00000004,
            "universal": 0x00000008,
        }.get(scope, 0x00000002)
        security_bit = 0x80000000 if category == "security" else 0
        group_type = scope_bits | security_bit

        try:
            from ldap3.utils.dn import escape_rdn
            cn_rdn = escape_rdn(name)
        except Exception:
            cn_rdn = name.replace("\\", "\\\\").replace(",", "\\,")

        new_dn = f"CN={cn_rdn},{ou_dn}"

        attrs: dict[str, Any] = {
            "objectClass": ["top", "group"],
            "sAMAccountName": name,
            "cn": name,
            "groupType": str(group_type),
        }
        if description:
            attrs["description"] = description

        conn: Connection | None = None
        try:
            conn = self._conn(self.cfg.bind_principal, self.cfg.bind_password)
            if not conn.bind():
                res = dict(conn.result or {})
                conn.unbind()
                return False, f"Ошибка bind: {res.get('description', 'неизвестная ошибка')}", ""

            ok = bool(conn.add(new_dn, attributes=attrs))
            res = dict(conn.result or {})
            conn.unbind()
            if not ok:
                desc = res.get("description", "") or "неизвестная ошибка"
                if "insufficientAccessRights" in desc:
                    desc = "Недостаточно прав. Учётная запись bind не имеет разрешений на создание объектов в выбранной OU."
                elif "entryAlreadyExists" in desc:
                    desc = "Объект с таким именем уже существует в данной OU."
                elif "noSuchObject" in desc:
                    desc = "Указанная OU не найдена в AD."
                return False, f"Не удалось создать группу: {desc}", ""
            return True, "Группа создана.", new_dn

        except LDAPException as e:
            try:
                if conn:
                    conn.unbind()
            except Exception:
                pass
            return False, f"LDAP ошибка: {e}", ""

    def delete_group(self, group_dn: str) -> tuple[bool, str]:
        dn = (group_dn or "").strip()
        if not dn:
            return False, "Пустой DN группы."

        conn: Connection | None = None
        try:
            conn = self._conn(self.cfg.bind_principal, self.cfg.bind_password)
            if not conn.bind():
                res = dict(conn.result or {})
                conn.unbind()
                return False, f"Ошибка bind: {res.get('description', 'неизвестная ошибка')}"

            ok = bool(conn.delete(dn))
            res = dict(conn.result or {})
            conn.unbind()
            if not ok:
                return False, f"Не удалось удалить группу: {res.get('description', 'неизвестная ошибка')}"
            return True, "Группа удалена."

        except LDAPException as e:
            try:
                if conn:
                    conn.unbind()
            except Exception:
                pass
            return False, f"LDAP ошибка: {e}"
