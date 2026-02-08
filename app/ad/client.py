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
    BASE,
    Tls,
    ALL_ATTRIBUTES,
    ALL_OPERATIONAL_ATTRIBUTES,
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
        try:
            conn = self._conn(self.cfg.bind_principal, self.cfg.bind_password)
            ok = bool(conn.bind())
            res = dict(conn.result or {})
            conn.unbind()
            return ok, res
        except LDAPException as e:
            return False, {"error": str(e), "description": str(e), "message": str(e)}

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

    def count_users(self, *, enabled_only: bool = False, page_size: int = 500) -> tuple[bool, str, int]:
        """Count AD users under BaseDN.

        We intentionally keep this lightweight and defensive:
        - paged search (to avoid server-side size limits)
        - no heavy attribute fetching

        Returns: (ok, message, count)
        """

        base = self.cfg.base_dn
        if not base:
            return False, "BaseDN пустой (проверьте домен в настройках).", 0

        # Filter:
        # - only user objects (exclude computers)
        # - optionally exclude disabled accounts via userAccountControl bit 2
        flt_parts = [
            "(objectCategory=person)",
            "(objectClass=user)",
            "(!(objectClass=computer))",
        ]
        if enabled_only:
            # LDAP_MATCHING_RULE_BIT_AND (1.2.840.113556.1.4.803)
            # userAccountControl:...:=2 => DISABLED
            flt_parts.append("(!(userAccountControl:1.2.840.113556.1.4.803:=2))")

        flt = "(&" + "".join(flt_parts) + ")"

        conn: Connection | None = None
        try:
            conn = self._conn(self.cfg.bind_principal, self.cfg.bind_password)
            if not conn.bind():
                res = dict(conn.result or {})
                conn.unbind()
                return False, f"Ошибка bind: {res}", 0

            # Use ldap3 paged search controls.
            # We request only DN (no attributes) to keep traffic minimal.
            count = 0
            cookie = None
            while True:
                ok = conn.search(
                    search_base=base,
                    search_filter=flt,
                    search_scope=SUBTREE,
                    attributes=[],
                    paged_size=int(page_size),
                    paged_cookie=cookie,
                )
                if not ok:
                    res = dict(conn.result or {})
                    conn.unbind()
                    return False, f"Поиск не выполнен: {res}", 0

                count += len(conn.entries)
                controls = conn.result.get("controls", {}) if isinstance(conn.result, dict) else {}
                paged = controls.get("1.2.840.113556.1.4.319", {})
                value = paged.get("value", {}) if isinstance(paged, dict) else {}
                cookie = value.get("cookie")
                if not cookie:
                    break

            conn.unbind()
            return True, "OK", int(count)

        except LDAPException as e:
            try:
                if conn:
                    conn.unbind()
            except Exception:
                pass
            return False, f"LDAP ошибка: {e}", 0
