from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from ..ad_utils import domain_to_base_dn, build_dc_fqdn


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
    dns_server: str = ""
    _resolved_host: str = field(default="", init=False, repr=False)

    @property
    def dc_list(self) -> list[str]:
        """dc_short may hold several DCs separated by comma/space ("dc1,dc2"): first is primary."""
        items = [x.strip() for x in (self.dc_short or "").replace(";", ",").replace(" ", ",").split(",")]
        return [x for x in items if x]

    @property
    def hosts(self) -> list[str]:
        """FQDNs of all configured DCs (primary first). Used for the LDAP server pool."""
        dcs = self.dc_list
        if not dcs:
            return [self.host]
        return [self.host] + [build_dc_fqdn(d, self.domain) for d in dcs[1:]]

    @property
    def host(self) -> str:
        if self._resolved_host:
            return self._resolved_host
        primary = (self.dc_list or [""])[0]
        # Если задан DNS сервер, используем его для резолва.
        # При проверке сертификата (tls_validate) подключаемся только по имени: сертификат DC
        # выписан на FQDN, и подключение по IP не пройдёт проверку имени.
        if self.dns_server and not self.tls_validate:
            from ..utils.net import resolve_hostname_with_dns
            resolved_ip = resolve_hostname_with_dns(build_dc_fqdn(primary, self.domain), self.dns_server)
            if resolved_ip:
                self._resolved_host = resolved_ip
                return self._resolved_host
        # Если DNS сервер не задан или резолв не удался, используем обычное формирование FQDN
        self._resolved_host = build_dc_fqdn(primary, self.domain)
        return self._resolved_host

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
