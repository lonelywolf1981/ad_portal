from __future__ import annotations

from dataclasses import dataclass
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

    @property
    def host(self) -> str:
        # Если задан DNS сервер, используем его для резолва
        if self.dns_server:
            from ..utils.net import resolve_hostname_with_dns
            resolved_ip = resolve_hostname_with_dns(build_dc_fqdn(self.dc_short, self.domain), self.dns_server)
            if resolved_ip:
                return resolved_ip
        # Если DNS сервер не задан или резолв не удался, используем обычное формирование FQDN
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
