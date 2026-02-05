from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Any

from ...ad import ADClient, ADConfig
from ...host_query.api import find_logged_on_users

from .schema import AppSettingsSchema


@dataclass
class ValidateResult:
    ok: bool
    message: str
    details: str = ""
    hints: list[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"ok": self.ok, "message": self.message}
        if self.details:
            d["details"] = self.details
        if self.hints:
            d["hints"] = self.hints
        return d


def validate_ad(settings: AppSettingsSchema, *, timeout_s: float = 3.0) -> ValidateResult:
    """Validate AD connection using current settings.

    - TCP connect + ldap bind (via ADClient.test_connection)
    """

    dc = settings.ad.dc_short
    domain = settings.ad.domain
    if not dc or not domain:
        return ValidateResult(False, "AD: заполните DC и домен")

    # Derive effective connection params.
    if settings.ad.conn_mode == "ldaps":
        port = 636
        use_ssl = True
        starttls = False
    else:
        port = 389
        use_ssl = False
        starttls = True

    if not settings.ad.bind_username:
        return ValidateResult(False, "AD: заполните Bind user")
    if not settings.ad.bind_password:
        return ValidateResult(False, "AD: укажите пароль Bind user (введите и сохраните/проверьте)")

    try:
        cfg = ADConfig(
            dc_short=dc,
            domain=domain,
            port=port,
            use_ssl=use_ssl,
            starttls=starttls,
            bind_username=settings.ad.bind_username,
            bind_password=settings.ad.bind_password,
            tls_validate=bool(settings.ad.tls_validate),
        )
        client = ADClient(cfg)
        ok = client.test_connection(timeout_s=timeout_s)
        if ok:
            return ValidateResult(True, "AD: подключение успешно")
        return ValidateResult(False, "AD: не удалось подключиться или выполнить bind")
    except Exception as e:
        return ValidateResult(
            False,
            "AD: ошибка подключения",
            details=str(e),
            hints=[
                "Проверьте DNS/доступность DC",
                "Проверьте порт 636 (LDAPS) или 389 (StartTLS)",
                "Если включена проверка TLS — проверьте сертификат/CA",
            ],
        )


def validate_host_query(settings: AppSettingsSchema) -> ValidateResult:
    """Validate host query configuration.

    - Checks that credentials are provided.
    - If `test_host` is provided:
        * DNS resolve check
        * quick TCP reachability probes (445, 5985, 5986)
        * optional lightweight query via `find_logged_on_users`
    """

    if not settings.host_query.username:
        return ValidateResult(False, "Host query: укажите пользователя")
    if not settings.host_query.password:
        return ValidateResult(False, "Host query: укажите пароль (введите и сохраните/проверьте)")

    host = (settings.host_query.test_host or "").strip()
    if not host:
        return ValidateResult(
            True,
            "Host query: базовая проверка пройдена",
            details="Для полной проверки укажите тестовый хост и нажмите “Проверить”.",
        )

    # DNS
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return ValidateResult(False, f"Host query: не удалось разрешить хост {host}", details=str(e))

    # TCP reachability probes (best-effort; Windows host may block some ports)
    probes = [(445, "SMB/445"), (5985, "WinRM/HTTP 5985"), (5986, "WinRM/HTTPS 5986")]
    open_ports: list[str] = []
    closed_ports: list[str] = []
    for port, label in probes:
        try:
            sock = socket.create_connection((ip, port), timeout=1.0)
            sock.close()
            open_ports.append(label)
        except Exception:
            closed_ports.append(label)

    details = f"{host} → {ip}"
    if open_ports:
        details += " | доступно: " + ", ".join(open_ports)
    if closed_ports:
        details += " | нет ответа: " + ", ".join(closed_ports)

    # Lightweight query
    try:
        domain_suffix = (settings.ad.domain or "").strip()
        users, _target, _total_ms, _attempts = find_logged_on_users(
            host,
            domain_suffix,
            settings.host_query.username,
            settings.host_query.password,
            int(settings.host_query.timeout_s or 60),
        )

        if not users:
            return ValidateResult(
                True,
                f"Host query: успешно (на {host} активные пользователи не найдены)",
                details=details,
            )

        example = (users[0] or "").strip()
        msg = f"Host query: успешно (пример: {example})" if example else "Host query: успешно"
        return ValidateResult(True, msg, details=details)
    except Exception as e:
        return ValidateResult(
            False,
            f"Host query: ошибка при запросе к {host}",
            details=str(e),
            hints=[
                "Проверьте WinRM/WMI/SMB доступность",
                "Проверьте права учётной записи",
                "Проверьте Firewall на хосте (5985/5986, 445, 135)",
            ],
        )


def validate_net_scan(settings: AppSettingsSchema) -> ValidateResult:
    """Validate network scan settings (CIDRs + limits)."""

    if not settings.net_scan.enabled:
        return ValidateResult(True, "Net scan: выключено (это нормально)")

    if not settings.net_scan.cidrs:
        return ValidateResult(False, "Net scan: включено, но CIDR не задан")

    bad: list[str] = []
    parsed: list[str] = []
    for s in settings.net_scan.cidrs:
        try:
            parsed.append(str(ipaddress.ip_network(s, strict=False)))
        except Exception:
            bad.append(s)

    if bad:
        return ValidateResult(False, "Net scan: ошибка CIDR", details="; ".join(bad))

    # Soft sanity check on size: avoid accidental /8 etc.
    too_big = []
    for n in parsed:
        net = ipaddress.ip_network(n, strict=False)
        if net.num_addresses > 65536:
            too_big.append(n)

    if too_big:
        return ValidateResult(
            False,
            "Net scan: слишком большой диапазон",
            details="; ".join(too_big),
            hints=["Используйте более узкие сети (например /24 или /23)"],
        )

    return ValidateResult(True, "Net scan: проверка пройдена")
