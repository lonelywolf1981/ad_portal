from __future__ import annotations

import ipaddress
import re
from typing import Literal, Any

from pydantic import BaseModel, Field, field_validator, model_validator

CURRENT_SCHEMA_VERSION = 6

MAX_NETSCAN_CIDRS = 64  # hard limit for net_scan.cidrs

AuthMode = Literal["local", "ad"]
ADConnMode = Literal["ldaps", "starttls"]


class CoreUISettings(BaseModel):
    """Core/UI flags (reserved for future stages)."""

    initialized: bool = Field(default=False)


class CoreSettings(BaseModel):
    ui: CoreUISettings = Field(default_factory=CoreUISettings)


class AuthSettings(BaseModel):
    mode: AuthMode = Field(default="local")


class ADSettings(BaseModel):
    dc_short: str = Field(default="", max_length=64)
    domain: str = Field(default="", max_length=255)
    conn_mode: ADConnMode = Field(default="ldaps")

    bind_username: str = Field(default="", max_length=128)
    bind_password: str = Field(default="")  # plaintext; storage decides how to persist

    tls_validate: bool = Field(default=False)
    ca_pem: str = Field(default="")

    allowed_app_group_dns: list[str] = Field(default_factory=list)
    allowed_settings_group_dns: list[str] = Field(default_factory=list)

    @field_validator("dc_short", "domain", "bind_username")
    @classmethod
    def _strip(cls, v: str) -> str:
        return (v or "").strip()

    @field_validator("domain")
    @classmethod
    def _validate_domain(cls, v: str) -> str:
        s = (v or "").strip().lower()
        if not s:
            return s
        if s[-1] in ".,;":
            raise ValueError("Имя домена не должно оканчиваться на точку/запятую/точку с запятой.")
        labels = s.split(".")
        for lab in labels:
            if not lab:
                raise ValueError("Некорректное имя домена: пустая часть между точками.")
            if len(lab) > 63:
                raise ValueError(f"Некорректное имя домена: часть '{lab}' слишком длинная (макс 63).")
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", lab):
                raise ValueError(f"Некорректное имя домена: недопустимые символы в части '{lab}'.")
        if len(s) > 253:
            raise ValueError("Некорректное имя домена: слишком длинное (макс 253).")
        return s

    @field_validator("dc_short")
    @classmethod
    def _validate_dc_short(cls, v: str) -> str:
        s = (v or "").strip()
        if not s:
            return s
        
        # Проверяем, является ли значение IP-адресом
        import ipaddress
        try:
            ipaddress.ip_address(s)
            # Если это IP-адрес, возвращаем его без дополнительной проверки
            return s
        except ValueError:
            # Если не IP-адрес, применяем стандартные правила
            if any(ch in s for ch in ".,;"):
                raise ValueError("Имя DC (короткое) не должно содержать точек/запятых.")
            if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9_-]{0,62}[A-Za-z0-9])?", s):
                raise ValueError("Некорректное имя DC: используйте буквы/цифры/дефис/подчёркивание без пробелов.")
        
        return s

    @field_validator("allowed_app_group_dns", "allowed_settings_group_dns")
    @classmethod
    def _strip_list(cls, v: list[str]) -> list[str]:
        return [(x or "").strip() for x in (v or []) if (x or "").strip()]


class HostQuerySettings(BaseModel):
    username: str = Field(default="", max_length=128)
    password: str = Field(default="")
    timeout_s: int = Field(default=60, ge=3, le=600)
    test_host: str = Field(default="", max_length=255)

    @field_validator("username", "test_host")
    @classmethod
    def _strip(cls, v: str) -> str:
        return (v or "").strip()


class IPPhonesSettings(BaseModel):
    enabled: bool = Field(default=False)
    ami_host: str = Field(default="", max_length=255)
    ami_port: int = Field(default=5038, ge=1, le=65535)
    ami_user: str = Field(default="", max_length=128)
    ami_password: str = Field(default="")
    ami_timeout_s: int = Field(default=5, ge=1, le=30)

    @field_validator("ami_host", "ami_user")
    @classmethod
    def _strip(cls, v: str) -> str:
        return (v or "").strip()


class NetScanSettings(BaseModel):
    enabled: bool = Field(default=False)
    cidrs: list[str] = Field(default_factory=list)
    dns_server: str = Field(default="", max_length=255)

    interval_min: int = Field(default=120, ge=1, le=24 * 60)
    concurrency: int = Field(default=64, ge=1, le=512)
    method_timeout_s: int = Field(default=20, ge=1, le=180)
    probe_timeout_ms: int = Field(default=350, ge=50, le=5000)
    stats_retention_days: int = Field(default=30, ge=7, le=365)

    @field_validator("cidrs")
    @classmethod
    def _cidrs_strip_and_validate(cls, v: list[str]) -> list[str]:
        """
        - trims empty lines
        - validates CIDR parseability
        - rejects duplicates (after canonical normalization)
        - rejects overlaps (e.g. 192.168.72.0/26 and 192.168.72.0/25)
        """
        raw_items: list[str] = []
        nets: list[ipaddress._BaseNetwork] = []  # type: ignore[attr-defined]

        for raw in (v or []):
            t = (raw or "").strip()
            if not t:
                continue
            try:
                net = ipaddress.ip_network(t, strict=False)
            except ValueError:
                raise ValueError(f"Некорректный CIDR: {t}")
            raw_items.append(t)
            nets.append(net)

        # Normalize to canonical strings (used by scanner and for duplicate detection)
        canon = [str(n) for n in nets]

        # Hard limit to keep scanning predictable and UI responsive.
        if len(canon) > MAX_NETSCAN_CIDRS:
            raise ValueError(f"Слишком много диапазонов CIDR (макс {MAX_NETSCAN_CIDRS}).")

        # Duplicates (exact same network/prefix)
        seen: set[str] = set()
        dups: list[str] = []
        for c in canon:
            if c in seen and c not in dups:
                dups.append(c)
            seen.add(c)
        if dups:
            raise ValueError("Повторяющийся диапазон CIDR: " + "; ".join(dups))

        # Overlaps (different networks that overlap)
        # Keep the message short (first offending pair).
        for i in range(len(nets)):
            for j in range(i + 1, len(nets)):
                a = nets[i]
                b = nets[j]
                if a.overlaps(b):
                    raise ValueError(f"Пересекающиеся диапазоны CIDR: {canon[i]} и {canon[j]}")

        # Return canonical list for storage
        return canon


class ChartColorsSettings(BaseModel):
    line_color: str = Field(default="#0d6efd", max_length=20)
    fill_color: str = Field(default="rgba(13,110,253,0.16)", max_length=30)
    point_color: str = Field(default="#0d6efd", max_length=20)

    @field_validator("line_color", "point_color")
    @classmethod
    def _validate_hex_color(cls, v: str) -> str:
        """Проверяет, что цвет задан в формате HEX (#RRGGBB)."""
        s = (v or "").strip()
        if not s:
            return s
        # Проверяем формат HEX (#RGB или #RRGGBB)
        if not re.fullmatch(r"#([A-Fa-f0-9]{3}|[A-Fa-f0-9]{6})", s):
            raise ValueError(f"Некорректный цвет в формате HEX: {s}")
        return s

    @field_validator("fill_color")
    @classmethod
    def _validate_rgba_color(cls, v: str) -> str:
        """Проверяет, что цвет задан в формате RGBA (rgba(R,G,B,A))."""
        s = (v or "").strip()
        if not s:
            return s
        # Проверяем формат RGBA
        rgba_pattern = r"rgba\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*(0|0?\.\d+|1(\.0)?)\s*\)"
        if not re.fullmatch(rgba_pattern, s, re.IGNORECASE):
            # Также проверяем формат HEX
            if not re.fullmatch(r"#([A-Fa-f0-9]{3}|[A-Fa-f0-9]{6})", s):
                raise ValueError(f"Некорректный цвет в формате RGBA или HEX: {s}")
        return s



def upgrade_payload(payload: dict) -> dict:
    """Best-effort upgrade for imported JSON (auto-upgrade on read)."""
    if not isinstance(payload, dict):
        return payload

    v = int(payload.get("schema_version") or 0)

    # v1 -> v2 changes:
    # - core.initialized -> core.ui.initialized
    # - auth_mode -> auth.mode (keep auth_mode for legacy UI/forms)
    if v < 2:
        core = payload.get("core") or {}
        if isinstance(core, dict) and "initialized" in core:
            ui = core.get("ui") or {}
            if isinstance(ui, dict):
                ui.setdefault("initialized", bool(core.get("initialized")))
            core.pop("initialized", None)
            core["ui"] = ui
            payload["core"] = core

        if "auth" not in payload and "auth_mode" in payload:
            payload["auth"] = {"mode": payload.get("auth_mode")}

        payload["schema_version"] = 2

    # v2 -> v3 changes:
    # - добавлено поле net_scan.dns_server
    if v < 3:
        if "net_scan" not in payload:
            payload["net_scan"] = {}
        if not isinstance(payload["net_scan"], dict):
            payload["net_scan"] = {}
        if "dns_server" not in payload["net_scan"]:
            payload["net_scan"]["dns_server"] = ""

        payload["schema_version"] = 3

    # v3 -> v4 changes:
    # - добавлено поле net_scan.stats_retention_days
    if v < 4:
        if "net_scan" not in payload:
            payload["net_scan"] = {}
        if not isinstance(payload["net_scan"], dict):
            payload["net_scan"] = {}
        if "stats_retention_days" not in payload["net_scan"]:
            payload["net_scan"]["stats_retention_days"] = 30

        payload["schema_version"] = 4

    # v4 -> v5 changes:
    # - добавлен раздел ip_phones для интеграции AMI
    if v < 5:
        if "ip_phones" not in payload:
            payload["ip_phones"] = {}
        if not isinstance(payload["ip_phones"], dict):
            payload["ip_phones"] = {}
        ip_phones = payload["ip_phones"]
        ip_phones.setdefault("enabled", False)
        ip_phones.setdefault("ami_host", "")
        ip_phones.setdefault("ami_port", 5038)
        ip_phones.setdefault("ami_user", "")
        ip_phones.setdefault("ami_password", "")
        ip_phones.setdefault("ami_timeout_s", 5)
        payload["schema_version"] = 5

    # v5 -> v6 changes:
    # - добавлен раздел chart_colors для настройки цветов графика
    if v < 6:
        if "chart_colors" not in payload:
            payload["chart_colors"] = {}
        if not isinstance(payload["chart_colors"], dict):
            payload["chart_colors"] = {}
        chart_colors = payload["chart_colors"]
        chart_colors.setdefault("line_color", "#0d6efd")
        chart_colors.setdefault("fill_color", "rgba(13,110,253,0.16)")
        chart_colors.setdefault("point_color", "#0d6efd")
        payload["schema_version"] = 6

    # normalize
    try:
        payload["schema_version"] = int(payload.get("schema_version") or CURRENT_SCHEMA_VERSION)
    except Exception:
        payload["schema_version"] = CURRENT_SCHEMA_VERSION

    return payload


class AppSettingsSchema(BaseModel):
    """Typed settings tree used by services/UI."""

    schema_version: int = Field(default=CURRENT_SCHEMA_VERSION)

    core: CoreSettings = Field(default_factory=CoreSettings)

    # New grouping (Этап 1)
    auth: AuthSettings = Field(default_factory=AuthSettings)

    # Legacy convenience for existing templates/forms.
    auth_mode: AuthMode = Field(default="local")

    ad: ADSettings = Field(default_factory=ADSettings)
    host_query: HostQuerySettings = Field(default_factory=HostQuerySettings)
    ip_phones: IPPhonesSettings = Field(default_factory=IPPhonesSettings)
    net_scan: NetScanSettings = Field(default_factory=NetScanSettings)
    chart_colors: ChartColorsSettings = Field(default_factory=ChartColorsSettings)

    @property
    def is_initialized(self) -> bool:
        """Проверяет, инициализировано ли приложение.
        
        Инициализация определяется по наличию обязательных полей.
        """
        # Минимальная инициализация по требованиям UI-чеклиста:
        # 1) выбран режим аутентификации (local/ad)
        # 2) если выбран AD — заполнены базовые параметры подключения
        # 3) заполнены учётные данные для опроса хостов
        # 4) сетевое сканирование (netscan) — опционально.
        #
        # Если оно выключено — это не должно блокировать основной функционал.
        # Если включено — диапазоны и остальные параметры валидируются отдельно.

        auth_configured = self.auth_mode in ["local", "ad"]

        if self.auth_mode == "ad":
            ad_configured = bool(
                (self.ad.domain or "").strip()
                and (self.ad.dc_short or "").strip()
                and (self.ad.bind_username or "").strip()
            )
        else:
            ad_configured = True

        host_query_configured = bool((self.host_query.username or "").strip())

        return bool(auth_configured and ad_configured and host_query_configured)


    @model_validator(mode="before")
    @classmethod
    def _upgrade_before_validate(cls, data: Any):
        if isinstance(data, dict):
            return upgrade_payload(data)
        return data

    @model_validator(mode="after")
    def _sync_auth(self):
        # Prefer explicit auth.mode if present; otherwise take auth_mode.
        mode = None
        try:
            mode = getattr(self.auth, "mode", None)
        except Exception:
            mode = None

        if mode:
            self.auth_mode = mode  # keep legacy in sync
        else:
            self.auth = AuthSettings(mode=self.auth_mode)

        return self
