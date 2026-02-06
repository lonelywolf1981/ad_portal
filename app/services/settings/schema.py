from __future__ import annotations

import ipaddress
import re
from typing import Literal, Any

from pydantic import BaseModel, Field, field_validator, model_validator

CURRENT_SCHEMA_VERSION = 2

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


class NetScanSettings(BaseModel):
    enabled: bool = Field(default=False)
    cidrs: list[str] = Field(default_factory=list)

    interval_min: int = Field(default=120, ge=1, le=24 * 60)
    concurrency: int = Field(default=64, ge=1, le=512)
    method_timeout_s: int = Field(default=20, ge=1, le=180)
    probe_timeout_ms: int = Field(default=350, ge=50, le=5000)

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
            net = ipaddress.ip_network(t, strict=False)
            raw_items.append(t)
            nets.append(net)

        # Normalize to canonical strings (used by scanner and for duplicate detection)
        canon = [str(n) for n in nets]

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
    net_scan: NetScanSettings = Field(default_factory=NetScanSettings)

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
