from __future__ import annotations

import ipaddress
from typing import Literal

from pydantic import BaseModel, Field, field_validator


CURRENT_SCHEMA_VERSION = 1


AuthMode = Literal["local", "ad"]
ADConnMode = Literal["ldaps", "starttls"]


class CoreSettings(BaseModel):
    """Core/UI flags.

    Note: `initialized` is reserved for Этап 4. We keep it here now to avoid
    churn later.
    """

    initialized: bool = Field(default=False)


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

    @field_validator("allowed_app_group_dns", "allowed_settings_group_dns")
    @classmethod
    def _strip_dns(cls, v: list[str]) -> list[str]:
        return [x.strip() for x in (v or []) if x and x.strip()]


class HostQuerySettings(BaseModel):
    username: str = Field(default="", max_length=128)
    password: str = Field(default="")
    timeout_s: int = Field(default=60, ge=5, le=300)
    test_host: str = Field(default="", max_length=255)

    @field_validator("username", "test_host")
    @classmethod
    def _strip(cls, v: str) -> str:
        return (v or "").strip()


class NetScanSettings(BaseModel):
    enabled: bool = Field(default=False)
    cidrs: list[str] = Field(default_factory=list)
    interval_min: int = Field(default=120, ge=30, le=24 * 60)

    concurrency: int = Field(default=64, ge=4, le=256)
    method_timeout_s: int = Field(default=20, ge=5, le=60)
    probe_timeout_ms: int = Field(default=350, ge=100, le=1500)

    @field_validator("cidrs")
    @classmethod
    def _normalize_cidrs(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        for raw in v or []:
            s = (raw or "").strip()
            if not s or s.startswith("#") or s.startswith(";"):
                continue
            try:
                net = ipaddress.ip_network(s, strict=False)
            except Exception:
                # keep raw value for error reporting in validator
                out.append(s)
                continue
            out.append(str(net))
        return out


class AppSettingsSchema(BaseModel):
    """Typed settings tree used by services/UI.

    This is NOT the DB model.
    """

    schema_version: int = Field(default=CURRENT_SCHEMA_VERSION)

    core: CoreSettings = Field(default_factory=CoreSettings)
    auth_mode: AuthMode = Field(default="local")

    ad: ADSettings = Field(default_factory=ADSettings)
    host_query: HostQuerySettings = Field(default_factory=HostQuerySettings)
    net_scan: NetScanSettings = Field(default_factory=NetScanSettings)
