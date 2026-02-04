from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from ...crypto import decrypt_str, encrypt_str
from ...models import AppSettings
from ...repo import get_or_create_settings

from .schema import AppSettingsSchema, CURRENT_SCHEMA_VERSION


def _migrate_settings_row(st: AppSettings) -> bool:
    """Apply in-place lightweight migrations for settings.

    Returns True if the row was modified.
    """

    changed = False
    v = int(getattr(st, "schema_version", 0) or 0)

    # v0 -> v1
    if v < 1:
        st.schema_version = 1
        changed = True

    # Future migrations go here (v1 -> v2 -> ...)
    if st.schema_version != CURRENT_SCHEMA_VERSION:
        # keep monotonicity; never downgrade
        st.schema_version = max(int(st.schema_version or 0), CURRENT_SCHEMA_VERSION)
        changed = True

    return changed


def get_settings(db: Session) -> AppSettingsSchema:
    st = get_or_create_settings(db)
    if _migrate_settings_row(st):
        st.updated_at = datetime.utcnow()
        db.commit()

    return AppSettingsSchema(
        schema_version=int(getattr(st, "schema_version", CURRENT_SCHEMA_VERSION) or CURRENT_SCHEMA_VERSION),
        auth_mode=(st.auth_mode or "local").strip() or "local",
        ad={
            "dc_short": (st.ad_dc_short or "").strip(),
            "domain": (st.ad_domain or "").strip(),
            "conn_mode": "ldaps" if bool(st.ad_use_ssl) else "starttls",
            "bind_username": (st.ad_bind_username or "").strip(),
            "bind_password": decrypt_str(st.ad_bind_password_enc) if (st.ad_bind_password_enc or "") else "",
            "tls_validate": bool(getattr(st, "ad_tls_validate", False)),
            "ca_pem": getattr(st, "ad_ca_pem", "") or "",
            "allowed_app_group_dns": _split_dns(st.allowed_app_group_dns),
            "allowed_settings_group_dns": _split_dns(st.allowed_settings_group_dns),
        },
        host_query={
            "username": (st.host_query_username or "").strip(),
            "password": decrypt_str(st.host_query_password_enc) if (st.host_query_password_enc or "") else "",
            "timeout_s": int(st.host_query_timeout_s or 60),
        },
        net_scan={
            "enabled": bool(st.net_scan_enabled),
            "cidrs": _split_lines(st.net_scan_cidrs),
            "interval_min": int(st.net_scan_interval_min or 120),
            "concurrency": int(getattr(st, "net_scan_concurrency", 64) or 64),
            "method_timeout_s": int(getattr(st, "net_scan_method_timeout_s", 20) or 20),
            "probe_timeout_ms": int(getattr(st, "net_scan_probe_timeout_ms", 350) or 350),
        },
    )


def save_settings(db: Session, data: AppSettingsSchema, *, keep_secrets_if_blank: bool = True) -> AppSettings:
    """Persist settings (typed schema) into DB row."""

    st = get_or_create_settings(db)

    # schema version
    st.schema_version = int(data.schema_version or CURRENT_SCHEMA_VERSION)

    # auth
    st.auth_mode = (data.auth_mode or "local").strip()

    # AD
    st.ad_dc_short = (data.ad.dc_short or "").strip()
    st.ad_domain = (data.ad.domain or "").strip()

    if data.ad.conn_mode == "ldaps":
        st.ad_port = 636
        st.ad_use_ssl = True
        st.ad_starttls = False
    else:
        st.ad_port = 389
        st.ad_use_ssl = False
        st.ad_starttls = True

    st.ad_bind_username = (data.ad.bind_username or "").strip()

    if data.ad.bind_password or not keep_secrets_if_blank:
        st.ad_bind_password_enc = encrypt_str(data.ad.bind_password or "")

    st.ad_tls_validate = bool(data.ad.tls_validate)
    st.ad_ca_pem = data.ad.ca_pem or ""

    st.allowed_app_group_dns = ";".join(data.ad.allowed_app_group_dns or [])
    st.allowed_settings_group_dns = ";".join(data.ad.allowed_settings_group_dns or [])

    # Host query
    st.host_query_username = (data.host_query.username or "").strip()
    st.host_query_timeout_s = int(data.host_query.timeout_s or 60)
    if data.host_query.password or not keep_secrets_if_blank:
        st.host_query_password_enc = encrypt_str(data.host_query.password or "")

    # Net scan
    st.net_scan_enabled = bool(data.net_scan.enabled)
    st.net_scan_cidrs = "\n".join(data.net_scan.cidrs or [])
    st.net_scan_interval_min = int(data.net_scan.interval_min or 120)
    st.net_scan_concurrency = int(data.net_scan.concurrency or 64)
    # `net_scan_method_timeout_s` may not exist in old DB; schema bootstrap adds it.
    setattr(st, "net_scan_method_timeout_s", int(data.net_scan.method_timeout_s or 20))
    st.net_scan_probe_timeout_ms = int(data.net_scan.probe_timeout_ms or 350)

    st.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(st)
    return st


def _split_lines(s: str) -> list[str]:
    lines: list[str] = []
    for raw in (s or "").splitlines():
        t = raw.strip()
        if not t:
            continue
        lines.append(t)
    return lines


def _split_dns(s: str) -> list[str]:
    out: list[str] = []
    for raw in (s or "").split(";"):
        t = raw.strip()
        if t:
            out.append(t)
    return out
