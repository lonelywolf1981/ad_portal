from __future__ import annotations

from datetime import datetime
from sqlalchemy import String, DateTime, Boolean, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


class LoginAudit(Base):
    __tablename__ = "login_audit"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    username: Mapped[str] = mapped_column(String(128), nullable=False)
    auth_type: Mapped[str] = mapped_column(String(16), default="local", nullable=False)  # local|ad
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)

    ip: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    user_agent: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    result_code: Mapped[str] = mapped_column(String(32), default="", nullable=False)  # ok|invalid|forbidden|error
    details: Mapped[str] = mapped_column(String(512), default="", nullable=False)


class LocalUser(Base):
    __tablename__ = "local_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)


class AppSettings(Base):
    __tablename__ = "app_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)  # always 1

    auth_mode: Mapped[str] = mapped_column(String(16), default="local", nullable=False)  # local|ad

    ad_dc_short: Mapped[str] = mapped_column(String(64), default="", nullable=False)     # e.g. DC1
    ad_domain: Mapped[str] = mapped_column(String(255), default="", nullable=False)     # e.g. ubc.local.net
    ad_port: Mapped[int] = mapped_column(Integer, default=636, nullable=False)
    ad_use_ssl: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    ad_starttls: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    ad_bind_username: Mapped[str] = mapped_column(String(128), default="", nullable=False)   # e.g. ldap_bind
    ad_bind_password_enc: Mapped[str] = mapped_column(String(2048), default="", nullable=False)

    # Remote host logon query settings (WinRM/WMI/SMB)
    host_query_username: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    host_query_password_enc: Mapped[str] = mapped_column(String(2048), default="", nullable=False)
    host_query_timeout_s: Mapped[int] = mapped_column(Integer, default=60, nullable=False)

    # Background network scan settings (periodic discovery: which user is logged on which host)
    net_scan_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    net_scan_cidrs: Mapped[str] = mapped_column(Text, default="", nullable=False)  # one CIDR per line
    net_scan_interval_min: Mapped[int] = mapped_column(Integer, default=120, nullable=False)

    # Advanced knobs (optional)
    net_scan_concurrency: Mapped[int] = mapped_column(Integer, default=64, nullable=False)
    net_scan_method_timeout_s: Mapped[int] = mapped_column(Integer, default=20, nullable=False)
    net_scan_probe_timeout_ms: Mapped[int] = mapped_column(Integer, default=350, nullable=False)

    # Runtime info
    net_scan_last_run_ts: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    net_scan_last_summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    net_scan_is_running: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    net_scan_run_started_ts: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


    ad_tls_validate: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    ad_ca_pem: Mapped[str] = mapped_column(Text, default="", nullable=False)

    allowed_app_group_dns: Mapped[str] = mapped_column(Text, default="", nullable=False)
    allowed_settings_group_dns: Mapped[str] = mapped_column(Text, default="", nullable=False)

    groups_cache_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    groups_cache_ts: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    last_ad_test_ts: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_ad_test_ok: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_ad_test_message: Mapped[str] = mapped_column(String(512), default="", nullable=False)

    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)


class UserPresence(Base):
    """Last known location for a user (from background network scan)."""

    __tablename__ = "user_presence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_login: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)  # normalized (lower)
    host: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    ip: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    method: Mapped[str] = mapped_column(String(16), default="", nullable=False)
    last_seen_ts: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
