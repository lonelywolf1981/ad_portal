from __future__ import annotations

"""DB schema bootstrap + minimal migrations (SQLite).

This project intentionally avoids Alembic. We keep migrations extremely small:
- create missing tables
- add missing columns to `app_settings`

IMPORTANT: this must be callable both from the web app and Celery worker.
"""

from .db import engine
from .models import Base


def ensure_schema() -> None:
    """Ensure DB schema is up to date.

    - creates missing tables (create_all)
    - adds newly introduced columns to app_settings
    """

    # Create all known tables (including newly added ones)
    Base.metadata.create_all(bind=engine)

    # Minimal column migrations for SQLite
    with engine.begin() as conn:
        cols = [r[1] for r in conn.exec_driver_sql("PRAGMA table_info(app_settings)").fetchall()]

        def add(sql: str) -> None:
            conn.exec_driver_sql(sql)

        # Settings schema version
        if "schema_version" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 1")

        # Remote host logon query settings
        if "host_query_username" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN host_query_username VARCHAR(128) NOT NULL DEFAULT ''")
        if "host_query_password_enc" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN host_query_password_enc VARCHAR(2048) NOT NULL DEFAULT ''")
        if "host_query_timeout_s" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN host_query_timeout_s INTEGER NOT NULL DEFAULT 60")

        # IP phones / AMI settings
        if "ip_phones_enabled" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN ip_phones_enabled BOOLEAN NOT NULL DEFAULT 0")
        if "ip_phones_ami_host" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN ip_phones_ami_host VARCHAR(255) NOT NULL DEFAULT ''")
        if "ip_phones_ami_port" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN ip_phones_ami_port INTEGER NOT NULL DEFAULT 5038")
        if "ip_phones_ami_user" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN ip_phones_ami_user VARCHAR(128) NOT NULL DEFAULT ''")
        if "ip_phones_ami_password_enc" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN ip_phones_ami_password_enc VARCHAR(2048) NOT NULL DEFAULT ''")
        if "ip_phones_ami_timeout_s" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN ip_phones_ami_timeout_s INTEGER NOT NULL DEFAULT 5")

        # Background network scan settings
        if "net_scan_enabled" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN net_scan_enabled BOOLEAN NOT NULL DEFAULT 0")
        if "net_scan_cidrs" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN net_scan_cidrs TEXT NOT NULL DEFAULT ''")
        if "net_scan_dns_server" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN net_scan_dns_server VARCHAR(255) NOT NULL DEFAULT ''")
        if "net_scan_interval_min" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN net_scan_interval_min INTEGER NOT NULL DEFAULT 120")
        if "net_scan_concurrency" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN net_scan_concurrency INTEGER NOT NULL DEFAULT 64")
        if "net_scan_method_timeout_s" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN net_scan_method_timeout_s INTEGER NOT NULL DEFAULT 20")
        if "net_scan_probe_timeout_ms" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN net_scan_probe_timeout_ms INTEGER NOT NULL DEFAULT 350")
        if "net_scan_stats_retention_days" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN net_scan_stats_retention_days INTEGER NOT NULL DEFAULT 30")

        if "net_scan_last_run_ts" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN net_scan_last_run_ts DATETIME")
        if "net_scan_last_summary" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN net_scan_last_summary TEXT NOT NULL DEFAULT ''")
        # net_scan_lock_ts is the authoritative marker that a background scan is in progress.
        # (Older builds used net_scan_is_running/net_scan_run_started_ts; we keep compatibility by
        # simply not requiring those legacy columns.)
        if "net_scan_lock_ts" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN net_scan_lock_ts DATETIME")
        # AD TLS validation / custom CA
        if "ad_tls_validate" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN ad_tls_validate BOOLEAN NOT NULL DEFAULT 0")
        if "ad_ca_pem" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN ad_ca_pem TEXT NOT NULL DEFAULT ''")
        
        # Access control: allowed groups
        if "allowed_app_group_dns" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN allowed_app_group_dns TEXT NOT NULL DEFAULT ''")
        if "allowed_settings_group_dns" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN allowed_settings_group_dns TEXT NOT NULL DEFAULT ''")
        
        # Cached AD groups (for UI/auto-complete)
        if "groups_cache_json" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN groups_cache_json TEXT NOT NULL DEFAULT '[]'")
        if "groups_cache_ts" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN groups_cache_ts DATETIME")
        
        # Last AD connection test result (for UX)
        if "last_ad_test_ts" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN last_ad_test_ts DATETIME")
        if "last_ad_test_ok" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN last_ad_test_ok BOOLEAN NOT NULL DEFAULT 0")
        if "last_ad_test_message" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN last_ad_test_message VARCHAR(512) NOT NULL DEFAULT ''")

        # Chart colors
        if "net_scan_chart_line_color" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN net_scan_chart_line_color VARCHAR(20) NOT NULL DEFAULT '#0d6efd'")
        if "net_scan_chart_fill_color" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN net_scan_chart_fill_color VARCHAR(30) NOT NULL DEFAULT 'rgba(13,110,253,0.16)'")
        if "net_scan_chart_point_color" not in cols:
            add("ALTER TABLE app_settings ADD COLUMN net_scan_chart_point_color VARCHAR(20) NOT NULL DEFAULT '#0d6efd'")
        
