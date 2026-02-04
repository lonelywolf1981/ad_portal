from __future__ import annotations

"""Legacy-compatible settings writer.

Routers in current codebase import `save_settings` from `app.services`.
Stage 1 introduces a typed settings schema + storage layer.

This module keeps the old signature:
    save_settings(db, st, form)

So we can update routers incrementally without breaking the app.
"""

from typing import Any

from sqlalchemy.orm import Session

from ..models import AppSettings

from .settings.schema import AppSettingsSchema
from .settings.storage import save_settings as save_settings_typed


def _split_cidrs(text: str) -> list[str]:
    out: list[str] = []
    for raw in (text or "").splitlines():
        s = raw.strip()
        if not s:
            continue
        if s.startswith("#") or s.startswith(";"):
            continue
        out.append(s)
    return out


def save_settings(db: Session, st: AppSettings, form: dict[str, Any]) -> None:
    """Persist settings coming from HTML form.

    `st` is kept for backward compatibility and is not required.
    """

    # Normalize bool checkbox
    net_scan_enabled = bool(form.get("net_scan_enabled"))

    payload = {
        "auth_mode": (form.get("auth_mode") or "local").strip(),
        "ad": {
            "dc_short": (form.get("ad_dc_short") or "").strip(),
            "domain": (form.get("ad_domain") or "").strip(),
            "conn_mode": (form.get("ad_conn_mode") or "ldaps").strip(),
            "bind_username": (form.get("ad_bind_username") or "").strip(),
            "bind_password": form.get("ad_bind_password") or "",
            "allowed_app_group_dns": list(form.get("allowed_app_group_dns") or []),
            "allowed_settings_group_dns": list(form.get("allowed_settings_group_dns") or []),
        },
        "host_query": {
            "username": (form.get("host_query_username") or "").strip(),
            "password": form.get("host_query_password") or "",
            "timeout_s": form.get("host_query_timeout_s") or 60,
            "test_host": (form.get("host_query_test_host") or "").strip(),
        },
        "net_scan": {
            "enabled": net_scan_enabled,
            "cidrs": _split_cidrs(form.get("net_scan_cidrs") or ""),
            "interval_min": form.get("net_scan_interval_min") or 120,
            "concurrency": form.get("net_scan_concurrency") or 64,
            "method_timeout_s": form.get("net_scan_method_timeout_s") or 20,
            "probe_timeout_ms": form.get("net_scan_probe_timeout_ms") or 350,
        },
    }

    data = AppSettingsSchema.model_validate(payload)
    save_settings_typed(db, data, keep_secrets_if_blank=True)
