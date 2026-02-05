from __future__ import annotations

import json
from typing import Any

from pydantic import ValidationError

from .schema import AppSettingsSchema, CURRENT_SCHEMA_VERSION


def _split_multiline_list(text: str) -> list[str]:
    out: list[str] = []
    for raw in (text or "").splitlines():
        s = raw.strip()
        if not s:
            continue
        if s.startswith("#") or s.startswith(";"):
            continue
        out.append(s)
    return out


def _coerce_legacy_payload(raw: Any) -> Any:
    """Coerce older exported JSON formats into the current AppSettingsSchema shape.

    Over iterations we had at least two JSON shapes:
    1) Current typed schema: {schema_version, auth:{mode}, ad:{dc_short,...}, host_query:{...}, net_scan:{...}}
    2) Legacy export: {auth_mode, ad:{dc,domain,conn_mode,...}, host_query:{...}, net_scan:{cidrs:"...\n..."}, ...}
    """

    if not isinstance(raw, dict):
        return raw

    # If it already looks like the typed schema, leave it as is.
    if isinstance(raw.get("ad"), dict) and "dc_short" in (raw.get("ad") or {}):
        return raw

    # Legacy export shape: map fields.
    if isinstance(raw.get("ad"), dict) and ("dc" in raw["ad"] or "domain" in raw["ad"]):
        ad = raw.get("ad") or {}
        hq = raw.get("host_query") or {}
        ns = raw.get("net_scan") or {}

        # auth
        auth_mode = (raw.get("auth_mode") or (raw.get("auth") or {}).get("mode") or "local")

        # net_scan.cidrs may be multiline string in legacy exports.
        cidrs = ns.get("cidrs")
        if isinstance(cidrs, str):
            cidrs_list = _split_multiline_list(cidrs)
        elif isinstance(cidrs, list):
            cidrs_list = [str(x).strip() for x in cidrs if str(x).strip()]
        else:
            cidrs_list = []

        return {
            "schema_version": int(raw.get("schema_version") or CURRENT_SCHEMA_VERSION),
            "core": raw.get("core") or {},
            "auth": {"mode": (str(auth_mode).strip() or "local")},
            "auth_mode": (str(auth_mode).strip() or "local"),
            "ad": {
                "dc_short": ad.get("dc") or ad.get("dc_short") or ad.get("dcShort") or "",
                "domain": ad.get("domain") or "",
                "conn_mode": (ad.get("conn_mode") or ad.get("connMode") or "ldaps"),
                "bind_username": ad.get("bind_username") or ad.get("bindUser") or "",
                "bind_password": ad.get("bind_password") or ad.get("bindPassword") or "",
                "tls_validate": bool(ad.get("tls_validate") or ad.get("tlsValidate") or False),
                "ca_pem": ad.get("ca_pem") or ad.get("caPem") or "",
                "allowed_app_group_dns": raw.get("allowed_app_group_dns") or ad.get("allowed_app_group_dns") or [],
                "allowed_settings_group_dns": raw.get("allowed_settings_group_dns")
                or ad.get("allowed_settings_group_dns")
                or [],
            },
            "host_query": {
                "username": hq.get("username") or "",
                "password": hq.get("password") or "",
                "timeout_s": int(hq.get("timeout_s") or 60),
                "test_host": hq.get("test_host") or "",
            },
            "net_scan": {
                "enabled": bool(ns.get("enabled") or False),
                "cidrs": cidrs_list,
                "interval_min": int(ns.get("interval_min") or 120),
                "concurrency": int(ns.get("concurrency") or 64),
                "method_timeout_s": int(ns.get("method_timeout_s") or 20),
                "probe_timeout_ms": int(ns.get("probe_timeout_ms") or 350),
            },
        }

    return raw


def export_settings(data: AppSettingsSchema, *, include_secrets: bool = False) -> dict[str, Any]:
    """Export settings to JSON-serializable dict.

    By default, secrets are redacted.
    """

    d = data.model_dump()
    d["schema_version"] = int(d.get("schema_version") or CURRENT_SCHEMA_VERSION)

    if not include_secrets:
        # Redact plaintext secrets.
        d.setdefault("ad", {})
        d["ad"]["bind_password"] = ""
        d.setdefault("host_query", {})
        d["host_query"]["password"] = ""

    return d


def import_settings(payload: str | bytes) -> AppSettingsSchema:
    """Parse + validate settings JSON.

    Accepts string/bytes. Raises ValueError on errors.
    """

    try:
        if isinstance(payload, bytes):
            payload = payload.decode("utf-8", errors="replace")
        raw = json.loads(payload)
    except Exception as e:
        raise ValueError(f"Invalid JSON: {e}")

    try:
        raw = _coerce_legacy_payload(raw)
        return AppSettingsSchema.model_validate(raw)
    except ValidationError as e:
        raise ValueError(str(e))