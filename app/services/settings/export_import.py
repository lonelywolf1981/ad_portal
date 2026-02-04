from __future__ import annotations

import json
from typing import Any

from pydantic import ValidationError

from .schema import AppSettingsSchema, CURRENT_SCHEMA_VERSION


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
        return AppSettingsSchema.model_validate(raw)
    except ValidationError as e:
        raise ValueError(str(e))