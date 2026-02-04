"""Settings service package (Stage 1).

This package introduces typed settings (schema), DB persistence (storage),
UI validations (validator) and config export/import.
"""

from .schema import AppSettingsSchema, CURRENT_SCHEMA_VERSION
from .storage import get_settings, save_settings
from .validator import validate_ad, validate_host_query, validate_net_scan, ValidateResult
from .export_import import export_settings, import_settings

__all__ = [
    "AppSettingsSchema",
    "CURRENT_SCHEMA_VERSION",
    "get_settings",
    "save_settings",
    "validate_ad",
    "validate_host_query",
    "validate_net_scan",
    "ValidateResult",
    "export_settings",
    "import_settings",
]
