"""Application service layer.

Stage 2 refactor: split former `services.py` into a package.

We keep a stable import surface for routers:
    from app.services import ...
"""

from .audit import audit_login
from .local_auth import local_authenticate
from .ad import ad_authenticate, ad_cfg_from_settings, ad_mgmt_cfg_from_settings, ad_test_and_load_groups
from .settings import save_settings
from .groups import get_groups_cache, groups_dn_to_name_map
from .auth.backend import authenticate as unified_authenticate

__all__ = [
    "audit_login",
    "local_authenticate",
    "ad_cfg_from_settings",
    "ad_mgmt_cfg_from_settings",
    "ad_test_and_load_groups",
    "ad_authenticate",
    "unified_authenticate",
    "save_settings",
    "get_groups_cache",
    "groups_dn_to_name_map",
]
